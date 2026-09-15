//! Shared integration-test harness.
//!
//! One Postgres and one Redis per test binary, migrated once; every test gets
//! its own tenant and its own small connection pools so tests run in parallel
//! without interfering.
//!
//! Set `RIDM_TEST_DATABASE_URL` and `RIDM_TEST_REDIS_URL` to use existing
//! servers (CI service containers, or the docker-compose stack). Otherwise
//! testcontainers starts `postgres:18.6-alpine` and `redis:8.10.1-alpine3.23`
//! as named, reusable containers (`ridm-test-postgres`, `ridm-test-valkey`) that
//! later test binaries and runs pick up again. Remove them with
//! `docker rm -f ridm-test-postgres ridm-test-valkey`.

#![allow(dead_code)]

pub mod admin;

use std::net::SocketAddr;
use std::sync::LazyLock;

use ridm_api::config::{Config, LogFormat};
use ridm_api::db::Db;
use ridm_api::state::AppState;
use ridm_api::util::secret::SecretBytes;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, ImageExt, ReuseDirective};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::redis::Redis;
use tokio::sync::OnceCell;
use uuid::Uuid;

pub const POSTGRES_TAG: &str = "18.6-alpine";
/// Valkey speaks the Redis protocol; the testcontainers `redis` module drives it.
pub const VALKEY_IMAGE: &str = "valkey/valkey";
pub const VALKEY_TAG: &str = "9.1.2-alpine3.24";

/// Every `#[tokio::test]` runs on its own short-lived runtime. Anything that
/// must outlive a single test (containers, their Docker client, the
/// one-time migration) runs on this dedicated runtime instead. Per-test pools
/// are created on the test's own runtime so their sockets die with it.
static RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .thread_name("ridm-test-infra")
        .build()
        .expect("infra runtime")
});

pub struct Infra {
    /// Non-superuser application role (DML only): what the API uses.
    pub database_url: String,
    /// Role that owns the schema and runs migrations; `None` when the
    /// provided URL was not a superuser (then `database_url` did both).
    pub migrator_url: Option<String>,
    /// The URL we were given (superuser in CI / testcontainers); used by the
    /// migration suite to create throwaway databases.
    pub admin_url: String,
    pub redis_url: String,
    // Kept alive for the life of the test binary.
    _postgres: Option<ContainerAsync<Postgres>>,
    _redis: Option<ContainerAsync<Redis>>,
}

static INFRA: OnceCell<Infra> = OnceCell::const_new();

pub async fn infra() -> &'static Infra {
    INFRA
        .get_or_init(|| async { RT.spawn(start_infra()).await.expect("infra init") })
        .await
}

async fn start_infra() -> Infra {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let (database_url, redis_url, pg, redis) = match (
        std::env::var("RIDM_TEST_DATABASE_URL"),
        std::env::var("RIDM_TEST_REDIS_URL"),
    ) {
        (Ok(d), Ok(r)) => (d, r, None, None),
        _ => {
            let pg = Postgres::default()
                .with_tag(POSTGRES_TAG)
                .with_container_name("ridm-test-postgres")
                .with_label("dev.ridm.test", "true")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("start postgres container");
            let redis = Redis::default()
                .with_name(VALKEY_IMAGE)
                .with_tag(VALKEY_TAG)
                .with_container_name("ridm-test-valkey")
                .with_label("dev.ridm.test", "true")
                .with_reuse(ReuseDirective::Always)
                .start()
                .await
                .expect("start redis container");
            let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
            let redis_port = redis.get_host_port_ipv4(6379).await.expect("redis port");
            (
                format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres"),
                format!("redis://127.0.0.1:{redis_port}"),
                Some(pg),
                Some(redis),
            )
        }
    };

    // Superusers bypass row level security, which would make the isolation
    // suite meaningless. If we were handed a superuser, create the production
    // role layout: a migrator that owns the schema and an application role
    // with DML privileges only.
    let admin_url = database_url.clone();
    let roles = ensure_roles(&admin_url).await;
    let (database_url, migrator_url) = match roles {
        Some((app, migrator)) => (app, Some(migrator)),
        None => (database_url, None),
    };

    // Migrate once with a throwaway pool owned by this runtime.
    //   * fresh database (superuser path): as the test migrator, so it owns the schema;
    //   * database migrated by some other role (e.g. the compose stack): as the
    //     superuser, then grant the app role access to whatever exists;
    //   * ordinary role given to us: skip when everything is already applied,
    //     otherwise try (and fail loudly if the role may not).
    match &migrator_url {
        Some(migrator) => {
            let migrate_as = if migrations_owned_by_other(&admin_url, MIGRATOR_ROLE).await {
                admin_url.clone()
            } else {
                migrator.clone()
            };
            let config = test_config(&migrate_as, &redis_url, "http://127.0.0.1:0");
            let db = ridm_api::db::connect(&config)
                .await
                .expect("connect postgres");
            ridm_api::db::migrate(&db).await.expect("migrate");
            db.close().await;
            if migrate_as == admin_url {
                // Objects we just created belong to whoever owns the schema
                // (e.g. the compose stack's migrator), not to the superuser.
                transfer_ownership_to_schema_owner(&admin_url).await;
            }
            grant_existing_objects(&admin_url).await;
        }
        None => {
            let config = test_config(&database_url, &redis_url, "http://127.0.0.1:0");
            let db = ridm_api::db::connect(&config)
                .await
                .expect("connect postgres");
            if !fully_migrated(&db).await {
                ridm_api::db::migrate(&db).await.expect("migrate");
            }
            db.close().await;
        }
    }

    Infra {
        database_url,
        migrator_url,
        admin_url,
        redis_url,
        _postgres: pg,
        _redis: redis,
    }
}

pub const APP_ROLE: &str = "ridm_test_app";
pub const APP_ROLE_PASSWORD: &str = "ridm_test_app";
pub const MIGRATOR_ROLE: &str = "ridm_test_migrator";
pub const MIGRATOR_ROLE_PASSWORD: &str = "ridm_test_migrator";

/// When `url` is a superuser, create (idempotently) the migrator and app roles
/// and return `(app_url, migrator_url)`. Returns `None` for ordinary roles.
async fn ensure_roles(url: &str) -> Option<(String, String)> {
    use sqlx::Connection as _;

    let mut conn = sqlx::PgConnection::connect(url)
        .await
        .expect("connect as bootstrap user");
    let is_super: bool =
        sqlx::query_scalar("SELECT rolsuper FROM pg_roles WHERE rolname = current_user")
            .fetch_one(&mut conn)
            .await
            .expect("query rolsuper");
    if !is_super {
        return None;
    }
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut conn)
        .await
        .expect("current database");
    let statements = [
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{MIGRATOR_ROLE}') THEN \
             CREATE ROLE {MIGRATOR_ROLE} LOGIN PASSWORD '{MIGRATOR_ROLE_PASSWORD}' \
             NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END $$"
        ),
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN \
             CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_ROLE_PASSWORD}' \
             NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END $$"
        ),
        format!("GRANT CONNECT, CREATE, TEMP ON DATABASE \"{db_name}\" TO {MIGRATOR_ROLE}"),
        format!("GRANT ALL ON SCHEMA public TO {MIGRATOR_ROLE}"),
        format!("GRANT CONNECT, TEMP ON DATABASE \"{db_name}\" TO {APP_ROLE}"),
        format!("GRANT USAGE ON SCHEMA public TO {APP_ROLE}"),
        // Tables the migrator creates later are automatically usable by the app role.
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATOR_ROLE} IN SCHEMA public \
             GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {APP_ROLE}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATOR_ROLE} IN SCHEMA public \
             GRANT USAGE, SELECT ON SEQUENCES TO {APP_ROLE}"
        ),
        format!(
            "ALTER DEFAULT PRIVILEGES FOR ROLE {MIGRATOR_ROLE} IN SCHEMA public \
             GRANT EXECUTE ON FUNCTIONS TO {APP_ROLE}"
        ),
    ];
    for stmt in statements {
        // DDL built from constants above, not from user input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt.clone()))
            .execute(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    conn.close().await.expect("close bootstrap connection");

    let with_creds = |user: &str, pass: &str| {
        let mut u = url::Url::parse(url).expect("parse database url");
        u.set_username(user).expect("set username");
        u.set_password(Some(pass)).expect("set password");
        u.to_string()
    };
    Some((
        with_creds(APP_ROLE, APP_ROLE_PASSWORD),
        with_creds(MIGRATOR_ROLE, MIGRATOR_ROLE_PASSWORD),
    ))
}

/// Is `_sqlx_migrations` present and owned by a role other than `role`?
async fn migrations_owned_by_other(admin_url: &str, role: &str) -> bool {
    use sqlx::Connection as _;
    let mut conn = sqlx::PgConnection::connect(admin_url)
        .await
        .expect("connect admin");
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = '_sqlx_migrations'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("query owner");
    conn.close().await.expect("close");
    owner.is_some_and(|o| o != role)
}

/// Hand every table/sequence/function owned by the admin role to the owner of
/// `_sqlx_migrations`, so a database migrated by another role stays consistent.
async fn transfer_ownership_to_schema_owner(admin_url: &str) {
    use sqlx::Connection as _;
    let mut conn = sqlx::PgConnection::connect(admin_url)
        .await
        .expect("connect admin");
    let owner: Option<String> = sqlx::query_scalar(
        "SELECT tableowner FROM pg_tables WHERE schemaname = 'public' AND tablename = '_sqlx_migrations'",
    )
    .fetch_optional(&mut conn)
    .await
    .expect("query owner");
    let Some(owner) = owner else { return };
    let stmt = format!(
        "DO $$ DECLARE r record; BEGIN \
           FOR r IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user LOOP \
             EXECUTE format('ALTER TABLE public.%I OWNER TO {owner}', r.tablename); END LOOP; \
           FOR r IN SELECT sequencename FROM pg_sequences WHERE schemaname = 'public' AND sequenceowner = current_user LOOP \
             EXECUTE format('ALTER SEQUENCE public.%I OWNER TO {owner}', r.sequencename); END LOOP; \
           FOR r IN SELECT p.proname, pg_get_function_identity_arguments(p.oid) AS args \
                    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace \
                    WHERE n.nspname = 'public' AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = current_user) LOOP \
             EXECUTE format('ALTER FUNCTION public.%I(%s) OWNER TO {owner}', r.proname, r.args); END LOOP; \
         END $$"
    );
    sqlx::raw_sql(sqlx::AssertSqlSafe(stmt))
        .execute(&mut conn)
        .await
        .expect("transfer ownership");
    conn.close().await.expect("close");
}

/// Grant the test app role DML on everything that already exists (objects
/// created by roles other than the test migrator).
async fn grant_existing_objects(admin_url: &str) {
    use sqlx::Connection as _;
    let mut conn = sqlx::PgConnection::connect(admin_url)
        .await
        .expect("connect admin");
    for stmt in [
        format!(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {APP_ROLE}"
        ),
        format!("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}"),
        format!("GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO {APP_ROLE}"),
    ] {
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt.clone()))
            .execute(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    conn.close().await.expect("close");
}

/// Every embedded migration is recorded as applied.
async fn fully_migrated(db: &Db) -> bool {
    let applied: Vec<i64> =
        match sqlx::query_scalar("SELECT version FROM _sqlx_migrations WHERE success")
            .fetch_all(db)
            .await
        {
            Ok(v) => v,
            Err(_) => return false,
        };
    ridm_api::db::MIGRATOR
        .iter()
        .all(|m| applied.contains(&m.version))
}

pub fn test_config(database_url: &str, redis_url: &str, public_url: &str) -> Config {
    Config {
        database_url: database_url.to_string(),
        redis_url: redis_url.to_string(),
        public_url: public_url.parse().expect("public url"),
        ui_url: public_url.parse().expect("ui url"),
        master_key: SecretBytes::new(vec![7u8; 32]),
        master_key_version: 1,
        master_key_previous: vec![],
        bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
        log_format: LogFormat::Pretty,
        docs_enabled: true,
        cookie_secure: false,
        trusted_proxies: vec![],
        tls: None,
        db_pool_min: 1,
        db_pool_max: 8,
        migrate_on_start: false,
        // Cheap parameters keep the test suite fast; production uses Config defaults.
        argon2: ridm_api::config::Argon2Params {
            m_cost: 8 * 1024,
            t_cost: 1,
            p_cost: 1,
        },
        smtp: None,
        bootstrap: None,
    }
}

/// A tenant created for one test.
#[derive(Debug, Clone)]
pub struct TestTenant {
    pub id: Uuid,
    pub slug: String,
}

/// A running in-process server bound to a random port, with its own tenant.
pub struct TestApp {
    pub base_url: String,
    pub http: reqwest::Client,
    pub state: AppState,
    pub tenant: TestTenant,
}

impl TestApp {
    pub async fn spawn() -> Self {
        Self::spawn_with(axum::Router::new()).await
    }

    /// Spawn with extra routes merged into the application router.
    pub async fn spawn_with(extra: axum::Router<AppState>) -> Self {
        Self::spawn_configured(extra, |_| {}).await
    }

    /// Spawn with extra routes and a hook that can replace parts of the state
    /// (e.g. mock senders) before the router is built.
    pub async fn spawn_configured(
        extra: axum::Router<AppState>,
        configure: impl FnOnce(&mut AppState),
    ) -> Self {
        let infra = infra().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let base_url = format!("http://{addr}");

        let config = test_config(&infra.database_url, &infra.redis_url, &base_url);
        let db = ridm_api::db::connect(&config)
            .await
            .expect("connect postgres");
        let redis = ridm_api::cache::connect(&config).expect("connect redis");
        let mut state = AppState::new(config, db, redis);
        configure(&mut state);
        let app = ridm_api::build_router_with(state.clone(), extra);
        tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("serve");
        });

        let tenant = create_tenant(&state.db).await;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .cookie_store(true)
            .build()
            .expect("http client");

        Self {
            base_url,
            http,
            state,
            tenant,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `/t/{slug}{path}` for the app's own tenant.
    pub fn tenant_url(&self, path: &str) -> String {
        format!("{}/t/{}{}", self.base_url, self.tenant.slug, path)
    }
}

/// Insert a fresh tenant with a unique slug.
pub async fn create_tenant(db: &Db) -> TestTenant {
    let slug = format!("t-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let id: Uuid =
        sqlx::query_scalar("INSERT INTO tenants (slug, display_name) VALUES ($1, $2) RETURNING id")
            .bind(&slug)
            .bind(format!("Test {slug}"))
            .fetch_one(db)
            .await
            .expect("insert tenant");
    TestTenant { id, slug }
}
