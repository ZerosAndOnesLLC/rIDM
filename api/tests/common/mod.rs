//! Shared integration-test harness.
//!
//! One Postgres and one Redis per test binary, migrated once; every test gets
//! its own tenant and its own small connection pools so tests run in parallel
//! without interfering.
//!
//! Set `RIDM_TEST_DATABASE_URL` and `RIDM_TEST_REDIS_URL` to use existing
//! servers (CI service containers, or the docker-compose stack). Otherwise
//! testcontainers starts `postgres:18.6-alpine` and `redis:8.10.1-alpine3.23`
//! as named, reusable containers (`ridm-test-postgres`, `ridm-test-redis`) that
//! later test binaries and runs pick up again. Remove them with
//! `docker rm -f ridm-test-postgres ridm-test-redis`.

#![allow(dead_code)]

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
pub const REDIS_TAG: &str = "8.10.1-alpine3.23";

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
    pub database_url: String,
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
                .with_tag(REDIS_TAG)
                .with_container_name("ridm-test-redis")
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
    // suite meaningless. If we were handed a superuser, create an ordinary
    // application role, migrate as it (so it owns the tables), and use it.
    let database_url = ensure_app_role(&database_url).await;

    // Migrate once with a throwaway pool owned by this runtime.
    let config = test_config(&database_url, &redis_url, "http://127.0.0.1:0");
    let db = ridm_api::db::connect(&config)
        .await
        .expect("connect postgres");
    ridm_api::db::migrate(&db).await.expect("migrate");
    db.close().await;

    Infra {
        database_url,
        redis_url,
        _postgres: pg,
        _redis: redis,
    }
}

pub const APP_ROLE: &str = "ridm_test_app";
pub const APP_ROLE_PASSWORD: &str = "ridm_test_app";

/// Returns a connection URL for a non-superuser role. When `url` is already an
/// ordinary role it is returned unchanged.
async fn ensure_app_role(url: &str) -> String {
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
        return url.to_string();
    }
    let db_name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut conn)
        .await
        .expect("current database");
    let statements = [
        format!(
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN \
             CREATE ROLE {APP_ROLE} LOGIN PASSWORD '{APP_ROLE_PASSWORD}' \
             NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS; END IF; END $$"
        ),
        format!("GRANT CONNECT, CREATE, TEMP ON DATABASE \"{db_name}\" TO {APP_ROLE}"),
        format!("GRANT ALL ON SCHEMA public TO {APP_ROLE}"),
        // Tables created earlier by the superuser (e.g. a CI migrate step).
        format!("GRANT ALL ON ALL TABLES IN SCHEMA public TO {APP_ROLE}"),
        format!("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}"),
    ];
    for stmt in statements {
        // DDL built from constants above, not from user input.
        sqlx::raw_sql(sqlx::AssertSqlSafe(stmt.clone()))
            .execute(&mut conn)
            .await
            .unwrap_or_else(|e| panic!("{stmt}: {e}"));
    }
    conn.close().await.expect("close bootstrap connection");

    let mut app_url = url::Url::parse(url).expect("parse database url");
    app_url.set_username(APP_ROLE).expect("set username");
    app_url
        .set_password(Some(APP_ROLE_PASSWORD))
        .expect("set password");
    app_url.to_string()
}

pub fn test_config(database_url: &str, redis_url: &str, public_url: &str) -> Config {
    Config {
        database_url: database_url.to_string(),
        redis_url: redis_url.to_string(),
        public_url: public_url.parse().expect("public url"),
        master_key: SecretBytes::new(vec![7u8; 32]),
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
        let state = AppState::new(config, db, redis);
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
