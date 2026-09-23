//! A database of a test's own, for tests that change deployment-wide state
//! (the master-key generations, a rotation of every row) which the shared
//! database must never be left in. Dropped with the guard, also when the test
//! fails.

use sqlx::Connection as _;
use uuid::Uuid;

pub struct ThrowawayDb {
    /// Superuser URL of the new database.
    pub url: String,
    name: String,
    admin_url: String,
}

impl ThrowawayDb {
    /// An empty database; `migrated` applies the schema too.
    pub async fn new(migrated: bool) -> Self {
        let infra = super::infra().await;
        let name = format!("ridm_tmp_{}", &Uuid::new_v4().simple().to_string()[..12]);
        let mut admin = sqlx::PgConnection::connect(&infra.admin_url).await.unwrap();
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE DATABASE {name}")))
            .execute(&mut admin)
            .await
            .expect("the test Postgres role can create databases");
        let mut url = url::Url::parse(&infra.admin_url).unwrap();
        url.set_path(&format!("/{name}"));
        let db = Self {
            url: url.to_string(),
            name,
            admin_url: infra.admin_url.clone(),
        };
        if migrated {
            let pool = sqlx::PgPool::connect(&db.url).await.unwrap();
            ridm_api::db::migrate(&pool).await.unwrap();
            pool.close().await;
        }
        db
    }
}

impl Drop for ThrowawayDb {
    fn drop(&mut self) {
        let (name, admin) = (self.name.clone(), self.admin_url.clone());
        // A runtime of its own: the test's may be shutting down.
        let _ = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                if let Ok(mut c) = sqlx::PgConnection::connect(&admin).await {
                    let _ = sqlx::raw_sql(sqlx::AssertSqlSafe(format!(
                        "DROP DATABASE IF EXISTS {name} WITH (FORCE)"
                    )))
                    .execute(&mut c)
                    .await;
                }
            });
        })
        .join();
    }
}
