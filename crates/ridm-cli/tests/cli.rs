//! The `ridm` binary against a real server: the server's own integration
//! harness (one in-process API on a random port, its own tenant per test)
//! and the CLI run as a separate process, exactly as an operator or a
//! pipeline runs it — flags, stdin, the profile file and the exit code are
//! what is under test, not the functions behind them.

#[path = "../../../api/tests/common/mod.rs"]
mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;

use common::TestApp;
use common::admin::{admin_token, user_with_role};
use ridm_api::models::MASTER_TENANT_ID;
use ridm_api::services::admin_access::OWNER_ROLE;
use ridm_api::services::password::{self, VerifyOutcome};
use ridm_api::services::{tenants, users};
use serde_json::{Value, json};
use tokio::io::AsyncWriteExt as _;
use uuid::Uuid;
use zeroize::Zeroizing;

/// What one run of `ridm` left behind.
#[derive(Debug)]
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("stdout is not JSON ({e}): {self:?}"))
    }

    #[track_caller]
    fn ok(self) -> Self {
        assert_eq!(self.code, 0, "{self:?}");
        self
    }
}

/// A private home for the CLI: its own working directory and profile file,
/// and nothing inherited from the environment of whoever runs the tests.
struct Cli {
    dir: PathBuf,
    env: Vec<(String, String)>,
}

impl Cli {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("ridm-cli-test-{}", Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self { dir, env: vec![] }
    }

    /// Set a variable for every later run (`RIDM_URL`, `RIDM_TOKEN`, …).
    fn with(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    fn config(&self) -> PathBuf {
        self.dir.join("config.json")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    async fn run(&self, args: &[&str]) -> Run {
        self.run_with(args, None, &[]).await
    }

    async fn run_stdin(&self, args: &[&str], stdin: &str) -> Run {
        self.run_with(args, Some(stdin), &[]).await
    }

    /// Async on purpose: the server under test runs on this test's runtime,
    /// so a blocking wait here would stop it answering the CLI.
    async fn run_with(&self, args: &[&str], stdin: Option<&str>, extra: &[(&str, &str)]) -> Run {
        let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_ridm"));
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", &self.dir)
            .env("RIDM_CONFIG", self.config())
            // `ridm` reads a `.env` from its working directory upwards.
            .current_dir(&self.dir)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        for (k, v) in &self.env {
            cmd.env(k, v);
        }
        for (k, v) in extra {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn ridm");
        if let Some(text) = stdin {
            let mut pipe = child.stdin.take().expect("stdin");
            pipe.write_all(text.as_bytes()).await.expect("write stdin");
            drop(pipe);
        }
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(120),
            child.wait_with_output(),
        )
        .await
        .expect("ridm finished within two minutes")
        .expect("ridm output");
        Run {
            code: out.status.code().expect("exited, not killed by a signal"),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }
    }
}

impl Drop for Cli {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A CLI pointed at `app`'s own tenant with a token for its owner, through
/// the environment alone — how a pipeline runs it.
async fn owner_cli(app: &TestApp) -> Cli {
    let token = admin_token(app, app.tenant.id, OWNER_ROLE).await;
    Cli::new()
        .with("RIDM_URL", &app.base_url)
        .with("RIDM_TENANT", &app.tenant.slug)
        .with("RIDM_TOKEN", &token)
}

fn items(page: &Value) -> Vec<Value> {
    page.get("items")
        .and_then(Value::as_array)
        .or_else(|| page.as_array())
        .cloned()
        .unwrap_or_default()
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
}

#[tokio::test]
async fn login_writes_a_private_profile_that_later_commands_use() {
    let app = TestApp::spawn().await;
    let token = admin_token(&app, app.tenant.id, OWNER_ROLE).await;
    let cli = Cli::new();

    let login = cli
        .run_stdin(
            &[
                "--url",
                &app.base_url,
                "--tenant",
                &app.tenant.slug,
                "login",
                "--name",
                "ci",
                "--token-stdin",
            ],
            &format!("{token}\n"),
        )
        .await
        .ok();
    assert!(login.stdout.contains("Logged in to"), "{login:?}");
    assert!(login.stdout.contains("profile `ci`"), "{login:?}");
    #[cfg(unix)]
    assert_eq!(mode(&cli.config()), 0o600, "the profile holds a credential");

    // `login --name` wrote the profile; `profile use` makes it the default,
    // and from then on nothing but the file says where or who.
    cli.run(&["profile", "use", "ci"]).await.ok();
    let me = cli.run(&["whoami", "--output", "json"]).await.ok().json();
    assert_eq!(me["tenant_slug"], app.tenant.slug, "{me}");
    let text = cli.run(&["whoami"]).await.ok();
    assert!(text.stdout.contains(OWNER_ROLE), "{text:?}");

    let list = cli.run(&["profile", "list"]).await.ok();
    assert!(list.stdout.contains("ci"), "{list:?}");
    let show = cli.run(&["profile", "show"]).await.ok();
    assert!(show.stdout.contains(&app.base_url), "{show:?}");
    assert!(
        !show.stdout.contains(&token),
        "profile show must redact the credential: {show:?}"
    );

    // The profile's tenant is used without --tenant: this lists exactly it.
    let tenants = cli
        .run(&["tenant", "list", "--output", "json"])
        .await
        .ok()
        .json();
    let slugs: Vec<Value> = items(&tenants).iter().map(|t| t["slug"].clone()).collect();
    assert_eq!(slugs, vec![json!(app.tenant.slug)]);

    // Logging out forgets the credential but keeps the profile.
    cli.run(&["logout"]).await.ok();
    let after = cli.run(&["whoami"]).await;
    assert_eq!(after.code, 2, "no credential is a usage error: {after:?}");
    assert!(after.stderr.contains("ridm login"), "{after:?}");
    let stored = std::fs::read_to_string(cli.config()).unwrap();
    assert!(!stored.contains(&token), "logout left the token on disk");
    assert!(stored.contains("\"ci\""), "{stored}");

    cli.run(&["logout", "--all"]).await.ok();
    let gone = cli.run(&["profile", "show", "ci"]).await;
    assert_ne!(gone.code, 0, "{gone:?}");
}

#[tokio::test]
async fn a_credential_the_server_refuses_is_reported_and_never_stored() {
    let app = TestApp::spawn().await;
    let cli = Cli::new();
    let run = cli
        .run_stdin(
            &[
                "--url",
                &app.base_url,
                "--tenant",
                &app.tenant.slug,
                "login",
                "--token-stdin",
            ],
            "rpat_not-a-token-this-server-issued\n",
        )
        .await;
    assert_eq!(run.code, 1, "{run:?}");
    assert!(run.stderr.contains("did not get through"), "{run:?}");
    assert!(!cli.config().exists(), "a refused credential was written");

    // A token for an ordinary user (no admin role) is refused the same way.
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();
    let nobody = user_with_role(&app, app.tenant.id, None).await;
    let plain =
        common::admin::token(&app, &tenant, nobody, common::admin::TokenOpts::default()).await;
    let run = cli
        .run_with(
            &[
                "--url",
                &app.base_url,
                "--tenant",
                &app.tenant.slug,
                "login",
            ],
            None,
            &[("RIDM_TOKEN", &plain)],
        )
        .await;
    assert_eq!(run.code, 1, "{run:?}");
    assert!(!cli.config().exists());
}

#[tokio::test]
async fn usage_mistakes_exit_2_before_anything_is_sent() {
    let app = TestApp::spawn().await;
    let cli = Cli::new();

    let run = cli.run(&["tenant", "list"]).await;
    assert_eq!(run.code, 2, "{run:?}");
    assert!(run.stderr.contains("no server URL"), "{run:?}");

    let run = cli.run(&["tenant", "frobnicate"]).await;
    assert_eq!(run.code, 2, "clap refuses an unknown command: {run:?}");

    let run = cli.run(&["--url", &app.base_url, "whoami"]).await;
    assert_eq!(run.code, 2, "a URL but no credential: {run:?}");

    // A document that is not JSON is the caller's mistake, found before any
    // request; a missing file is a failure to read one.
    let cli = owner_cli(&app).await;
    std::fs::write(cli.file("bad.json"), "{ not json").unwrap();
    let bad = cli.file("bad.json");
    let run = cli
        .run(&["tenant", "diff", "-f", bad.to_str().unwrap()])
        .await;
    assert_eq!(run.code, 2, "{run:?}");
    assert!(
        run.stderr.contains("not a tenant configuration document"),
        "{run:?}"
    );
    let run = cli
        .run(&["tenant", "diff", "-f", "/no/such/file.json"])
        .await;
    assert_eq!(run.code, 1, "{run:?}");
    let run = cli.run(&["tenant", "diff"]).await;
    assert_eq!(run.code, 2, "an empty stdin is no document: {run:?}");
}

#[tokio::test]
async fn tenant_configuration_round_trips_through_export_diff_and_import() {
    let app = TestApp::spawn().await;
    let cli = owner_cli(&app).await;
    let doc_path = cli.file("tenant.json");
    let doc_arg = doc_path.to_str().unwrap();

    let export = cli.run(&["tenant", "export", "-o", doc_arg]).await.ok();
    assert!(export.stderr.contains("Wrote"), "{export:?}");
    let mut doc: Value =
        serde_json::from_str(&std::fs::read_to_string(&doc_path).unwrap()).unwrap();
    assert_eq!(doc["format"], "ridm.tenant/1", "{doc}");
    assert_eq!(doc["tenant"]["slug"], app.tenant.slug, "{doc}");
    // Stdout export is the same document.
    let stdout_doc = cli.run(&["tenant", "export"]).await.ok().json();
    assert_eq!(stdout_doc, doc);

    // A tenant matches its own export.
    let same = cli
        .run(&["tenant", "diff", "-f", doc_arg, "--exit-code"])
        .await
        .ok();
    assert!(
        same.stdout
            .contains("0 to create, 0 to update, 0 to delete"),
        "{same:?}"
    );

    // One new role: the plan shows it and --exit-code says so with 3.
    let role = format!("auditors-{}", &Uuid::new_v4().simple().to_string()[..6]);
    let roles = doc
        .as_object_mut()
        .unwrap()
        .entry("roles")
        .or_insert_with(|| json!([]));
    roles
        .as_array_mut()
        .unwrap()
        .push(json!({"name": role, "description": "Reads the audit log"}));
    std::fs::write(&doc_path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();
    let changed = cli
        .run(&["tenant", "diff", "-f", doc_arg, "--exit-code"])
        .await;
    assert_eq!(changed.code, 3, "{changed:?}");
    assert!(changed.stdout.contains(&role), "{changed:?}");
    assert!(changed.stdout.contains("+ "), "{changed:?}");
    assert!(changed.stdout.contains("1 to create"), "{changed:?}");
    // Without --exit-code a non-empty plan is still a successful diff.
    cli.run(&["tenant", "diff", "-f", doc_arg]).await.ok();
    let plan = cli
        .run(&["tenant", "diff", "-f", doc_arg, "--output", "json"])
        .await
        .ok()
        .json();
    assert_eq!(plan["dry_run"], true, "{plan}");

    // An import with nobody to ask refuses instead of assuming yes, and
    // applies nothing.
    let refused = cli.run(&["tenant", "import", "-f", doc_arg]).await;
    assert_eq!(refused.code, 2, "{refused:?}");
    assert!(refused.stderr.contains("--yes"), "{refused:?}");
    let still = cli
        .run(&["tenant", "diff", "-f", doc_arg, "--exit-code"])
        .await;
    assert_eq!(
        still.code, 3,
        "the refused import changed something: {still:?}"
    );

    // From stdin, with --yes: applied, and the tenant matches the document.
    let text = std::fs::read_to_string(&doc_path).unwrap();
    let applied = cli
        .run_stdin(&["tenant", "import", "-f", "-", "--yes"], &text)
        .await
        .ok();
    assert!(
        applied.stdout.contains("1 change(s) applied"),
        "{applied:?}"
    );
    cli.run(&["tenant", "diff", "-f", doc_arg, "--exit-code"])
        .await
        .ok();
    // Applying it again is a no-op.
    let again = cli
        .run(&["tenant", "import", "-f", doc_arg, "--yes"])
        .await
        .ok();
    assert!(again.stdout.contains("0 change(s) applied"), "{again:?}");

    let shown = cli.run(&["tenant", "show"]).await.ok().json();
    assert_eq!(shown["slug"], app.tenant.slug);

    // Everything above went through the environment: no profile was written.
    assert!(
        !cli.config().exists(),
        "a pipeline run wrote a profile file"
    );
}

#[tokio::test]
async fn a_tenant_scoped_admin_cannot_reach_another_tenant() {
    let app = TestApp::spawn().await;
    let other = common::create_tenant(&app.state.db).await;
    let cli = owner_cli(&app).await;

    let run = cli.run(&["tenant", "export", &other.slug]).await;
    assert_eq!(run.code, 1, "{run:?}");
    assert!(run.stderr.contains("403"), "{run:?}");
    let run = cli.run(&["--tenant", &other.slug, "key", "list"]).await;
    assert_eq!(run.code, 1, "{run:?}");
    let run = cli.run(&["tenant", "create", "not-mine"]).await;
    assert_eq!(run.code, 1, "creating tenants is global-only: {run:?}");
    let run = cli.run(&["master-key", "status"]).await;
    assert_eq!(run.code, 1, "{run:?}");
}

#[tokio::test]
async fn users_are_created_and_their_passwords_reset_by_name_or_email() {
    let app = TestApp::spawn().await;
    let cli = owner_cli(&app).await;
    let tenant = tenants::get(&app.state, app.tenant.id).await.unwrap();

    let created = cli
        .run_stdin(
            &[
                "user",
                "create",
                "alice",
                "--email",
                "alice@example.com",
                "--email-verified",
                "--password-stdin",
            ],
            "First-Horse-Battery-9\n",
        )
        .await
        .ok();
    assert!(created.stdout.contains("alice"), "{created:?}");
    let alice = users::find_by_identifier(&app.state, app.tenant.id, "alice")
        .await
        .unwrap()
        .expect("alice exists");
    assert!(alice.email_verified);

    let dup = cli
        .run(&["user", "create", "alice", "--email", "alice2@example.com"])
        .await;
    assert_eq!(dup.code, 1, "{dup:?}");
    assert!(dup.stderr.contains("409"), "{dup:?}");

    // Reset by email, keeping the password past the next sign-in.
    let reset = cli
        .run_stdin(
            &[
                "user",
                "reset",
                "alice@example.com",
                "--password-stdin",
                "--no-must-change",
            ],
            "Second-Horse-Battery-9\n",
        )
        .await
        .ok();
    assert!(reset.stdout.contains("set"), "{reset:?}");
    let alice = users::get(&app.state, app.tenant.id, alice.id)
        .await
        .unwrap();
    assert_eq!(
        password::verify_and_upgrade(
            &app.state,
            app.tenant.id,
            &tenant.settings.password,
            &alice,
            Zeroizing::new("Second-Horse-Battery-9".into()),
        )
        .await
        .unwrap(),
        VerifyOutcome::Valid { must_change: false }
    );

    // Reset by username without a password: one is generated, shown once,
    // and must be changed at the next sign-in.
    let generated = cli
        .run(&["user", "reset", "alice", "--output", "json"])
        .await
        .ok()
        .json();
    let temporary = generated["temporary_password"]
        .as_str()
        .unwrap_or_else(|| panic!("{generated}"))
        .to_string();
    let alice = users::get(&app.state, app.tenant.id, alice.id)
        .await
        .unwrap();
    assert_eq!(
        password::verify_and_upgrade(
            &app.state,
            app.tenant.id,
            &tenant.settings.password,
            &alice,
            Zeroizing::new(temporary),
        )
        .await
        .unwrap(),
        VerifyOutcome::Valid { must_change: true }
    );

    // Anything but exactly one account is refused.
    let run = cli.run(&["user", "reset", "nobody-at-all"]).await;
    assert_eq!(run.code, 1, "{run:?}");

    // A generated temporary password on create.
    let bob = cli
        .run(&[
            "user",
            "create",
            "bob",
            "--temporary-password",
            "--output",
            "json",
        ])
        .await
        .ok()
        .json();
    assert_eq!(bob["username"], "bob", "{bob}");
    assert!(
        bob["temporary_password"]
            .as_str()
            .is_some_and(|p| p.len() >= 12),
        "{bob}"
    );
}

#[tokio::test]
async fn a_client_created_by_the_cli_gets_tokens_with_the_secret_it_printed() {
    let app = TestApp::spawn().await;
    let cli = owner_cli(&app).await;

    let client = cli
        .run(&[
            "client",
            "create",
            "--name",
            "Nightly job",
            "--client-id",
            "nightly",
            "--type",
            "machine",
            "--grant",
            "client_credentials",
            "--output",
            "json",
        ])
        .await
        .ok()
        .json();
    assert_eq!(client["client_id"], "nightly", "{client}");
    let secret = client["client_secret"]
        .as_str()
        .unwrap_or_else(|| panic!("a machine client's secret is shown once: {client}"));

    let res = app
        .http
        .post(app.tenant_url("/token"))
        .basic_auth("nightly", Some(secret))
        .form(&[("grant_type", "client_credentials")])
        .send()
        .await
        .unwrap();
    let status = res.status();
    let body: Value = res.json().await.unwrap();
    assert_eq!(status, 200, "{body}");
    assert!(body["access_token"].is_string(), "{body}");

    // The text form prints the secret too, once, for a person.
    let text = cli
        .run(&[
            "client",
            "create",
            "--name",
            "Web",
            "--type",
            "web",
            "--redirect-uri",
            "https://app.example/cb",
        ])
        .await
        .ok();
    assert!(text.stdout.contains("secret"), "{text:?}");

    // A public client has no secret to print.
    let spa = cli
        .run(&[
            "client",
            "create",
            "--name",
            "SPA",
            "--type",
            "spa",
            "--redirect-uri",
            "https://spa.example/callback",
            "--output",
            "json",
        ])
        .await
        .ok()
        .json();
    assert!(spa.get("client_secret").is_none(), "{spa}");

    // Initial access tokens: created (shown once), listed without the secret, revoked.
    let iat = cli
        .run(&[
            "client",
            "iat",
            "create",
            "--description",
            "ci",
            "--max-uses",
            "1",
            "--output",
            "json",
        ])
        .await
        .ok()
        .json();
    let id = iat["id"]
        .as_str()
        .unwrap_or_else(|| panic!("{iat}"))
        .to_string();
    let list = cli
        .run(&["client", "iat", "list", "--output", "json"])
        .await
        .ok();
    assert!(list.stdout.contains(&id), "{list:?}");
    if let Some(token) = iat["token"].as_str() {
        assert!(!list.stdout.contains(token), "the list shows a secret");
    }
    cli.run(&["client", "iat", "revoke", &id]).await.ok();
}

#[tokio::test]
async fn signing_keys_rotate_from_the_cli() {
    let app = TestApp::spawn().await;
    let cli = owner_cli(&app).await;

    let before = cli
        .run(&["key", "list", "--output", "json"])
        .await
        .ok()
        .json();
    let active: Vec<Value> = items(&before)
        .into_iter()
        .filter(|k| k["status"] == "active")
        .collect();
    assert_eq!(active.len(), 1, "{before}");
    let old_kid = active[0]["kid"].as_str().unwrap().to_string();

    let rotated = cli.run(&["key", "rotate"]).await.ok();
    assert!(rotated.stdout.contains("now signs with"), "{rotated:?}");

    let after = cli
        .run(&["key", "list", "--output", "json"])
        .await
        .ok()
        .json();
    let status_of = |kid: &str| {
        items(&after)
            .into_iter()
            .find(|k| k["kid"] == kid)
            .map(|k| k["status"].as_str().unwrap_or_default().to_string())
    };
    assert_eq!(status_of(&old_kid).as_deref(), Some("retiring"), "{after}");
    let new_active: Vec<Value> = items(&after)
        .into_iter()
        .filter(|k| k["status"] == "active")
        .collect();
    assert_eq!(new_active.len(), 1, "{after}");
    assert_ne!(new_active[0]["kid"], old_kid);

    let filtered = cli
        .run(&["key", "list", "--status", "retiring", "--output", "json"])
        .await
        .ok()
        .json();
    assert!(
        items(&filtered).iter().all(|k| k["status"] == "retiring"),
        "{filtered}"
    );
    let table = cli.run(&["key", "list"]).await.ok();
    assert!(table.stdout.starts_with("KID"), "{table:?}");
}

#[tokio::test]
async fn a_global_owner_creates_tenants_and_reads_the_master_key_status() {
    let app = TestApp::spawn().await;
    let token = admin_token(&app, MASTER_TENANT_ID, OWNER_ROLE).await;
    let cli = Cli::new()
        .with("RIDM_URL", &app.base_url)
        .with("RIDM_TOKEN", &token);
    let slug = format!("cli-{}", &Uuid::new_v4().simple().to_string()[..10]);

    let created = cli
        .run(&["tenant", "create", &slug, "--name", "Made by the CLI"])
        .await
        .ok();
    assert!(created.stdout.contains(&slug), "{created:?}");
    let shown = cli.run(&["tenant", "show", &slug]).await.ok().json();
    assert_eq!(shown["display_name"], "Made by the CLI");
    // The default tenant, without --tenant, is `master`.
    let master = cli.run(&["tenant", "show"]).await.ok().json();
    assert_eq!(master["slug"], "master");

    let taken = cli.run(&["tenant", "create", &slug]).await;
    assert_eq!(taken.code, 1, "{taken:?}");

    let status = cli.run(&["master-key", "status"]).await.ok();
    assert!(status.stdout.contains("older generation"), "{status:?}");
    // Nothing to ask on a pipe: either nothing is pending, or it refuses.
    let rotate = cli.run(&["master-key", "rotate"]).await;
    assert!(
        rotate.code == 0 && rotate.stdout.contains("Nothing to rotate")
            || rotate.code == 2 && rotate.stderr.contains("--yes"),
        "{rotate:?}"
    );
}

#[cfg(feature = "bootstrap")]
#[tokio::test]
async fn bootstrap_mints_a_token_the_rest_of_the_cli_accepts() {
    let app = TestApp::spawn().await;
    let infra = common::infra().await;
    // An owner already exists (as it does after the server's own bootstrap),
    // so the command creates nobody and only mints the token.
    let owner = user_with_role(&app, MASTER_TENANT_ID, Some(OWNER_ROLE)).await;
    let username = users::get(&app.state, MASTER_TENANT_ID, owner)
        .await
        .unwrap()
        .username;
    // The harness's master key is 32 bytes of 7.
    let master_key = "07".repeat(32);
    let server_env = [
        ("DATABASE_URL", infra.database_url.as_str()),
        ("REDIS_URL", infra.redis_url.as_str()),
        ("PUBLIC_URL", app.base_url.as_str()),
        ("MASTER_KEY", master_key.as_str()),
    ];
    let cli = Cli::new();

    let run = cli
        .run_with(
            &[
                "bootstrap",
                "--no-migrate",
                "--username",
                &username,
                "--issue-token",
                "cli-test",
                "--token-days",
                "1",
            ],
            None,
            &server_env,
        )
        .await
        .ok();
    // Stdout is the token alone, so `TOKEN=$(ridm bootstrap …)` works.
    let pat = run.stdout.trim_end_matches('\n');
    assert!(pat.starts_with("rpat_") && !pat.contains('\n'), "{run:?}");
    assert!(run.stderr.contains("Already bootstrapped"), "{run:?}");

    let me = cli
        .run_with(
            &["--url", &app.base_url, "whoami", "--output", "json"],
            None,
            &[("RIDM_TOKEN", pat)],
        )
        .await
        .ok()
        .json();
    assert_eq!(me["username"], username, "{me}");
    assert_eq!(me["tenant_slug"], "master", "{me}");

    // A user who is not there is the caller's mistake.
    let run = cli
        .run_with(
            &[
                "bootstrap",
                "--no-migrate",
                "--username",
                "no-such-admin",
                "--issue-token",
                "x",
            ],
            None,
            &server_env,
        )
        .await;
    assert_eq!(run.code, 2, "{run:?}");
    assert!(run.stdout.is_empty(), "no token on a failure: {run:?}");

    // Without the server's configuration there is nothing to connect to.
    let run = cli.run(&["bootstrap", "--no-migrate"]).await;
    assert_eq!(run.code, 2, "{run:?}");
    assert!(run.stderr.contains("configuration error"), "{run:?}");
}

#[tokio::test]
async fn an_audit_export_is_verified_offline_and_tampering_is_caught() {
    let app = TestApp::spawn().await;
    let cli = owner_cli(&app).await;
    // Setting the CLI up created a user and granted a role: rows to check.
    let mut report = Value::Null;
    for _ in 0..100 {
        report = cli
            .run(&["audit", "verify", "--output", "json"])
            .await
            .ok()
            .json();
        if report["checked"].as_u64().unwrap_or(0) >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let head = report["last_hash"].as_str().expect("a head").to_string();

    let file = cli.file("chain.json");
    let path = file.to_str().unwrap();
    let wrote = cli.run(&["audit", "export", "-o", path]).await.ok();
    assert!(wrote.stderr.contains("Wrote"), "{wrote:?}");
    let checked = cli
        .run(&["audit", "verify", "-f", path, "--head", &head])
        .await
        .ok();
    assert!(checked.stdout.starts_with("Intact:"), "{checked:?}");
    assert!(checked.stdout.contains(&head), "{checked:?}");

    // A head from elsewhere, a predecessor that is not there: refused.
    let wrong = "ab".repeat(32);
    let run = cli
        .run(&["audit", "verify", "-f", path, "--head", &wrong])
        .await;
    assert_ne!(run.code, 0, "{run:?}");
    let run = cli
        .run(&["audit", "verify", "-f", path, "--after", &wrong])
        .await;
    assert_ne!(run.code, 0, "{run:?}");

    // One changed payload in the file breaks it at that row.
    let mut rows: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
    let seq = rows[1]["seq"].as_i64().unwrap();
    rows[1]["payload"]["tampered"] = json!(true);
    let bad = cli.file("tampered.json");
    std::fs::write(&bad, serde_json::to_string(&rows).unwrap()).unwrap();
    let run = cli
        .run(&["audit", "verify", "-f", bad.to_str().unwrap()])
        .await;
    assert_ne!(run.code, 0, "{run:?}");
    assert!(
        run.stderr.contains(&format!("broken at seq {seq}")),
        "{run:?}"
    );

    // A row dropped from the middle is a gap.
    rows.remove(1);
    std::fs::write(&bad, serde_json::to_string(&rows).unwrap()).unwrap();
    let run = cli
        .run(&["audit", "verify", "-f", bad.to_str().unwrap()])
        .await;
    assert!(run.stderr.contains("gap"), "{run:?}");

    // The server's own copy, rewritten, fails the server-side check too.
    let mut tx = ridm_api::db::bypass_tx(&app.state.db).await.unwrap();
    sqlx::query(
        "UPDATE audit_events SET payload = payload || '{\"tampered\": true}' \
         WHERE tenant_id = $1 AND seq = 1",
    )
    .bind(app.tenant.id)
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let run = cli.run(&["audit", "verify"]).await;
    assert_ne!(run.code, 0, "{run:?}");
    assert!(run.stderr.contains("broken at seq 1"), "{run:?}");
}
