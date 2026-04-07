//! Integration tests for pgwire-supabase-proxy
//!
//! These tests spawn the proxy in-process against a real Postgres backend
//! (orbstack postgres-dev) and exercise it by spawning the real flicknote CLI
//! binary with a valid JWT.
//!
//! Prerequisites:
//!   - kubectl context pointing at orbstack
//!   - postgres-dev svc deployed in the orbstack cluster
//!   - flicknote binary at ~/.cargo/bin/flicknote
//!
//! Run with (from repo root):
//!   ./scripts/run-integration-tests.sh
//!   cargo test --test integration -- --ignored

use pgwire_supabase_proxy::{serve, Config, Claims};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command as TokioCommand;
use tokio::sync::oneshot;
use tokio::time::sleep;

/// Postgres backend connection info — port-forward must be running on 127.0.0.1:5433.
const BACKEND_HOST: &str = "127.0.0.1";
const BACKEND_PORT: u16 = 5433;
const BACKEND_USER: &str = "supabase_admin";
const BACKEND_PASSWORD: &str = "dev-password";
const BACKEND_DB: &str = "supabase";

/// One-time setup: patch auth.uid() once before any test runs.
/// Test JWT secret — must match what psp is configured with.
const TEST_JWT_SECRET: &str = "test-jwt-secret-for-integration-testing-only";
/// A fixed user_id to use for all test operations.
const TEST_USER_ID: &str = "00000000-0000-0000-0000-000000000001";

/// Mint a JWT with the given sub claim using HMAC-SHA256.
fn mint_jwt(sub: &str) -> String {
    let header = Header::new(Algorithm::HS256);
    let claims = Claims {
        sub: sub.to_string(),
        exp: Some(9999999999),
        iat: None,
        role: Some("authenticated".to_string()),
        email: None,
    };
    encode(
        &header,
        &claims,
        &EncodingKey::from_secret(TEST_JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

/// Path to the flicknote CLI binary.
fn flicknote_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/neil".to_string());
    PathBuf::from(home).join(".cargo/bin/flicknote")
}

/// Spawn psp on an ephemeral port, return the port.
async fn spawn_psp(database_url: String, jwt_secret: String) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let port = addr.port();

    let config = Config::new(database_url, jwt_secret, format!("127.0.0.1:{}", port)).unwrap();

    let (_shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    tokio::spawn(async move {
        let _ = serve(config, listener, async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    let mut attempts = 0;
    loop {
        attempts += 1;
        if attempts > 50 {
            panic!("psp server did not start in time");
        }
        if TcpStream::connect(addr).await.is_ok() {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }

    sleep(Duration::from_millis(50)).await;
    port
}

/// Run a flicknote command, return exit status and stdout.
async fn run_flicknote(port: u16, jwt: &str, args: &[&str]) -> (bool, String) {
    let db_url = format!(
        "postgres://authenticated:{}@127.0.0.1:{}/supabase",
        jwt, port
    );

    let mut cmd = TokioCommand::new(flicknote_path());
    cmd.env("FLICKNOTE_TOKEN", jwt)
        .env("DATABASE_URL", &db_url)
        .env("RUST_LOG", "warn")
        .args(args);

    let output = cmd.output().await.expect("failed to spawn flicknote");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let success = output.status.success();
    (success, stdout)
}

/// Build DATABASE_URL for PSP backend connection.
fn psp_database_url() -> String {
    format!(
        "host={} port={} user={} password={} dbname={}",
        BACKEND_HOST, BACKEND_PORT, BACKEND_USER, BACKEND_PASSWORD, BACKEND_DB
    )
}

/// Serial setup test — must run before any parallel test.
/// Uses #[serial] (via crate feature) to ensure it runs first.
/// Patches auth.uid() so RLS works for all subsequent tests.
#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_setup() {
    let url = psp_database_url();
    let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("failed to connect to postgres for auth.uid patch");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("setup postgres connection error: {}", e);
        }
    });

    client
        .batch_execute(
            "CREATE OR REPLACE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$ \
             SELECT nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;",
        )
        .await
        .expect("failed to patch auth.uid()");
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_list() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "list"]).await;

    assert!(status, "note list failed (exit != 0):\nstdout:\n{}\n", stdout);
    assert!(
        stdout.trim().starts_with('[') || stdout.trim().starts_with('{'),
        "note list should produce JSON:\n{}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_list_json() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "list", "--json"]).await;

    assert!(status, "note list --json failed:\nstdout:\n{}\n", stdout);
    assert!(
        stdout.trim().starts_with('['),
        "note list --json should produce a JSON array:\n{}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_count() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "count"]).await;

    assert!(status, "note count failed:\nstdout:\n{}\n", stdout);
    assert!(
        stdout.trim().parse::<u64>().is_ok(),
        "note count should output a number:\n{}",
        stdout
    );
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_find() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "find", "test"]).await;

    assert!(status, "note find failed:\nstdout:\n{}\n", stdout);
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_project_list() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "project", "list"]).await;

    assert!(status, "note project list failed:\nstdout:\n{}\n", stdout);
}

#[tokio::test]
#[ignore = "requires orbstack cluster — run ./scripts/run-integration-tests.sh"]
async fn integration_note_add() {
    let psp_db_url = psp_database_url();
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(
        port,
        &jwt,
        &["note", "add", "__psp_it__integration test note"],
    )
    .await;

    assert!(status, "note add failed:\nstdout:\n{}\n", stdout);
}
