//! Integration tests for pgwire-supabase-proxy
//!
//! These tests spawn the proxy in-process against a real Postgres backend
//! (orbstack postgres-dev at 192.168.194.227:5432) and exercise it by spawning
//! the real flicknote CLI binary with a valid JWT.
//!
//! Run with:
//!   cargo test --test integration -- --ignored
//!
//! Prerequisites:
//!   - Postgres at 192.168.194.227:5432 reachable from the host
//!   - flicknote binary at ~/.cargo/bin/flicknote
//!   - Schema deployed via db-init (no bootstrap needed)

use pgwire_supabase_proxy::{serve, Config, Claims};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::oneshot;
use tokio::time::sleep;

/// Postgres backend connection info (orbstack postgres-dev).
const BACKEND_HOST: &str = "192.168.194.227";
const BACKEND_PORT: u16 = 5432;
const BACKEND_USER: &str = "supabase_admin";
const BACKEND_PASSWORD: &str = "dev-password";
const BACKEND_DB: &str = "supabase";

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

    // Spawn the server
    tokio::spawn(async move {
        let _ = serve(config, listener, async move {
            let _ = shutdown_rx.await;
        }).await;
    });

    // Wait for the server to be ready
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

    sleep(Duration::from_millis(50)).await; // extra settle time
    port
}

/// Patch auth.uid() via direct Postgres connection as superuser.
/// This makes auth.uid() read from current_setting('request.jwt.claim.sub').
async fn patch_auth_uid(database_url: &str) {
    let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls)
        .await
        .expect("failed to connect to postgres for auth.uid patch");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("postgres connection error: {}", e);
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

/// Run a flicknote command, return exit status and stdout.
async fn run_flicknote(port: u16, jwt: &str, args: &[&str]) -> (bool, String) {
    let db_url = format!(
        "postgres://authenticated:{}@127.0.0.1:{}/supabase",
        jwt, port
    );

    let mut cmd = Command::new(flicknote_path());
    cmd.env("FLICKNOTE_TOKEN", jwt)
        .env("DATABASE_URL", &db_url)
        .env("RUST_LOG", "warn")
        .args(args);

    let output = cmd.output().await.expect("failed to spawn flicknote");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let success = output.status.success();
    (success, stdout)
}

/// Clean up test notes created during the test.
async fn cleanup_notes(database_url: &str, _jwt: &str) {
    let (client, connection) = tokio_postgres::connect(database_url, tokio_postgres::NoTls)
        .await
        .expect("failed to connect for cleanup");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("cleanup connection error: {}", e);
        }
    });

    // Run cleanup as the test user (via SET ROLE)
    let cleanup_sql = format!(
        "SET ROLE authenticated; \
         SET request.jwt.claim.sub = '{}'; \
         DELETE FROM notes WHERE title LIKE '__psp_it__%';",
        TEST_USER_ID
    );
    let _ = client.batch_execute(&cleanup_sql).await;
}

/// Build the DATABASE_URL for direct Postgres connections (admin).
fn admin_database_url() -> String {
    format!(
        "host={} port={} user={} password={} dbname={}",
        BACKEND_HOST, BACKEND_PORT, BACKEND_USER, BACKEND_PASSWORD, BACKEND_DB
    )
}

/// Build the DATABASE_URL for the PSP config (psp connects as superuser to build per-user pools).
fn psp_database_url() -> String {
    format!(
        "host={} port={} user={} password={} dbname={}",
        BACKEND_HOST, BACKEND_PORT, BACKEND_USER, BACKEND_PASSWORD, BACKEND_DB
    )
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_list() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    // Patch auth.uid() so RLS works
    patch_auth_uid(&admin_url).await;

    // Spawn psp
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "list"]).await;

    assert!(
        status,
        "note list failed (exit != 0):\nstdout:\n{}\n",
        stdout
    );
    // Should produce JSON output with notes array (possibly empty)
    assert!(
        stdout.trim().starts_with('[') || stdout.trim().starts_with('{'),
        "note list should produce JSON:\n{}",
        stdout
    );

    cleanup_notes(&admin_url, &jwt).await;
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_list_json() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    patch_auth_uid(&admin_url).await;
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "list", "--json"]).await;

    assert!(status, "note list --json failed:\nstdout:\n{}\n", stdout);
    assert!(
        stdout.trim().starts_with('['),
        "note list --json should produce a JSON array:\n{}",
        stdout
    );
    cleanup_notes(&admin_url, &jwt).await;
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_count() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    patch_auth_uid(&admin_url).await;
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "count"]).await;

    assert!(status, "note count failed:\nstdout:\n{}\n", stdout);
    // Output should contain a number
    assert!(
        stdout.trim().parse::<u64>().is_ok(),
        "note count should output a number:\n{}",
        stdout
    );
    cleanup_notes(&admin_url, &jwt).await;
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_find() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    patch_auth_uid(&admin_url).await;
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "find", "test"]).await;

    assert!(status, "note find failed:\nstdout:\n{}\n", stdout);
    cleanup_notes(&admin_url, &jwt).await;
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_project_list() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    patch_auth_uid(&admin_url).await;
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(port, &jwt, &["note", "project", "list"]).await;

    assert!(
        status,
        "note project list failed:\nstdout:\n{}\n",
        stdout
    );
    cleanup_notes(&admin_url, &jwt).await;
}

#[tokio::test]
#[ignore = "requires orbstack postgres-dev at 192.168.194.227:5432"]
async fn integration_note_add() {
    let admin_url = admin_database_url();
    let psp_db_url = psp_database_url();

    patch_auth_uid(&admin_url).await;
    let port = spawn_psp(psp_db_url, TEST_JWT_SECRET.to_string()).await;

    let jwt = mint_jwt(TEST_USER_ID);
    let (status, stdout) = run_flicknote(
        port,
        &jwt,
        &["note", "add", "__psp_it__integration test note"],
    )
    .await;

    assert!(
        status,
        "note add failed:\nstdout:\n{}\n",
        stdout
    );
    cleanup_notes(&admin_url, &jwt).await;
}
