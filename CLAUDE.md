# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make build      # cargo build --release
make test       # cargo test
make clippy     # cargo clippy --all-targets -- -D warnings
make fmt        # cargo fmt
make ci         # clippy + test + build (full pre-merge check)
make qlty       # qlty check --all (clippy + security scan)
```

Run a single test:
```bash
cargo test test_valid_jwt          # by name
cargo test auth::tests             # by module path
```

## Architecture

The proxy is a single Rust binary implementing the PostgreSQL wire protocol (pgwire crate). One `AppFactory` is created **per accepted socket** inside a `tokio::spawn`, so all shared state between handlers is wrapped in `Arc`.

### Connection lifecycle

```
Client TCP socket
  └─ AppFactory (Arc, per socket)
       ├─ StartupHandler — validates JWT, acquires backend conn, stores in Session
       └─ ProxyQueryHandler — forwards queries over Session's backend conn
            └─ Session (Arc<Mutex<Option<deadpool_postgres::Object>>>)
                 └─ Drop impl: takes & drops the connection → returned to pool
```

`Session` is the shared "connection slot" — `StartupHandler` populates it after auth, `ProxyQueryHandler` takes it out for each query and puts it back. When the socket closes, `Arc<AppFactory>` is dropped, which drops `Arc<Session>`, which runs `Session::drop` to return the connection to the pool.

### Per-user connection pools

`ConnectionManager` (`pool.rs`) maintains an LRU cache of up to 1024 `deadpool_postgres::Pool` instances keyed by `user_id` (JWT `sub`). Every `check_out` runs:
```sql
SET ROLE authenticated;
SET request.jwt.claim.sub = '<user_id>';
```
This wires RLS: `auth.uid()` in Postgres reads `current_setting('request.jwt.claim.sub')`.

### Auth flow (`auth.rs`)

JWT arrives in the pgwire `StartupMessage` `user` field. `JwtAuthenticator::validate_token` decodes it with HMAC-SHA256. On success, `sub` is stored in `ClientInfo::metadata` under `METADATA_USER_ID` for downstream handlers.

### Query handling (`handler.rs`)

- **Simple query**: `do_query` forwards via `simple_query`, detects SELECT vs. command, appends transaction state messages for `BEGIN`/`COMMIT`/`ROLLBACK`.
- **Extended query**: `do_query` substitutes `$1`/`$2` placeholders (text format only) via `substitute_params`, then runs as a simple query. Binary parameters are not supported.

### Known limitations

- **Session cleanup is deferred**: `Session::drop` drops the `deadpool_postgres::Object`, returning it to the pool. `RecyclingMethod::Clean` runs `DISCARD ALL` at the *start of the next checkout*, not on disconnect. This is intentional — the next connection start does the cleanup.
- **Extended query binary parameters not supported**: `substitute_params` assumes `Bytes` contains UTF-8 text. Binary-encoded parameters (e.g. raw integer bytes) are left unsubstituted. Not an issue for tch, which only sends `SqlParam::Text(String)` and `SqlParam::Null`.
- **JWT expiry mid-session**: JWT is only validated at startup. If it expires during a session, the client must reconnect with a fresh token.

## Deployment

Managed via [Tanka](https://tanka.dev/). Manifests live in `tanka/environments/`:

```bash
cd tanka
tk eval environments/dev    # preview rendered manifests
tk apply environments/dev   # deploy to cluster
```

Environments: `dev` → `supa-dev` namespace, `prod` → `supa-prod` namespace.

Docker image is published to GHCR on git tag (see CI). `SUPABASE_JWT_SECRET` and `DATABASE_URL` are required env vars at runtime.
