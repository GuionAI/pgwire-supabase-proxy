# pgwire-supabase-proxy

A Postgres wire protocol proxy that validates Supabase JWTs and enforces RLS (Row Level Security) via `SET ROLE authenticated` + `SET request.jwt.claim.sub`. Built for the `tw` CLI (TaskChampion) running in sandbox pods inside the cluster.

## Concept: PostgREST over pgwire

PostgREST validates a JWT, sets `SET ROLE authenticated` and `SET request.jwt.claim.sub = $sub`, then forwards SQL. This proxy does the same over the pgwire (PostgreSQL binary) protocol instead of HTTP.

```
pgwire client (tw CLI)
  │ JWT as "user" field in startup
  ▼
pgwire-supabase-proxy
  │ Validates JWT using SUPABASE_JWT_SECRET
  │ Acquires backend connection from CNPG pool
  │ SET ROLE authenticated
  │ SET request.jwt.claim.sub = $user_id
  ▼
CNPG pooler → Postgres (RLS enforces tenant isolation)
```

The `auth.uid()` function in Postgres reads `current_setting('request.jwt.claim.sub')`, so no application-level filtering is needed — RLS does the work.

## Auth flow

1. Client sends pgwire `StartupMessage` with JWT as the `user` field (no password)
2. Proxy validates the JWT, extracts the `sub` claim
3. Proxy acquires a backend connection from the per-user pool
4. Proxy runs `SET ROLE authenticated` and `SET request.jwt.claim.sub = '$user_id'`
5. Proxy returns `AuthenticationOk` and holds the connection for the session
6. All subsequent queries are forwarded over the same backend connection
7. On session end: `DISCARD ALL` and return connection to pool

## SQL parameter substitution (Extended Query Protocol)

When clients use the extended query protocol (prepared statements with `$1`, `$2`, ... placeholders), parameters are substituted into the SQL string before forwarding. Parameters are expected in **text format** (UTF-8 strings). Binary format parameters are not yet supported.

## Transaction handling

The proxy preserves transaction state per session. `BEGIN`/`COMMIT`/`ROLLBACK` are forwarded to the backend, and pgwire `TransactionStart`/`TransactionEnd` responses are returned to the client.

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SUPABASE_JWT_SECRET` | Yes | Supabase JWT signing secret (HMAC-SHA256) |
| `DATABASE_URL` | Yes | Backend Postgres connection string (postgresql://user:pass@host:5432/db) |
| `LISTEN_ADDR` | No | Listen address (default: `0.0.0.0:5432`) |
| `POOL_SIZE` | No | Connections per user pool (default: `10`) |

## Building

```bash
cargo build --release
```

## Docker

```bash
docker build -t pgwire-supabase-proxy .
```

## Deployment

Managed via Tanka. Environments:
- `environments/dev/` — `supa-dev` namespace, `0.0.0.0:5432`
- `environments/prod/` — `supa-prod` namespace

```bash
cd tanka
tk eval environments/dev   # preview manifests
tk show environments/dev  # full manifests
tk apply environments/dev # deploy
```

## Limitations

- **Extended query binary parameters**: Not yet supported. Clients must use text format for parameters.
- **Session cleanup**: The `DISCARD ALL` on disconnect is not wired — the pgwire library (v0.38) does not expose a disconnect hook. Connections accumulate until the proxy restarts. This is tracked for future attention.
- **Token refresh**: If the JWT expires mid-session, Postgres returns an error. The client must reconnect with a fresh token.
