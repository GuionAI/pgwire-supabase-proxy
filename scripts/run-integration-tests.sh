#!/usr/bin/env bash
# Run integration tests against orbstack postgres-dev.
# Manages kubectl port-forward lifecycle: start → test → cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
LOCAL_PORT=5433
NAMESPACE=default
SERVICE=postgres-dev-postgres-dev

cleanup() {
    if [[ -n "${PF_PID:-}" ]] && kill -0 "$PF_PID" 2>/dev/null; then
        echo "killing kubectl port-forward (PID $PF_PID)..."
        kill "$PF_PID" 2>/dev/null || true
        wait "$PF_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Kill any existing port-forward on this port
if nc -z 127.0.0.1 "$LOCAL_PORT" 2>/dev/null; then
    echo "port $LOCAL_PORT already in use — killing stale process..."
    fuser -k "$LOCAL_PORT"/tcp 2>/dev/null || true
    sleep 1
fi

echo "starting kubectl port-forward on 127.0.0.1:$LOCAL_PORT..."
kubectl port-forward -n "$NAMESPACE" "svc/$SERVICE" "$LOCAL_PORT:5432" &
PF_PID=$!

# Wait for port to be open (up to 15s)
echo "waiting for port $LOCAL_PORT to open..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 "$LOCAL_PORT" 2>/dev/null; then
        echo "port $LOCAL_PORT is open"
        break
    fi
    if ! kill -0 "$PF_PID" 2>/dev/null; then
        echo "kubectl port-forward exited unexpectedly" >&2
        exit 1
    fi
    sleep 0.5
done

if ! nc -z 127.0.0.1 "$LOCAL_PORT" 2>/dev/null; then
    echo "port $LOCAL_PORT did not open in time" >&2
    exit 1
fi

echo "running integration tests..."
cd "$REPO_ROOT"
cargo test --test integration -- --ignored
