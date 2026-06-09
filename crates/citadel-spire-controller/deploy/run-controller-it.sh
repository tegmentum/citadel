#!/usr/bin/env bash
# Bring up a real SPIRE server, bridge its admin Entry API socket to TCP (colima
# doesn't propagate container UDS to the host, so we use a socat sidecar over a
# shared named volume), and run the #[ignore]d controller integration test.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${CITADEL_SPIRE_PORT:-9090}"

docker rm -f citadel-spire-srv citadel-spire-socat >/dev/null 2>&1 || true
docker volume rm citadel-spire-priv >/dev/null 2>&1 || true
docker volume create citadel-spire-priv >/dev/null

docker run -d --name citadel-spire-srv \
  -v "$HERE/controller-server.conf:/c/server.conf:ro" \
  -v citadel-spire-priv:/tmp/spire-server/private \
  --entrypoint /opt/spire/bin/spire-server \
  ghcr.io/spiffe/spire-server:1.9.6 run -config /c/server.conf >/dev/null
sleep 5
docker run -d --name citadel-spire-socat \
  -v citadel-spire-priv:/tmp/spire-server/private \
  -p "${PORT}:9090" \
  alpine/socat TCP-LISTEN:9090,fork,reuseaddr UNIX-CONNECT:/tmp/spire-server/private/api.sock >/dev/null
sleep 3

CITADEL_SPIRE_ENTRY_ADDR="http://127.0.0.1:${PORT}" \
  cargo test -p citadel-spire-controller --test entry_api -- --ignored --nocapture
status=$?

docker rm -f citadel-spire-srv citadel-spire-socat >/dev/null 2>&1 || true
docker volume rm citadel-spire-priv >/dev/null 2>&1 || true
exit $status
