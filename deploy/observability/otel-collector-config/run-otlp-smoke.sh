#!/usr/bin/env bash
# OBS4 OTLP smoke: run an OTel Collector (OTLP/HTTP receiver + debug exporter),
# POST a Citadel containment trace, and confirm the Collector logged the spans.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"

docker rm -f citadel-otelcol >/dev/null 2>&1 || true
docker run -d --name citadel-otelcol \
  -v "$HERE/collector-otlp-smoke.yaml:/etc/otelcol/config.yaml:ro" \
  -p 4318:4318 \
  otel/opentelemetry-collector:0.103.1 --config /etc/otelcol/config.yaml >/dev/null
sleep 4

( cd "$ROOT" && cargo run -q -p citadel-telemetry --example emit_containment ) > /tmp/citadel-trace.json
curl -fsS -X POST -H "Content-Type: application/json" \
  --data @/tmp/citadel-trace.json http://localhost:4318/v1/traces && echo "  <- POST 200"
sleep 2
echo "--- Collector received: ---"
docker logs citadel-otelcol 2>&1 | grep -E "Name +: citadel" | head
docker rm -f citadel-otelcol >/dev/null 2>&1 || true
