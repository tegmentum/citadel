# Citadel observability (OBS3)

The deployment artifacts for the Prometheus/Grafana/OpenTelemetry plane. Each is
validated against the real tool (see below) — the design principle is that these
are first-class, tool-checked configs, not sketches.

- `prometheus-rules/citadel-alerts.yml` — security-state alerts. Rules in the
  `citadel-trust` group are backed by the OBS2 exporter today
  (`citadel_cluster_trust_score`, `citadel_node_trust_state`,
  `citadel_nodes_quarantined`, `citadel_tpm_quote_failure_total`); the
  `citadel-mesh-obs4` group references agent-emitted metrics added with the OTLP
  layer (OBS4).
- `grafana-dashboards/cluster-trust-overview.json` — the opinionated trust
  dashboard (trust score, quarantined count, nodes-by-state, per-node trust,
  attestation failure rate).
- `otel-collector-config/collector.yaml` — Collector scraping the control-plane
  `/metrics`, enriching with `citadel.cluster.id`, exporting to Prometheus/OTLP.
- `alertmanager-rules/alertmanager.yml` — routing for the alerts.
- `prometheus.yml` + `docker-compose.yml` — a runnable stack.

## Validated (all pass)

```sh
# Prometheus rules
docker run --rm --entrypoint promtool -v "$PWD/prometheus-rules:/r:ro" \
  prom/prometheus:v2.53.0 check rules /r/citadel-alerts.yml        # SUCCESS: 6 rules found
# Alertmanager config
docker run --rm --entrypoint amtool -v "$PWD/alertmanager-rules:/a:ro" \
  prom/alertmanager:v0.27.0 check-config /a/alertmanager.yml
# OTel Collector config
docker run --rm -v "$PWD/otel-collector-config:/c:ro" \
  otel/opentelemetry-collector:0.103.1 validate --config /c/collector.yaml
```

## Serving /metrics (the one wiring step)

The metrics body is produced by `citadel_metrics_exporter::render(&control_plane)`.
A server binary that already holds the `ControlPlane` mounts it at `/metrics`
(e.g. an axum route returning `render(&cp)` with content-type
`text/plain; version=0.0.4`). It lives in the server/daemon binary — which depends
on both the control plane and the exporter — to avoid a crate cycle (the exporter
depends on the control plane). Point the compose `citadel` scrape job there.

## OBS5 — long-term storage & multi-cluster

`otel-collector-config/collector-full.yaml` exports to Mimir (metrics), Tempo
(traces), and Loki (logs); `collector-gateway.yaml` is the per-cluster forwarder
for multi-cluster federation. `docker-compose-full.yml` + `grafana-datasources.yaml`
run the full LGTM stack. See `multi-cluster.md`. Both collector configs are
validated with `otelcol validate` against `otel-collector-contrib:0.103`.
