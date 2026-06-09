# OBS5 — long-term storage & multi-cluster

## Long-term storage

`otel-collector-config/collector-full.yaml` fans the Citadel signals into the
Grafana LGTM backends, all native to Grafana:

- **Metrics** → Mimir / Thanos via `prometheusremotewrite`.
- **Traces** → Tempo via OTLP.
- **Logs** → Loki via OTLP/HTTP.

`docker-compose-full.yml` brings the stack up; `grafana-datasources.yaml`
provisions the three datasources. (Validated: `otelcol validate` accepts
`collector-full.yaml` and `collector-gateway.yaml` against
`otel-collector-contrib:0.103`.)

## Multi-cluster federation

Every signal already carries `citadel.cluster.id` (OBS1), so a global view is just
aggregation by that label. Two tiers:

```text
cluster A agent-collector ─┐
cluster B agent-collector ─┼─OTLP→ gateway-collector → Mimir / Tempo / Loki (global)
cluster C agent-collector ─┘
```

Each cluster runs `collector-gateway.yaml` (forward to the central gateway); the
gateway stamps/keeps `citadel.cluster.id` and writes to the global backends. This
is the telemetry side of the design's **mesh trust bundles** (§18) — trust state
shared across sites, queryable as one fabric (`citadel_cluster_trust_score` per
`citadel.cluster.id`).
