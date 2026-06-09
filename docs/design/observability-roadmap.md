# Citadel Observability — implementation roadmap

Prometheus (metrics + PromQL alerting), Grafana (dashboards), and OpenTelemetry
(the vendor-neutral spine for metrics/logs/traces). The point isn't "is the
cluster up?" but **"is the cluster still trustworthy?"** — Citadel exposes
*security-state* telemetry derived from its verified trust fabric.

## Design calls

- **OBS1 — metrics are a projection of verified state, not a parallel store.** The
  security-state metrics (trust, attestation pass/fail, containment) are *derived*
  from the control plane's already-verified verdicts/trust — the CP is the
  verifying aggregator; `/metrics` is a read-only projection of it. Hot-path
  counters that the CP can't see (quote latency histograms, gossip latency, Hexis
  eBPF) are **agent-side OTLP**, layered on top (OBS4).

- **OBS2 — one canonical schema, two faces.** `citadel-otel-schema` defines the
  metric names *and* the OTel attribute keys once, so Prometheus labels and OTel
  resource attributes agree. The concrete first surface is a Prometheus text
  `/metrics` exposition (scraped by the OTel Collector's Prometheus receiver,
  enriched, and exported onward) — vendor-neutral without coupling Citadel to one
  backend.

- **OBS3 — categorical trust → a stable numeric gauge.** `citadel_node_trust_state`
  is a documented ordinal projection of the categorical `TrustState` (higher =
  more trusted; negative = compromised), so PromQL/Grafana can threshold and alert;
  `citadel_cluster_trust_score` is the Trusted fraction. The gauge projects state —
  it is not a new "trust score" authority (cf. the agreement-first stance).

- **OBS4 — config artifacts are first-class + tool-validated.** The Prometheus
  alert rules, Grafana dashboards, and OTel Collector config are real files,
  validated against the actual tools (`promtool`, `otelcol`) in Docker — like the
  SPIRE config validation.

- **OBS5 — three signals, layered.** Metrics show *state* (the CP `/metrics`);
  logs/events explain *what happened* (the CP's signed timeline/audit, exported as
  OTel logs); traces explain *distributed causality* (observation → quorum →
  containment, agent/mesh-instrumented). This turn delivers metrics + the schema;
  logs/traces export is the agent OTLP layer (OBS4).

## Phases

| Phase | Component | Scope | Status |
|-------|-----------|-------|--------|
| OBS1 | `citadel-otel-schema` | Canonical metric names + OTel attribute keys + the categorical-trust → ordinal mapping. A shared vocabulary, no backend coupling. | ✅ done |
| OBS2 | `citadel-metrics-exporter` | Prometheus text `/metrics` projecting the CP's verified state (cluster trust score, per-node trust gauge, node-state counts, attestation pass/fail, mesh peers, quarantine). Unit-tested render. | ✅ done |
| OBS3 | `citadel-prometheus-rules` / `citadel-grafana-dashboards` / `citadel-otel-collector-config` | Alert rules (§9), opinionated dashboards (§10), Collector config (Prometheus receiver → enrich → export). Validated with `promtool` / `otelcol` in Docker. | ✅ done |
| OBS4 | agent OTLP | Agent-side OTLP export of metrics/logs/traces incl. the containment trace + Hexis/quote-latency counters. Needs a running Collector. | planned |
| OBS5 | long-term + multi-cluster | Thanos/Mimir (metrics), Loki (logs), Tempo (traces); regional/global aggregation. Deployment. | planned |

OBS1–OBS3 are the testable Citadel surface (projection + artifacts, validated
against the real tools); OBS4–OBS5 are the live telemetry pipeline + storage,
deployment-scoped like the SPIRE live steps and the 10k load rig.
