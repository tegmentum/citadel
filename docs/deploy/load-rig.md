# CP7 load rig — fleet-scale benchmark

Status: Reference (ready to run; not yet run)
Audience: Platform, Performance
Related: `docs/deploy/control-plane.md`, `crates/citadel-control-plane/tests/cp7_load_bench.rs`

A runnable benchmark for the control plane's ingestion and query path at fleet
scale. It is written and compile-checked but **not part of CI** (it's
`#[ignore]`d) and has not been run here — this doc is the methodology + targets so
a run is a one-liner.

## Run it

```sh
cargo test -p citadel-control-plane --release --test cp7_load_bench \
    -- --ignored --nocapture
```

Tunables (env):

| Var | Default | Meaning |
|-----|---------|---------|
| `CITADEL_BENCH_NODES` | `10000` | fleet size (subjects) |
| `CITADEL_BENCH_VERIFIERS` | `4` | witnesses reporting per subject |
| `CITADEL_BENCH_ROUNDS` | `3` | steady-state re-attestation passes |

Default load = 10000 × 4 × 3 = **120,000 verified verdicts** (each Ed25519-
verified on ingest). Use `--release`; debug is ~10–20× slower and not
representative.

## What it measures

1. **Ingestion throughput** — verified verdicts/second. Every `ingest_verdict`
   re-verifies the verifier's signature (M1) and re-derives the subject's trust,
   so this is the real verify+aggregate cost, not a parse.
2. **Fleet rollup query latency** — `fleet_health()` over the whole fleet (the
   dashboard's hot read).
3. **Rollup compaction ratio** — how much steady-state verdict history
   `rollup_verdicts()` collapses, and that trust is unchanged after.

## Reading the output

```text
== CP7 load rig == 10000 nodes x 4 verifiers x 3 rounds
ingest: 120000 verified verdicts in <T>s = <R> verdicts/s
fleet_health() over 10000 nodes in <Q>ms -> 10000 trusted
rollup: 120000 -> 40000 verdicts (66% collapsed) in <U>s
```

The rollup collapses to ~`nodes × verifiers` (one current verdict per
(subject, verifier)) because the rounds are identical — real traffic with
occasional transitions collapses slightly less but keeps every transition.

## Targets (acceptance)

These are the numbers to validate against; fill in measured values on first run.

| Metric | Target | Rationale |
|--------|--------|-----------|
| Ingestion (single shard, MemStore) | ≥ 50k verdicts/s | a 10k fleet re-attested every ~10 min is ~70 verdicts/s steady-state; one shard must absorb large bursts with headroom |
| `fleet_health()` latency | ≤ 50 ms @ 10k | the dashboard polls it every 3 s |
| Rollup of a steady-state fleet | collapses ≥ 60% | bounds the durable store's growth |
| Per-shard load with S shards | ~1/S of single-shard | HRW balance (verified by `hrw_sharding_is_balanced_and_minimally_disruptive`) |

## Scaling beyond one process

- **Ingestion** scales horizontally by HRW sharding (CP7): S shards each carry
  ~1/S of the subject space. The `cp7_scale` tests already prove the partition is
  balanced, has no overlap/full coverage, and self-heals on shard loss; this rig
  quantifies the per-shard ceiling that sets how many shards a fleet needs.
- **Reads** scale by stateless replicas over a shared store; the relevant number
  there is store read latency (Postgres), measured against `PgStore`, not the
  in-memory rig.

## Variants to add for a full run

- **`RedbStore` / `PgStore`** — re-run with a durable backend to capture the
  store write cost (the rig uses `MemStore` to isolate verify+aggregate CPU).
  For `PgStore`, set `CITADEL_PG_TEST_URL` and point the rig's store constructor
  at it.
- **Sustained stream** — raise `CITADEL_BENCH_ROUNDS` to model hours of
  steady-state and confirm rollup keeps the store bounded.
- **Self-heal under load** — drop a shard mid-run and measure backfill time from
  the shared store.
