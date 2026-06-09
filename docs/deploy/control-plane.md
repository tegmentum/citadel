# Deploying the Citadel control plane

Status: Reference
Audience: Platform, Operations
Related: `docs/design/monitoring-control-plane.md`, `docs/design/control-plane-roadmap.md`

The control plane is a **verifying aggregator** over the attestation mesh — it
re-verifies every signed artifact, derives trust (never asserts it), and serves
the agreement-first dashboard + JSON API. It holds **no key that decides trust**,
so a compromised control plane, store, or replica cannot fabricate trust,
agreement, durability, or a write the mesh did not independently evaluate.

This guide covers running it at three sizes. The binary is `control-plane`
(`crates/citadel-control-plane/src/bin/control-plane.rs`).

## Roles

A control-plane deployment has two roles, decoupled by a **shared store**:

| Role | What it does | Scales by |
|------|--------------|-----------|
| **Observer / ingestion shard** | runs an observer `Node` (M0) in the mesh, drains verified verdicts, `ControlPlane::observe`s them into the store, polls evidence durability, and relays operator writes | HRW sharding by subject (CP7) |
| **Read replica** | serves the dashboard + read API straight off the store | stateless replicas behind a load balancer |

Both roles are the same `ControlPlane<S>` over the same `ControlPlaneStore`; a
small deployment runs them in one process, a large one separates them.

## Store backends

Pick the backend with `CITADEL_CP_STORE` — the rest of the system is identical.

| Store | `CITADEL_CP_STORE` | Build | Use |
|-------|--------------------|-------|-----|
| In-memory | `mem` | default | tests, ephemeral demos |
| Embedded ([redb]) | `redb` | default | single-node durable; per-shard local store |
| Postgres | `pg` | `--features postgres-store` | HA, shared store for replicas + shards |

## Sizes

### 1. Single node (small fleet)

One process, durable on disk:

```sh
CITADEL_CP_STORE=redb \
CITADEL_CP_REDB_PATH=/var/lib/citadel/control-plane.redb \
CITADEL_CP_ADDR=0.0.0.0:8088 \
control-plane
```

Open `http://<host>:8088/` for the dashboard. Run an agent in **observer mode**
on the same host writing to the same redb file to feed it (see *Ingestion*).

### 2. Scaled read API (one shared Postgres)

Run Postgres once, then **N stateless read replicas** of the binary against it
behind a load balancer. Each replica is interchangeable; losing one drops no
data (the store is shared and durable):

```sh
# build with the feature once
cargo build --release -p citadel-control-plane --features postgres-store

# each replica (identical):
CITADEL_CP_STORE=pg \
CITADEL_PG_URL=postgres://citadel:...@pg-primary/citadel \
CITADEL_CP_ADDR=0.0.0.0:8088 \
control-plane
```

Point read replicas at a Postgres **read replica**; point ingestion shards at the
primary. The schema is created on first connect.

### 3. Sharded ingestion (10k+ nodes)

Beyond one process's ingestion budget, split the **subject space** across shards
by rendezvous (HRW) hashing — the same hashing the mesh uses for witnesses, so
ownership is balanced and losing a shard reassigns only its subjects. Each shard
ingests only the subjects it owns; **membership is still replicated to every
shard** (it needs all verifier keys + the roster). Set:

```sh
CITADEL_CP_STORE=pg
CITADEL_PG_URL=postgres://.../citadel
CITADEL_CP_SHARD_ID=<this shard's observer node id, hex>
CITADEL_CP_SHARDS=<id1>,<id2>,<id3>      # all shard ids, including self
CITADEL_CP_REPLICATION=2                 # shards per subject (hot standby)
```

`replication = 2` keeps a hot standby per subject; on shard loss the surviving
replica already owns the subject and backfills any gap from the shared store
(self-heal). Reassign by editing `CITADEL_CP_SHARDS` fleet-wide and restarting —
only the departed shard's subjects move.

## Ingestion (the observer feed)

An ingestion shard runs an observer `Node` and a host loop:

```text
loop {
    node.tick(); deliver gossip            // via the agent's mTLS transport
    cp.observe(&mut node, tick);            // drain + verify + store verdicts
    for n in owned_nodes { cp.poll_durability(n); }
    for m in cp.drain_pending_manifests()  { node.broadcast_reference_manifest(m); }
    for a in cp.drain_pending_quarantine_approvals() { node.relay_quarantine_approval(a); }
}
```

The observer `Node` joins the mesh exactly like a worker but in `observer: true`
mode (non-voting, never a witness). Wire it with `citadel-agent`'s transport
(`serve_mtls`/`mtls_client`) pointed at the mesh seeds; register operator keys
with `cp.authorize_operator` so `POST /v1/policies` and quarantine relays are
accepted. (This combined ingestion binary is the one networked piece left to
assemble from the existing agent + control-plane crates.)

## Maintenance jobs

Run periodically against the store (any shard / a maintenance job):

* **Rollup** — `cp.rollup_verdicts()` collapses steady-state verdict history
  while preserving every transition; derived trust + agreement are unchanged.
* **Retention** — `cp.retain_events(keep_from_tick)` prunes old timeline events.
  The operator audit chain is immutable and never pruned.

## Endpoints

`GET /` dashboard · `GET /v1/mesh/health` · `/v1/nodes` · `/v1/nodes/{id}` ·
`/v1/nodes/{id}/agreement` · `/v1/nodes/{id}/evidence` · `/v1/nodes/{id}/timeline`
· `/v1/events?since=` · `/v1/audit` · `POST /v1/policies` (operator-signed).

## Security notes

* The dashboard/API has **no built-in auth** — front it with an authenticating
  reverse proxy (OIDC/mTLS) and restrict `POST` to operators. Writes are *also*
  gated cryptographically: only a registered operator's signature is relayed, and
  nodes adopt a relayed artifact only if they trust its authority.
* The store is a **verified-fact sink** — it is never trusted for integrity, so a
  read replica or a compromised database cannot manufacture a verdict; everything
  is re-verified on ingest and the audit chain self-verifies.
