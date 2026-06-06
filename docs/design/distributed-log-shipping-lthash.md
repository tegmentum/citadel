# Citadel: Distributed TPM Log Shipping and LtHash Reconciliation Architecture

Document Version: 0.2
Status: Partially implemented — the LtHash anti-entropy engine, gossip,
binary-search reconciliation, equivocation detection, and erasure-coded durable
preservation are built and tested in `crates/citadel-mesh`; signed quote-bound
checkpoints, real event-source ingestion, and on-disk persistence are not yet
built. See the **Implementation Status** section below for the section-by-section
map; each section carries its own **Status:** line.
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `distributed-attestation-mesh.md`, `measured-merkle-anchoring.md`, `mma-upgrade.md`, `measured-state-transitions.md`

> Relationship to the other designs (citadel repo): this is the **evidence /
> log-shipping layer** that sits beneath the [distributed attestation
> mesh](distributed-attestation-mesh.md). The mesh doc covers membership,
> witnessing, trust scoring, and quarantine; this doc covers how the
> *measurement log itself* is canonicalized, accumulated (LtHash),
> checkpointed, gossiped, reconciled, and preserved. They share the
> signed-checkpoint, gossip, quorum, and erasure-coded-evidence concepts —
> implementations should converge those, not duplicate them. Existing
> primitives to reuse: `secure-log` already provides hash-chained entries,
> Merkle-rooted segments, TPM-signed checkpoints, anti-rollback, and a
> witness log; MMA provides measurement/enrollment; the LtHash accumulator
> and the anti-entropy reconciliation engine are the new pieces.
>
> **The LtHash engine already exists** as a sibling component,
> `lthash-wasm` (`~/git/lthash-wasm`), which wraps the `lthash-rs` crate
> (LtHash16 / LtHash32 over SHA3 `Shake256`) and ships native Rust, a
> JS/WASM binding, *and* a Wasmtime WASI component
> (`cli/target/lthash_cli.component.wasm`, `wasm32-wasip2`) — the same
> sandboxed-component delivery model as `vtpm-wasm`. Citadel reuses it for
> the accumulator rather than reimplementing LtHash; see §8.

---

## Implementation Status (v0.2)

Section-by-section map of this design against `crates/citadel-mesh`. ✅ done,
◑ partial, ✗ not yet built.

| § | Topic | Status | Where |
|---|---|---|---|
| 8 | LtHash design (windowed, sequence-bound) | ✅ | `logship.rs` (`EventLog`, `window_root`/`range_root`, `EventRecord::element`) |
| 11 | Gossip (`DigestAdvertisement`) | ✅ | `node.rs` `advertise_logs` / `GossipMessage::LogDigest` |
| 12 | Reconciliation (binary-search subranges) | ✅ | `on_log_digest` / `on_log_range_root`, `LOG_LEAF_WIDTH` |
| 13 | Equivocation (`CHECKPOINT_EQUIVOCATION`) | ✅ | `sealed_roots`, `detect_equivocation` → distrust |
| 14 | Log preservation / replication | ✅ (evolved) | HRW erasure-coded holder placement; supersedes the flat `R=5` |
| 15 | Erasure coding (Reed-Solomon) | ✅ | `erasure.rs`, wired in `node.rs` |
| 6 | Canonical event format | ◑ | implemented `EventRecord` carries node/boot/seq/payload only |
| 7 | Sequence numbers | ◑ | sequences yes; explicit gap/replay/reorder detection no |
| 16 | Quarantine workflow | ◑ | scopes/votes/operator gate done; most scope→action enforcement still inert |
| 18 | Scaling | ◑ | advertisements-only steady state holds; legacy full-replication path is N-1 |
| 20 | Future (mesh / cluster identity / consensus) | ◑ | mesh + TPM-keyed identity + witness-quorum trust exist; no Cluster Trust Score / PCR-outlier correlation |
| 9 | Signed checkpoints | ✗ | no standalone `Checkpoint`; advertisements ride signed envelopes but aren't quote-bound |
| 10 | TPM quote ↔ checkpoint link | ✗ | log-shipping and attestation are separate subsystems |
| 5 | Event sources (`binary_bios_measurements`, IMA) | ✗ | events fed abstractly via `append_event(payload_hash)` |
| 17 | Storage layout (on-disk) | ✗ | in-memory only (in-process harness + HTTP transport) |

The three structural gaps are **signed quote-bound checkpoints (§9–10)**,
**real event-source ingestion (§5)**, and **persistence (§17)**.

---

## 1. Executive Summary

Traditional TPM deployments suffer from a fundamental limitation:

```text
Machine Compromise
        ↓
Local Event Log Modified/Deleted
        ↓
Forensic Evidence Lost
```

Even where TPM PCRs remain trustworthy, event logs are often local artifacts
vulnerable to deletion, corruption, or isolation.

Citadel transforms TPM measurements from a local security mechanism into a
distributed security fabric.

Instead of treating TPM logs as machine-local evidence, Citadel continuously
distributes, reconciles, validates, and preserves measurement data across the
cluster.

The resulting architecture creates:

* Distributed attestation
* Distributed forensic preservation
* Compromise amplification
* Tamper evidence
* Erasure-coded durability
* Peer-based anomaly detection

The core innovation is using LtHash accumulators as an anti-entropy mechanism
for efficient log synchronization while retaining cryptographic attestation
through TPM quotes and signed checkpoints.

---

## 2. Design Goals

**G1: Distributed Preservation** — No single machine should possess the sole
copy of critical attestation evidence.

**G2: Rapid Divergence Detection** — A compromised machine should become
detectable through disagreement with peers.

**G3: Efficient Synchronization** — Nodes should determine log differences
without transferring entire logs.

**G4: Scalability** — Support 10 / 100 / 1,000 / 10,000+ nodes.

**G5: Remote Attestation Integration** — Leverage existing TPM infrastructure.

**G6: Compromise Amplification** — Adding more machines should improve security
rather than weaken it.

---

## 3. Threat Model

### Defended Against

**Attacker compromises node** — attempts to:

* Modify logs
* Delete logs
* Suppress measurements
* Hide persistence

**Insider administrator** — attempts:

* Log removal
* Measurement tampering
* Selective disclosure

**Hardware loss** — machine destroyed or stolen.

**Ransomware** — attempts:

* Encrypt evidence
* Remove audit history

### Not Defended Against

**Majority capture** — if an attacker controls more than the quorum threshold,
security guarantees degrade.

**TPM compromise** — physical extraction attacks remain out of scope.

**Supply-chain attacks before first measurement** — must be handled separately.

---

## 4. Architecture Overview

```text
                ┌──────────────┐
                │     TPM      │
                └──────┬───────┘
                       │
                       ▼
              ┌─────────────────┐
              │ TPM Event Log   │
              └────────┬────────┘
                       │
                       ▼
             ┌──────────────────┐
             │ Log Canonicalizer│
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ LtHash Builder   │
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ Signed Checkpoint│
             └────────┬─────────┘
                      │
                      ▼
             ┌──────────────────┐
             │ Gossip Protocol  │
             └────────┬─────────┘
                      │
          ┌───────────┼───────────┐
          ▼           ▼           ▼
       Peer A      Peer B      Peer C
```

---

## 5. Event Sources

**Status: ✗ Not yet built.** No ingestion from `binary_bios_measurements`, the
TCG event log, or IMA exists. Events are currently appended abstractly via
`Node::append_event(payload_hash)`; wiring real sources is the boundary between
"protocol works" and "runs on a real machine."

Initially supported:

**TPM Event Log**

* Linux: `/sys/kernel/security/tpm0/binary_bios_measurements`
* Windows: Measured Boot APIs
* UEFI: TCG Event Log

**IMA Measurements** — Linux Integrity Measurement Architecture (`/etc/ima/*`)
provides runtime measurement data.

**Future Sources**

* eBPF Sensors — runtime integrity events.
* Citadel Runtime Events — attestation state.
* Security Alerts — policy violations.

---

## 6. Canonical Event Format

**Status: ◑ Simplified.** The implemented `EventRecord` (`logship.rs`) carries
`node_id`, `boot_id`, `sequence`, and `payload_hash` only — enough for the
LtHash element and reconciliation. The richer fields below (`source`,
`timestamp`, `pcr`, `digest_algorithm`, `event_type`) are not yet present and
land with real event-source ingestion (§5).

All measurements normalized into:

```rust
struct EventRecord {
    node_id: UUID,
    boot_id: UUID,
    source: SourceType,
    sequence: u64,
    timestamp: u64,
    pcr: Option<u8>,
    digest_algorithm: String,
    digest: [u8; 32],
    event_type: String,
    payload_hash: [u8; 32],
}
```

---

## 7. Sequence Numbers

**Status: ◑ Partial.** Records carry monotonic sequences and the LtHash element
binds the sequence (so the same payload at a different seq is a distinct
element). Divergence is currently found by root comparison and sealed-window
equivocation rather than explicit gap/replay/reorder scans.

Every source maintains monotonic sequence numbers:

```text
1
2
3
4
5
```

No gaps allowed. This permits:

* Missing-event detection
* Replay detection
* Reordering detection

---

## 8. LtHash Design

**Status: ✅ Implemented** (`logship.rs`, over `lthash-rs` `LtHash16<Shake256>`).

### Core Idea

Each record becomes:

```text
EventElement = H( node_id ‖ boot_id ‖ sequence ‖ payload_hash )
```

The sequence number is included. Therefore Event A @ seq 5 and Event A @ seq 6
produce different values.

### Accumulator

```text
LtHashRoot = Σ EventElements
```

Properties:

* Incremental
* Homomorphic
* Commutative

### Windowed Accumulators

Instead of one giant hash:

```text
Window 0: 1-10,000
Window 1: 10,001-20,000
Window 2: 20,001-30,000
```

Each window has an `LtHashWindowRoot`. This enables binary-search-style
divergence detection.

### Implementation: the `lthash-wasm` / `lthash-rs` component

The accumulator is provided by the sibling `lthash-wasm` repo
(`~/git/lthash-wasm`), which wraps `lthash-rs` — LtHash16 / LtHash32 backed
by SHA3 `Shake256` — and already exposes exactly the operations this design
needs:

| Design concept | `lthash` operation |
|---|---|
| `Σ EventElements` (accumulate a record) | `union` / add the element's bytes |
| Remove / supersede a record | `difference` / remove (homomorphic inverse) |
| `LtHashRoot`, `LtHashWindowRoot` | the hash **snapshot** (bytes / hex) |
| Compare two windows for divergence (§11–12) | snapshot equality / `compare` |
| Reconcile only the differing sub-range (§12) | accumulate the sub-range and diff snapshots |
| Equivocation `A != B` at same `(boot, seq)` (§13) | snapshot inequality |

Because LtHash is commutative and incremental, a window root is just the
running snapshot after folding each window's `EventElement`s in any order,
and a sub-range root is the snapshot over that sub-range — so binary-search
reconciliation is a sequence of cheap snapshot comparisons, no log transfer.

Integration options, mirroring how the TPM backends are structured
(`vtpm-wasm` sandboxed component vs. native backends in `tpm-core`):

* **Native (default for the in-cluster engine):** depend on `lthash-rs`
  directly from the citadel mesh/evidence crate — no Wasmtime on the hot
  path, simplest for `EventRecord` folding and checkpointing.
* **Sandboxed component:** run `lthash_cli.component.wasm` (`wasm32-wasip2`)
  under Wasmtime when the accumulator must be isolated or shared with a
  JS/TS surface, exactly as `vtpm-wasm` is run for the vTPM.

The element preimage stays as specified —
`H(node_id ‖ boot_id ‖ sequence ‖ payload_hash)` — and that digest is the
value folded into the LtHash, so the cluster-wide identity of a record (and
thus divergence detection) is unchanged regardless of which integration is
used.

---

## 9. Signed Checkpoints

**Status: ✗ Gap.** There is no standalone `Checkpoint` type. Per-window
`DigestAdvertisement`s carry `node_id`/`boot_id`/`window_id`/`max_sequence`/`root`
and travel inside a signed `GossipEnvelope`, so the payload is authenticated —
but it is **not** an independently signed, quote-bound checkpoint. This is the
highest-leverage gap: a `Checkpoint` binding `lthash_root` + `pcr_quote_hash`,
signed by the node key, would tie the distributed log to TPM attestation (§10)
and make equivocation (§13) provably attributable.

Every interval (N events or T seconds) a node emits a checkpoint:

```rust
struct Checkpoint {
    node_id: UUID,
    boot_id: UUID,
    max_sequence: u64,
    window_id: u64,
    lthash_root: [u8; 32],
    pcr_quote_hash: [u8; 32],
    timestamp: u64,
}
```

Signed:

```text
Sign(node_private_key, checkpoint)
```

---

## 10. TPM Quote Integration

**Status: ✗ Gap.** Log-shipping (`logship.rs`) and attestation (`attest.rs`)
are currently separate subsystems; nothing binds a window's `lthash_root` to a
TPM quote. Closes together with §9.

The checkpoint references a quote:

```text
TPM Quote
     ↓
PCR State
     ↓
Quote Hash
     ↓
Checkpoint
```

This links the distributed log ↔ TPM attestation.

---

## 11. Gossip Protocol

**Status: ✅ Implemented.** `node.rs` `advertise_logs` emits
`GossipMessage::LogDigest` on `log_advertise_interval`; the implemented
`DigestAdvertisement` additionally carries `boot_id` (and `root` is a
variable-length `Vec<u8>` LtHash snapshot, not a fixed `[u8; 32]`).

### Periodic Exchange

Every ~30 seconds, nodes gossip:

```rust
struct DigestAdvertisement {
    node_id: NodeId,
    boot_id: u64,       // implemented: present (the design omitted it)
    window_id: u64,
    max_sequence: u64,
    root: Vec<u8>,      // LtHash snapshot
}
```

### Comparison

A peer receives e.g. `window 55, root ABC` and compares against its local copy:

* If equal: no action.
* If different: begin reconciliation.

---

## 12. Reconciliation Protocol

**Status: ✅ Implemented** (`on_log_digest` / `on_log_range_root`, `LOG_LEAF_WIDTH`):
a window-root mismatch starts a recursive bisection that pulls records only at
the divergent leaf ranges — proven to transfer only the diff, not the window.

1. Compare the window root; if it mismatches, continue.
2. Request subranges (`55.0`, `55.1`, `55.2`, `55.3`), each represented by a
   smaller LtHash.
3. Repeat until the divergent range is isolated.
4. Transfer the missing records.

Result: instead of transferring a 500 MB log, transfer a few KB of hashes plus
the missing records.

---

## 13. Equivocation Detection

**Status: ✅ Implemented** (`sealed_roots`, `detect_equivocation`): a conflicting
root for an already-sealed `(node, boot, window)` sets the forking node
`Suspicious` across the mesh.

Suppose a node publishes:

```text
boot X, seq 1000, root A
```

then later publishes:

```text
boot X, seq 1000, root B
```

Peers immediately detect `A != B` and generate a `CHECKPOINT_EQUIVOCATION`
violation.

---

## 14. Log Preservation

A sealed window is preserved on a **bounded set of holders** chosen by
rendezvous (HRW) hashing keyed on the window's content id — not full-replicated
to every peer. Example (record id `→` its 5 assigned holders):

```text
window(node 17, boot 3, win 0)
    ↓ record_id = BLAKE3(encode_records(window))
    ↓ stored on (HRW)
24, 102, 488, 932, 17
```

**Implemented** (`node.rs` `ship_sealed_windows` / `eligible_holders`, gated by
`evidence_replication`): on seal, the origin erasure-codes the window and emits
one shard per holder via `LogFragmentStore`; each holder returns a signed
`EvidenceReceipt` (`LogFragmentAck`) so the origin tracks live durability
(`window_durability`). Holder selection skips nodes quarantined at/above
`RestrictEvidenceHolding`.

### Placement policy (self-describing)

Holders are chosen under a `PlacementPolicy` recorded *on the window* (a
`WindowPlacement`: record id, subject, policy):

* **`FullRoster`** — holders drawn from the whole roster; the subject may hold
  a shard of its own evidence.
* **`OffBox`** — the subject is excluded from its own holder set, so no node is
  ever custodian of evidence about itself (separation of custody).

Because each window carries the policy it was placed under, a recoverer replays
the *exact* holder set the origin used (`request_reconstruction(&placement)`),
even after the mesh's current policy changes — which is what makes flipping the
policy safe on a live mesh. Trade-off: `OffBox` removes one candidate, so in a
mesh whose roster is no larger than the shard count it can force shards to
double up on holders (weaker fault tolerance); at scale the subject is rarely
its own holder anyway, so the two policies converge. Set `evidence_offbox`.

To offset that in small meshes, **pair `OffBox` with a parity bump**. The
window records not just its policy but its holder count (the erasure scheme's
`total`), so a *scheme* change is just as self-describing as a policy change —
a recoverer still replays the exact holder set. `set_evidence_placement(offbox,
parity, migration_rate)` flips the policy and raises parity together; the extra
parity restores the holder losses the mesh can tolerate
(`offbox_paired_with_a_parity_bump_raises_fault_tolerance`).

### Migration

Flipping `evidence_offbox` (or bumping parity) only changes *new* windows;
already-shipped windows migrate gradually under `evidence_migration_rate`
(windows in flight at once; `0` disables). A window is migrated when its
committed policy *or* erasure scheme differs from the current target. Each
migration is **re-ship then drop**: the window is erasure-shipped to its new
holder set (under the new policy and scheme) first, and only once that new
placement is durable does the origin tell the now-unassigned holders to drop
their shards (`LogFragmentDrop`) — so a window is never below its
reconstruction threshold mid-migration (`migrate_windows` / `cut_over`;
`logship_migration.rs`).

---

## 15. Erasure Coding

Cold storage uses Reed-Solomon. Example: 10 data shards + 4 parity shards
survives 4 shard losses without reconstruction failure.

**Implemented** (`erasure.rs`; wired in `node.rs`): each sealed window is split
into `data + parity` shards (configurable via `evidence_data_shards` /
`evidence_parity_shards`, default 3-of-5). Any `data` shards reconstruct it, so
the window survives losing up to `parity` holders. A recoverer rebuilds over
the network by requesting shards from the assigned holders
(`request_reconstruction` → `LogFragmentRequest`/`LogFragmentReply`),
reconstructing once a threshold returns and verifying the result against the
record id before folding the records into its replica
(`logship_erasure.rs`).

---

## 16. Quarantine Workflow

**Status: ◑ Partial** (`quarantine.rs`). The quorum machinery is built —
graded `QuarantineScope`s, signed proposals/votes, eligible-witness tally, and
an operator gate for the most severe scopes. But most scopes are *declared,
not enforced*: only loss-of-vote (`restricts_voting`), trust-freeze/isolation
(`isolates`), and exclusion from evidence-holding (`restricts_evidence_holding`)
actually change runtime behaviour. Workload-scheduling and credential-revoke
scopes are inert.

When a node diverges:

```text
Mismatch
     ↓
Verification
     ↓
Policy Engine
```

Possible actions:

* **Informational** — alert only.
* **Suspicious** — increase attestation frequency.
* **Critical** — quarantine node.
* **Severe** — cluster vote, shut down node.

---

## 17. Storage Layout

**Status: ✗ Not yet built.** All state (logs, windows, replicas, fragments,
shipped-window tracking) is in-memory in the in-process harness and over the
HTTP transport; there is no on-disk store. The durable-evidence *logic*
(erasure placement, reconstruction) is complete (§14–15) but a crash currently
loses local state — persistence behind it is the remaining piece.

```text
/node/{nodeid}/
    checkpoints/
    logs/
    windows/
/cluster/
    advertisements/
    quorum/
```

---

## 18. Scaling Characteristics

**Status: ◑ Partial.** The advertisements-only steady state and on-divergence
reconciliation hold as designed. Caveat: the *legacy* full-window replication
path is N-1 (a replica on every peer); the erasure-coded holder placement
(§14) is the bounded-fan-out path and is what scales — make it the default
before claiming the 10,000-node profile.

For 10,000 nodes, only advertisements are exchanged routinely. A typical
message is < 256 bytes, so total gossip remains manageable. Reconciliation
occurs only on divergence.

---

## 19. Security Properties

* **Integrity** — TPM, signatures, checkpoints.
* **Availability** — replication, erasure coding.
* **Non-Repudiation** — signed checkpoints.
* **Tamper Evidence** — LtHash divergence, checkpoint equivocation detection.
* **Forensic Durability** — distributed storage.

---

## 20. Future Enhancements

**Remote Attestation Mesh** — nodes verify peers continuously. **✅ Built** as
`crates/citadel-mesh` (`distributed-attestation-mesh.md`): SWIM membership,
HRW witness sets, quorum trust.

**TPM-backed Cluster Identity** — machine identity rooted in TPM keys. **✅
Built**: `NodeId` derives from the mesh key + TPM AK, with endorsement-anchored
AK trust.

**Cross-Node PCR Correlation** — detect anomalous measurements (9999 nodes
report kernel hash A, 1 reports B → alert). **◑ Adjacent**: the multi-value
reference appraisal (`measured-state-transitions.md`) accepts/denies measured
states per policy, but explicit fleet-wide outlier correlation is not a feature.

**Attestation Consensus** — a Cluster Trust Score from peer agreement. **◑
Partial**: per-subject trust is decided by witness quorum and `FleetView`
aggregates counts; there is no single cluster-wide trust score yet.

---

## 21. Key Insight

Traditional TPM deployments answer:

> "Can this machine prove what it booted?"

Citadel extends this to:

> "Can the entire cluster prove what every machine booted, preserve the
> evidence indefinitely, detect disagreements automatically, and make
> compromise impossible to hide?"

LtHash serves as the anti-entropy and reconciliation engine that makes this
practical at large scale, while TPM quotes, signed checkpoints, and distributed
replication provide the trust foundation. The result is a distributed
attestation mesh in which increasing node count increases visibility and tamper
resistance rather than merely increasing attack surface.
