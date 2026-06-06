# Citadel: Distributed TPM Log Shipping and LtHash Reconciliation Architecture

Document Version: 0.1
Status: First cut implemented — `crates/citadel-mesh/src/logship.rs`
(windowed LtHash accumulators over `lthash-rs`, digest advertisements,
binary-search reconciliation, and equivocation detection; deterministic and
unit-tested). Remaining: gossip the advertisements over the agent transport,
erasure-code the transferred records into the Phase-4 evidence store, and
feed equivocation into trust as `Suspicious`.
Project: Citadel
Audience: Architecture, Security, Platform, Runtime Engineers
Related: `distributed-attestation-mesh.md`, `measured-merkle-anchoring.md`, `mma-upgrade.md`

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

### Periodic Exchange

Every ~30 seconds, nodes gossip:

```rust
struct DigestAdvertisement {
    node_id: UUID,
    window_id: u64,
    max_sequence: u64,
    lthash_root: [u8; 32],
}
```

### Comparison

A peer receives e.g. `window 55, root ABC` and compares against its local copy:

* If equal: no action.
* If different: begin reconciliation.

---

## 12. Reconciliation Protocol

1. Compare the window root; if it mismatches, continue.
2. Request subranges (`55.0`, `55.1`, `55.2`, `55.3`), each represented by a
   smaller LtHash.
3. Repeat until the divergent range is isolated.
4. Transfer the missing records.

Result: instead of transferring a 500 MB log, transfer a few KB of hashes plus
the missing records.

---

## 13. Equivocation Detection

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

All events are replicated. Replication factor `R = 5`. Example:

```text
Node 17
    ↓ stored on
17, 24, 102, 488, 932
```

---

## 15. Erasure Coding

Cold storage uses Reed-Solomon. Example: 10 data shards + 4 parity shards
survives 4 shard losses without reconstruction failure.

---

## 16. Quarantine Workflow

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

**Remote Attestation Mesh** — nodes verify peers continuously.

**TPM-backed Cluster Identity** — machine identity rooted in TPM keys.

**Cross-Node PCR Correlation** — detect anomalous measurements. Example: 9999
nodes report kernel hash A, 1 node reports kernel hash B → automatic alert.

**Attestation Consensus** — the cluster computes a Cluster Trust Score based on
peer agreement.

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
