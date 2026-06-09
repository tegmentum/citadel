# Citadel ↔ SPIFFE/SPIRE — implementation roadmap

Citadel becomes the **trust authority** that gates SPIRE's identity issuance:
SPIRE issues SVIDs, Citadel decides — continuously — whether a node may obtain,
keep, or must lose one. "Identity is not granted; identity is continuously
earned." This roadmap records the design calls and the phased build.

## Design calls

- **SP1 — language boundary.** SPIRE is Go; its plugins are external processes
  speaking the SPIRE plugin gRPC protocol. We split the work: the **trust→identity
  decision logic is pure Rust, in-tree and unit-tested** (`citadel-spiffe`); the
  gRPC SPIRE-plugin *shell* that exposes it to a SPIRE server is deployment-scoped
  (it needs a live SPIRE to integration-test, like the daemon's live mTLS). We do
  not reimplement SPIRE.

- **SP2 — continuous identity = the MSS lease model applied to SVIDs.** "Identity
  continues only while trusted" / "SVID renewal denied" is exactly the
  Mesh-Sealed-Secrets lease + **deny-at-renewal** mechanism. An SVID is a
  short-lived credential whose **renewal is gated on current mesh trust**; loss of
  trust is enforced at the next renewal (and, for quarantine, by active
  revocation). SPIFFE identity and MSS secrets are the same kind of object: a
  continuously-earned, mesh-gated credential.

- **SP3 — categorical trust, not a score.** Citadel's `TrustState` (a categorical,
  witness-agreement classification — never a numeric score; cf. MSS C3) maps onto
  the design's four SPIFFE trust levels. The doc's "trust score" is realized as
  this categorical level. Mapping:
  `Trusted → Verified`; `Probationary/ProvisionallyAdmitted/Degraded/Untrusted/Unknown → Suspect`;
  `Suspicious → Quarantined`; `Isolated/Retired → Revoked`.

- **SP4 — selectors are derived, not asserted.** The `citadel:` selectors
  (`trust-level`, `quorum-state`, `ima-policy`, `tpm-ak`, `mma-profile`, …) are
  **computed from the node's verified mesh state** (the control plane's agreement
  + the node's attestation evidence), never claimed by the node. A node cannot
  assert `trust-level=verified`; the mesh's agreement determines it.

- **SP5 — naming + trust source.** Trust domain is configurable (`citadel.local`
  default). A node's SPIFFE ID is `spiffe://<td>/node/<mesh-node-id>`; workloads
  `…/workload/<service>`; clusters `…/cluster/<name>`. The **control plane is the
  trust source** (`TrustProvider`), since it already derives categorical trust from
  the verified verdicts.

## Phases

| Phase | Component | Scope | Status |
|-------|-----------|-------|--------|
| SP1 | `citadel-spiffe` | SPIFFE IDs, trust-level mapping, issuance/renewal/revocation decision, derived selectors, `TrustProvider` trait + control-plane impl. The trust→identity core, unit-tested. | ✅ done |
| SP2 | `citadel-spire-plugin` | gRPC NodeAttestor + Config (real protos) over the SP1 core; go-plugin handshake binary; Docker harness (config validates against spire-server 1.9.6). AutoMTLS + agent-side plugin = remaining live steps. | ✅ done |
| SP3 | `citadel-spire-controller` | Create/update/delete SPIRE registration entries from mesh state (SPIRE server API). | planned |
| SP4 | `citadel-trust-sync` | Push trust/quarantine/revocation into SPIRE; gate renewal (the SP2 lease enforcement, live). | planned |
| SP5 | demo | 3-node OptiPlex cluster: attest → issue SVID → mTLS → degrade trust → deny renewal → revoke → quarantine. | planned |

SP1 is the novel, testable Citadel contribution (trust gates identity); SP2–SP4
are the external SPIRE wiring (gRPC + the SPIRE server API), which require a live
SPIRE to exercise and are therefore deployment-scoped, like the observer daemon's
live mTLS and the 10k load rig.
