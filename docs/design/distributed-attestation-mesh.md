# Citadel Distributed Attestation Mesh

## Design Document

Status: Design (handoff) — not yet implemented
Related: `measured-merkle-anchoring.md`, `mma-upgrade.md`, `tpm-nv-counter-and-policy-signing.md`

> Implementation note (citadel repo): this mesh is designed to build on
> primitives this repo already has rather than reinvent them —
> `attest` (TPM quote/verify, AK/EK) is the Attester/Verifier evidence
> path; `secure-log` + the witness log are the hash-chained,
> witness-countersigned evidence store; `identity`/`policy` and the
> PolicyAuthorize approval flow cover node identity, reference values, and
> signed policy; and `tpmd` (axum + tokio + mTLS) is the natural host for
> the agent API and gossip transport. See the mapping at the end.

## 1. Purpose

Citadel is a distributed attestation and evidence mesh for clusters of machines equipped with TPMs or equivalent hardware roots of trust.

The goal is not to prevent every compromise. The goal is to make compromise **observable, attributable, and difficult to hide**.

Citadel turns a large cluster from a large attack surface into a distributed sensor fabric:

> Instead of 10,000 machines giving an attacker 10,000 places to hide, 10,000 machines become 10,000 observers.

This document excludes UEFI/WAMR boot-time work. That will be designed separately. This document assumes the Citadel agent is running in an already-booted operating system.

---

## 2. Core Thesis

Centralized security layers tend to shift the attack point:

```text
Protect the app.
Then attack the database.

Protect the database.
Then attack the logger.

Protect the logger.
Then attack the key.

Protect the key.
Then attack the keystore.

Protect the keystore.
Then attack the identity provider.
```

Citadel avoids introducing a single new trust choke point. Instead, it distributes trust evaluation, evidence storage, and anomaly detection across the cluster.

The system objective is:

> Make deception require distributed collusion.

A compromised node should not be able to hide its compromise unless the attacker can also compromise enough of the witness mesh to suppress or rewrite evidence.

---

## 3. Standards and Reference Model

Citadel should align terminology with the IETF RATS architecture. RATS defines remote attestation roles such as **Attester**, **Verifier**, **Relying Party**, **Endorser**, and **Reference Value Provider**. Citadel maps these roles into a distributed mesh rather than a purely centralized verifier model. (RFC 9334)

TPM-backed attestation relies on TPM capabilities such as quote generation over selected PCRs. TCG describes TPM 2.0 as the core command and capability specification for platform-specific trust systems, and the TPM 2.0 library documentation describes quote-based attestation through `TPM2_Quote()`.

Citadel should also account for measured firmware and boot evidence. NIST SP 800-155 describes BIOS integrity measurement and reporting chains, which are relevant to future UEFI integration and to interpreting boot measurements already available from the OS.

For membership and gossip, Citadel should use a SWIM-inspired protocol. SWIM combines failure detection and infection-style dissemination, using direct and indirect probes plus suspicion before declaring failure.

References:
- RFC 9334 — Remote ATtestation procedureS (RATS) Architecture — https://datatracker.ietf.org/doc/rfc9334/
- TCG TPM 2.0 Library — https://trustedcomputinggroup.org/resource/tpm-library-specification/
- NIST SP 800-155 — BIOS Integrity Measurement Guidelines — https://csrc.nist.gov/pubs/sp/800/155/ipd
- SWIM — Scalable Weakly-consistent Infection-style Process Group Membership — https://www.cs.cornell.edu/projects/Quicksilver/public_pdfs/SWIM.pdf

---

## 4. Non-Goals

This version does not include:

```text
- UEFI boot gating
- WAMR pre-OS enrollment
- Secure boot policy design
- Full SIEM replacement
- Kernel-level EDR
- Full confidential computing attestation
- Byzantine consensus for every event
- Blockchain/token/ledger mechanics
```

Citadel is not a blockchain. It may use append-only hash chains, quorum logic, and replicated evidence, but the product should avoid blockchain terminology unless there is a concrete protocol reason.

---

## 5. System Overview

### 5.1 High-Level Architecture

```text
+--------------------------------------------------------------+
|                         Dashboard/API                        |
|  Fleet health | Node status | Evidence | Quorum | Forensics  |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
|                     Citadel Control Plane                    |
|  Policy registry | Reference values | Enrollment state       |
|  Trust scoring   | Quarantine decisions | Operator workflow   |
+-----------------------------+--------------------------------+
                              |
                              v
+--------------------------------------------------------------+
|                    Distributed Attestation Mesh              |
|                                                              |
|  Node A <----> Node B <----> Node C                          |
|    ^           ^   ^           ^                             |
|    |           |   |           |                             |
|  Node D <----> Node E <----> Node F                          |
|                                                              |
|  Gossip | Witnessing | Remote attestation | Evidence shards   |
+--------------------------------------------------------------+
```

### 5.2 Node Agent

Each machine runs a `citadel-agent`.

Responsibilities:

```text
- Maintain TPM-backed node identity.
- Generate local attestation evidence.
- Challenge peer nodes.
- Verify peer attestation responses.
- Participate in gossip membership protocol.
- Witness and replicate security events.
- Store assigned evidence fragments.
- Report aggregate state to dashboard/API.
- Enforce local quarantine instructions when permitted.
```

### 5.3 Mesh Control Plane

The control plane is not a single root of trust. It is an operational coordination layer.

Responsibilities:

```text
- Store policy definitions.
- Store expected reference measurements.
- Manage enrollment workflows.
- Aggregate mesh health.
- Provide dashboard APIs.
- Record operator decisions.
- Coordinate quarantine policy.
```

A deployment may begin with a centralized control plane, but the protocol must not depend on absolute trust in it. Nodes should treat control-plane messages as signed policy inputs, not as unquestionable truth.

---

## 6. Identity Model

### 6.1 Node Identity

Each node has multiple identities:

```text
Hardware identity:
  Derived from TPM EK/AK material and manufacturer endorsement chain.

Mesh identity:
  Citadel-issued node identity after enrollment.

Operational identity:
  Hostname, cluster role, service role, network identity, cloud instance ID, etc.

Evidence identity:
  Signing key used for evidence records and witness reports.
```

The hardware identity should not be casually exposed everywhere. Citadel should use privacy-preserving derived identities where possible.

### 6.2 Node ID

Canonical node ID:

```text
node_id = BLAKE3(
  mesh_id ||
  enrollment_epoch ||
  attestation_key_fingerprint ||
  assigned_random_salt
)
```

Rationale:

```text
- Stable inside one mesh.
- Not globally linkable by default.
- Bound to attested hardware identity.
- Allows re-enrollment with a new epoch.
```

---

## 7. Enrollment Protocol

### 7.1 Enrollment States

```text
Unseen
  -> Claimed
  -> Challenged
  -> ProvisionallyAdmitted
  -> Probationary
  -> Trusted
  -> Degraded
  -> Suspicious
  -> Isolated
  -> Retired
```

### 7.2 Enrollment Principle

A new node should not become trusted merely because an administrator added it.

A node joins because it presents a bounded, auditable identity claim and enough of the mesh accepts that claim.

### 7.3 Enrollment Inputs

A new node submits:

```text
EnrollmentClaim {
  mesh_id
  claimed_hostname
  claimed_role
  platform_identity
  attestation_key_certificate_or_chain
  tpm_quote
  selected_pcrs
  boot_event_log_digest
  os_image_digest
  agent_version
  network_location
  provisioning_token_or_operator_approval_ref
  nonce
  timestamp
  signature
}
```

### 7.4 Enrollment Flow

```text
1. Node starts citadel-agent.

2. Node discovers enrollment endpoint or seed nodes.

3. Node submits EnrollmentHello:
   - claimed role
   - platform identity summary
   - agent version
   - supported algorithms

4. Mesh returns EnrollmentChallenge:
   - nonce
   - PCR selection
   - required evidence types
   - policy revision
   - witness set

5. Node asks TPM to quote selected PCRs.

6. Node submits EnrollmentClaim.

7. Witness set verifies:
   - TPM quote signature
   - nonce freshness
   - AK/EK endorsement chain
   - PCR values against reference policy
   - boot/event log consistency
   - role authorization
   - duplicate identity detection
   - network plausibility

8. Witnesses gossip signed EnrollmentVote records.

9. If threshold is met, node becomes ProvisionallyAdmitted.

10. Node receives:
    - mesh node ID
    - peer list
    - witness assignments
    - evidence storage assignments
    - policy snapshot
    - probation duration
```

### 7.5 Probation

New nodes should not immediately affect trust decisions.

Probationary nodes:

```text
- May be observed.
- May submit evidence.
- May store low-criticality evidence fragments.
- May not vote on enrollment of other nodes.
- May not trigger automatic quarantine.
- May not hold sole copies of critical evidence.
- May not participate in high-confidence quorum decisions.
```

Promotion to `Trusted` requires:

```text
- Stable attestation over N intervals.
- No unresolved witness objections.
- Successful gossip participation.
- Successful evidence replication checks.
- Policy-compatible software state.
```

---

## 8. Remote Attestation Design

### 8.1 RATS Role Mapping

Citadel maps RATS roles as follows:

```text
Attester:
  The node being challenged.

Verifier:
  Peer witness nodes and/or control-plane verifier services.

Relying Party:
  The mesh decision engine, dashboard, quarantine subsystem, scheduler, or operator.

Endorser:
  TPM manufacturer, platform vendor, cloud provider, or enterprise asset authority.

Reference Value Provider:
  Citadel policy registry, golden image registry, package/build provenance system.
```

This keeps Citadel compatible with RATS terminology while using a distributed verifier model.

### 8.2 Attestation Evidence

Minimum evidence bundle:

```text
AttestationEvidence {
  subject_node_id
  challenge_nonce
  tpm_quote
  quoted_pcrs
  pcr_selection
  event_log_digest
  event_log_ref
  ak_certificate_or_chain
  agent_measurement
  os_release_info
  kernel_version
  loaded_policy_revision
  timestamp
  signature
}
```

Optional evidence:

```text
- Full TPM event log
- IMA measurement list
- Package manifest
- Container image digests
- Workload identity claims
- Secure Boot state
- Kernel module inventory
- eBPF program inventory
- Service account identity
- Cloud metadata claims
```

### 8.3 Attestation Challenge

```text
AttestationChallenge {
  challenger_node_id
  subject_node_id
  nonce
  pcr_selection
  evidence_requirements
  policy_revision
  expires_at
  signature
}
```

### 8.4 Attestation Result

```text
AttestationResult {
  subject_node_id
  verifier_node_id
  challenge_id
  result: Pass | Warn | Fail | Inconclusive
  reason_codes[]
  observed_measurements[]
  expected_measurements[]
  policy_revision
  confidence
  timestamp
  signature
}
```

Reason codes:

```text
PCR_MISMATCH
QUOTE_SIGNATURE_INVALID
NONCE_MISMATCH
AK_UNTRUSTED
EVENT_LOG_MISSING
EVENT_LOG_INCONSISTENT
AGENT_VERSION_DEPRECATED
POLICY_REVISION_STALE
ROLE_NOT_AUTHORIZED
NETWORK_LOCATION_UNEXPECTED
CLOCK_SKEW_EXCESSIVE
EVIDENCE_INCOMPLETE
```

### 8.5 Attestation Cadence

Use multiple cadences:

```text
Enrollment attestation:
  Required before provisional admission.

Periodic attestation:
  Regular health verification.

Triggered attestation:
  Requested after anomaly, policy change, deployment, reboot, or suspicious gossip.

Challenge attestation:
  Randomized peer-initiated challenge.

Quarantine attestation:
  Required before isolated node can rejoin.
```

### 8.6 Anti-Replay Requirements

Every attestation challenge must include:

```text
- cryptographic nonce
- expiration time
- challenger identity
- subject identity
- PCR selection
- policy revision
```

A quote without a fresh nonce is not acceptable for live attestation.

---

## 9. Gossip Protocol

### 9.1 Purpose

The gossip protocol distributes:

```text
- membership updates
- liveness state
- attestation results
- suspicion reports
- evidence availability records
- policy revision announcements
- quarantine state
- enrollment votes
```

### 9.2 Design Basis

Use a SWIM-inspired design:

```text
- Periodic direct probe.
- Indirect probe through peers.
- Suspicion before failure.
- Infection-style dissemination by piggybacking updates.
- Bounded message sizes.
```

SWIM is appropriate because it separates failure detection from dissemination and supports scalable membership through infection-style update propagation.

### 9.3 Node Membership State

```text
MemberState {
  node_id
  incarnation
  address_set
  role
  trust_state
  liveness_state
  attestation_state
  policy_revision
  last_seen
  suspicion_level
  witness_set
  signature
}
```

Liveness states:

```text
Alive
Suspect
Faulty
Left
Retired
```

Trust states:

```text
Untrusted
ProvisionallyAdmitted
Probationary
Trusted
Degraded
Suspicious
Isolated
Retired
```

### 9.4 Gossip Message

```text
GossipEnvelope {
  mesh_id
  sender_node_id
  sender_incarnation
  sequence_number
  message_type
  payload
  piggyback_records[]
  vector_summary
  timestamp
  signature
}
```

Message types:

```text
PING
ACK
PING_REQ
SUSPECT
ALIVE
FAULTY
ATTESTATION_RESULT
EVIDENCE_RECEIPT
EVIDENCE_REQUEST
POLICY_ANNOUNCEMENT
ENROLLMENT_VOTE
QUARANTINE_NOTICE
```

### 9.5 Failure Detection

Direct probe:

```text
Every probe_interval:
  target = select_probe_target()
  send PING(target)

If ACK received:
  mark target Alive

If ACK timeout:
  select K indirect peers
  send PING_REQ(target) to indirect peers

If indirect ACK received:
  keep target Alive or Degraded

If no indirect ACK:
  mark target Suspect
  gossip SUSPECT(target)
```

Suspicion phase:

```text
When node is Suspect:
  start suspicion_timer
  continue accepting ALIVE refutations

If node proves liveness with higher incarnation:
  mark Alive

If suspicion_timer expires:
  mark Faulty
```

This avoids immediately treating packet loss as compromise.

### 9.6 Trust Gossip vs Liveness Gossip

Citadel must not conflate "down" with "compromised."

```text
Liveness failure:
  Node did not respond.

Trust failure:
  Node responded with invalid, inconsistent, or suspicious evidence.

Evidence failure:
  Node cannot produce, store, or reconstruct required records.

Policy failure:
  Node is alive but incompatible with current policy.
```

A node can be:

```text
Alive + Suspicious
Alive + Isolated
Faulty + PreviouslyTrusted
Alive + Degraded
```

### 9.7 Gossip Security

All gossip messages must be signed.

Each recipient verifies:

```text
- sender identity
- sender membership status
- message signature
- sequence monotonicity
- incarnation validity
- timestamp tolerance
- policy compatibility
```

Replay protection:

```text
- sender sequence numbers
- incarnation numbers
- bounded gossip cache
- signed timestamps
```

### 9.8 Gossip Fanout

Recommended initial defaults:

```text
probe_interval: 1s-5s
indirect_probe_count: 3
piggyback_limit: 32 records
gossip_fanout: 3-5
suspicion_timeout: adaptive
```

For large clusters, use locality-aware gossip:

```text
- rack-local peers
- zone-local peers
- cross-zone peers
- random long-range peers
```

This prevents partitioned trust islands.

---

## 10. Witness Model

### 10.1 Witness Assignment

Each node has a witness set:

```text
WitnessSet {
  subject_node_id
  witnesses[]
  quorum_threshold
  assignment_epoch
  assignment_policy
  signature
}
```

Witness selection should consider:

```text
- failure domain diversity
- rack diversity
- availability zone diversity
- role diversity
- hardware/vendor diversity if available
- historical trust score
- network proximity balanced against independence
```

### 10.2 Witness Responsibilities

Witnesses:

```text
- Challenge the subject periodically.
- Verify attestation evidence.
- Store recent evidence summaries.
- Gossip signed results.
- Escalate inconsistencies.
- Participate in quarantine votes.
```

### 10.3 Witness Rotation

Witnesses must rotate to avoid predictable targeting.

Rotation triggers:

```text
- time interval
- node role change
- trust degradation
- topology change
- operator request
- detected witness correlation risk
```

### 10.4 Anti-Collusion

A witness set should not be concentrated in one trust domain.

Bad witness set:

```text
- same rack
- same hypervisor
- same admin group
- same cloud zone
- same image build
```

Better witness set:

```text
- multiple racks
- multiple zones
- mixed roles
- independent failure domains
```

---

## 11. Trust Scoring

### 11.1 Trust State Is Not Binary

Citadel should avoid simple trusted/untrusted logic.

Recommended states:

```text
Trusted:
  Evidence matches policy and quorum agrees.

Degraded:
  Minor issue, stale policy, missing optional evidence, delayed response.

Suspicious:
  Material inconsistency, failed quote, contradictory observations.

Isolated:
  Removed from normal participation.

Retired:
  Deliberately removed from mesh.

Unknown:
  Insufficient evidence.
```

### 11.2 Trust Score Inputs

```text
- TPM quote validity
- PCR match
- event log consistency
- agent version
- policy freshness
- witness agreement ratio
- liveness history
- evidence replication health
- network behavior reports
- role-specific checks
- prior incidents
```

### 11.3 Example Score Calculation

```text
trust_score =
  0.35 * attestation_score +
  0.20 * witness_agreement_score +
  0.15 * evidence_health_score +
  0.10 * liveness_score +
  0.10 * policy_freshness_score +
  0.10 * behavioral_consistency_score
```

Scores should be explainable. The dashboard must show why a score changed.

### 11.4 Quorum-Based Classification

Example:

```text
Trusted:
  >= 80% witness pass
  no critical failures
  evidence durability above threshold

Degraded:
  >= 60% witness pass
  no critical attestation failure
  recoverable evidence or liveness issue

Suspicious:
  >= 33% critical witness objections
  or any verified quote failure
  or contradictory signed claims

Isolated:
  quarantine policy threshold met
  or operator action
```

---

## 12. Distributed Evidence Storage

### 12.1 Goal

Evidence must survive node deletion, local log tampering, and partial compromise.

Citadel does this by:

```text
- hash-chaining event records
- signing evidence
- distributing evidence fragments
- using erasure coding
- gossiping evidence receipts
- auditing reconstruction
```

### 12.2 Evidence Record

```text
EvidenceRecord {
  record_id
  mesh_id
  subject_node_id
  producer_node_id
  record_type
  previous_record_hash
  payload_hash
  payload_ref
  timestamp
  policy_revision
  signatures[]
}
```

Record types:

```text
ATTESTATION_EVIDENCE
ATTESTATION_RESULT
ENROLLMENT_CLAIM
ENROLLMENT_VOTE
GOSSIP_SUSPICION
QUARANTINE_DECISION
OPERATOR_ACTION
LOG_FRAGMENT
RECONSTRUCTION_PROOF
```

### 12.3 Hash Chain

Each node maintains an append-only local evidence chain:

```text
record_n.hash = HASH(
  record_n.header ||
  record_n.payload_hash ||
  record_n-1.hash
)
```

Witnesses periodically countersign chain heads:

```text
ChainHeadWitness {
  subject_node_id
  chain_head_hash
  sequence_number
  witness_node_id
  timestamp
  signature
}
```

This makes local rewriting detectable.

### 12.4 Erasure Coding

For larger evidence payloads:

```text
payload -> split into N fragments
requires K fragments to reconstruct
fragments distributed to assigned evidence holders
```

Example default:

```text
N = 20
K = 7
```

Evidence fragment:

```text
EvidenceFragment {
  record_id
  fragment_index
  fragment_count
  reconstruction_threshold
  fragment_hash
  fragment_payload
  holder_node_id
  timestamp
  signature
}
```

### 12.5 Evidence Receipts

Every holder returns a signed receipt:

```text
EvidenceReceipt {
  record_id
  fragment_index
  holder_node_id
  fragment_hash
  retention_class
  expires_at
  timestamp
  signature
}
```

Receipts are gossiped.

### 12.6 Reconstruction Audit

Citadel periodically tests reconstruction:

```text
1. Select evidence record.
2. Query fragment holders.
3. Reconstruct payload from K fragments.
4. Verify payload hash.
5. Emit ReconstructionProof.
```

```text
ReconstructionProof {
  record_id
  requested_fragments
  received_fragments
  reconstruction_success
  reconstructed_payload_hash
  verifier_node_id
  timestamp
  signature
}
```

### 12.7 Evidence Durability Score

```text
evidence_durability =
  available_fragments / required_fragments
```

Dashboard example:

```text
Evidence durability: 17/20 fragments available, K=7, PASS
```

---

## 13. Quarantine Protocol

### 13.1 Quarantine Principle

Quarantine must be quorum-driven and reversible.

A single node should not be able to isolate another node unilaterally except under very narrow local safety rules.

### 13.2 Quarantine Decision

```text
QuarantineProposal {
  subject_node_id
  proposer_node_id
  reason_codes[]
  supporting_evidence_refs[]
  proposed_scope
  expires_at
  timestamp
  signature
}
```

Scopes:

```text
ObserveOnly
RestrictMeshVoting
RestrictEvidenceHolding
BlockWorkloadScheduling
NetworkIsolate
CredentialRevoke
FullIsolation
```

### 13.3 Quarantine Vote

```text
QuarantineVote {
  proposal_id
  voter_node_id
  vote: Approve | Reject | Abstain
  reason
  timestamp
  signature
}
```

### 13.4 Quarantine Thresholds

Example:

```text
RestrictMeshVoting:
  3 of 5 assigned witnesses approve

BlockWorkloadScheduling:
  5 of 7 witnesses approve

NetworkIsolate:
  7 of 10 mixed-domain witnesses approve
  or operator approval + 3 witness confirmations

FullIsolation:
  high-confidence policy only
  requires operator override unless emergency mode enabled
```

### 13.5 Rejoin Flow

```text
1. Isolated node requests rejoin.
2. Mesh issues fresh attestation challenge.
3. Node submits new evidence.
4. Witnesses verify.
5. Quarantine removal vote occurs.
6. Node returns to Probationary, not immediately Trusted.
```

---

## 14. Policy Model

### 14.1 Policy Objects

```text
MeshPolicy {
  mesh_id
  policy_revision
  accepted_pcr_profiles
  accepted_agent_versions
  accepted_os_images
  role_definitions
  enrollment_rules
  witness_assignment_rules
  quarantine_rules
  evidence_retention_rules
  gossip_parameters
  signature
}
```

### 14.2 Reference Measurements

```text
ReferenceMeasurement {
  measurement_id
  role
  os_image_digest
  kernel_digest
  initramfs_digest
  secure_boot_state
  expected_pcrs
  package_manifest_digest
  valid_from
  valid_until
  signer
  signature
}
```

### 14.3 Policy Distribution

Policy revisions are gossiped but must be signed by authorized policy signers.

Nodes should reject unsigned policy changes.

Policy activation should support:

```text
Immediate:
  Emergency response.

Staged:
  Percentage rollout.

Epoch-based:
  Activate at mesh epoch N.

Role-specific:
  Apply only to specific node roles.
```

---

## 15. Data Model Summary

### 15.1 Core Tables / Collections

```text
nodes
node_id
state
role
first_seen
last_seen
trust_score
policy_revision
enrollment_epoch

attestations
attestation_id
subject_node_id
verifier_node_id
result
reason_codes
timestamp
evidence_ref

witness_sets
subject_node_id
witness_node_id
assignment_epoch
status

evidence_records
record_id
subject_node_id
record_type
payload_hash
chain_prev_hash
timestamp

evidence_fragments
record_id
fragment_index
holder_node_id
fragment_hash
available

quarantine_events
proposal_id
subject_node_id
scope
status
reason_codes
timestamp

gossip_events
event_id
sender_node_id
message_type
sequence_number
timestamp
```

---

## 16. APIs

### 16.1 Agent API

```text
POST /v1/attestation/challenge
POST /v1/attestation/respond
POST /v1/gossip
POST /v1/evidence/fragment
GET  /v1/evidence/fragment/{record_id}/{index}
POST /v1/quarantine/proposal
POST /v1/quarantine/vote
GET  /v1/status
```

### 16.2 Control Plane API

```text
POST /v1/enrollment/hello
POST /v1/enrollment/claim
GET  /v1/nodes
GET  /v1/nodes/{node_id}
GET  /v1/nodes/{node_id}/attestations
GET  /v1/nodes/{node_id}/evidence
GET  /v1/mesh/health
GET  /v1/policies/current
POST /v1/policies
POST /v1/quarantine/operator-action
```

### 16.3 Dashboard API Views

```text
FleetHealthView
NodeTrustView
WitnessAgreementView
EvidenceDurabilityView
QuarantineView
ForensicTimelineView
PolicyComplianceView
```

---

## 17. Dashboard Requirements

The dashboard should answer:

```text
Is the mesh healthy?
Which nodes are trusted, degraded, suspicious, or isolated?
What changed?
Who agrees?
Can evidence be reconstructed?
What action should the operator take?
```

### 17.1 Fleet View

```text
Cluster: prod-east-1
Mesh health: 98.7%
Trusted nodes: 9,842
Degraded nodes: 121
Suspicious nodes: 34
Isolated nodes: 3
Evidence durability: 99.992%
Quorum health: PASS
Policy revision: 184
```

### 17.2 Node View

```text
node-1842
Status: Suspicious
Reason: TPM quote mismatch
First seen: 08:42:17
Witnesses: 37/40 agree
Last known good: policy rev 183
Current claim: policy rev 184
Observed behavior: unexpected egress + log gap
Recommended action: quarantine
```

### 17.3 Evidence View

```text
Record: attest-node-1842-20260605T084217Z
Fragments: 17/20 available
Threshold: 7 required
Reconstruction: PASS
Witness receipts: 19/20
Chain continuity: PASS
```

### 17.4 Agreement View

The most important dashboard concept is agreement.

Bad dashboard:

```text
Alert: node-1842 suspicious
```

Citadel dashboard:

```text
37 of 40 witnesses independently report quote mismatch for node-1842.
Evidence is reconstructable.
Policy revision 184 expected PCR profile X but observed Y.
```

---

## 18. Security Considerations

### 18.1 Threats

Citadel should explicitly model:

```text
- Single node compromise
- Multiple node compromise
- Malicious new node enrollment
- Replay of old attestation evidence
- Gossip message forgery
- Gossip flooding
- Evidence deletion
- Evidence fragment withholding
- Policy rollback
- Clock manipulation
- Network partition
- Compromised operator account
- Control plane compromise
- TPM key cloning claims / duplicate identity
```

### 18.2 Mitigations

```text
Single node compromise:
  Witness quorum and external evidence.

Multiple node compromise:
  failure-domain-diverse witness selection.

Malicious enrollment:
  probation, quorum admission, duplicate TPM detection.

Replay:
  nonce-bound challenges and signed timestamps.

Gossip forgery:
  signed messages and membership validation.

Evidence deletion:
  erasure coding and distributed receipts.

Policy rollback:
  monotonic policy revisions and signed policy chain.

Clock manipulation:
  tolerate bounded skew; rely on witness timestamps.

Network partition:
  degrade trust confidence; do not overreact as compromise.

Control plane compromise:
  nodes verify signed policy and require mesh evidence.

Operator compromise:
  multi-party approval for destructive actions.
```

---

## 19. Implementation Plan

### Phase 0: Prototype Skeleton

Deliverables:

```text
citadel-agent
citadel-control
citadel-dashboard minimal API
local file evidence store
static policy file
mock TPM provider
```

Acceptance:

```text
- 3 agents form a mesh.
- Agents gossip liveness.
- Mock attestation challenge/response works.
- Dashboard shows node states.
```

### Phase 1: Real TPM Attestation — DONE

Deliverables:

```text
TPM quote provider          ✓ Attestor over Box<dyn TpmBackend> (real vTPM)
AK/EK handling              ✓ create_ak + quote/verify_quote (AK endorsement: Phase 5)
PCR selection config        ✓ NodeConfig.pcr_selection, carried in the challenge
attestation verifier        ✓ Attestor::verify (signature+nonce, reason codes)
reference measurement match  ✓ ReferenceMeasurements golden, not the verifier's own PCRs
```

Acceptance (proven by `mesh_peer_attestation_over_real_vtpm`, gated on
`TPM_VTPM_COMPONENT`, plus mock-backed unit tests in `attest.rs`):

```text
- Agent produces real TPM quote.            ✓ real TPM2_Sign on the vTPM
- Peer verifies nonce-bound quote.          ✓ separate vTPM instance verifies
- PCR mismatch creates Suspicious state.    ✓ divergence from golden → Fail → Suspicious
```

Key Phase 1 correction: a verifier matches a subject's quoted PCRs against a
**policy golden** (`ReferenceMeasurements`), not against the verifier's *own*
measured state — so heterogeneous machines can witness each other.

Follow-up hardening completed: the vTPM `verify_quote` now **cryptographically
verifies the AK signature** (LoadExternal + TPM2_VerifySignature over the
attestation digest, plus the digest-binds-these-PCRs+nonce check), so a
forged/corrupted quote is rejected as `QUOTE_SIGNATURE_INVALID`
(`forged_quote_signature_is_rejected_on_real_vtpm`). Still deferred: real
AK/EK **endorsement-chain** validation that binds the AK to genuine hardware
(Phase 5 enrollment) — until then the AK public is taken from the quote.

### Phase 2: Gossip Membership

Deliverables:

```text
SWIM-inspired probe loop
PING / ACK / PING_REQ
SUSPECT / ALIVE / FAULTY
signed gossip envelopes
piggyback dissemination
```

Acceptance:

```text
- 100 local simulated nodes converge on membership.
- Node failure becomes Suspect before Faulty.
- Restarted node refutes suspicion with higher incarnation.
```

### Phase 3: Witness Sets

Deliverables:

```text
witness assignment engine
periodic peer attestation
witness result gossip
trust score aggregation
```

Acceptance:

```text
- Each node has assigned witnesses.
- Witnesses periodically challenge subjects.
- Dashboard shows witness agreement ratio.
```

### Phase 4: Distributed Evidence

Deliverables:

```text
hash-chained evidence records
fragmenting/erasure coding
evidence receipts
reconstruction checks
```

Acceptance:

```text
- Evidence survives loss of N-K fragment holders.
- Reconstruction proof is emitted.
- Local evidence chain rewrite is detected.
```

### Phase 5: Enrollment and Probation

Deliverables:

```text
enrollment claim
challenge flow
enrollment voting
probation state
promotion logic
```

Acceptance:

```text
- New node joins only after quorum approval.
- New node cannot vote during probation.
- Duplicate identity attempt is flagged.
```

### Phase 6: Quarantine

Deliverables:

```text
quarantine proposals
quarantine voting
scope-based isolation
operator approval workflow
rejoin flow
```

Acceptance:

```text
- Suspicious node can be moved to RestrictedMeshVoting.
- Stronger isolation requires configured quorum.
- Rejoin requires fresh attestation and probation.
```

---

## 20. Recommended Initial Technology Choices

```text
Agent language:
  Rust

Transport:
  QUIC or mTLS over HTTP/2

Serialization:
  protobuf, postcard, or CBOR

Hashing:
  BLAKE3 for internal content addressing
  SHA-256 where TPM/reference ecosystem requires it

Signing:
  Ed25519 for mesh messages
  TPM-backed keys for attestation identity

Storage:
  SQLite for local prototype
  object store or embedded log store later

Dashboard:
  simple web UI first
  topology + trust state + evidence health
```

---

## 21. Open Design Questions

```text
1. Should every node verify every policy signature locally?

2. Should mesh message signing keys be TPM-sealed?

3. How much RATS/EAT compatibility is required in v1?

4. Should Citadel support non-TPM attesters in the same mesh?

5. How aggressive should automatic quarantine be by default?

6. Should control-plane services themselves be ordinary mesh nodes?

7. Should evidence storage be role-specific or assigned randomly?

8. Should witness assignment be deterministic from mesh epoch, or control-plane assigned?

9. How should Citadel handle planned maintenance windows?

10. How should cloud instance identity be combined with TPM identity?
```

---

## 22. Minimal MVP Definition

The smallest real product version is:

```text
Citadel MVP:
  TPM-backed remote attestation for cluster nodes.
  SWIM-style gossip membership.
  Peer witness attestation.
  Signed trust results.
  Dashboard showing node trust state and witness agreement.
```

Do not start with full autonomous quarantine or complex erasure-coded evidence. Those are strong differentiators, but the first proof point is:

> A cluster that continuously checks whether its machines are still the machines it believes they are.

Once that works, the product naturally expands into:

```text
- distributed evidence vault
- quorum quarantine
- forensic reconstruction
- supply-chain measurement policy
- pre-OS UEFI/WAMR enrollment
```

---

## 23. One-Sentence Product Description

> Citadel is a distributed attestation mesh that uses TPM-backed evidence, peer witnessing, gossip, and quorum logic to make machine compromise difficult to hide across a cluster.

---

## Appendix A: Mapping onto the existing citadel codebase

The mesh is an extension of this repo, not a greenfield product. Existing
primitives map onto the design as follows:

| Design concept | Existing primitive to reuse |
|---|---|
| Attester evidence (TPM quote) | `attest quote` / `backend.quote()` (AK over PCRs, nonce-bound) |
| Verifier (quote check) | `attest verify` / `backend.verify_quote()` |
| Evidence identity / mesh signing key | `identity` (TPM-backed keys); Ed25519 for gossip is new |
| Reference values / golden state | `policy` + PCR baselines + MMA reference digests |
| Signed policy distribution | `policy` objects + PolicyAuthorize approvals (signed, witnessed) |
| Hash-chained evidence + witness countersign | `secure-log` entries/segments + witness log (`witness_log_*`) |
| Anti-rollback / monotonic revision | NV counter anti-rollback (`measure`/`secure_log_signer`) |
| Agent API / transport host | `tpmd` (axum + tokio + mTLS, witness endpoint already present) |
| Node self-measurement / agent provenance | MMA `measure enroll` (IMA-corroborated) |

New surface this design adds (not yet in the repo): node identity/epoch
model, SWIM-inspired gossip membership, witness-set assignment + rotation,
distributed (erasure-coded) evidence fragments, trust scoring, and the
quarantine protocol.
