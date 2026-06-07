//! Distributed, tamper-evident evidence (design §12).
//!
//! Three mechanisms combine so that evidence is durable and rewriting it is
//! detectable:
//!
//! * **Hash-chained records** ([`EvidenceChain`]) — each node keeps an
//!   append-only chain where every record commits to the previous one, so a
//!   *partial* rewrite breaks the links.
//! * **Witnessed chain heads** ([`ChainHeadWitness`]) — peers countersign a
//!   node's chain head at a sequence; a *full* (internally consistent)
//!   rewrite still no longer matches the head a witness signed.
//! * **Erasure-coded fragments** ([`crate::erasure`]) scattered to assigned
//!   **holders**, each returning a signed [`EvidenceReceipt`]; a periodic
//!   [`audit_reconstruction`] proves the evidence can still be rebuilt.

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::erasure::{self, EvidenceFragment};
use crate::id::{MeshId, NodeId};

/// What an evidence record attests (design §12.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    AttestationEvidence,
    AttestationResult,
    EnrollmentClaim,
    EnrollmentVote,
    GossipSuspicion,
    QuarantineDecision,
    OperatorAction,
    LogFragment,
    ReconstructionProof,
    /// A signed reference manifest this node adopted (measured-state-transitions
    /// §10.2) — the audit trail of accepted-state changes.
    ReferenceUpdate,
    /// A signed application appraisal (`application-appraisal.md` §5.1).
    AppAttestationResult,
}

/// One link in a node's evidence chain. The record commits to a content
/// digest of the evidence (`payload_hash`) and to the previous link
/// (`previous_record_hash`); the record's own hash is
/// `BLAKE3(content ‖ previous_record_hash)` (design §12.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRecord {
    pub seq: u64,
    pub mesh_id: MeshId,
    pub subject: NodeId,
    pub producer: NodeId,
    pub record_type: RecordType,
    pub previous_record_hash: [u8; 32],
    pub payload_hash: [u8; 32],
    pub timestamp_tick: u64,
    pub policy_revision: u64,
}

impl EvidenceRecord {
    /// The record's own fields, excluding the chain link — the "header".
    fn content_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&(
            self.seq,
            &self.mesh_id,
            &self.subject,
            &self.producer,
            &self.record_type,
            &self.payload_hash,
            self.timestamp_tick,
            self.policy_revision,
        ))
        .expect("record fields are serializable")
    }

    /// `BLAKE3(content ‖ previous_record_hash)`.
    pub fn record_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.content_bytes());
        h.update(&self.previous_record_hash);
        *h.finalize().as_bytes()
    }
}

/// Content id of a payload (used as the erasure `record_id`): `BLAKE3(payload)`.
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// A node's append-only evidence chain.
#[derive(Clone, Serialize, Deserialize)]
pub struct EvidenceChain {
    owner: NodeId,
    mesh_id: MeshId,
    records: Vec<EvidenceRecord>,
    head: [u8; 32],
}

impl EvidenceChain {
    pub fn new(owner: NodeId, mesh_id: MeshId) -> Self {
        EvidenceChain {
            owner,
            mesh_id,
            records: Vec::new(),
            head: [0u8; 32],
        }
    }

    pub fn owner(&self) -> NodeId {
        self.owner
    }

    pub fn head(&self) -> [u8; 32] {
        self.head
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, seq: u64) -> Option<&EvidenceRecord> {
        self.records.get(seq as usize)
    }

    /// Append a record committing to `payload_hash`, advancing the head.
    pub fn append(
        &mut self,
        subject: NodeId,
        record_type: RecordType,
        payload_hash: [u8; 32],
        timestamp_tick: u64,
        policy_revision: u64,
    ) -> &EvidenceRecord {
        let record = EvidenceRecord {
            seq: self.records.len() as u64,
            mesh_id: self.mesh_id.clone(),
            subject,
            producer: self.owner,
            record_type,
            previous_record_hash: self.head,
            payload_hash,
            timestamp_tick,
            policy_revision,
        };
        self.head = record.record_hash();
        self.records.push(record);
        self.records.last().expect("just pushed")
    }

    /// The hash of the record at `seq`, recomputed from its current contents.
    pub fn head_at(&self, seq: u64) -> Option<[u8; 32]> {
        self.records.get(seq as usize).map(|r| r.record_hash())
    }

    /// Verify the chain links: every record must point at the previous one
    /// and the stored head must match. `Err(i)` names the first broken link
    /// (or `len` if only the head is wrong) — i.e. a partial rewrite.
    pub fn verify_integrity(&self) -> Result<(), u64> {
        let mut prev = [0u8; 32];
        for (i, r) in self.records.iter().enumerate() {
            if r.previous_record_hash != prev {
                return Err(i as u64);
            }
            prev = r.record_hash();
        }
        if prev != self.head {
            return Err(self.records.len() as u64);
        }
        Ok(())
    }

    /// Detect a rewrite against a witnessed head: `true` if the chain no
    /// longer hashes to what `witnessed` countersigned at its sequence.
    /// Catches even a *fully relinked* rewrite that `verify_integrity` would
    /// accept, because a witness already signed the old head.
    pub fn contradicts_witness(&self, witnessed: &ChainHeadWitness) -> bool {
        witnessed.subject == self.owner
            && self.head_at(witnessed.seq) != Some(witnessed.chain_head_hash)
    }

    /// Recompute all links and the head from the current record contents
    /// (used to model a fully consistent — but still witness-detectable —
    /// rewrite; not something an honest node does).
    #[cfg(test)]
    fn relink(&mut self) {
        let mut prev = [0u8; 32];
        for r in &mut self.records {
            r.previous_record_hash = prev;
            prev = r.record_hash();
        }
        self.head = prev;
    }
}

/// A witness's signed statement that node `subject`'s chain head was
/// `chain_head_hash` at sequence `seq` (design §12.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainHeadWitness {
    pub subject: NodeId,
    pub seq: u64,
    pub chain_head_hash: [u8; 32],
    pub witness: NodeId,
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl ChainHeadWitness {
    fn signing_bytes(subject: NodeId, seq: u64, head: [u8; 32], witness: NodeId, tick: u64) -> Vec<u8> {
        serde_json::to_vec(&("chain-head", subject, seq, head, witness, tick))
            .expect("serializable")
    }

    /// Countersign a subject's chain head as `witness`.
    pub fn sign(
        kp: &MeshKeypair,
        witness: NodeId,
        subject: NodeId,
        seq: u64,
        chain_head_hash: [u8; 32],
        timestamp_tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(subject, seq, chain_head_hash, witness, timestamp_tick));
        ChainHeadWitness {
            subject,
            seq,
            chain_head_hash,
            witness,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify(&self, witness_pub: &MeshPublicKey) -> bool {
        witness_pub.verify(
            &Self::signing_bytes(self.subject, self.seq, self.chain_head_hash, self.witness, self.timestamp_tick),
            &self.signature,
        )
    }
}

/// A holder's signed acknowledgement that it stores a given fragment
/// (design §12.5). Gossiped so the mesh tracks durability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceReceipt {
    pub record_id: [u8; 32],
    pub fragment_index: usize,
    pub holder: NodeId,
    pub fragment_hash: [u8; 32],
    pub timestamp_tick: u64,
    pub signature: Signature,
}

impl EvidenceReceipt {
    fn signing_bytes(record_id: [u8; 32], index: usize, holder: NodeId, fragment_hash: [u8; 32], tick: u64) -> Vec<u8> {
        serde_json::to_vec(&("evidence-receipt", record_id, index, holder, fragment_hash, tick))
            .expect("serializable")
    }

    /// Sign a receipt for `fragment` as `holder`.
    pub fn sign(kp: &MeshKeypair, holder: NodeId, fragment: &EvidenceFragment, timestamp_tick: u64) -> Self {
        let signature = kp.sign(&Self::signing_bytes(
            fragment.record_id,
            fragment.index,
            holder,
            fragment.fragment_hash,
            timestamp_tick,
        ));
        EvidenceReceipt {
            record_id: fragment.record_id,
            fragment_index: fragment.index,
            holder,
            fragment_hash: fragment.fragment_hash,
            timestamp_tick,
            signature,
        }
    }

    pub fn verify(&self, holder_pub: &MeshPublicKey) -> bool {
        holder_pub.verify(
            &Self::signing_bytes(self.record_id, self.fragment_index, self.holder, self.fragment_hash, self.timestamp_tick),
            &self.signature,
        )
    }
}

/// The result of a reconstruction audit (design §12.6).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconstructionProof {
    pub record_id: [u8; 32],
    pub requested: usize,
    pub received: usize,
    pub success: bool,
    pub reconstructed_payload_hash: [u8; 32],
    pub verifier: NodeId,
    pub timestamp_tick: u64,
}

/// Attempt to rebuild a record's payload from the `available` fragments and
/// check it against `expected_payload_hash`, emitting a proof (design §12.6).
pub fn audit_reconstruction(
    record_id: [u8; 32],
    expected_payload_hash: [u8; 32],
    available: &[EvidenceFragment],
    verifier: NodeId,
    timestamp_tick: u64,
) -> ReconstructionProof {
    let (success, got_hash) = match erasure::reconstruct(available) {
        Ok(payload) => {
            let h = payload_hash(&payload);
            (h == expected_payload_hash, h)
        }
        Err(_) => (false, [0u8; 32]),
    };
    ReconstructionProof {
        record_id,
        requested: available.len(),
        received: available.iter().filter(|f| f.integrity_ok()).count(),
        success,
        reconstructed_payload_hash: got_hash,
        verifier,
        timestamp_tick,
    }
}

/// Assign `count` fragment **holders** for `record_id` from `roster` via
/// rendezvous (HRW) hashing — independent of the witness/attestation
/// assignment, keyed on the record so different records spread differently
/// (design §12.4, §14). Deterministic; every node computes the same holders.
pub fn assign_holders(record_id: [u8; 32], roster: &[NodeId], count: usize) -> Vec<NodeId> {
    let mut scored: Vec<([u8; 32], NodeId)> = roster
        .iter()
        .map(|n| {
            let mut h = blake3::Hasher::new();
            h.update(b"citadel-evidence-holder\x00");
            h.update(&record_id);
            h.update(&n.0);
            (*h.finalize().as_bytes(), *n)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0));
    scored.into_iter().take(count).map(|(_, n)| n).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::erasure::ErasureScheme;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }
    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }

    fn chain_of(n: usize) -> EvidenceChain {
        let mut c = EvidenceChain::new(nid(1), MeshId::new("m"));
        for i in 0..n {
            let ph = payload_hash(format!("evidence-{i}").as_bytes());
            c.append(nid(2), RecordType::AttestationResult, ph, i as u64, 1);
        }
        c
    }

    #[test]
    fn chain_links_and_integrity() {
        let c = chain_of(5);
        assert_eq!(c.len(), 5);
        assert_eq!(c.verify_integrity(), Ok(()));
        // Each record points at the previous one's hash.
        for i in 1..5u64 {
            assert_eq!(
                c.get(i).unwrap().previous_record_hash,
                c.get(i - 1).unwrap().record_hash()
            );
        }
    }

    #[test]
    fn partial_rewrite_breaks_the_links() {
        let mut c = chain_of(5);
        // Tamper a record's payload without relinking downstream.
        c.records[2].payload_hash = payload_hash(b"forged");
        // Record 2's hash changed, but record 3 still points at the old one.
        assert_eq!(c.verify_integrity(), Err(3));
    }

    #[test]
    fn full_rewrite_is_caught_by_a_witnessed_head() {
        let mut c = chain_of(5);
        let witnessed = ChainHeadWitness::sign(&kp(9), nid(9), c.owner(), 4, c.head_at(4).unwrap(), 100);
        assert!(witnessed.verify(&kp(9).public()));
        assert!(!c.contradicts_witness(&witnessed), "honest chain agrees");

        // Attacker rewrites a past record AND relinks the whole chain so the
        // internal links stay consistent...
        c.records[2].payload_hash = payload_hash(b"forged");
        c.relink();
        // ...verify_integrity now passes (links consistent)...
        assert_eq!(c.verify_integrity(), Ok(()));
        // ...but the head no longer matches what a witness signed.
        assert!(c.contradicts_witness(&witnessed), "witnessed head detects the rewrite");
    }

    #[test]
    fn receipts_sign_and_verify() {
        let scheme = ErasureScheme::new(3, 3).unwrap();
        let frags = scheme.encode([7u8; 32], b"payload").unwrap();
        let receipt = EvidenceReceipt::sign(&kp(4), nid(4), &frags[0], 10);
        assert!(receipt.verify(&kp(4).public()));
        assert!(!receipt.verify(&kp(5).public()), "wrong holder key fails");
    }

    #[test]
    fn reconstruction_proof_success_and_failure() {
        let scheme = ErasureScheme::new(7, 13).unwrap();
        let payload = b"durable attestation evidence".to_vec();
        let rid = payload_hash(&payload);
        let frags = scheme.encode(rid, &payload).unwrap();

        // Enough fragments → proof succeeds and the hash matches.
        let kept: Vec<EvidenceFragment> = frags.iter().skip(13).cloned().collect();
        let proof = audit_reconstruction(rid, rid, &kept, nid(3), 5);
        assert!(proof.success);
        assert_eq!(proof.reconstructed_payload_hash, rid);

        // Too few fragments → proof records failure (no panic).
        let too_few: Vec<EvidenceFragment> = frags.iter().take(3).cloned().collect();
        let proof = audit_reconstruction(rid, rid, &too_few, nid(3), 6);
        assert!(!proof.success);
    }

    #[test]
    fn holders_are_deterministic_and_sized() {
        let roster: Vec<NodeId> = (1..=20).map(nid).collect();
        let a = assign_holders([1u8; 32], &roster, 5);
        let b = assign_holders([1u8; 32], &roster, 5);
        assert_eq!(a, b);
        assert_eq!(a.len(), 5);
        // A different record spreads to a (generally) different holder set.
        let c = assign_holders([2u8; 32], &roster, 5);
        assert_ne!(a, c);
    }
}
