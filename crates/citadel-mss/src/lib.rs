//! # citadel-mss — Mesh-Sealed Secrets (the sealing layer)
//!
//! The **release protocol** (request → assigned-witness vote → quorum
//! authorization, gossip-wired, lease-bound) lives in
//! [`citadel_mesh::release`] and runs in the live mesh (`Node::request_release`
//! / `release_authorized`). This crate is the **TPM-sealing layer** on top: it
//! seals a secret under a mesh-gated policy and only [`open`]s it when handed a
//! satisfied [`ReleaseAuthorization`] — so a secret's bytes are released only by
//! the continuous agreement of the mesh, not by one machine's claim.
//!
//! Design calls (`mss-roadmap.md`): the requester's own TPM holds the sealed
//! blob (C1 — no continuous custodian); the quorum authorization is the unseal
//! gate (C2); categorical witness agreement decides (C3); the assigned set is
//! bounded by HRW (C4); the authorization is nonce-bound (C5).

use citadel_mesh::crypto::MeshPublicKey;
use citadel_mesh::id::Epoch;
use citadel_mesh::{witness, NodeId};
use tpm_core::backend::{SealedData, TpmBackend};

pub use citadel_mesh::release::{ReleaseAuthorization, ReleaseRequest, ReleaseVote};

/// An assigned witness and its mesh public key (for verifying its release vote).
pub type WitnessKey = (NodeId, MeshPublicKey);

/// A mesh-sealed secret's release policy.
#[derive(Clone, Debug)]
pub struct SecretPolicy {
    pub secret_id: [u8; 32],
    pub version: u32,
    /// Approvals required (k).
    pub quorum: usize,
    /// Size of the assigned witness set (n) chosen by HRW over `secret_id`.
    pub witnesses: usize,
    /// Lease lifetime in ticks (the mesh enforces renewal).
    pub lease_ticks: u64,
}

/// A secret sealed under a mesh-gated policy. The blob is held by the requester's
/// own TPM (C1): no continuous custodian — it opens only with a live quorum
/// authorization.
pub struct MeshSealedSecret {
    pub policy: SecretPolicy,
    pub sealed: SealedData,
}

/// The assigned witness set for a secret — the **bounded** quorum (C4), chosen by
/// the same rendezvous hashing the mesh uses for witnesses, keyed on `secret_id`.
pub fn assigned_witnesses(
    secret_id: [u8; 32],
    roster: &[NodeId],
    epoch: u64,
    n: usize,
) -> Vec<NodeId> {
    witness::assign(NodeId(secret_id), roster, Epoch(epoch), n).witnesses
}

/// The policy digest a secret is sealed under — binds the blob to this secret +
/// version (a real TPM would make this a PolicyAuthorize digest the quorum
/// authority satisfies; roadmap S0).
fn policy_digest(policy: &SecretPolicy) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"mss-secret-policy\x00");
    h.update(&policy.secret_id);
    h.update(&policy.version.to_le_bytes());
    *h.finalize().as_bytes()
}

/// Seal `plaintext` under `policy` (provisioning-time; the one trust point, C1).
pub fn seal(
    backend: &dyn TpmBackend,
    plaintext: &[u8],
    policy: SecretPolicy,
) -> anyhow::Result<MeshSealedSecret> {
    let sealed = backend.seal(plaintext, Some(&policy_digest(&policy)))?;
    Ok(MeshSealedSecret { policy, sealed })
}

/// Open a sealed secret **iff** the mesh's release authorization is a satisfied
/// quorum of the secret's eligible witnesses for this exact (nonce-bound)
/// request. Otherwise refuse — the blob is never unsealed without live mesh
/// agreement.
pub fn open(
    backend: &dyn TpmBackend,
    secret: &MeshSealedSecret,
    auth: &ReleaseAuthorization,
    eligible: &[WitnessKey],
) -> anyhow::Result<Vec<u8>> {
    if auth.secret_id != secret.policy.secret_id {
        anyhow::bail!("authorization is for a different secret");
    }
    if !auth.satisfies(secret.policy.quorum, eligible) {
        anyhow::bail!(
            "quorum not satisfied: {} of {} required approvals",
            auth.approvals(eligible),
            secret.policy.quorum
        );
    }
    backend.unseal(&secret.sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use tpm_core::backend::MockBackend;

    fn id(n: u8) -> NodeId {
        NodeId(MeshKeypair::from_seed([n; 32]).public().fingerprint())
    }
    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }
    fn seed_of(wid: NodeId) -> u8 {
        (1u8..=7).find(|s| id(*s) == wid).unwrap()
    }

    fn fixture() -> (Vec<WitnessKey>, [u8; 32], SecretPolicy) {
        let roster: Vec<NodeId> = (1u8..=7).map(id).collect();
        let secret_id = [42u8; 32];
        let policy = SecretPolicy {
            secret_id,
            version: 1,
            quorum: 3,
            witnesses: 5,
            lease_ticks: 10,
        };
        let eligible: Vec<WitnessKey> = assigned_witnesses(secret_id, &roster, 1, policy.witnesses)
            .into_iter()
            .map(|wid| (wid, kp(seed_of(wid)).public()))
            .collect();
        (eligible, secret_id, policy)
    }

    fn request(
        secret_id: [u8; 32],
        policy: &SecretPolicy,
        requester_kp: &MeshKeypair,
        nonce: [u8; 32],
    ) -> ReleaseRequest {
        ReleaseRequest::create(
            requester_kp,
            NodeId(requester_kp.public().fingerprint()),
            secret_id,
            nonce,
            policy.quorum,
            policy.witnesses,
            policy.lease_ticks,
            5,
        )
    }

    #[test]
    fn opens_with_a_quorum_of_trusting_witnesses() {
        let backend = MockBackend::new();
        let (eligible, secret_id, policy) = fixture();
        let secret = seal(&backend, b"db-prod-password", policy.clone()).unwrap();
        let rkp = kp(100);
        let req = request(secret_id, &policy, &rkp, [9u8; 32]);

        let votes: Vec<ReleaseVote> = eligible
            .iter()
            .map(|(wid, _)| ReleaseVote::sign(&kp(seed_of(*wid)), &req, *wid, true, 6))
            .collect();
        let auth = ReleaseAuthorization {
            secret_id,
            requester: req.requester,
            nonce: req.nonce,
            votes,
        };
        assert!(auth.approvals(&eligible) >= 3);
        assert_eq!(
            open(&backend, &secret, &auth, &eligible).unwrap(),
            b"db-prod-password"
        );
    }

    #[test]
    fn denied_without_a_quorum() {
        let backend = MockBackend::new();
        let (eligible, secret_id, policy) = fixture();
        let secret = seal(&backend, b"top-secret", policy.clone()).unwrap();
        let rkp = kp(100);
        let req = request(secret_id, &policy, &rkp, [9u8; 32]);

        // Only 2 of the 5 eligible witnesses approve (the rest see it compromised).
        let votes: Vec<ReleaseVote> = eligible
            .iter()
            .enumerate()
            .map(|(i, (wid, _))| ReleaseVote::sign(&kp(seed_of(*wid)), &req, *wid, i < 2, 6))
            .collect();
        let auth = ReleaseAuthorization {
            secret_id,
            requester: req.requester,
            nonce: req.nonce,
            votes,
        };
        assert_eq!(auth.approvals(&eligible), 2);
        assert!(open(&backend, &secret, &auth, &eligible).is_err());
    }

    #[test]
    fn replayed_authorization_is_rejected() {
        let backend = MockBackend::new();
        let (eligible, secret_id, policy) = fixture();
        let secret = seal(&backend, b"secret", policy.clone()).unwrap();
        let rkp = kp(100);
        // A full quorum approved an OLD request (nonce A).
        let old = request(secret_id, &policy, &rkp, [0xAA; 32]);
        let votes: Vec<ReleaseVote> = eligible
            .iter()
            .map(|(wid, _)| ReleaseVote::sign(&kp(seed_of(*wid)), &old, *wid, true, 6))
            .collect();
        // Replay it against a fresh nonce B: tampering the nonce voids every sig.
        let auth = ReleaseAuthorization {
            secret_id,
            requester: old.requester,
            nonce: [0xBB; 32],
            votes,
        };
        assert_eq!(auth.approvals(&eligible), 0);
        assert!(open(&backend, &secret, &auth, &eligible).is_err());
    }

    #[test]
    fn unassigned_and_forged_votes_do_not_count() {
        let backend = MockBackend::new();
        let (eligible, secret_id, policy) = fixture();
        let secret = seal(&backend, b"secret", policy.clone()).unwrap();
        let rkp = kp(100);
        let req = request(secret_id, &policy, &rkp, [9u8; 32]);

        let mut votes: Vec<ReleaseVote> = eligible
            .iter()
            .take(2)
            .map(|(wid, _)| ReleaseVote::sign(&kp(seed_of(*wid)), &req, *wid, true, 6))
            .collect();
        // A vote from a node NOT in the eligible set, and a forged vote claiming
        // an eligible voter but signed by an impostor.
        votes.push(ReleaseVote::sign(&kp(200), &req, id(200), true, 6));
        votes.push(ReleaseVote::sign(&kp(201), &req, eligible[2].0, true, 6));
        let auth = ReleaseAuthorization {
            secret_id,
            requester: req.requester,
            nonce: req.nonce,
            votes,
        };

        assert_eq!(
            auth.approvals(&eligible),
            2,
            "only genuine eligible approvals count"
        );
        assert!(open(&backend, &secret, &auth, &eligible).is_err());
    }
}
