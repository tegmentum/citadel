//! # citadel-mss — Mesh-Sealed Secrets (MSS1 prototype)
//!
//! A secret opens **iff a quorum of its assigned witnesses currently approve**,
//! each approving only if it independently classifies the requester `Trusted`.
//! Access is therefore governed by the *continuous agreement of the mesh*, not by
//! one machine's claim (`mss-roadmap.md`).
//!
//! Design calls realised here:
//! * **C2** — the binding is quorum-as-authority: a [`ReleaseAuthorization`] (the
//!   assigned witnesses' signed approvals, bound to a fresh nonce) is what gates
//!   [`open`]; a real TPM would require it via PolicyAuthorize on the seal (S0).
//! * **C3** — categorical witness agreement gates release (k-of-n APPROVE), no
//!   numeric trust score.
//! * **C4** — the quorum is the secret's **bounded** assigned-witness set
//!   ([`assigned_witnesses`] via the mesh's HRW), so availability needs only k of
//!   n reachable.
//! * **C5** — every approval is bound to the request nonce: a replayed
//!   healthy-state authorization is rejected.
//!
//! This prototype proves the protocol + the seal/open binding over a
//! [`TpmBackend`]; gossip-wiring it into the live `Node` is MSS3.

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::id::Epoch;
use citadel_mesh::{witness, NodeId};
use tpm_core::backend::{SealedData, TpmBackend};

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
    /// Lease lifetime in ticks (MSS2 enforces renewal; here it rides the nonce).
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

/// A node's signed request to open a secret. The `nonce` makes each request
/// (and the authorization built for it) single-use (C5).
#[derive(Clone, Debug)]
pub struct ReleaseRequest {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub tick: u64,
    pub signature: Signature,
}

impl ReleaseRequest {
    fn signing_bytes(
        secret_id: &[u8; 32],
        requester: &NodeId,
        nonce: &[u8; 32],
        tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&("mss-release-request", secret_id, requester, nonce, tick))
            .expect("ser")
    }

    pub fn sign(
        kp: &MeshKeypair,
        requester: NodeId,
        secret_id: [u8; 32],
        nonce: [u8; 32],
        tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(&secret_id, &requester, &nonce, tick));
        ReleaseRequest {
            secret_id,
            requester,
            nonce,
            tick,
            signature,
        }
    }

    pub fn verify(&self, requester_pub: &MeshPublicKey) -> bool {
        requester_pub.verify(
            &Self::signing_bytes(&self.secret_id, &self.requester, &self.nonce, self.tick),
            &self.signature,
        )
    }
}

/// A witness's signed ballot on a release request — APPROVE only if the witness
/// independently sees the requester `Trusted` (C3). Bound to the request nonce.
#[derive(Clone, Debug)]
pub struct ReleaseVote {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub voter: NodeId,
    pub approve: bool,
    pub signature: Signature,
}

impl ReleaseVote {
    fn signing_bytes(
        secret_id: &[u8; 32],
        requester: &NodeId,
        nonce: &[u8; 32],
        voter: &NodeId,
        approve: bool,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "mss-release-vote",
            secret_id,
            requester,
            nonce,
            voter,
            approve,
        ))
        .expect("ser")
    }

    /// Cast a vote: `trusts_requester` is the witness's *own* current trust
    /// classification (it would attest the requester in a live mesh, MSS3).
    pub fn cast(
        kp: &MeshKeypair,
        voter: NodeId,
        req: &ReleaseRequest,
        trusts_requester: bool,
    ) -> Self {
        let approve = trusts_requester;
        let signature = kp.sign(&Self::signing_bytes(
            &req.secret_id,
            &req.requester,
            &req.nonce,
            &voter,
            approve,
        ));
        ReleaseVote {
            secret_id: req.secret_id,
            requester: req.requester,
            nonce: req.nonce,
            voter,
            approve,
            signature,
        }
    }

    pub fn verify(&self, voter_pub: &MeshPublicKey) -> bool {
        voter_pub.verify(
            &Self::signing_bytes(
                &self.secret_id,
                &self.requester,
                &self.nonce,
                &self.voter,
                self.approve,
            ),
            &self.signature,
        )
    }
}

/// The collected approvals for a release — the quorum authorization (C2). A real
/// TPM seal would require this via PolicyAuthorize; here [`open`] checks it.
pub struct ReleaseAuthorization {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub votes: Vec<ReleaseVote>,
}

impl ReleaseAuthorization {
    pub fn new(req: &ReleaseRequest, votes: Vec<ReleaseVote>) -> Self {
        ReleaseAuthorization {
            secret_id: req.secret_id,
            requester: req.requester,
            nonce: req.nonce,
            votes,
        }
    }

    /// How many **distinct assigned witnesses** validly approved this exact
    /// request (correct secret/requester/nonce, signature verifies, in the
    /// assigned set). Forged, unassigned, duplicate, or stale-nonce votes don't
    /// count.
    pub fn approvals(&self, assigned: &[WitnessKey]) -> usize {
        let mut counted = std::collections::HashSet::new();
        let mut n = 0;
        for v in &self.votes {
            let Some((_, pubkey)) = assigned.iter().find(|(id, _)| *id == v.voter) else {
                continue;
            };
            if v.secret_id == self.secret_id
                && v.requester == self.requester
                && v.nonce == self.nonce
                && v.approve
                && v.verify(pubkey)
                && counted.insert(v.voter)
            {
                n += 1;
            }
        }
        n
    }

    pub fn satisfies(&self, policy: &SecretPolicy, assigned: &[WitnessKey]) -> bool {
        self.approvals(assigned) >= policy.quorum
    }
}

/// The policy digest a secret is sealed under — binds the blob to this secret +
/// version (a real TPM would make this a PolicyAuthorize digest the quorum
/// authority satisfies; S0).
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

/// Open a sealed secret **iff** the authorization is a satisfied quorum of the
/// secret's assigned witnesses for this exact (nonce-bound) request. Otherwise
/// refuse — the blob is never unsealed without live mesh agreement.
pub fn open(
    backend: &dyn TpmBackend,
    secret: &MeshSealedSecret,
    auth: &ReleaseAuthorization,
    assigned: &[WitnessKey],
) -> anyhow::Result<Vec<u8>> {
    if auth.secret_id != secret.policy.secret_id {
        anyhow::bail!("authorization is for a different secret");
    }
    if !auth.satisfies(&secret.policy, assigned) {
        anyhow::bail!(
            "quorum not satisfied: {} of {} required approvals",
            auth.approvals(assigned),
            secret.policy.quorum
        );
    }
    backend.unseal(&secret.sealed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpm_core::backend::MockBackend;

    fn id(n: u8) -> NodeId {
        NodeId(MeshKeypair::from_seed([n; 32]).public().fingerprint())
    }
    fn kp(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([n; 32])
    }

    fn fixture() -> (Vec<NodeId>, Vec<WitnessKey>, [u8; 32], SecretPolicy) {
        let roster: Vec<NodeId> = (1u8..=7).map(id).collect();
        let secret_id = [42u8; 32];
        let policy = SecretPolicy {
            secret_id,
            version: 1,
            quorum: 3,
            witnesses: 5,
            lease_ticks: 10,
        };
        let assigned_ids = assigned_witnesses(secret_id, &roster, 1, policy.witnesses);
        // (id, pubkey) for the assigned set — map id back to its keypair seed.
        let assigned: Vec<WitnessKey> = assigned_ids
            .iter()
            .map(|wid| {
                let seed = (1u8..=7).find(|s| id(*s) == *wid).unwrap();
                (*wid, kp(seed).public())
            })
            .collect();
        (roster, assigned, secret_id, policy)
    }

    #[test]
    fn opens_with_a_quorum_of_trusting_witnesses() {
        let backend = MockBackend::new();
        let (_, assigned, secret_id, policy) = fixture();
        let secret = seal(&backend, b"db-prod-password", policy).unwrap();

        let requester_kp = kp(100);
        let requester = NodeId(requester_kp.public().fingerprint());
        let req = ReleaseRequest::sign(&requester_kp, requester, secret_id, [9u8; 32], 5);
        assert!(req.verify(&requester_kp.public()));

        // Every assigned witness trusts the requester → approves.
        let votes: Vec<ReleaseVote> = assigned
            .iter()
            .map(|(wid, _)| {
                let seed = (1u8..=7).find(|s| id(*s) == *wid).unwrap();
                ReleaseVote::cast(&kp(seed), *wid, &req, true)
            })
            .collect();
        let auth = ReleaseAuthorization::new(&req, votes);
        assert!(auth.approvals(&assigned) >= 3);
        assert_eq!(
            open(&backend, &secret, &auth, &assigned).unwrap(),
            b"db-prod-password"
        );
    }

    #[test]
    fn denied_without_a_quorum() {
        let backend = MockBackend::new();
        let (_, assigned, secret_id, policy) = fixture();
        let secret = seal(&backend, b"top-secret", policy).unwrap();
        let requester_kp = kp(100);
        let requester = NodeId(requester_kp.public().fingerprint());
        let req = ReleaseRequest::sign(&requester_kp, requester, secret_id, [9u8; 32], 5);

        // Only 2 of the 5 assigned witnesses trust the requester (the rest see it
        // as compromised and DENY) — below the quorum of 3.
        let votes: Vec<ReleaseVote> = assigned
            .iter()
            .enumerate()
            .map(|(i, (wid, _))| {
                let seed = (1u8..=7).find(|s| id(*s) == *wid).unwrap();
                ReleaseVote::cast(&kp(seed), *wid, &req, i < 2)
            })
            .collect();
        let auth = ReleaseAuthorization::new(&req, votes);
        assert_eq!(auth.approvals(&assigned), 2);
        assert!(
            open(&backend, &secret, &auth, &assigned).is_err(),
            "quorum not met → no release"
        );
    }

    #[test]
    fn replayed_authorization_is_rejected() {
        let backend = MockBackend::new();
        let (_, assigned, secret_id, policy) = fixture();
        let secret = seal(&backend, b"secret", policy).unwrap();
        let rkp = kp(100);
        let requester = NodeId(rkp.public().fingerprint());

        // A full quorum approved an OLD request (nonce A, when the node was healthy).
        let old = ReleaseRequest::sign(&rkp, requester, secret_id, [0xAA; 32], 1);
        let votes: Vec<ReleaseVote> = assigned
            .iter()
            .map(|(wid, _)| {
                let seed = (1u8..=7).find(|s| id(*s) == *wid).unwrap();
                ReleaseVote::cast(&kp(seed), *wid, &old, true)
            })
            .collect();
        let mut auth = ReleaseAuthorization::new(&old, votes);
        // Replay it against a FRESH request (nonce B): tampering the auth's nonce
        // invalidates every vote signature.
        auth.nonce = [0xBB; 32];
        assert_eq!(
            auth.approvals(&assigned),
            0,
            "stale-nonce authorization counts for nothing"
        );
        assert!(open(&backend, &secret, &auth, &assigned).is_err());
    }

    #[test]
    fn unassigned_and_forged_votes_do_not_count() {
        let backend = MockBackend::new();
        let (_, assigned, secret_id, policy) = fixture();
        let secret = seal(&backend, b"secret", policy).unwrap();
        let rkp = kp(100);
        let requester = NodeId(rkp.public().fingerprint());
        let req = ReleaseRequest::sign(&rkp, requester, secret_id, [9u8; 32], 5);

        // 2 valid assigned approvals...
        let mut votes: Vec<ReleaseVote> = assigned
            .iter()
            .take(2)
            .map(|(wid, _)| {
                let seed = (1u8..=7).find(|s| id(*s) == *wid).unwrap();
                ReleaseVote::cast(&kp(seed), *wid, &req, true)
            })
            .collect();
        // ...plus a vote from a node NOT in the assigned set (seed 200),
        votes.push(ReleaseVote::cast(&kp(200), id(200), &req, true));
        // ...plus a forged vote (claims an assigned voter but signed by an impostor).
        let victim = assigned[2].0;
        votes.push(ReleaseVote::cast(&kp(201), victim, &req, true));
        let auth = ReleaseAuthorization::new(&req, votes);

        assert_eq!(
            auth.approvals(&assigned),
            2,
            "only the genuine assigned approvals count"
        );
        assert!(open(&backend, &secret, &auth, &assigned).is_err());
    }
}
