//! Mesh-governed secret release (Mesh-Sealed Secrets — `mss-roadmap.md`).
//!
//! A node *requests* release of a secret; the secret's **assigned witnesses**
//! (rendezvous-hashed over `secret_id`, the requester excluded) each vote
//! APPROVE only if they independently classify the requester `Trusted` (C3);
//! `quorum` approvals form a [`ReleaseAuthorization`]. The authorization is bound
//! to the request `nonce` (single-use, C5) and lives for the request's lease (C4)
//! — renewal is a fresh request that re-runs the vote, so a node whose trust
//! dropped is denied at renewal even though it kept access mid-lease.
//!
//! This is the gossip protocol + tally; the TPM seal/open that turns an
//! authorization into bytes is `citadel-mss`.

use serde::{Deserialize, Serialize};

use crate::crypto::{MeshKeypair, MeshPublicKey, Signature};
use crate::id::NodeId;

/// A node's signed request to open a secret. Carries the policy essentials so any
/// witness can compute the assigned set + quorum without external state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseRequest {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    /// Approvals required (k).
    pub quorum: usize,
    /// Size of the assigned witness set (n) chosen by HRW over `secret_id`.
    pub witness_count: usize,
    /// Ticks the granted authorization remains valid before renewal (C4).
    pub lease_ticks: u64,
    /// A **bootstrap-class** secret (MSS7 / C5): witnesses approve a requester at
    /// `Probationary` trust, not only `Trusted` — for low-value cold-start secrets
    /// (e.g. a new node's own service cert). `false` = full `Trusted` required.
    pub bootstrap: bool,
    pub tick: u64,
    pub signature: Signature,
}

impl ReleaseRequest {
    /// The round key: `BLAKE3(secret_id ‖ requester ‖ nonce)`.
    pub fn id(&self) -> [u8; 32] {
        request_id(&self.secret_id, &self.requester, &self.nonce)
    }

    #[allow(clippy::too_many_arguments)]
    fn signing_bytes(
        secret_id: &[u8; 32],
        requester: &NodeId,
        nonce: &[u8; 32],
        quorum: usize,
        witness_count: usize,
        lease_ticks: u64,
        bootstrap: bool,
        tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "mss-release-request",
            secret_id,
            requester,
            nonce,
            quorum,
            witness_count,
            lease_ticks,
            bootstrap,
            tick,
        ))
        .expect("serializable")
    }

    /// A standard release request (full `Trusted` required).
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        kp: &MeshKeypair,
        requester: NodeId,
        secret_id: [u8; 32],
        nonce: [u8; 32],
        quorum: usize,
        witness_count: usize,
        lease_ticks: u64,
        tick: u64,
    ) -> Self {
        Self::create_classed(
            kp,
            requester,
            secret_id,
            nonce,
            quorum,
            witness_count,
            lease_ticks,
            false,
            tick,
        )
    }

    /// A release request for a chosen class (`bootstrap = true` accepts a
    /// `Probationary` requester — MSS7 cold-start).
    #[allow(clippy::too_many_arguments)]
    pub fn create_classed(
        kp: &MeshKeypair,
        requester: NodeId,
        secret_id: [u8; 32],
        nonce: [u8; 32],
        quorum: usize,
        witness_count: usize,
        lease_ticks: u64,
        bootstrap: bool,
        tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(
            &secret_id,
            &requester,
            &nonce,
            quorum,
            witness_count,
            lease_ticks,
            bootstrap,
            tick,
        ));
        ReleaseRequest {
            secret_id,
            requester,
            nonce,
            quorum,
            witness_count,
            lease_ticks,
            bootstrap,
            tick,
            signature,
        }
    }

    pub fn verify_signature(&self, requester_pub: &MeshPublicKey) -> bool {
        requester_pub.verify(
            &Self::signing_bytes(
                &self.secret_id,
                &self.requester,
                &self.nonce,
                self.quorum,
                self.witness_count,
                self.lease_ticks,
                self.bootstrap,
                self.tick,
            ),
            &self.signature,
        )
    }
}

/// An assigned witness's signed ballot on a release request (bound to the nonce).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseVote {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub voter: NodeId,
    pub approve: bool,
    pub tick: u64,
    pub signature: Signature,
}

impl ReleaseVote {
    pub fn request_id(&self) -> [u8; 32] {
        request_id(&self.secret_id, &self.requester, &self.nonce)
    }

    fn signing_bytes(
        secret_id: &[u8; 32],
        requester: &NodeId,
        nonce: &[u8; 32],
        voter: &NodeId,
        approve: bool,
        tick: u64,
    ) -> Vec<u8> {
        serde_json::to_vec(&(
            "mss-release-vote",
            secret_id,
            requester,
            nonce,
            voter,
            approve,
            tick,
        ))
        .expect("serializable")
    }

    pub fn sign(
        kp: &MeshKeypair,
        req: &ReleaseRequest,
        voter: NodeId,
        approve: bool,
        tick: u64,
    ) -> Self {
        let signature = kp.sign(&Self::signing_bytes(
            &req.secret_id,
            &req.requester,
            &req.nonce,
            &voter,
            approve,
            tick,
        ));
        ReleaseVote {
            secret_id: req.secret_id,
            requester: req.requester,
            nonce: req.nonce,
            voter,
            approve,
            tick,
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
                self.tick,
            ),
            &self.signature,
        )
    }
}

/// The collected approvals for a release — the quorum authorization (C2). The TPM
/// seal (`citadel-mss`) requires this to open the bytes.
#[derive(Clone, Debug)]
pub struct ReleaseAuthorization {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub votes: Vec<ReleaseVote>,
}

impl ReleaseAuthorization {
    /// Distinct **eligible** witnesses that validly approved this exact request.
    /// Forged, unassigned, duplicate, or stale-nonce votes don't count.
    pub fn approvals(&self, eligible: &[(NodeId, MeshPublicKey)]) -> usize {
        let mut counted = std::collections::HashSet::new();
        let mut n = 0;
        for v in &self.votes {
            let Some((_, pubkey)) = eligible.iter().find(|(id, _)| *id == v.voter) else {
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

    pub fn satisfies(&self, quorum: usize, eligible: &[(NodeId, MeshPublicKey)]) -> bool {
        self.approvals(eligible) >= quorum
    }
}

/// A node's tally of one release round — the auditable record of a secret-access
/// decision (MSS4): who requested, the quorum, how many eligible witnesses
/// approved vs. denied, and whether it was authorized. Every node that saw the
/// signed request + votes derives the same decision (witnessed + replicated).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReleaseDecision {
    pub secret_id: [u8; 32],
    pub requester: NodeId,
    pub nonce: [u8; 32],
    pub quorum: usize,
    /// Eligible (assigned, requester-excluded) witnesses.
    pub eligible: usize,
    pub approvals: usize,
    pub denials: usize,
    pub authorized: bool,
    pub lease_ticks: u64,
    pub authorized_at: Option<u64>,
}

/// The secret-class id for a node's **mesh-sealed service identity** (MSS5): the
/// node's TLS/credential identity is released like any secret, so it is minted
/// only while the mesh currently trusts the node. Stable per node.
pub fn identity_secret_id(node: NodeId) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"mss-service-identity\x00");
    h.update(&node.0);
    *h.finalize().as_bytes()
}

fn request_id(secret_id: &[u8; 32], requester: &NodeId, nonce: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"mss-release\x00");
    h.update(secret_id);
    h.update(&requester.0);
    h.update(nonce);
    *h.finalize().as_bytes()
}
