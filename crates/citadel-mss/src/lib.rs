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

pub mod threshold;
pub mod tsig;

use std::collections::HashSet;

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::id::Epoch;
use citadel_mesh::{witness, NodeId};
use serde::{Deserialize, Serialize};
use tpm_core::backend::{KeyHandle, SealedData, TpmBackend};

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
    /// Security officers required **in addition to** the mesh quorum for escrow
    /// release (MSS7 / §15). `0` = no officer requirement.
    pub min_officers: usize,
    /// Whether this secret allows **break-glass**: officers alone (no mesh quorum)
    /// may release it when the mesh is unreachable (MSS7 / C4). Audited loudly.
    pub break_glass: bool,
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

// -- Real-TPM binding (roadmap S0) ------------------------------------------
//
// The application-layer `open` above checks the mesh quorum then plain-unseals;
// a misbehaving node could bypass it by calling `backend.unseal` directly. The
// functions below bind release to the **TPM**: the secret is sealed under its
// policy digest, and the TPM unseals only with an authority approval over that
// policy (S0's `unseal_authorized`). The authority is the mesh's release
// authority — a single key here (the MVP); distributing it across the quorum
// without any node holding it is threshold mode (MSS6).

/// As the release authority, approve a secret's policy (after the mesh quorum
/// authorizes) — produces the approval the TPM requires to unseal. `policy_ref`
/// binds freshness (e.g. the request nonce), so an approval is single-use.
pub fn approve_release(
    backend: &dyn TpmBackend,
    authority: &KeyHandle,
    secret: &MeshSealedSecret,
    policy_ref: &[u8],
) -> anyhow::Result<Vec<u8>> {
    backend.approve_policy(authority, &policy_digest(&secret.policy), policy_ref)
}

/// Open a secret via the TPM's authority-approved unseal (S0): the TPM refuses
/// unless the blob was sealed under this policy **and** the authority signed the
/// approval — so holding the blob is not enough; a live approval is required.
pub fn open_authorized(
    backend: &dyn TpmBackend,
    secret: &MeshSealedSecret,
    authority_pub: &[u8],
    policy_ref: &[u8],
    approval_sig: &[u8],
) -> anyhow::Result<Vec<u8>> {
    backend.unseal_authorized(
        &secret.sealed,
        authority_pub,
        &policy_digest(&secret.policy),
        policy_ref,
        approval_sig,
    )
}

// -- Officer escrow + break-glass (roadmap MSS7) ----------------------------
//
// High-value/recovery secrets can require N-of-M **security officers** in
// addition to the mesh quorum (escrow, §15); and a secret may opt into
// **break-glass**, where officers alone release it when the mesh is unreachable
// (a partition). Break-glass is the emergency path and must be audited loudly.

/// A security officer's signed approval of a secret release, bound to the
/// request nonce (single-use, like a witness vote).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OfficerApproval {
    pub officer: MeshPublicKey,
    pub secret_id: [u8; 32],
    pub nonce: [u8; 32],
    pub signature: Signature,
}

impl OfficerApproval {
    fn signing_bytes(secret_id: &[u8; 32], nonce: &[u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&("mss-officer-approval", secret_id, nonce)).expect("serializable")
    }

    /// Sign an approval as an officer.
    pub fn sign(officer: &MeshKeypair, secret_id: [u8; 32], nonce: [u8; 32]) -> Self {
        let signature = officer.sign(&Self::signing_bytes(&secret_id, &nonce));
        OfficerApproval {
            officer: officer.public(),
            secret_id,
            nonce,
            signature,
        }
    }

    pub fn verify(&self) -> bool {
        self.officer.verify(
            &Self::signing_bytes(&self.secret_id, &self.nonce),
            &self.signature,
        )
    }
}

/// Count the **distinct registered officers** that validly approved this exact
/// (secret, nonce). Forged, unregistered, duplicate, or stale approvals don't
/// count.
pub fn count_officer_approvals(
    approvals: &[OfficerApproval],
    officers: &[MeshPublicKey],
    secret_id: [u8; 32],
    nonce: [u8; 32],
) -> usize {
    let registered: HashSet<&MeshPublicKey> = officers.iter().collect();
    let mut seen = HashSet::new();
    approvals
        .iter()
        .filter(|a| {
            a.secret_id == secret_id
                && a.nonce == nonce
                && registered.contains(&a.officer)
                && a.verify()
                && seen.insert(a.officer)
        })
        .count()
}

/// Open an escrowed secret (MSS7 / §15): requires **both** the mesh release
/// quorum **and** ≥ `min_officers` registered officer approvals (officers + the
/// mesh, bound to the same nonce). Either alone is insufficient.
pub fn open_escrow(
    backend: &dyn TpmBackend,
    secret: &MeshSealedSecret,
    mesh_auth: &ReleaseAuthorization,
    eligible: &[WitnessKey],
    officer_approvals: &[OfficerApproval],
    officers: &[MeshPublicKey],
) -> anyhow::Result<Vec<u8>> {
    if mesh_auth.secret_id != secret.policy.secret_id {
        anyhow::bail!("authorization is for a different secret");
    }
    if !mesh_auth.satisfies(secret.policy.quorum, eligible) {
        anyhow::bail!("mesh quorum not satisfied");
    }
    let o = count_officer_approvals(
        officer_approvals,
        officers,
        secret.policy.secret_id,
        mesh_auth.nonce,
    );
    if o < secret.policy.min_officers {
        anyhow::bail!(
            "officer quorum not satisfied: {o} of {}",
            secret.policy.min_officers
        );
    }
    backend.unseal(&secret.sealed)
}

/// **Break-glass** open (MSS7 / C4): when the mesh is unreachable, ≥ `min_officers`
/// registered officers alone release the secret — only if its policy opts in.
/// The mesh quorum is bypassed, so the caller MUST record this as a loud,
/// high-severity audit event.
pub fn open_breakglass(
    backend: &dyn TpmBackend,
    secret: &MeshSealedSecret,
    nonce: [u8; 32],
    officer_approvals: &[OfficerApproval],
    officers: &[MeshPublicKey],
) -> anyhow::Result<Vec<u8>> {
    if !secret.policy.break_glass {
        anyhow::bail!("break-glass is not permitted for this secret");
    }
    let o = count_officer_approvals(officer_approvals, officers, secret.policy.secret_id, nonce);
    if o < secret.policy.min_officers {
        anyhow::bail!(
            "officer quorum not satisfied: {o} of {}",
            secret.policy.min_officers
        );
    }
    backend.unseal(&secret.sealed)
}

// -- Threshold / distributed-HSM custody (roadmap MSS6) ---------------------
//
// A secret is Shamir-split into shares, each **sealed to a distinct holder's
// TPM** and placed across the fleet — so no single node holds the whole secret
// at rest (C1). Reconstruction needs `threshold` holders to release + unseal
// their shares; each release reuses the mesh-gated `open` path (MSS1–3). Below
// is the distribution + reconstruction core; per-share mesh-gating is the same
// quorum machinery already tested.

/// Split `secret` into one sealed share per holder (Shamir `threshold`-of-N),
/// each share sealed to that holder's TPM. Returns `(holder, sealed share)`.
/// Hand each holder its own entry; no node receives more than its share.
pub fn distribute(
    backend: &dyn TpmBackend,
    secret: &[u8],
    threshold: u8,
    holders: &[NodeId],
) -> anyhow::Result<Vec<(NodeId, SealedData)>> {
    let shares = threshold::split(secret, threshold, holders.len() as u8);
    holders
        .iter()
        .zip(shares)
        .map(|(h, s)| {
            let bytes = serde_json::to_vec(&s)?;
            Ok((*h, backend.seal(&bytes, None)?))
        })
        .collect()
}

/// Reconstruct a distributed secret from `threshold` holders' (unsealed) shares.
/// Fewer than the threshold yields a different value, not the secret.
pub fn reconstruct(
    backend: &dyn TpmBackend,
    sealed_shares: &[SealedData],
) -> anyhow::Result<Vec<u8>> {
    let shares: Vec<threshold::Share> = sealed_shares
        .iter()
        .map(|s| {
            let bytes = backend.unseal(s)?;
            Ok(serde_json::from_slice(&bytes)?)
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(threshold::combine(&shares))
}

/// Generate a `threshold`-of-N FROST **signing** key (MSS6b) and seal one key
/// package to each holder's TPM. Returns the group public package + the sealed
/// per-holder packages. The signing key is never reassembled after this.
pub fn distribute_signing_key(
    backend: &dyn TpmBackend,
    threshold: u16,
    holders: &[NodeId],
) -> anyhow::Result<(tsig::PublicKeyPackage, Vec<(NodeId, SealedData)>)> {
    let (public, packages) = tsig::keygen(threshold, holders.len() as u16)?;
    let sealed = holders
        .iter()
        .zip(packages)
        .map(|(h, kp)| {
            let bytes = serde_json::to_vec(&kp)?;
            Ok((*h, backend.seal(&bytes, None)?))
        })
        .collect::<anyhow::Result<_>>()?;
    Ok((public, sealed))
}

/// Produce a group signature over `message` from a threshold of holders' sealed
/// key packages — the key is never reconstructed (MSS6b).
pub fn threshold_sign(
    backend: &dyn TpmBackend,
    sealed_packages: &[SealedData],
    public: &tsig::PublicKeyPackage,
    message: &[u8],
) -> anyhow::Result<tsig::Signature> {
    let packages: Vec<tsig::KeyPackage> = sealed_packages
        .iter()
        .map(|s| {
            let bytes = backend.unseal(s)?;
            Ok(serde_json::from_slice(&bytes)?)
        })
        .collect::<anyhow::Result<_>>()?;
    tsig::sign(&packages, public, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use tpm_core::backend::MockBackend;
    use tpm_core::model::{Algorithm, ObjectPath};

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
            min_officers: 0,
            break_glass: false,
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

    #[test]
    fn tpm_enforces_the_authority_approval_on_unseal() {
        let backend = MockBackend::new();
        let (_, _, policy) = fixture();
        let secret = seal(&backend, b"db-prod-password", policy).unwrap();
        let nonce = b"request-nonce";

        // The release authority (gated by the mesh quorum) approves the policy.
        let authority = backend
            .create_key(
                Algorithm::EccP256,
                &ObjectPath::new("mss/release-authority").unwrap(),
            )
            .unwrap();
        let approval = approve_release(&backend, &authority, &secret, nonce).unwrap();

        // With the approval the TPM unseals; holding the blob alone does not.
        assert_eq!(
            open_authorized(&backend, &secret, &authority.id, nonce, &approval).unwrap(),
            b"db-prod-password"
        );
        assert!(open_authorized(&backend, &secret, &authority.id, nonce, b"forged").is_err());
        // The approval is nonce-bound: it doesn't open under a different nonce.
        assert!(
            open_authorized(&backend, &secret, &authority.id, b"other-nonce", &approval).is_err()
        );
    }

    #[test]
    fn distributed_custody_needs_a_threshold_of_holders() {
        let backend = MockBackend::new();
        let secret = b"ca-signing-key-material-distributed";
        let holders: Vec<NodeId> = (1u8..=5).map(id).collect();

        // Split into one sealed share per holder, 3-of-5.
        let sealed = distribute(&backend, secret, 3, &holders).unwrap();
        assert_eq!(sealed.len(), 5);

        // No node holds the whole secret: each sealed share unseals to just a
        // Shamir share, never the plaintext.
        for (_, s) in &sealed {
            let bytes = backend.unseal(s).unwrap();
            let share: threshold::Share = serde_json::from_slice(&bytes).unwrap();
            assert_ne!(share.ys, secret.to_vec());
        }

        // Any 3 holders reconstruct it; 2 do not.
        let blobs: Vec<_> = sealed.iter().map(|(_, s)| s.clone()).collect();
        assert_eq!(reconstruct(&backend, &blobs[0..3]).unwrap(), secret);
        assert_eq!(
            reconstruct(
                &backend,
                &[blobs[1].clone(), blobs[3].clone(), blobs[4].clone()]
            )
            .unwrap(),
            secret
        );
        assert_ne!(
            reconstruct(&backend, &blobs[0..2]).unwrap(),
            secret.to_vec()
        );
    }

    #[test]
    fn threshold_signing_over_sealed_shares() {
        let backend = MockBackend::new();
        let holders: Vec<NodeId> = (1u8..=5).map(id).collect();
        let (public, sealed) = distribute_signing_key(&backend, 3, &holders).unwrap();
        assert_eq!(sealed.len(), 5);

        let msg = b"issue-cert: cn=workload-7";
        let blobs: Vec<_> = sealed.iter().map(|(_, s)| s.clone()).collect();

        // A threshold of holders produce a valid group signature; the signing
        // key is never reconstructed.
        let sig = threshold_sign(&backend, &blobs[0..3], &public, msg).unwrap();
        assert!(tsig::verify(&public, msg, &sig));
        assert!(!tsig::verify(&public, b"issue-cert: cn=attacker", &sig));
    }

    // -- MSS7: officer escrow + break-glass --

    fn officer(n: u8) -> MeshKeypair {
        MeshKeypair::from_seed([200 + n; 32])
    }

    #[test]
    fn escrow_needs_both_the_mesh_quorum_and_officers() {
        let backend = MockBackend::new();
        let (eligible, secret_id, mut policy) = fixture();
        policy.min_officers = 2; // a recovery secret
        let secret = seal(&backend, b"root-ca-key", policy).unwrap();
        let rkp = kp(100);
        let req = request(secret_id, &secret.policy, &rkp, [9u8; 32]);

        // Full mesh quorum.
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

        let officers = vec![
            officer(1).public(),
            officer(2).public(),
            officer(3).public(),
        ];
        let two = vec![
            OfficerApproval::sign(&officer(1), secret_id, req.nonce),
            OfficerApproval::sign(&officer(2), secret_id, req.nonce),
        ];
        let one = vec![OfficerApproval::sign(&officer(1), secret_id, req.nonce)];

        // Quorum + 2 officers → opens.
        assert_eq!(
            open_escrow(&backend, &secret, &auth, &eligible, &two, &officers).unwrap(),
            b"root-ca-key"
        );
        // Quorum + only 1 officer → refused.
        assert!(open_escrow(&backend, &secret, &auth, &eligible, &one, &officers).is_err());
        // 2 officers but NO mesh quorum → refused.
        let no_quorum = ReleaseAuthorization {
            secret_id,
            requester: req.requester,
            nonce: req.nonce,
            votes: vec![],
        };
        assert!(open_escrow(&backend, &secret, &no_quorum, &eligible, &two, &officers).is_err());
    }

    #[test]
    fn break_glass_lets_officers_release_without_the_mesh() {
        let backend = MockBackend::new();
        let (_, secret_id, mut policy) = fixture();
        policy.min_officers = 2;
        policy.break_glass = true;
        let secret = seal(&backend, b"emergency-recovery-key", policy).unwrap();
        let nonce = [0xEEu8; 32];
        let officers = vec![
            officer(1).public(),
            officer(2).public(),
            officer(3).public(),
        ];
        let two = vec![
            OfficerApproval::sign(&officer(1), secret_id, nonce),
            OfficerApproval::sign(&officer(2), secret_id, nonce),
        ];

        // Officers alone (no mesh) open a break-glass secret.
        assert_eq!(
            open_breakglass(&backend, &secret, nonce, &two, &officers).unwrap(),
            b"emergency-recovery-key"
        );
        // One officer is not enough.
        assert!(open_breakglass(&backend, &secret, nonce, &two[0..1], &officers).is_err());

        // A non-break-glass secret refuses the emergency path entirely.
        let (_, sid2, mut p2) = fixture();
        p2.min_officers = 2; // break_glass stays false
        let normal = seal(&backend, b"x", p2).unwrap();
        let two2 = vec![
            OfficerApproval::sign(&officer(1), sid2, nonce),
            OfficerApproval::sign(&officer(2), sid2, nonce),
        ];
        assert!(open_breakglass(&backend, &normal, nonce, &two2, &officers).is_err());
    }
}
