//! # citadel-ca (CA1) — mesh-operated signing service / threshold CA
//!
//! The cluster has a signing authority that **no node holds** and that **signs
//! only under live quorum and a healthy trust state** — it won't act while the
//! mesh is compromised. Productizes the threshold crypto of MSS6b as a service.
//!
//! Design calls: every signature is a fresh quorum decision over the release
//! protocol (the witnesses vote on the requester's trust), gated additionally on
//! cluster health — no standing signing oracle (CA-C1). The CA key is generated
//! by **DKG**, so it is never formed anywhere (CA-C2). What it signs is typically
//! a mesh-witnessed *fact* (`citadel-facts`), so the signature attests a checked
//! fact, not just bytes (CA-C3).
//!
//! CA1 is the gate + FROST signing core (reuses `citadel-mss::tsig`). CA2 makes
//! it a request/approve/sign service over gossip; CA3 is deployment.

use citadel_mesh::crypto::MeshPublicKey;
use citadel_mesh::release::ReleaseAuthorization;
use citadel_mesh::NodeId;
use citadel_mss::tsig::{self, KeyPackage, PublicKeyPackage, Signature};

/// Generate the CA's `threshold`-of-`n` signing key by **DKG** — no node, not
/// even a dealer, ever holds the whole key (CA-C2). Returns the group public
/// package + the per-holder key packages (each sealed to its holder's TPM in a
/// deployment).
pub fn ca_keygen(threshold: u16, n: u16) -> anyhow::Result<(PublicKeyPackage, Vec<KeyPackage>)> {
    tsig::keygen_dkg(threshold, n)
}

/// The release secret-class id for a signing request: the requester asks the mesh
/// to authorize signing `artifact` (by digest), so the assigned witnesses vote on
/// its trust before the CA acts.
pub fn signing_secret_id(requester: NodeId, artifact_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"citadel-ca-sign\x00");
    h.update(&requester.0);
    h.update(artifact_digest);
    *h.finalize().as_bytes()
}

/// The cluster's trust health, as the control plane derives it (the OBS2
/// `cluster_trust_score`): the fraction of known nodes currently Trusted.
#[derive(Clone, Copy, Debug)]
pub struct ClusterHealth {
    pub trusted: usize,
    pub total: usize,
}

impl ClusterHealth {
    /// The Trusted fraction (0 if no nodes are known).
    pub fn score(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.trusted as f64 / self.total as f64
        }
    }
    /// Healthy enough to sign: the Trusted fraction meets `min_score`.
    pub fn is_healthy(&self, min_score: f64) -> bool {
        self.total > 0 && self.score() >= min_score
    }
}

/// A CA-signed artifact, verifiable against the group key.
#[derive(Clone, Debug)]
pub struct SignedArtifact {
    pub artifact: Vec<u8>,
    pub signature: Signature,
}

impl SignedArtifact {
    pub fn verify(&self, public: &PublicKeyPackage) -> bool {
        tsig::verify(public, &self.artifact, &self.signature)
    }
}

/// Sign `artifact` with the CA's threshold key **iff** the mesh authorized this
/// exact signing request (a satisfied quorum of the requester's eligible
/// witnesses) **and** the cluster is healthy. Otherwise refuse — no signature is
/// produced while the mesh is compromised or unauthorized (CA-C1). `holders` are
/// ≥ threshold CA key packages (in a deployment they co-sign over gossip — the
/// MSS6b session).
#[allow(clippy::too_many_arguments)]
pub fn sign_artifact(
    holders: &[KeyPackage],
    public: &PublicKeyPackage,
    artifact: &[u8],
    requester: NodeId,
    auth: &ReleaseAuthorization,
    quorum: usize,
    eligible: &[(NodeId, MeshPublicKey)],
    health: &ClusterHealth,
    min_health: f64,
) -> Option<SignedArtifact> {
    let digest = *blake3::hash(artifact).as_bytes();
    if auth.secret_id != signing_secret_id(requester, &digest)
        || auth.requester != requester
        || !auth.satisfies(quorum, eligible)
        || !health.is_healthy(min_health)
    {
        return None;
    }
    let signature = tsig::sign(holders, public, artifact).ok()?;
    Some(SignedArtifact {
        artifact: artifact.to_vec(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::release::{ReleaseRequest, ReleaseVote};

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }

    #[test]
    fn signs_only_under_quorum_and_cluster_health() {
        // The CA key via DKG (no dealer ever holds it).
        let (public, holders) = ca_keygen(3, 5).unwrap();

        let requester = idk(1);
        let artifact = b"release: hexis v1.2.3 (reproduced build)".to_vec();
        let digest = *blake3::hash(&artifact).as_bytes();
        let secret_id = signing_secret_id(requester.0, &digest);
        let quorum = 3;

        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let req = ReleaseRequest::create(
            &requester.1,
            requester.0,
            secret_id,
            [9u8; 32],
            quorum,
            5,
            100,
            5,
        );
        let auth_of = |take: usize| ReleaseAuthorization {
            secret_id,
            requester: requester.0,
            nonce: req.nonce,
            votes: witnesses
                .iter()
                .take(take)
                .map(|(id, kp)| ReleaseVote::sign(kp, &req, *id, true, 6))
                .collect(),
        };

        let healthy = ClusterHealth {
            trusted: 9,
            total: 10,
        };
        let unhealthy = ClusterHealth {
            trusted: 5,
            total: 10,
        };

        // Quorum + healthy cluster → the CA signs, and the signature verifies
        // against the group key (which no node holds).
        let signed = sign_artifact(
            &holders[0..3],
            &public,
            &artifact,
            requester.0,
            &auth_of(quorum),
            quorum,
            &eligible,
            &healthy,
            0.8,
        )
        .expect("CA signs under quorum + health");
        assert!(signed.verify(&public));
        assert_eq!(signed.artifact, artifact);
        // A tampered artifact doesn't verify.
        let mut tampered = signed.clone();
        tampered.artifact = b"release: malware".to_vec();
        assert!(!tampered.verify(&public));

        // Unhealthy cluster → refused (won't sign while compromised, CA-C1).
        assert!(sign_artifact(
            &holders[0..3],
            &public,
            &artifact,
            requester.0,
            &auth_of(quorum),
            quorum,
            &eligible,
            &unhealthy,
            0.8,
        )
        .is_none());

        // Below quorum → refused.
        assert!(sign_artifact(
            &holders[0..3],
            &public,
            &artifact,
            requester.0,
            &auth_of(quorum - 1),
            quorum,
            &eligible,
            &healthy,
            0.8,
        )
        .is_none());

        // A request for a different artifact (secret-id mismatch) → refused.
        assert!(sign_artifact(
            &holders[0..3],
            &public,
            b"a different artifact",
            requester.0,
            &auth_of(quorum),
            quorum,
            &eligible,
            &healthy,
            0.8,
        )
        .is_none());
    }

    #[test]
    fn cluster_health_score() {
        assert!(ClusterHealth {
            trusted: 8,
            total: 10
        }
        .is_healthy(0.8));
        assert!(!ClusterHealth {
            trusted: 7,
            total: 10
        }
        .is_healthy(0.8));
        assert!(!ClusterHealth {
            trusted: 0,
            total: 0
        }
        .is_healthy(0.0));
    }
}
