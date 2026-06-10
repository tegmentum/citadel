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

// -- CA2: the service shape (request / halt-on-incident / issuance) -----------

use serde::{Deserialize, Serialize};

/// The `AppRelay` topic the CA request/approve/sign flow runs on.
pub const CA_TOPIC: [u8; 32] = *b"citadel-ca-signing-topic\x00\x00\x00\x00\x00\x00\x00\x00";

/// A request for the CA to sign `artifact`, gossiped to the requester's witnesses
/// (who vote on its trust via the release protocol).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SigningRequest {
    pub requester: NodeId,
    pub artifact: Vec<u8>,
    pub quorum: usize,
    pub witness_count: usize,
}

impl SigningRequest {
    pub fn new(requester: NodeId, artifact: Vec<u8>, quorum: usize, witness_count: usize) -> Self {
        SigningRequest {
            requester,
            artifact,
            quorum,
            witness_count,
        }
    }
    /// The release secret-class id this request is authorized under.
    pub fn secret_id(&self) -> [u8; 32] {
        signing_secret_id(self.requester, blake3::hash(&self.artifact).as_bytes())
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("request is serializable")
    }
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// Whether the CA is currently issuing or **halted** because the cluster is
/// unhealthy — issuance pauses automatically during an incident (CA-C1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaStatus {
    Available,
    Halted,
}

/// The CA's issuance posture given current cluster health.
pub fn ca_status(health: &ClusterHealth, min_health: f64) -> CaStatus {
    if health.is_healthy(min_health) {
        CaStatus::Available
    } else {
        CaStatus::Halted
    }
}

/// Canonical bytes for a release artifact (a build/release the CA attests by
/// signing) — typically the digest of a reproduced build (CA-C3: a witnessed fact).
pub fn release_artifact(name: &str, digest: &[u8; 32]) -> Vec<u8> {
    serde_json::to_vec(&("citadel-ca-release", name, digest)).expect("serializable")
}

/// Canonical bytes for a certificate the CA issues (subject + SubjectPublicKeyInfo).
pub fn cert_artifact(subject: &str, spki: &[u8]) -> Vec<u8> {
    serde_json::to_vec(&("citadel-ca-cert", subject, spki)).expect("serializable")
}

/// The service entry point: sign a request iff the CA is **Available** (cluster
/// healthy) and the request is quorum-authorized. Refuses (no signature) while
/// halted — the explicit service-level halt-on-incident on top of
/// [`sign_artifact`]'s gate.
#[allow(clippy::too_many_arguments)]
pub fn service_sign(
    holders: &[KeyPackage],
    public: &PublicKeyPackage,
    request: &SigningRequest,
    auth: &ReleaseAuthorization,
    eligible: &[(NodeId, MeshPublicKey)],
    health: &ClusterHealth,
    min_health: f64,
) -> Option<SignedArtifact> {
    if ca_status(health, min_health) == CaStatus::Halted {
        return None;
    }
    sign_artifact(
        holders,
        public,
        &request.artifact,
        request.requester,
        auth,
        request.quorum,
        eligible,
        health,
        min_health,
    )
}

#[cfg(test)]
mod service_tests {
    use super::*;
    use citadel_mesh::crypto::MeshKeypair;
    use citadel_mesh::release::{ReleaseRequest, ReleaseVote};

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }

    #[test]
    fn the_service_signs_when_available_and_halts_during_an_incident() {
        let (public, holders) = ca_keygen(3, 5).unwrap();
        let requester = idk(1);
        let artifact = release_artifact("hexis v1.2.3", &[7u8; 32]);
        let request = SigningRequest::new(requester.0, artifact, 3, 5);
        let quorum = 3;

        let witnesses: Vec<(NodeId, MeshKeypair)> = (10u8..=14).map(idk).collect();
        let eligible: Vec<(NodeId, MeshPublicKey)> = witnesses
            .iter()
            .map(|(id, kp)| (*id, kp.public()))
            .collect();
        let secret_id = request.secret_id();
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
        let auth = ReleaseAuthorization {
            secret_id,
            requester: requester.0,
            nonce: req.nonce,
            votes: witnesses
                .iter()
                .take(quorum)
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

        // Available → signs, and the release artifact verifies.
        assert_eq!(ca_status(&healthy, 0.8), CaStatus::Available);
        let signed = service_sign(
            &holders[0..3],
            &public,
            &request,
            &auth,
            &eligible,
            &healthy,
            0.8,
        )
        .expect("signed while available");
        assert!(signed.verify(&public));

        // Halted during an incident → refuses (issuance pauses).
        assert_eq!(ca_status(&unhealthy, 0.8), CaStatus::Halted);
        assert!(service_sign(
            &holders[0..3],
            &public,
            &request,
            &auth,
            &eligible,
            &unhealthy,
            0.8
        )
        .is_none());
    }

    #[test]
    fn issuance_helpers_and_request_round_trip() {
        // Distinct artifact namespaces for releases vs certs.
        assert_ne!(
            release_artifact("x", &[0u8; 32]),
            cert_artifact("x", &[0u8; 32])
        );
        // The request round-trips over the wire and keeps its secret-class id.
        let r = SigningRequest::new(idk(1).0, b"artifact".to_vec(), 3, 5);
        let back = SigningRequest::from_bytes(&r.to_bytes()).unwrap();
        assert_eq!(back.secret_id(), r.secret_id());
    }
}

// -- CA3 (in-tree slice): the key-rotation / epoch ceremony -------------------
//
// Pinning holders across nodes + release-pipeline integration are deployment; the
// rotation ceremony (key continuity across epochs) is in-tree and testable here.

/// A signed attestation that a new CA key supersedes the current one — produced
/// by the **outgoing** key's threshold, so a verifier who trusts the old key can
/// follow the chain to the new one (no flag day, no re-rooting).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RotationAttestation {
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub new_public: PublicKeyPackage,
    pub signature: Signature,
}

fn rotation_message(to_epoch: u64, new_public: &PublicKeyPackage) -> Vec<u8> {
    let np = serde_json::to_vec(new_public).expect("public package is serializable");
    let mut m = b"citadel-ca-rotate\x00".to_vec();
    m.extend_from_slice(&to_epoch.to_le_bytes());
    m.extend_from_slice(&np);
    m
}

impl RotationAttestation {
    /// Verify the rotation was authorized by the outgoing (`old_public`) key.
    pub fn verify(&self, old_public: &PublicKeyPackage) -> bool {
        tsig::verify(
            old_public,
            &rotation_message(self.to_epoch, &self.new_public),
            &self.signature,
        )
    }
}

/// Rotate the CA key to the next epoch: DKG a fresh key (no node holds it), then
/// have the outgoing holders threshold-sign an attestation binding the new key to
/// the new epoch. Returns the new public package, the new holder key packages, and
/// the signed rotation attestation.
pub fn rotate(
    old_holders: &[KeyPackage],
    old_public: &PublicKeyPackage,
    old_epoch: u64,
    threshold: u16,
    n: u16,
) -> anyhow::Result<(PublicKeyPackage, Vec<KeyPackage>, RotationAttestation)> {
    let (new_public, new_holders) = ca_keygen(threshold, n)?;
    let to_epoch = old_epoch + 1;
    let signature = tsig::sign(
        old_holders,
        old_public,
        &rotation_message(to_epoch, &new_public),
    )?;
    let attestation = RotationAttestation {
        from_epoch: old_epoch,
        to_epoch,
        new_public: new_public.clone(),
        signature,
    };
    Ok((new_public, new_holders, attestation))
}

#[cfg(test)]
mod rotation_tests {
    use super::*;

    #[test]
    fn rotation_preserves_key_continuity() {
        let (old_public, old_holders) = ca_keygen(3, 5).unwrap();
        let (new_public, new_holders, att) =
            rotate(&old_holders[0..3], &old_public, 0, 3, 5).unwrap();

        // A verifier trusting the old key follows the rotation to the new key.
        assert!(att.verify(&old_public));
        assert_eq!((att.from_epoch, att.to_epoch), (0, 1));

        // The new key is a working CA key (it signs + verifies).
        let sig = tsig::sign(&new_holders[0..3], &new_public, b"release v2").unwrap();
        assert!(tsig::verify(&new_public, b"release v2", &sig));

        // A rotation "attestation" signed by the new key itself (not the old) is
        // rejected — only the outgoing key authorizes its successor.
        let self_sig = tsig::sign(
            &new_holders[0..3],
            &new_public,
            &rotation_message(1, &new_public),
        )
        .unwrap();
        let forged = RotationAttestation {
            from_epoch: 0,
            to_epoch: 1,
            new_public,
            signature: self_sig,
        };
        assert!(
            !forged.verify(&old_public),
            "the successor cannot self-authorize"
        );
    }
}
