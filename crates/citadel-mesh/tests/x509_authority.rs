//! A2: Secure Boot authority validation via X.509 CA chains (roadmap A2, using
//! the shared `x509-path` crate). Gated on the `x509-authority` feature.
//!
//! An image authorized by a *leaf cert that chains to a trusted `db` CA* is
//! accepted without enumerating either the image digest or the leaf cert —
//! provenance by CA, not by pin. Revoking the leaf via `dbx` then rejects it.
#![cfg(feature = "x509-authority")]

use citadel_mesh::reference::{
    AcceptedReferences, FleetArtifactPolicy, PcrClass, ReferenceOutcome,
};
use rcgen::{date_time_ymd, BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

const NOW: u64 = 1_700_000_000; // within 2000..2100 validity

fn ca() -> (rcgen::Certificate, KeyPair) {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.not_before = date_time_ymd(2000, 1, 1);
    p.not_after = date_time_ymd(2100, 1, 1);
    p.distinguished_name
        .push(DnType::CommonName, "Vendor UEFI CA");
    let key = KeyPair::generate().unwrap();
    let cert = p.self_signed(&key).unwrap();
    (cert, key)
}

fn leaf(cn: &str, ca_cert: &rcgen::Certificate, ca_key: &KeyPair) -> Vec<u8> {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.not_before = date_time_ymd(2000, 1, 1);
    p.not_after = date_time_ymd(2100, 1, 1);
    p.distinguished_name.push(DnType::CommonName, cn);
    let key = KeyPair::generate().unwrap();
    p.signed_by(&key, ca_cert, ca_key)
        .unwrap()
        .der()
        .as_ref()
        .to_vec()
}

/// A PCR-4 semantic appraisal with a single EV_EFI_VARIABLE_AUTHORITY event
/// whose data is the (digest-bound) authority cert.
fn appraise_with_authority(policy: FleetArtifactPolicy, authority_der: &[u8]) -> ReferenceOutcome {
    use tpm_core::backend::hash_for_bank;
    let mut refs = AcceptedReferences::new("sha256");
    refs.set_pcr_class(4, PcrClass::Semantic);
    refs.set_artifact_policy(policy);

    let event = tpm_core::eventlog::MeasurementEvent {
        pcr: 4,
        event_type: tpm_core::eventlog::EventType::Unknown(
            tpm_core::eventlog::ev::EFI_VARIABLE_AUTHORITY,
        ),
        // The authority event's data is the cert; digest-bound so it's trusted.
        digests: vec![(
            "sha256".into(),
            hash_for_bank("sha256", authority_der).unwrap(),
        )],
        data: authority_der.to_vec(),
    };
    let log = tpm_core::eventlog::BootEventLog::new(vec![event]);
    let semantic: std::collections::BTreeSet<u32> = [4].into_iter().collect();
    refs.appraise_eventlog(&log, "sha256", &semantic)
}

#[test]
fn an_authority_chaining_to_a_db_ca_is_accepted() {
    let (ca_cert, ca_key) = ca();
    let signer = leaf("kernel-signer", &ca_cert, &ca_key);

    // db holds the CA (not the leaf); require authorized boot.
    let policy = FleetArtifactPolicy::new()
        .require_authorized_boot()
        .trust_ca(ca_cert.der().as_ref().to_vec())
        .as_of(NOW);

    assert_eq!(
        appraise_with_authority(policy, &signer),
        ReferenceOutcome::Accepted,
        "an authority chaining to a trusted db CA should be accepted"
    );
}

#[test]
fn an_authority_from_an_untrusted_ca_is_denied() {
    let (_real, _real_key) = ca();
    let (rogue, rogue_key) = ca();
    let signer = leaf("rogue-signer", &rogue, &rogue_key);

    // db trusts a *different* CA than the one that signed the authority.
    let (trusted_ca, _k) = ca();
    let policy = FleetArtifactPolicy::new()
        .require_authorized_boot()
        .trust_ca(trusted_ca.der().as_ref().to_vec())
        .as_of(NOW);

    assert_eq!(
        appraise_with_authority(policy, &signer),
        ReferenceOutcome::Denied,
        "an authority not chaining to a trusted CA must be denied"
    );
}

#[test]
fn revoking_the_authority_cert_via_dbx_denies_it() {
    let (ca_cert, ca_key) = ca();
    let signer = leaf("kernel-signer", &ca_cert, &ca_key);

    let policy = FleetArtifactPolicy::new()
        .require_authorized_boot()
        .trust_ca(ca_cert.der().as_ref().to_vec())
        .revoke_authority(signer.clone()) // dbx the leaf
        .as_of(NOW);

    assert_eq!(
        appraise_with_authority(policy, &signer),
        ReferenceOutcome::Denied,
        "a dbx-revoked authority must be denied even though it chains to a CA"
    );
}
