//! # citadel-tripwire (TW1) — distributed tripwires / honeytokens
//!
//! Seed decoy secrets/credentials/files across the fleet; any access trips a
//! **signed** event that feeds the mesh's existing quarantine. Cheap, high-signal
//! deception that closes the detection→containment loop — the mesh stops merely
//! verifying good state and starts actively detecting compromise.
//!
//! Design calls: a trip is **signed evidence, not a bare alert** — the node that
//! observed the access signs what was touched, when, and by whom (TW-C1), so a
//! forged trip doesn't enact. Trips feed the existing quarantine **gated by
//! class** — a high-confidence trip (a sealed honeytoken decrypted) proposes
//! quarantine via the M2 flow; a low-confidence one raises a finding (TW-C2).
//! Decoy *contents* are MSS-sealed and never gossiped; only their **identifiers**
//! + the access detection ride the wire (TW-C3) — so the `Tripwire` here carries
//! an `id`, never the secret itself.
//!
//! TW1 is the pure core (the trip event, its signature, and the confidence→action
//! mapping). TW2 wires it over `AppRelay` + the quarantine flow; TW3 adds the
//! detection adapters (file/credential honeytokens, sealed decoys).

use citadel_mesh::crypto::{MeshKeypair, MeshPublicKey, Signature};
use citadel_mesh::NodeId;
use serde::{Deserialize, Serialize};

/// The kind of decoy that was tripped — determines the response confidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TripClass {
    /// A sealed honeytoken was decrypted — unambiguous compromise.
    SealedDecoy,
    /// A honey-credential was presented/used.
    Credential,
    /// A decoy file was read — could be benign scanning.
    DecoyFile,
    /// A canary token / beacon was hit — could be external noise.
    Canary,
}

/// How much a trip is trusted to mean real compromise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confidence {
    High,
    Low,
}

/// What a trip should trigger (TW-C2). The high path proposes mesh-wide
/// quarantine (the M2 propose→vote→enact flow); the low path raises a finding /
/// degrades trust without auto-isolating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TripAction {
    ProposeQuarantine,
    RaiseFinding,
}

impl TripClass {
    pub fn confidence(self) -> Confidence {
        match self {
            TripClass::SealedDecoy | TripClass::Credential => Confidence::High,
            TripClass::DecoyFile | TripClass::Canary => Confidence::Low,
        }
    }

    /// The response a trip of this class warrants.
    pub fn action(self) -> TripAction {
        match self.confidence() {
            Confidence::High => TripAction::ProposeQuarantine,
            Confidence::Low => TripAction::RaiseFinding,
        }
    }
}

/// A seeded decoy — its *identifier* and class (never its contents; TW-C3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tripwire {
    pub id: [u8; 32],
    pub class: TripClass,
}

impl Tripwire {
    /// Derive a stable decoy id from a name (the secret contents stay
    /// MSS-sealed elsewhere).
    pub fn new(name: &str, class: TripClass) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"citadel-tripwire\x00");
        h.update(name.as_bytes());
        Tripwire {
            id: *h.finalize().as_bytes(),
            class,
        }
    }
}

/// A signed record that a tripwire was accessed (TW-C1): who observed it, what
/// was touched, who touched it (if attributable), and when.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TripEvent {
    pub tripwire_id: [u8; 32],
    pub class: TripClass,
    pub observer: NodeId,
    pub subject: Option<NodeId>,
    pub tick: u64,
    pub signature: Signature,
}

impl TripEvent {
    fn signing_bytes(
        tripwire_id: &[u8; 32],
        class: TripClass,
        observer: &NodeId,
        subject: &Option<NodeId>,
        tick: u64,
    ) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"citadel-trip-event\x00");
        b.extend_from_slice(tripwire_id);
        b.push(class as u8);
        b.extend_from_slice(&observer.0);
        match subject {
            Some(s) => {
                b.push(1);
                b.extend_from_slice(&s.0);
            }
            None => b.push(0),
        }
        b.extend_from_slice(&tick.to_le_bytes());
        b
    }

    /// Sign a trip the observing node detected.
    pub fn sign(
        observer_kp: &MeshKeypair,
        tripwire: &Tripwire,
        observer: NodeId,
        subject: Option<NodeId>,
        tick: u64,
    ) -> Self {
        let signature = observer_kp.sign(&Self::signing_bytes(
            &tripwire.id,
            tripwire.class,
            &observer,
            &subject,
            tick,
        ));
        TripEvent {
            tripwire_id: tripwire.id,
            class: tripwire.class,
            observer,
            subject,
            tick,
            signature,
        }
    }

    /// Verify the trip was signed by the claimed observer (TW-C1 — forged trips
    /// don't enact).
    pub fn verify(&self, observer_pub: &MeshPublicKey) -> bool {
        observer_pub.verify(
            &Self::signing_bytes(
                &self.tripwire_id,
                self.class,
                &self.observer,
                &self.subject,
                self.tick,
            ),
            &self.signature,
        )
    }

    /// The response this trip warrants (its class's action).
    pub fn action(&self) -> TripAction {
        self.class.action()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn idk(n: u8) -> (NodeId, MeshKeypair) {
        let kp = MeshKeypair::from_seed([n; 32]);
        (NodeId(kp.public().fingerprint()), kp)
    }

    #[test]
    fn confidence_to_action_mapping() {
        assert_eq!(
            TripClass::SealedDecoy.action(),
            TripAction::ProposeQuarantine
        );
        assert_eq!(
            TripClass::Credential.action(),
            TripAction::ProposeQuarantine
        );
        assert_eq!(TripClass::DecoyFile.action(), TripAction::RaiseFinding);
        assert_eq!(TripClass::Canary.action(), TripAction::RaiseFinding);
    }

    #[test]
    fn a_signed_trip_verifies_and_a_forged_one_does_not() {
        let (observer, observer_kp) = idk(1);
        let (subject, _) = idk(2);
        let tw = Tripwire::new("db/root-password-decoy", TripClass::SealedDecoy);

        let trip = TripEvent::sign(&observer_kp, &tw, observer, Some(subject), 42);
        assert!(trip.verify(&observer_kp.public()));
        assert_eq!(trip.action(), TripAction::ProposeQuarantine);

        // Tampering with who/what/when breaks the signature.
        let mut tampered = trip.clone();
        tampered.subject = Some(idk(9).0);
        assert!(!tampered.verify(&observer_kp.public()));
        let mut retimed = trip.clone();
        retimed.tick = 99;
        assert!(!retimed.verify(&observer_kp.public()));

        // A trip "signed" by a different key fails against the claimed observer.
        let (_, impostor) = idk(7);
        let forged = TripEvent::sign(&impostor, &tw, observer, Some(subject), 42);
        assert!(
            !forged.verify(&observer_kp.public()),
            "forged trip does not enact"
        );
    }

    #[test]
    fn tripwire_ids_are_stable_and_distinct() {
        let a = Tripwire::new("svc/api-key-decoy", TripClass::Credential);
        let b = Tripwire::new("svc/api-key-decoy", TripClass::Credential);
        let c = Tripwire::new("svc/other-decoy", TripClass::Credential);
        assert_eq!(a.id, b.id);
        assert_ne!(a.id, c.id);
    }
}
