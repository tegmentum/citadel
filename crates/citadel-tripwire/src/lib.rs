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
//! and the access detection ride the wire (TW-C3) — so the `Tripwire` here
//! carries an `id`, never the secret itself.
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

// -- TW2: gossip + triage into the quarantine flow ---------------------------

use citadel_mesh::quarantine::QuarantineScope;

/// The `AppRelay` topic trip events are gossiped on.
pub const TRIP_TOPIC: [u8; 32] = *b"citadel-tripwire-event-topic\x00\x00\x00\x00";

impl TripEvent {
    /// Serialize for gossip (`AppRelay` payload).
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("trip event is serializable")
    }
    /// Deserialize a gossiped trip.
    pub fn from_bytes(b: &[u8]) -> Option<Self> {
        serde_json::from_slice(b).ok()
    }
}

/// The quarantine scope a trip warrants — `Some` for high-confidence classes
/// (which propose quarantine via the M2 flow), `None` for low-confidence ones
/// (which only raise a finding).
pub fn quarantine_scope(class: TripClass) -> Option<QuarantineScope> {
    match class.action() {
        TripAction::ProposeQuarantine => Some(QuarantineScope::BlockWorkloadScheduling),
        TripAction::RaiseFinding => None,
    }
}

/// A containment recommendation derived from a verified high-confidence trip:
/// propose this scope for this subject (the caller enacts it via the mesh
/// quarantine flow).
#[derive(Clone, Debug)]
pub struct Containment {
    pub subject: NodeId,
    pub scope: QuarantineScope,
    pub trip: TripEvent,
}

/// Verify gossiped trips against their observers and return the containment
/// actions. A high-confidence trip with a known, attributable subject becomes a
/// quarantine recommendation; forged trips (TW-C1) and low-confidence trips
/// (TW-C2) produce none.
pub fn triage(payloads: &[Vec<u8>], observers: &[(NodeId, MeshPublicKey)]) -> Vec<Containment> {
    let mut out = Vec::new();
    for p in payloads {
        let Some(trip) = TripEvent::from_bytes(p) else {
            continue;
        };
        let Some((_, pubkey)) = observers.iter().find(|(id, _)| *id == trip.observer) else {
            continue;
        };
        if !trip.verify(pubkey) {
            continue;
        }
        if let (Some(scope), Some(subject)) = (quarantine_scope(trip.class), trip.subject) {
            out.push(Containment {
                subject,
                scope,
                trip,
            });
        }
    }
    out
}

// -- TW3 (in-tree slice): the detection adapter ------------------------------
//
// Real detection hooks (eBPF/file/credential-store, MSS-sealed-decoy unsealing)
// are deployment; the adapter trait + an in-process software detector are in-tree.

use std::collections::HashMap;

/// A detection adapter: it watches seeded decoys and, on an access, emits a
/// **signed** trip (TW-C1). Real adapters hook the filesystem / credential store /
/// eBPF; `SoftwareDetector` is the in-process registry (for tests and the
/// sealed-decoy path).
pub trait Detector {
    /// Arm a tripwire to be watched.
    fn arm(&mut self, tripwire: Tripwire);
    /// Report an access to a decoy by id → a signed trip if that decoy is armed.
    fn on_access(
        &self,
        tripwire_id: &[u8; 32],
        subject: Option<NodeId>,
        tick: u64,
    ) -> Option<TripEvent>;
}

/// An in-process detector that signs trips with the observing node's key.
pub struct SoftwareDetector {
    observer: NodeId,
    observer_kp: MeshKeypair,
    armed: HashMap<[u8; 32], Tripwire>,
}

impl SoftwareDetector {
    pub fn new(observer: NodeId, observer_kp: MeshKeypair) -> Self {
        SoftwareDetector {
            observer,
            observer_kp,
            armed: HashMap::new(),
        }
    }
}

impl Detector for SoftwareDetector {
    fn arm(&mut self, tripwire: Tripwire) {
        self.armed.insert(tripwire.id, tripwire);
    }

    fn on_access(
        &self,
        tripwire_id: &[u8; 32],
        subject: Option<NodeId>,
        tick: u64,
    ) -> Option<TripEvent> {
        let tripwire = self.armed.get(tripwire_id)?;
        Some(TripEvent::sign(
            &self.observer_kp,
            tripwire,
            self.observer,
            subject,
            tick,
        ))
    }
}

#[cfg(test)]
mod detector_tests {
    use super::*;

    #[test]
    fn software_detector_arms_and_signs_trips_on_access() {
        let observer_kp = MeshKeypair::from_seed([1; 32]);
        let observer = NodeId(observer_kp.public().fingerprint());
        let mut det = SoftwareDetector::new(observer, observer_kp.clone());

        let tw = Tripwire::new("db/root-password-decoy", TripClass::SealedDecoy);
        det.arm(tw);

        // An access to the armed decoy → a verifiable, attributable trip.
        let attacker = NodeId([5; 32]);
        let trip = det
            .on_access(&tw.id, Some(attacker), 42)
            .expect("armed decoy trips");
        assert!(trip.verify(&observer_kp.public()));
        assert_eq!(trip.subject, Some(attacker));
        assert_eq!(trip.action(), TripAction::ProposeQuarantine);

        // An access to something that was never armed → no trip.
        assert!(det.on_access(&[9u8; 32], Some(attacker), 42).is_none());
    }
}
