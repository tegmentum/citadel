//! The membership table and SWIM merge precedence.
//!
//! Each node keeps a view of every member it knows: that member's mesh
//! public key, its current SWIM *incarnation*, its [`LivenessState`], and
//! the locally-decided [`TrustState`]. Liveness propagates by gossip and
//! is merged by SWIM precedence; trust is decided locally from attestation
//! and witness results (it does not ride incarnation).
//!
//! ## SWIM precedence
//!
//! An update `(incarnation=i, liveness=l)` supersedes the current
//! `(incarnation=j, liveness=m)` iff `i > j`, or `i == j` and `l` outranks
//! `m` where `Alive < Suspect < Faulty`. A node refutes a false suspicion
//! by re-broadcasting `Alive` at a *higher* incarnation, which by this
//! rule beats the `Suspect`. `Faulty` at a given incarnation is effectively
//! terminal — only a strictly higher incarnation (a genuine restart/rejoin)
//! can revive the member.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto::MeshPublicKey;
use crate::id::NodeId;
use crate::state::{LivenessState, TrustState};

/// A gossiped membership claim about one node (rides in `piggyback`).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberUpdate {
    pub node_id: NodeId,
    pub public_key: MeshPublicKey,
    pub incarnation: u64,
    pub liveness: LivenessState,
    /// The node's TLS certificate (DER), for E2 mutual-TLS peer pinning. Rides
    /// membership gossip so the roster of pinned peer certs assembles itself.
    /// `None` for nodes that haven't advertised one (back-compat via serde).
    #[serde(default)]
    pub tls_cert: Option<Vec<u8>>,
    /// Observer (control-plane) node: excluded from witness assignment
    /// fleet-wide (M0). Gossiped so every node leaves observers out of its
    /// witness rosters.
    #[serde(default)]
    pub observer: bool,
}

/// A node's view of one member.
#[derive(Clone, Debug)]
pub struct Member {
    pub node_id: NodeId,
    pub public_key: MeshPublicKey,
    pub incarnation: u64,
    pub liveness: LivenessState,
    pub trust: TrustState,
    pub role: String,
    /// Tick at which `liveness` last changed (drives the suspicion timer).
    pub last_change_tick: u64,
    /// The member's TLS certificate (DER) for mutual-TLS pinning (E2), learned
    /// via gossip; `None` until advertised.
    pub tls_cert: Option<Vec<u8>>,
    /// Whether this member is an observer (control plane) — excluded from
    /// witness assignment (M0). Learned via gossip.
    pub observer: bool,
}

impl Member {
    pub fn update(&self) -> MemberUpdate {
        MemberUpdate {
            node_id: self.node_id,
            public_key: self.public_key,
            incarnation: self.incarnation,
            liveness: self.liveness,
            tls_cert: self.tls_cert.clone(),
            observer: self.observer,
        }
    }
}

/// Rank within one incarnation: higher wins.
fn rank(l: LivenessState) -> u8 {
    match l {
        LivenessState::Alive => 0,
        LivenessState::Suspect => 1,
        LivenessState::Faulty => 2,
        LivenessState::Left => 3,
        LivenessState::Retired => 4,
    }
}

/// SWIM precedence: does `(ni, nl)` supersede `(ci, cl)`?
fn supersedes(ni: u64, nl: LivenessState, ci: u64, cl: LivenessState) -> bool {
    if ni > ci {
        return true;
    }
    if ni == ci {
        return rank(nl) > rank(cl);
    }
    false
}

/// A node's full membership view, including an entry for itself.
pub struct Membership {
    me: NodeId,
    members: BTreeMap<NodeId, Member>,
}

impl Membership {
    /// Create a view seeded with `self` as `Alive`/`Trusted` (a node
    /// trusts its own measured state until told otherwise).
    pub fn new(me: NodeId, my_key: MeshPublicKey, role: impl Into<String>, tick: u64) -> Self {
        let mut members = BTreeMap::new();
        members.insert(
            me,
            Member {
                node_id: me,
                public_key: my_key,
                incarnation: 0,
                liveness: LivenessState::Alive,
                trust: TrustState::Trusted,
                role: role.into(),
                last_change_tick: tick,
                tls_cert: None,
                observer: false,
            },
        );
        Membership { me, members }
    }

    pub fn me(&self) -> NodeId {
        self.me
    }

    pub fn my_incarnation(&self) -> u64 {
        self.members
            .get(&self.me)
            .map(|m| m.incarnation)
            .unwrap_or(0)
    }

    pub fn get(&self, id: &NodeId) -> Option<&Member> {
        self.members.get(id)
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// All members except self.
    pub fn others(&self) -> impl Iterator<Item = &Member> {
        let me = self.me;
        self.members.values().filter(move |m| m.node_id != me)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Member> {
        self.members.values()
    }

    /// Learn about a member (e.g. from a seed list or enrollment) if not
    /// already known. Returns true if newly inserted.
    pub fn learn(
        &mut self,
        node_id: NodeId,
        public_key: MeshPublicKey,
        role: impl Into<String>,
        tick: u64,
    ) -> bool {
        if self.members.contains_key(&node_id) {
            return false;
        }
        self.members.insert(
            node_id,
            Member {
                node_id,
                public_key,
                incarnation: 0,
                liveness: LivenessState::Alive,
                trust: TrustState::Unknown,
                role: role.into(),
                last_change_tick: tick,
                tls_cert: None,
                observer: false,
            },
        );
        true
    }

    /// Set this node's own TLS certificate (DER) — advertised to peers via the
    /// next membership gossip so they can pin it (E2).
    pub fn set_my_tls_cert(&mut self, cert: Vec<u8>) {
        if let Some(m) = self.members.get_mut(&self.me) {
            m.tls_cert = Some(cert);
        }
    }

    /// Mark this node as an observer (control plane) — advertised via gossip so
    /// peers exclude it from witness assignment (M0).
    pub fn set_my_observer(&mut self) {
        if let Some(m) = self.members.get_mut(&self.me) {
            m.observer = true;
        }
    }

    /// Record a known member's TLS certificate (e.g. learned from its signed
    /// enrolment claim on the bootstrap channel).
    pub fn learn_cert(&mut self, id: &NodeId, cert: Vec<u8>) {
        if let Some(m) = self.members.get_mut(id) {
            m.tls_cert = Some(cert);
        }
    }

    /// The pinnable peer roster: `(node, cert DER)` for every *other* member
    /// that has advertised a TLS certificate.
    pub fn tls_roster(&self) -> Vec<(NodeId, Vec<u8>)> {
        self.others()
            .filter_map(|m| m.tls_cert.clone().map(|c| (m.node_id, c)))
            .collect()
    }

    /// Apply a gossiped [`MemberUpdate`] under SWIM precedence. Returns
    /// true if our view changed. A claim about *ourselves* is ignored here
    /// (we own our incarnation; the node loop refutes suspicions).
    pub fn apply(&mut self, u: &MemberUpdate, tick: u64) -> bool {
        if u.node_id == self.me {
            return false;
        }
        match self.members.get_mut(&u.node_id) {
            None => {
                self.members.insert(
                    u.node_id,
                    Member {
                        node_id: u.node_id,
                        public_key: u.public_key,
                        incarnation: u.incarnation,
                        liveness: u.liveness,
                        trust: TrustState::Unknown,
                        role: String::new(),
                        last_change_tick: tick,
                        tls_cert: u.tls_cert.clone(),
                        observer: u.observer,
                    },
                );
                true
            }
            Some(m) => {
                // Learn a peer's TLS cert from gossip (orthogonal to liveness
                // precedence): adopt it the first time we see one.
                if m.tls_cert.is_none() && u.tls_cert.is_some() {
                    m.tls_cert = u.tls_cert.clone();
                }
                // Observer-ness is a stable property; learn it from gossip.
                if u.observer {
                    m.observer = true;
                }
                if supersedes(u.incarnation, u.liveness, m.incarnation, m.liveness) {
                    let changed_liveness = m.liveness != u.liveness;
                    m.incarnation = u.incarnation;
                    m.liveness = u.liveness;
                    if changed_liveness {
                        m.last_change_tick = tick;
                    }
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Locally mark a peer `Suspect` at its current incarnation (the SWIM
    /// failure detector fired). No-op unless currently `Alive`. Returns the
    /// update to gossip if the state changed.
    pub fn suspect(&mut self, id: &NodeId, tick: u64) -> Option<MemberUpdate> {
        let m = self.members.get_mut(id)?;
        if matches!(m.liveness, LivenessState::Alive) {
            m.liveness = LivenessState::Suspect;
            m.last_change_tick = tick;
            return Some(m.update());
        }
        None
    }

    /// Confirm a suspected peer `Faulty`. Returns the update to gossip.
    pub fn confirm_faulty(&mut self, id: &NodeId, tick: u64) -> Option<MemberUpdate> {
        let m = self.members.get_mut(id)?;
        if matches!(m.liveness, LivenessState::Suspect) {
            m.liveness = LivenessState::Faulty;
            m.last_change_tick = tick;
            return Some(m.update());
        }
        None
    }

    /// Confirm a peer is `Alive` again (we just heard from it). Returns an
    /// update to gossip if it had been `Suspect`.
    pub fn confirm_alive(&mut self, id: &NodeId, tick: u64) -> Option<MemberUpdate> {
        let m = self.members.get_mut(id)?;
        if matches!(m.liveness, LivenessState::Suspect) {
            m.liveness = LivenessState::Alive;
            m.last_change_tick = tick;
            return Some(m.update());
        }
        None
    }

    /// Refute a suspicion about ourselves: bump our incarnation and assert
    /// `Alive`. The higher incarnation makes our `Alive` beat the `Suspect`.
    pub fn refute(&mut self, tick: u64) -> MemberUpdate {
        let m = self
            .members
            .get_mut(&self.me)
            .expect("self is always present");
        m.incarnation += 1;
        m.liveness = LivenessState::Alive;
        m.last_change_tick = tick;
        m.update()
    }

    /// Set a member's locally-decided trust state. Returns true if changed.
    pub fn set_trust(&mut self, id: &NodeId, trust: TrustState) -> bool {
        match self.members.get_mut(id) {
            Some(m) if m.trust != trust => {
                m.trust = trust;
                true
            }
            _ => false,
        }
    }

    /// A bounded set of member updates to piggyback on an outgoing message.
    pub fn digest(&self, limit: usize) -> Vec<MemberUpdate> {
        self.members
            .values()
            .take(limit)
            .map(|m| m.update())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> MeshPublicKey {
        crate::crypto::MeshKeypair::from_seed([n; 32]).public()
    }
    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn fresh() -> Membership {
        let mut m = Membership::new(nid(1), key(1), "worker", 0);
        m.learn(nid(2), key(2), "worker", 0);
        m
    }

    #[test]
    fn higher_incarnation_alive_refutes_suspect() {
        let mut m = fresh();
        m.apply(
            &MemberUpdate {
                node_id: nid(2),
                public_key: key(2),
                incarnation: 0,
                liveness: LivenessState::Suspect,
                tls_cert: None,
                observer: false,
            },
            1,
        );
        assert_eq!(m.get(&nid(2)).unwrap().liveness, LivenessState::Suspect);

        // Same incarnation Alive does NOT supersede Suspect.
        let changed = m.apply(
            &MemberUpdate {
                node_id: nid(2),
                public_key: key(2),
                incarnation: 0,
                liveness: LivenessState::Alive,
                tls_cert: None,
                observer: false,
            },
            2,
        );
        assert!(!changed);
        assert_eq!(m.get(&nid(2)).unwrap().liveness, LivenessState::Suspect);

        // Higher incarnation Alive refutes.
        let changed = m.apply(
            &MemberUpdate {
                node_id: nid(2),
                public_key: key(2),
                incarnation: 1,
                liveness: LivenessState::Alive,
                tls_cert: None,
                observer: false,
            },
            3,
        );
        assert!(changed);
        assert_eq!(m.get(&nid(2)).unwrap().liveness, LivenessState::Alive);
    }

    #[test]
    fn suspect_beats_alive_at_same_incarnation() {
        let mut m = fresh();
        let changed = m.apply(
            &MemberUpdate {
                node_id: nid(2),
                public_key: key(2),
                incarnation: 0,
                liveness: LivenessState::Suspect,
                tls_cert: None,
                observer: false,
            },
            1,
        );
        assert!(changed, "suspect outranks alive at the same incarnation");
    }

    #[test]
    fn cannot_be_marked_faulty_about_self() {
        let mut m = fresh();
        let changed = m.apply(
            &MemberUpdate {
                node_id: nid(1),
                public_key: key(1),
                incarnation: 5,
                liveness: LivenessState::Faulty,
                tls_cert: None,
                observer: false,
            },
            1,
        );
        assert!(!changed);
        assert_eq!(m.get(&nid(1)).unwrap().liveness, LivenessState::Alive);
    }

    #[test]
    fn refute_bumps_incarnation() {
        let mut m = fresh();
        assert_eq!(m.my_incarnation(), 0);
        let u = m.refute(1);
        assert_eq!(u.incarnation, 1);
        assert_eq!(m.my_incarnation(), 1);
    }

    #[test]
    fn suspect_then_confirm_faulty() {
        let mut m = fresh();
        assert!(m.suspect(&nid(2), 1).is_some());
        assert!(m.suspect(&nid(2), 2).is_none(), "already suspect");
        assert!(m.confirm_faulty(&nid(2), 3).is_some());
        assert_eq!(m.get(&nid(2)).unwrap().liveness, LivenessState::Faulty);
    }
}
