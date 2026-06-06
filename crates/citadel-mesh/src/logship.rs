//! LtHash log-shipping & anti-entropy reconciliation
//! (`docs/design/distributed-log-shipping-lthash.md`).
//!
//! Each node folds its measurement log into **windowed LtHash accumulators**:
//! a window's root is the homomorphic set-hash of its events. Two nodes
//! compare window roots (a few bytes); on a mismatch they binary-search
//! sub-ranges — comparing only roots — to isolate the divergent records and
//! transfer just those, never the whole log. Because LtHash is commutative
//! and incremental, a sub-range root is simply the accumulator over that
//! range, so the search is `O(log n)` root comparisons.
//!
//! The accumulator is [`lthash_rs`] (LtHash16 over SHA3-`Shake256`) — the
//! native side of the sibling `lthash-wasm` component.

use std::collections::BTreeMap;

use lthash_rs::{LtHash, LtHash16};
use serde::{Deserialize, Serialize};
use sha3::Shake256;

use crate::erasure::EvidenceFragment;
use crate::id::NodeId;

/// The LtHash variant used for measurement-log accumulators.
type Accumulator = LtHash16<Shake256>;

/// Sub-range width at which reconciliation stops bisecting and fetches the
/// actual records to compare (design §12 reconciliation).
const LEAF_WIDTH: u64 = 4;

/// A canonical measurement event (design §6). The **element** folded into the
/// LtHash binds the producer, boot, sequence, and payload, so the same
/// payload at a different `(boot, sequence)` is a distinct element — and a
/// node that re-uses a sequence for different content is detectable (§8).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventRecord {
    pub node_id: NodeId,
    pub boot_id: u64,
    pub sequence: u64,
    pub payload_hash: [u8; 32],
}

impl EventRecord {
    /// `BLAKE3(node_id ‖ boot_id ‖ sequence ‖ payload_hash)` — the bytes
    /// folded into the accumulator.
    pub fn element(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&self.node_id.0);
        h.update(&self.boot_id.to_be_bytes());
        h.update(&self.sequence.to_be_bytes());
        h.update(&self.payload_hash);
        *h.finalize().as_bytes()
    }
}

/// A node's append-only event log, accumulated into windowed LtHash roots.
#[derive(Clone)]
pub struct EventLog {
    records: BTreeMap<u64, EventRecord>,
    window_size: u64,
}

impl EventLog {
    pub fn new(window_size: u64) -> Self {
        EventLog {
            records: BTreeMap::new(),
            window_size: window_size.max(1),
        }
    }

    /// Insert (or overwrite) the record at its sequence.
    pub fn append(&mut self, record: EventRecord) {
        self.records.insert(record.sequence, record);
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn get(&self, sequence: u64) -> Option<&EventRecord> {
        self.records.get(&sequence)
    }

    /// Highest sequence present (0 if empty).
    pub fn max_sequence(&self) -> u64 {
        self.records.keys().next_back().copied().unwrap_or(0)
    }

    /// LtHash root over the events with sequence in `[lo, hi)`.
    pub fn range_root(&self, lo: u64, hi: u64) -> Vec<u8> {
        let mut acc = Accumulator::new();
        for record in self.records.range(lo..hi).map(|(_, r)| r) {
            acc.insert(record.element());
        }
        acc.into_bytes()
    }

    /// LtHash root over the whole log.
    pub fn root(&self) -> Vec<u8> {
        self.range_root(0, self.max_sequence().saturating_add(1))
    }

    /// LtHash root of window `window_id` (`[id*size, (id+1)*size)`).
    pub fn window_root(&self, window_id: u64) -> Vec<u8> {
        let lo = window_id.saturating_mul(self.window_size);
        self.range_root(lo, lo.saturating_add(self.window_size))
    }

    /// The window ids that hold at least one record.
    pub fn windows(&self) -> Vec<u64> {
        let mut ids: Vec<u64> = self.records.keys().map(|s| s / self.window_size).collect();
        ids.dedup();
        ids
    }

    /// The records with sequence in `[lo, hi)`.
    pub fn records_in(&self, lo: u64, hi: u64) -> Vec<EventRecord> {
        self.records.range(lo..hi).map(|(_, r)| r.clone()).collect()
    }

    /// Advertise this log's per-window digests (design §11).
    pub fn advertise(&self, node_id: NodeId, boot_id: u64) -> Vec<DigestAdvertisement> {
        self.windows()
            .into_iter()
            .map(|window_id| DigestAdvertisement {
                node_id,
                boot_id,
                window_id,
                max_sequence: self.max_sequence(),
                root: self.window_root(window_id),
            })
            .collect()
    }
}

/// One erasure-coded shard of a *sealed* log window, in flight to (or stored
/// by) a holder. It carries the window's identity alongside the shard so a
/// holder can place it and a reconstructor can route the rebuilt records back
/// to the right replica — the unit of the bounded-fan-out durable evidence
/// vault (design §12.4). The shard's `record_id` is `BLAKE3` of the window's
/// [`encode_records`] payload, so it is also the reconstruction key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogFragment {
    pub node_id: NodeId,
    pub boot_id: u64,
    pub window_id: u64,
    pub fragment: EvidenceFragment,
}

/// Canonical bytes of a set of records — used to preserve a window as a
/// durable, erasure-coded evidence payload (the Phase-4 store).
pub fn encode_records(records: &[EventRecord]) -> Vec<u8> {
    serde_json::to_vec(records).expect("records are serializable")
}

/// Decode records preserved with [`encode_records`].
pub fn decode_records(bytes: &[u8]) -> anyhow::Result<Vec<EventRecord>> {
    Ok(serde_json::from_slice(bytes)?)
}

/// A gossiped per-window digest (design §11). A peer compares it to its own
/// window root; a mismatch triggers reconciliation of that window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestAdvertisement {
    pub node_id: NodeId,
    pub boot_id: u64,
    pub window_id: u64,
    pub max_sequence: u64,
    pub root: Vec<u8>,
}

/// The outcome of reconciling a local log against a remote one.
#[derive(Clone, Debug, Default)]
pub struct Reconciliation {
    /// Records present (or differing) in the remote that the local lacks.
    pub to_pull: Vec<EventRecord>,
    /// LtHash root comparisons performed — the work the binary search did
    /// (sub-linear in the log size).
    pub root_comparisons: usize,
    /// Records actually fetched (only at the leaves of the search).
    pub records_fetched: usize,
}

/// Reconcile `local` against `remote`, returning the records `local` must
/// pull so its root matches `remote`'s — found by binary-searching only the
/// sub-ranges whose LtHash roots differ (design §12).
pub fn reconcile(local: &EventLog, remote: &EventLog) -> Reconciliation {
    let mut out = Reconciliation::default();
    let hi = local.max_sequence().max(remote.max_sequence()).saturating_add(1);
    reconcile_range(local, remote, 0, hi, &mut out);
    out
}

fn reconcile_range(local: &EventLog, remote: &EventLog, lo: u64, hi: u64, out: &mut Reconciliation) {
    out.root_comparisons += 1;
    if local.range_root(lo, hi) == remote.range_root(lo, hi) {
        return; // this range already agrees — prune
    }
    if hi - lo <= LEAF_WIDTH {
        let remote_records = remote.records_in(lo, hi);
        out.records_fetched += remote_records.len();
        for record in remote_records {
            if local.get(record.sequence) != Some(&record) {
                out.to_pull.push(record);
            }
        }
        return;
    }
    let mid = lo + (hi - lo) / 2;
    reconcile_range(local, remote, lo, mid, out);
    reconcile_range(local, remote, mid, hi, out);
}

/// A detected equivocation: the same node published two different roots for
/// the same `(boot, window)` — `CHECKPOINT_EQUIVOCATION` (design §13).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Equivocation {
    pub node_id: NodeId,
    pub boot_id: u64,
    pub window_id: u64,
    pub root_a: Vec<u8>,
    pub root_b: Vec<u8>,
}

/// Scan advertisements for equivocation: a node that, for one `(boot,
/// window)`, advertised two distinct roots is forking its own log.
pub fn detect_equivocation(adverts: &[DigestAdvertisement]) -> Vec<Equivocation> {
    use std::collections::HashMap;
    let mut seen: HashMap<(NodeId, u64, u64), Vec<u8>> = HashMap::new();
    let mut out = Vec::new();
    for a in adverts {
        let key = (a.node_id, a.boot_id, a.window_id);
        match seen.get(&key) {
            Some(prev) if prev != &a.root => out.push(Equivocation {
                node_id: a.node_id,
                boot_id: a.boot_id,
                window_id: a.window_id,
                root_a: prev.clone(),
                root_b: a.root.clone(),
            }),
            Some(_) => {}
            None => {
                seen.insert(key, a.root.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(n: u8) -> NodeId {
        NodeId([n; 32])
    }

    fn record(node: u8, boot: u64, seq: u64, payload: &str) -> EventRecord {
        EventRecord {
            node_id: nid(node),
            boot_id: boot,
            sequence: seq,
            payload_hash: *blake3::hash(payload.as_bytes()).as_bytes(),
        }
    }

    /// A log of `n` events for one (node, boot) stream.
    fn log_of(n: u64, window: u64) -> EventLog {
        let mut log = EventLog::new(window);
        for seq in 0..n {
            log.append(record(1, 7, seq, &format!("event-{seq}")));
        }
        log
    }

    #[test]
    fn equal_logs_have_equal_roots() {
        let a = log_of(50, 16);
        let b = log_of(50, 16);
        assert_eq!(a.root(), b.root());
        // Window-by-window too.
        for w in a.windows() {
            assert_eq!(a.window_root(w), b.window_root(w));
        }
    }

    #[test]
    fn reconciliation_transfers_only_the_divergence_sublinearly() {
        // Remote has the full log; local is missing three records.
        let remote = log_of(100, 16);
        let mut local = remote.clone();
        for missing in [17u64, 42, 88] {
            local.records.remove(&missing);
        }
        assert_ne!(local.root(), remote.root());

        let result = reconcile(&local, &remote);
        let mut pulled: Vec<u64> = result.to_pull.iter().map(|r| r.sequence).collect();
        pulled.sort_unstable();
        assert_eq!(pulled, vec![17, 42, 88], "pull exactly the missing records");
        assert!(
            result.root_comparisons < 100,
            "binary search is sub-linear: {} comparisons",
            result.root_comparisons
        );
        assert!(result.records_fetched < 30, "few records fetched: {}", result.records_fetched);

        // Applying the diff makes the logs identical.
        for r in result.to_pull {
            local.append(r);
        }
        assert_eq!(local.root(), remote.root());
    }

    #[test]
    fn reconciliation_detects_a_differing_payload_at_the_same_sequence() {
        let remote = log_of(40, 8);
        let mut local = remote.clone();
        // Same sequence, different payload (a divergent event).
        local.append(record(1, 7, 21, "tampered"));
        assert_ne!(local.root(), remote.root());

        let result = reconcile(&local, &remote);
        assert_eq!(result.to_pull.len(), 1);
        assert_eq!(result.to_pull[0].sequence, 21);
        for r in result.to_pull {
            local.append(r);
        }
        assert_eq!(local.root(), remote.root());
    }

    #[test]
    fn advertisement_mismatch_localizes_to_a_window() {
        let mut a = log_of(40, 10); // windows 0..=3
        let mut b = log_of(40, 10);
        // Diverge one record in window 2 (seq 25).
        b.append(record(1, 7, 25, "different"));

        let ads_a = a.advertise(nid(1), 7);
        // The peer compares each advertised window root to its own.
        let mut differing_windows: Vec<u64> = ads_a
            .iter()
            .filter(|ad| b.window_root(ad.window_id) != ad.root)
            .map(|ad| ad.window_id)
            .collect();
        differing_windows.sort_unstable();
        assert_eq!(differing_windows, vec![2], "only window 2 differs");
        let _ = (&mut a, &mut b);
    }

    #[test]
    fn equivocation_is_detected() {
        // Node 1 advertises two different roots for the same (boot, window).
        let honest = log_of(20, 10);
        let mut forked = log_of(20, 10);
        forked.append(record(1, 7, 5, "forked"));

        let mut ads = honest.advertise(nid(1), 7);
        ads.extend(forked.advertise(nid(1), 7));
        // Also a different node — must not be flagged.
        ads.extend(log_of(20, 10).advertise(nid(2), 7));

        let equivocations = detect_equivocation(&ads);
        assert!(
            equivocations.iter().any(|e| e.node_id == nid(1) && e.window_id == 0),
            "node 1 forked window 0: {equivocations:?}"
        );
        assert!(
            !equivocations.iter().any(|e| e.node_id == nid(2)),
            "the honest second node is not flagged"
        );
    }
}
