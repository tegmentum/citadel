//! Bridge: a shipped log window is preserved in the Phase-4 durable evidence
//! store — hash-chained, erasure-coded, and reconstructable after losing
//! holders. Composes logship (Item 3) with evidence + erasure (Phase 4).

use citadel_mesh::erasure::{self, ErasureScheme, EvidenceFragment};
use citadel_mesh::evidence::{self, audit_reconstruction, EvidenceChain, RecordType};
use citadel_mesh::id::MeshId;
use citadel_mesh::logship::{decode_records, encode_records, EventLog, EventRecord};
use citadel_mesh::NodeId;

fn nid(n: u8) -> NodeId {
    NodeId([n; 32])
}

fn window_records(node: u8, boot: u64, lo: u64, hi: u64) -> Vec<EventRecord> {
    let mut log = EventLog::new(hi - lo);
    for seq in lo..hi {
        log.append(EventRecord {
            node_id: nid(node),
            boot_id: boot,
            sequence: seq,
            payload_hash: *blake3::hash(format!("event-{seq}").as_bytes()).as_bytes(),
        });
    }
    log.records_in(lo, hi)
}

#[test]
fn a_shipped_window_is_preserved_as_durable_reconstructable_evidence() {
    let subject = nid(7);
    // The window of log records a peer received during reconciliation.
    let records = window_records(7, 3, 0, 16);
    let payload = encode_records(&records);
    let record_id = evidence::payload_hash(&payload);

    // 1) Hash-chain a LogFragment evidence record committing to the window.
    let mut chain = EvidenceChain::new(nid(1), MeshId::new("prod-east-1"));
    let committed = chain
        .append(subject, RecordType::LogFragment, record_id, 100, 1)
        .clone();
    assert_eq!(chain.verify_integrity(), Ok(()));
    assert_eq!(committed.payload_hash, record_id);

    // 2) Erasure-code the window into N=20 fragments scattered to holders.
    let scheme = ErasureScheme::new(7, 13).unwrap();
    let fragments = scheme.encode(record_id, &payload).unwrap();
    assert_eq!(fragments.len(), 20);

    // 3) Lose 13 holders; reconstruct from the surviving 7.
    let surviving: Vec<EvidenceFragment> = fragments.into_iter().skip(13).collect();
    assert_eq!(surviving.len(), 7);
    let rebuilt = erasure::reconstruct(&surviving).unwrap();

    // 4) The reconstructed payload decodes to exactly the original records and
    //    matches what the evidence chain committed to.
    assert_eq!(evidence::payload_hash(&rebuilt), committed.payload_hash);
    assert_eq!(decode_records(&rebuilt).unwrap(), records);

    // 5) A reconstruction audit emits a passing proof.
    let proof = audit_reconstruction(record_id, record_id, &surviving, nid(2), 200);
    assert!(proof.success);
    assert_eq!(proof.reconstructed_payload_hash, record_id);
}
