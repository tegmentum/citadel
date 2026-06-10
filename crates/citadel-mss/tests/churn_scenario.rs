//! P1 — the MSS8 churn loop end to end: the membership-reactive driver
//! (decide_reshare) feeds the custody reshare (reshare_committee), and the new
//! committee reconstructs the SAME secret while the evicted holder is fenced.

use citadel_mesh::NodeId;
use citadel_mss::{
    decide_reshare, reshare_committee, threshold, CustodyCommittee, HolderLiveness, ReshareDecision,
};
use tpm_core::backend::{MockBackend, TpmBackend};

fn nodes(range: std::ops::RangeInclusive<u8>) -> Vec<NodeId> {
    range.map(|n| NodeId([n; 32])).collect()
}

fn gen0(secret: &[u8], k: u8, n: u8) -> Vec<threshold::GenShare> {
    threshold::split(secret, k, n)
        .into_iter()
        .map(|share| threshold::GenShare {
            generation: 0,
            share,
        })
        .collect()
}

#[test]
fn churn_drives_reshare_keeping_the_secret_and_fencing_the_evicted() {
    let backend = MockBackend::new();
    let sid = [7u8; 32];
    let secret = b"cluster custody secret".to_vec();
    let trusted = nodes(1..=6);
    let (n, k) = (5usize, 3u8);

    let c0 = CustodyCommittee::target(sid, &trusted, n, k, 0);
    let shares0 = gen0(&secret, k, c0.members.len() as u8);
    assert_eq!(
        threshold::combine_gen(&shares0[..k as usize]),
        Some(secret.clone())
    );

    let (grace, now) = (20u64, 100u64);
    let fresh: Vec<HolderLiveness> = c0
        .members
        .iter()
        .map(|&node| HolderLiveness {
            node,
            last_seen_tick: now - 1,
        })
        .collect();

    // 1. All holders fresh → NoChange.
    assert_eq!(
        decide_reshare(&c0, &trusted, &fresh, now, grace, n),
        ReshareDecision::NoChange
    );

    // 2. A holder transiently absent (within grace) → NoChange.
    let mut blip = fresh.clone();
    blip[0].last_seen_tick = now - (grace - 5);
    assert_eq!(
        decide_reshare(&c0, &trusted, &blip, now, grace, n),
        ReshareDecision::NoChange
    );

    // 3. A holder durably gone → Reshare to the current trusted set; the gen-1
    //    committee reconstructs the SAME secret and the evicted share is fenced.
    let gone = c0.members[0];
    let mut live = fresh.clone();
    live[0].last_seen_tick = now - (grace + 5);
    let trusted_after: Vec<NodeId> = trusted
        .iter()
        .cloned()
        .filter(|m| *m != gone)
        .chain([NodeId([99; 32])])
        .collect();

    let next = match decide_reshare(&c0, &trusted_after, &live, now, grace, n) {
        ReshareDecision::Reshare { next, evicted } => {
            assert!(
                evicted.contains(&gone),
                "the durably-gone holder is evicted"
            );
            next
        }
        other => panic!("expected Reshare, got {other:?}"),
    };
    assert_eq!(next.generation, 1);
    assert!(!next.contains(&gone));

    let sealed = reshare_committee(&backend, &shares0[..k as usize], &next).unwrap();
    assert_eq!(sealed.len(), next.members.len());

    // A quorum of the new gen-1 shares reconstructs the original secret.
    let recovered: Vec<threshold::GenShare> = sealed[..k as usize]
        .iter()
        .map(|(_, s)| serde_json::from_slice(&backend.unseal(s).unwrap()).unwrap())
        .collect();
    assert!(recovered
        .iter()
        .all(|gs: &threshold::GenShare| gs.generation == 1));
    assert_eq!(threshold::combine_gen(&recovered), Some(secret.clone()));

    // The evicted holder's gen-0 share can't combine with the gen-1 committee.
    let mut zombie = recovered[..2].to_vec();
    zombie.push(shares0[0].clone());
    assert_eq!(
        threshold::combine_gen(&zombie),
        None,
        "stale generation is fenced"
    );

    // 4. Trusted pool below k → Escalate (never run unsafe).
    let starved = nodes(1..=2);
    match decide_reshare(&c0, &starved, &live, now, grace, n) {
        ReshareDecision::Escalate { .. } => {}
        other => panic!("expected Escalate, got {other:?}"),
    }
}
