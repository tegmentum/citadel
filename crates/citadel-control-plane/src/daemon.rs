//! The combined observer-ingestion daemon (CP7, feature `daemon`).
//!
//! Bridges a live observer [`AgentHandle`](citadel_agent::AgentHandle) — a
//! non-voting observer `Node` running in the mesh over the agent's transport —
//! into a [`ControlPlane`](crate::ControlPlane): each cycle it pulls the
//! observer's verified feed (members + verdicts), ingests it (re-verifying every
//! verdict), and relays any pending operator writes back into the mesh through
//! the same observer. The control plane is shared (`api::Shared`) with the HTTP
//! API, so a single process both ingests and serves.

use std::time::Duration;

use citadel_agent::AgentHandle;

use crate::api::Shared;
use crate::ControlPlaneStore;

/// Run one ingestion cycle: pull the observer feed, ingest it, and relay any
/// queued policy manifests / quarantine approvals back into the mesh. Exposed
/// for tests and custom drivers; [`run_observer_daemon`] calls it in a loop.
pub async fn ingest_once<S: ControlPlaneStore + 'static>(
    cp: &Shared<S>,
    observer: &AgentHandle,
    tick: u64,
) {
    let feed = observer.observer_feed().await;
    // Hold the lock only for the synchronous ingest + drain; never across await.
    let (manifests, approvals) = {
        let mut g = cp.lock().unwrap();
        g.ingest_observer_feed(
            feed.members,
            feed.verdicts,
            feed.epoch,
            feed.witness_count,
            tick,
        );
        (
            g.drain_pending_manifests(),
            g.drain_pending_quarantine_approvals(),
        )
    };
    for m in manifests {
        observer.broadcast_reference_manifest(m).await;
    }
    for a in approvals {
        observer.relay_quarantine_approval(a).await;
    }
}

/// Run the ingestion daemon until cancelled: every `interval`, pull + ingest the
/// observer's verified feed and relay pending operator writes.
pub async fn run_observer_daemon<S: ControlPlaneStore + 'static>(
    cp: Shared<S>,
    observer: AgentHandle,
    interval: Duration,
) {
    let mut tick = 0u64;
    loop {
        tick += 1;
        ingest_once(&cp, &observer, tick).await;
        tokio::time::sleep(interval).await;
    }
}
