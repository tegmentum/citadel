//! CP7 — observer sharding by HRW subject-space.
//!
//! At fleet scale one control-plane process can't ingest every subject's verdict
//! stream. Shards split the **subject space** by the same rendezvous
//! (highest-random-weight) hashing the mesh uses for witnesses: a subject's
//! verdict/event history is owned by the top-`replication` shards by HRW weight.
//! This is coordinator-free and **minimally disruptive** — adding or losing a
//! shard reassigns only the subjects whose top set changes, not the whole space
//! (the defining HRW property). Membership (the small current-state + verifier
//! keys) is still replicated to every shard; only the unbounded append history
//! is partitioned.
//!
//! A shard is identified by its observer node's [`NodeId`].

use citadel_mesh::id::Epoch;
use citadel_mesh::{witness, NodeId};

/// A control-plane shard, identified by its observer node id.
pub type ShardId = NodeId;

/// The shards responsible for `subject`: the top-`replication` shard ids by the
/// mesh's HRW hashing (the primary owner first). `replication = 1` is a single
/// owner; higher gives hot-standby replicas for failover.
pub fn responsible_shards(subject: NodeId, shards: &[ShardId], replication: usize) -> Vec<ShardId> {
    // Shard ids are observer node ids, disjoint from subject (worker) ids, so
    // `witness::assign`'s self-exclusion never drops a shard.
    witness::assign(subject, shards, Epoch(0), replication.max(1)).witnesses
}

/// Is shard `me` responsible for `subject` under this shard set + replication?
pub fn owns(me: ShardId, subject: NodeId, shards: &[ShardId], replication: usize) -> bool {
    responsible_shards(subject, shards, replication).contains(&me)
}
