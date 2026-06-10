//! P2 / MSS8 D3 — persisted sealed shares, so a committee member **reclaims its
//! share on restart** (reboots are free, no reshare needed), with a **generation
//! fence on reclaim**: a node that was reshared out while down discards its now
//! stale-generation share and re-enrols fresh.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tpm_core::backend::SealedData;

/// A persisted sealed share a node holds: which secret, which committee
/// generation, and the sealed bytes (sealed to this node's TPM).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StoredShare {
    pub secret_id: [u8; 32],
    pub generation: u64,
    pub sealed: SealedData,
}

/// Durable storage for a node's sealed shares across restarts.
pub trait ShareStore {
    fn put(&mut self, share: StoredShare) -> anyhow::Result<()>;
    fn get(&self, secret_id: &[u8; 32]) -> Option<StoredShare>;
    fn remove(&mut self, secret_id: &[u8; 32]) -> anyhow::Result<()>;
}

/// In-memory store (a fresh instance is empty — for durability across a real
/// restart use [`FileShareStore`]).
#[derive(Default)]
pub struct MemShareStore {
    shares: HashMap<[u8; 32], StoredShare>,
}

impl MemShareStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ShareStore for MemShareStore {
    fn put(&mut self, share: StoredShare) -> anyhow::Result<()> {
        self.shares.insert(share.secret_id, share);
        Ok(())
    }
    fn get(&self, secret_id: &[u8; 32]) -> Option<StoredShare> {
        self.shares.get(secret_id).cloned()
    }
    fn remove(&mut self, secret_id: &[u8; 32]) -> anyhow::Result<()> {
        self.shares.remove(secret_id);
        Ok(())
    }
}

/// A file-backed store (JSON) — survives a real process restart, so a node
/// reloads its sealed shares on reboot.
pub struct FileShareStore {
    path: PathBuf,
    shares: HashMap<[u8; 32], StoredShare>,
}

impl FileShareStore {
    /// Open the store, loading any persisted shares (modelling a node coming back
    /// up and reading its durable share state).
    pub fn open(path: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let path = path.into();
        let shares = if path.exists() {
            let list: Vec<StoredShare> = serde_json::from_slice(&std::fs::read(&path)?)?;
            list.into_iter().map(|s| (s.secret_id, s)).collect()
        } else {
            HashMap::new()
        };
        Ok(Self { path, shares })
    }

    fn flush(&self) -> anyhow::Result<()> {
        let list: Vec<&StoredShare> = self.shares.values().collect();
        std::fs::write(&self.path, serde_json::to_vec(&list)?)?;
        Ok(())
    }
}

impl ShareStore for FileShareStore {
    fn put(&mut self, share: StoredShare) -> anyhow::Result<()> {
        self.shares.insert(share.secret_id, share);
        self.flush()
    }
    fn get(&self, secret_id: &[u8; 32]) -> Option<StoredShare> {
        self.shares.get(secret_id).cloned()
    }
    fn remove(&mut self, secret_id: &[u8; 32]) -> anyhow::Result<()> {
        self.shares.remove(secret_id);
        self.flush()
    }
}

/// Reclaim a held share for `secret_id` against the committee's current
/// `generation` (MSS8 D3/D4). Returns the sealed share iff it is the current
/// generation — a reboot returning with a still-valid share, free. Otherwise it
/// **discards** the share (the node was reshared out while down: stale generation,
/// fenced) and returns `None`, so the node re-enrols fresh.
pub fn reclaim_share(
    store: &mut dyn ShareStore,
    secret_id: &[u8; 32],
    generation: u64,
) -> Option<SealedData> {
    match store.get(secret_id) {
        Some(s) if s.generation == generation => Some(s.sealed),
        Some(_) => {
            let _ = store.remove(secret_id);
            None
        }
        None => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threshold::{self, GenShare};
    use tpm_core::backend::{MockBackend, TpmBackend};

    #[test]
    fn reboot_reclaims_a_current_gen_share_and_fences_a_stale_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shares.json");
        let backend = MockBackend::new();
        let sid = [7u8; 32];

        // Seal a gen-1 share and persist it (this node is a gen-1 committee member).
        let secret = b"db-master-key".to_vec();
        let g = threshold::split(&secret, 3, 5)
            .into_iter()
            .map(|share| GenShare {
                generation: 1,
                share,
            })
            .collect::<Vec<_>>();
        let sealed = backend
            .seal(&serde_json::to_vec(&g[0]).unwrap(), None)
            .unwrap();
        {
            let mut store = FileShareStore::open(&path).unwrap();
            store
                .put(StoredShare {
                    secret_id: sid,
                    generation: 1,
                    sealed,
                })
                .unwrap();
        } // drop → process exits

        // "Reboot": a fresh store loads the persisted share; reclaim at the current
        // generation (1) succeeds — the node is back with its share, no reshare.
        let mut store = FileShareStore::open(&path).unwrap();
        let reclaimed = reclaim_share(&mut store, &sid, 1).expect("reclaim current-gen share");
        let gs: GenShare = serde_json::from_slice(&backend.unseal(&reclaimed).unwrap()).unwrap();
        assert_eq!(gs.generation, 1);

        // The committee has since moved to gen 2 (this node was reshared out while
        // down). Reclaiming its gen-1 share fails and discards it (the zombie fence
        // at reclaim time).
        let mut store2 = FileShareStore::open(&path).unwrap();
        assert!(
            reclaim_share(&mut store2, &sid, 2).is_none(),
            "stale generation is fenced"
        );
        let store3 = FileShareStore::open(&path).unwrap();
        assert!(
            store3.get(&sid).is_none(),
            "the stale share was discarded on reclaim"
        );
    }

    #[test]
    fn mem_store_round_trips() {
        let mut store = MemShareStore::new();
        let sid = [1u8; 32];
        store
            .put(StoredShare {
                secret_id: sid,
                generation: 3,
                sealed: MockBackend::new().seal(b"x", None).unwrap(),
            })
            .unwrap();
        assert_eq!(store.get(&sid).map(|s| s.generation), Some(3));
        store.remove(&sid).unwrap();
        assert!(store.get(&sid).is_none());
    }
}
