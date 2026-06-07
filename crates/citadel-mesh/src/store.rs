//! Durable storage for a node's evidence state (design
//! `distributed-log-shipping-lthash.md` §17): a small key→bytes [`Store`]
//! abstraction with an in-memory default (tests) and a filesystem backend
//! (deployment), so logs, replicas, fragments, manifests, and audit chains
//! survive a restart rather than living only in memory.
//!
//! The node serializes a [`crate::node::NodeSnapshot`] and persists it under a
//! per-node key; on start it hydrates from the same key. Transient state
//! (membership liveness/trust) is intentionally **not** persisted — it
//! re-converges via gossip and re-attestation, which is the safe default
//! (trust is re-earned on restart, not blindly restored).

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

/// A durable key→bytes store. Implementations must be cheap and thread-safe.
pub trait Store: Send + Sync {
    /// Persist `bytes` under `key`, overwriting any prior value.
    fn save(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()>;
    /// Load the bytes stored under `key`, or `None` if absent.
    fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>>;
}

/// An in-memory store — for tests and ephemeral nodes. Not durable across
/// process restart (use [`FileStore`] for that).
#[derive(Default)]
pub struct MemStore {
    inner: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Store for MemStore {
    fn save(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        self.inner.lock().unwrap().insert(key.to_string(), bytes.to_vec());
        Ok(())
    }
    fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self.inner.lock().unwrap().get(key).cloned())
    }
}

/// A filesystem-backed store: each key is a file under `root`. Durable across
/// restart. Writes are atomic (write-to-temp + rename) so a crash mid-write
/// cannot corrupt a prior good snapshot.
pub struct FileStore {
    root: PathBuf,
}

impl FileStore {
    /// Open (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(FileStore { root })
    }

    /// Map a key to a path, rejecting separators so a key can't escape `root`.
    fn path_for(&self, key: &str) -> anyhow::Result<PathBuf> {
        if key.is_empty() || key.contains(['/', '\\']) || key.contains("..") {
            anyhow::bail!("invalid store key: {key:?}");
        }
        Ok(self.root.join(key))
    }
}

impl Store for FileStore {
    fn save(&self, key: &str, bytes: &[u8]) -> anyhow::Result<()> {
        let path = self.path_for(key)?;
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
    fn load(&self, key: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.path_for(key)?;
        match std::fs::read(&path) {
            Ok(b) => Ok(Some(b)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_store_roundtrips() {
        let s = MemStore::new();
        assert!(s.load("k").unwrap().is_none());
        s.save("k", b"hello").unwrap();
        assert_eq!(s.load("k").unwrap().as_deref(), Some(b"hello".as_slice()));
        s.save("k", b"world").unwrap(); // overwrite
        assert_eq!(s.load("k").unwrap().as_deref(), Some(b"world".as_slice()));
    }

    #[test]
    fn file_store_rejects_path_traversal() {
        let dir = std::env::temp_dir().join(format!("citadel-store-{}", std::process::id()));
        let s = FileStore::open(&dir).unwrap();
        assert!(s.save("../escape", b"x").is_err());
        assert!(s.save("a/b", b"x").is_err());
        assert!(s.save("ok.json", b"x").is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
