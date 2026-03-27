use std::collections::HashMap;
use std::sync::Mutex;

use crate::model::{Algorithm, ObjectPath};

use super::traits::{BackendStatus, KeyHandle, TpmBackend};

/// Deterministic mock backend for development and testing.
pub struct MockBackend {
    keys: Mutex<HashMap<String, MockKey>>,
}

struct MockKey {
    #[allow(dead_code)]
    algorithm: Algorithm,
    id: Vec<u8>,
}

impl MockBackend {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for MockBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl TpmBackend for MockBackend {
    fn status(&self) -> anyhow::Result<BackendStatus> {
        Ok(BackendStatus {
            backend_type: "mock".to_string(),
            manufacturer: "Mock TPM".to_string(),
            firmware_version: "0.0.0".to_string(),
            available: true,
        })
    }

    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle> {
        let mut keys = self.keys.lock().unwrap();
        let id: Vec<u8> = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            path.as_str().hash(&mut h);
            h.finish().to_le_bytes().to_vec()
        };
        keys.insert(
            path.as_str().to_string(),
            MockKey {
                algorithm,
                id: id.clone(),
            },
        );
        Ok(KeyHandle {
            id,
            path: path.as_str().to_string(),
        })
    }

    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        let keys = self.keys.lock().unwrap();
        if !keys.contains_key(&handle.path) {
            anyhow::bail!("key not found: {}", handle.path);
        }
        // Deterministic "signature": hash of handle id + data
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        handle.id.hash(&mut h);
        data.hash(&mut h);
        Ok(h.finish().to_le_bytes().to_vec())
    }

    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>> {
        let keys = self.keys.lock().unwrap();
        Ok(keys
            .iter()
            .map(|(path, key)| KeyHandle {
                id: key.id.clone(),
                path: path.clone(),
            })
            .collect())
    }
}
