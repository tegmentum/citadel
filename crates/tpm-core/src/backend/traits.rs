use serde::{Deserialize, Serialize};

use crate::model::{Algorithm, ObjectPath};

/// Abstract interface to a TPM backend (real hardware, simulator, or mock).
pub trait TpmBackend: Send + Sync {
    fn status(&self) -> anyhow::Result<BackendStatus>;
    fn create_key(&self, algorithm: Algorithm, path: &ObjectPath) -> anyhow::Result<KeyHandle>;
    fn sign(&self, handle: &KeyHandle, data: &[u8]) -> anyhow::Result<Vec<u8>>;
    fn list_handles(&self) -> anyhow::Result<Vec<KeyHandle>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub backend_type: String,
    pub manufacturer: String,
    pub firmware_version: String,
    pub available: bool,
}

#[derive(Debug, Clone)]
pub struct KeyHandle {
    pub id: Vec<u8>,
    pub path: String,
}
