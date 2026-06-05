//! Pure Rust in-memory store backend.
//!
//! Used for WASM targets and testing. State is lost when the
//! process/instance terminates.

use std::sync::Mutex;

use crate::model::{
    ApprovalRequest, ApprovalStatus, Identity, ObjectPath, Policy, Profile, TpmObject,
};

use super::traits::{AuditEntry, StoreBackend};

struct Inner {
    objects: Vec<TpmObject>,
    profiles: Vec<Profile>,
    policies: Vec<Policy>,
    nv_indices: Vec<NvSlot>,
    pcr_baselines: Vec<PcrBaseline>,
    audit_log: Vec<AuditEntry>,
    approvals: Vec<ApprovalRequest>,
    identities: Vec<Identity>,
    checkpoint_counters: std::collections::HashMap<String, u64>,
    next_audit_id: i64,
}

struct NvSlot {
    name: String,
    nv_index: u32,
    size: usize,
    data: Option<Vec<u8>>,
}

struct PcrBaseline {
    name: String,
    bank: String,
    values: serde_json::Value,
}

/// In-memory store backend.
pub struct MemoryStore {
    inner: Mutex<Inner>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                objects: Vec::new(),
                profiles: Vec::new(),
                policies: Vec::new(),
                nv_indices: Vec::new(),
                pcr_baselines: Vec::new(),
                audit_log: Vec::new(),
                approvals: Vec::new(),
                identities: Vec::new(),
                checkpoint_counters: std::collections::HashMap::new(),
                next_audit_id: 1,
            }),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreBackend for MemoryStore {
    fn insert_object(&self, obj: &TpmObject) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.objects.iter().any(|o| o.path == obj.path) {
            anyhow::bail!("UNIQUE constraint failed: objects.path");
        }
        inner.objects.push(obj.clone());
        Ok(())
    }

    fn get_object(&self, path: &ObjectPath) -> anyhow::Result<Option<TpmObject>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.objects.iter().find(|o| &o.path == path).cloned())
    }

    fn get_object_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<TpmObject>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.objects.iter().find(|o| o.id == *id).cloned())
    }

    fn list_objects(&self) -> anyhow::Result<Vec<TpmObject>> {
        let inner = self.inner.lock().unwrap();
        let mut objects = inner.objects.clone();
        objects.sort_by(|a, b| a.path.as_str().cmp(b.path.as_str()));
        Ok(objects)
    }

    fn delete_object(&self, path: &ObjectPath) -> anyhow::Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let len_before = inner.objects.len();
        inner.objects.retain(|o| &o.path != path);
        Ok(inner.objects.len() < len_before)
    }

    fn rename_object(&self, old_path: &ObjectPath, new_path: &ObjectPath) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let obj = inner
            .objects
            .iter_mut()
            .find(|o| &o.path == old_path)
            .ok_or_else(|| anyhow::anyhow!("object not found: {}", old_path))?;
        obj.path = new_path.clone();
        Ok(())
    }

    fn set_object_state(&self, path: &ObjectPath, _state: &str) -> anyhow::Result<()> {
        let inner = self.inner.lock().unwrap();
        if !inner.objects.iter().any(|o| &o.path == path) {
            anyhow::bail!("object not found: {}", path);
        }
        // State field is in metadata for memory backend
        Ok(())
    }

    fn touch_object(&self, _path: &ObjectPath) -> anyhow::Result<()> {
        Ok(())
    }

    fn object_count(&self) -> anyhow::Result<usize> {
        Ok(self.inner.lock().unwrap().objects.len())
    }

    fn insert_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.profiles.push(profile.clone());
        Ok(())
    }

    fn get_active_profile(&self) -> anyhow::Result<Option<Profile>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.profiles.iter().find(|p| p.is_active).cloned())
    }

    fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        let inner = self.inner.lock().unwrap();
        let mut profiles = inner.profiles.clone();
        profiles.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(profiles)
    }

    fn set_active_profile(&self, name: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let found = inner.profiles.iter().any(|p| p.name == name);
        if !found {
            anyhow::bail!("profile not found: {}", name);
        }
        for p in &mut inner.profiles {
            p.is_active = p.name == name;
        }
        Ok(())
    }

    fn insert_policy(&self, policy: &Policy) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.policies.push(policy.clone());
        Ok(())
    }

    fn get_policy(&self, name: &str) -> anyhow::Result<Option<Policy>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.policies.iter().find(|p| p.name == name).cloned())
    }

    fn get_policy_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<Policy>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.policies.iter().find(|p| p.id == *id).cloned())
    }

    fn list_policies(&self) -> anyhow::Result<Vec<Policy>> {
        let inner = self.inner.lock().unwrap();
        let mut policies = inner.policies.clone();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(policies)
    }

    fn delete_policy(&self, name: &str) -> anyhow::Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let len_before = inner.policies.len();
        inner.policies.retain(|p| p.name != name);
        Ok(inner.policies.len() < len_before)
    }

    fn insert_nv_index(&self, name: &str, nv_index: u32, size: usize) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.nv_indices.push(NvSlot {
            name: name.to_string(),
            nv_index,
            size,
            data: None,
        });
        Ok(())
    }

    fn get_nv_index(&self, name: &str) -> anyhow::Result<Option<(u32, usize)>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .nv_indices
            .iter()
            .find(|n| n.name == name)
            .map(|n| (n.nv_index, n.size)))
    }

    fn list_nv_indices(&self) -> anyhow::Result<Vec<(String, u32, usize)>> {
        let inner = self.inner.lock().unwrap();
        let mut indices: Vec<_> = inner
            .nv_indices
            .iter()
            .map(|n| (n.name.clone(), n.nv_index, n.size))
            .collect();
        indices.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(indices)
    }

    fn nv_write_data(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let slot = inner
            .nv_indices
            .iter_mut()
            .find(|n| n.name == name)
            .ok_or_else(|| anyhow::anyhow!("NV index not found: {}", name))?;
        slot.data = Some(data.to_vec());
        Ok(())
    }

    fn nv_read_data(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .nv_indices
            .iter()
            .find(|n| n.name == name)
            .and_then(|n| n.data.clone()))
    }

    fn delete_nv_index(&self, name: &str) -> anyhow::Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let len_before = inner.nv_indices.len();
        inner.nv_indices.retain(|n| n.name != name);
        Ok(inner.nv_indices.len() < len_before)
    }

    fn save_pcr_baseline(
        &self,
        name: &str,
        bank: &str,
        values: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.pcr_baselines.retain(|b| b.name != name);
        inner.pcr_baselines.push(PcrBaseline {
            name: name.to_string(),
            bank: bank.to_string(),
            values: values.clone(),
        });
        Ok(())
    }

    fn get_pcr_baseline(&self, name: &str) -> anyhow::Result<Option<(String, serde_json::Value)>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .pcr_baselines
            .iter()
            .find(|b| b.name == name)
            .map(|b| (b.bank.clone(), b.values.clone())))
    }

    fn list_pcr_baselines(&self) -> anyhow::Result<Vec<String>> {
        let inner = self.inner.lock().unwrap();
        let mut names: Vec<_> = inner.pcr_baselines.iter().map(|b| b.name.clone()).collect();
        names.sort();
        Ok(names)
    }

    fn log_action(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_audit_id;
        inner.next_audit_id += 1;
        inner.audit_log.push(AuditEntry {
            id,
            timestamp: chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            action: action.to_string(),
            object_path: object_path.map(String::from),
            details: details.to_string(),
        });
        Ok(())
    }

    fn log_action_with_correlation(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
        _correlation_id: &str,
    ) -> anyhow::Result<()> {
        self.log_action(action, object_path, details)
    }

    fn list_audit_log(
        &self,
        filter_object: Option<&str>,
        filter_action: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        let inner = self.inner.lock().unwrap();
        let filtered: Vec<_> = inner
            .audit_log
            .iter()
            .rev()
            .filter(|e| {
                if let Some(obj) = filter_object {
                    if e.object_path.as_deref() != Some(obj) {
                        return false;
                    }
                }
                if let Some(act) = filter_action {
                    if !e.action.contains(act) {
                        return false;
                    }
                }
                true
            })
            .take(limit)
            .cloned()
            .collect();
        Ok(filtered)
    }

    fn insert_approval(&self, approval: &ApprovalRequest) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.approvals.push(approval.clone());
        Ok(())
    }

    fn get_approval(&self, id: &uuid::Uuid) -> anyhow::Result<Option<ApprovalRequest>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.approvals.iter().find(|a| a.id == *id).cloned())
    }

    fn list_approvals(&self) -> anyhow::Result<Vec<ApprovalRequest>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.approvals.clone())
    }

    fn update_approval_status(
        &self,
        id: &uuid::Uuid,
        status: ApprovalStatus,
        _resolved_by: Option<&str>,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(a) = inner.approvals.iter_mut().find(|a| a.id == *id) {
            a.status = status;
            a.resolved_at = Some(chrono::Utc::now());
            Ok(())
        } else {
            anyhow::bail!("approval not found")
        }
    }

    fn insert_identity(&self, identity: &Identity) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if inner.identities.iter().any(|i| i.name == identity.name) {
            anyhow::bail!("UNIQUE constraint failed: identities.name");
        }
        inner.identities.push(identity.clone());
        Ok(())
    }

    fn get_identity(&self, name: &str) -> anyhow::Result<Option<Identity>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.identities.iter().find(|i| i.name == name).cloned())
    }

    fn get_identity_by_key(&self, key_object_id: &uuid::Uuid) -> anyhow::Result<Vec<Identity>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .identities
            .iter()
            .filter(|i| i.key_object_id == *key_object_id)
            .cloned()
            .collect())
    }

    fn list_identities(&self) -> anyhow::Result<Vec<Identity>> {
        let inner = self.inner.lock().unwrap();
        let mut identities = inner.identities.clone();
        identities.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(identities)
    }

    fn update_identity_key(
        &self,
        name: &str,
        new_key_object_id: &uuid::Uuid,
        rotated_from: &uuid::Uuid,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let identity = inner
            .identities
            .iter_mut()
            .find(|i| i.name == name)
            .ok_or_else(|| anyhow::anyhow!("identity not found: {}", name))?;
        identity.key_object_id = *new_key_object_id;
        identity.rotated_from = Some(*rotated_from);
        Ok(())
    }

    fn set_identity_cert(&self, name: &str, certificate_pem: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let identity = inner
            .identities
            .iter_mut()
            .find(|i| i.name == name)
            .ok_or_else(|| anyhow::anyhow!("identity not found: {}", name))?;
        identity.certificate_pem = Some(certificate_pem.to_string());
        Ok(())
    }

    fn delete_identity(&self, name: &str) -> anyhow::Result<bool> {
        let mut inner = self.inner.lock().unwrap();
        let len_before = inner.identities.len();
        inner.identities.retain(|i| i.name != name);
        Ok(inner.identities.len() < len_before)
    }

    fn set_checkpoint_counter(&self, checkpoint_hash: &str, counter: u64) -> anyhow::Result<()> {
        self.inner
            .lock()
            .unwrap()
            .checkpoint_counters
            .insert(checkpoint_hash.to_string(), counter);
        Ok(())
    }

    fn get_checkpoint_counter(&self, checkpoint_hash: &str) -> anyhow::Result<Option<u64>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .checkpoint_counters
            .get(checkpoint_hash)
            .copied())
    }

    fn max_checkpoint_counter(&self) -> anyhow::Result<Option<u64>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .checkpoint_counters
            .values()
            .copied()
            .max())
    }

}
