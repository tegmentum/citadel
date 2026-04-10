//! Pure Rust in-memory store backend.
//!
//! Used for WASM targets and testing. State is lost when the
//! process/instance terminates.

use std::sync::Mutex;

use crate::model::{
    ApprovalRequest, ApprovalStatus, Identity, ObjectPath, Policy, Profile, TpmObject,
};

use super::traits::{
    AuditEntry, SecureLogRow, SecureLogSegmentRow, SecureLogStreamRow, StoreBackend,
    WitnessLogRow,
};

struct Inner {
    objects: Vec<TpmObject>,
    profiles: Vec<Profile>,
    policies: Vec<Policy>,
    nv_indices: Vec<NvSlot>,
    pcr_baselines: Vec<PcrBaseline>,
    audit_log: Vec<AuditEntry>,
    approvals: Vec<ApprovalRequest>,
    identities: Vec<Identity>,
    secure_log: Vec<SecureLogRow>,
    secure_log_segments: Vec<SecureLogSegmentRow>,
    secure_log_segment_entries: Vec<(u64, u64, u64)>, // (segment_id, seqno, leaf_index)
    witness_log: Vec<WitnessLogRow>,
    secure_log_streams: Vec<SecureLogStreamRow>,
    next_audit_id: i64,
    next_secure_seqno: u64,
    next_segment_id: u64,
    next_witness_id: i64,
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
                secure_log: Vec::new(),
                secure_log_segments: Vec::new(),
                secure_log_segment_entries: Vec::new(),
                witness_log: Vec::new(),
                // Seed the default stream so the memory backend
                // matches the V9 migration seed in sqlite.
                secure_log_streams: vec![SecureLogStreamRow {
                    name: "default".into(),
                    tier: "public".into(),
                    description: Some(
                        "Default stream created automatically at init.".into(),
                    ),
                    created_at_rfc3339: chrono::Utc::now().to_rfc3339(),
                    deprecated_at_rfc3339: None,
                }],
                next_audit_id: 1,
                next_secure_seqno: 1,
                next_segment_id: 1,
                next_witness_id: 1,
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

    // -- Secure log --

    fn secure_log_insert(&self, row: &SecureLogRow) -> anyhow::Result<u64> {
        let seqno = row
            .seqno
            .ok_or_else(|| anyhow::anyhow!("secure_log_insert requires row.seqno to be Some"))?;
        let mut inner = self.inner.lock().unwrap();
        if inner.secure_log.iter().any(|r| r.seqno == Some(seqno)) {
            anyhow::bail!("UNIQUE constraint failed: secure_log.seqno ({})", seqno);
        }
        if seqno >= inner.next_secure_seqno {
            inner.next_secure_seqno = seqno + 1;
        }
        inner.secure_log.push(row.clone());
        Ok(seqno)
    }

    fn secure_log_global_head(&self) -> anyhow::Result<Option<u64>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner.secure_log.iter().filter_map(|r| r.seqno).max())
    }

    fn secure_log_get(&self, seqno: u64) -> anyhow::Result<Option<SecureLogRow>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log
            .iter()
            .find(|r| r.seqno == Some(seqno))
            .cloned())
    }

    fn secure_log_range(
        &self,
        stream_id: &str,
        from: u64,
        to: u64,
    ) -> anyhow::Result<Vec<SecureLogRow>> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<_> = inner
            .secure_log
            .iter()
            .filter(|r| {
                r.stream_id == stream_id
                    && r.seqno.map(|s| s >= from && s <= to).unwrap_or(false)
            })
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.seqno);
        Ok(rows)
    }

    fn secure_log_head(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log
            .iter()
            .filter(|r| r.stream_id == stream_id)
            .filter_map(|r| r.seqno)
            .max())
    }

    fn secure_log_last(&self, stream_id: &str) -> anyhow::Result<Option<SecureLogRow>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log
            .iter()
            .filter(|r| r.stream_id == stream_id)
            .max_by_key(|r| r.seqno)
            .cloned())
    }

    fn secure_log_segment_insert(
        &self,
        row: &SecureLogSegmentRow,
        entries: &[(u64, u64)],
    ) -> anyhow::Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        let segment_id = inner.next_segment_id;
        inner.next_segment_id += 1;
        let mut stored = row.clone();
        stored.segment_id = Some(segment_id);
        inner.secure_log_segments.push(stored);
        for (seqno, leaf_index) in entries {
            inner
                .secure_log_segment_entries
                .push((segment_id, *seqno, *leaf_index));
        }
        Ok(segment_id)
    }

    fn secure_log_segment_get(
        &self,
        segment_id: u64,
    ) -> anyhow::Result<Option<SecureLogSegmentRow>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log_segments
            .iter()
            .find(|s| s.segment_id == Some(segment_id))
            .cloned())
    }

    fn secure_log_segments_list(
        &self,
        stream_id: &str,
    ) -> anyhow::Result<Vec<SecureLogSegmentRow>> {
        let inner = self.inner.lock().unwrap();
        let mut out: Vec<_> = inner
            .secure_log_segments
            .iter()
            .filter(|s| s.stream_id == stream_id)
            .cloned()
            .collect();
        out.sort_by_key(|s| s.segment_id);
        Ok(out)
    }

    fn secure_log_segment_last_seqno(&self, stream_id: &str) -> anyhow::Result<Option<u64>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log_segments
            .iter()
            .filter(|s| s.stream_id == stream_id)
            .map(|s| s.seq_end)
            .max())
    }

    fn secure_log_segment_entry_seqnos(&self, segment_id: u64) -> anyhow::Result<Vec<u64>> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<_> = inner
            .secure_log_segment_entries
            .iter()
            .filter(|(sid, _, _)| *sid == segment_id)
            .cloned()
            .collect();
        rows.sort_by_key(|(_, _, leaf)| *leaf);
        Ok(rows.into_iter().map(|(_, seqno, _)| seqno).collect())
    }

    fn secure_log_segment_for_seqno(&self, seqno: u64) -> anyhow::Result<Option<u64>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log_segment_entries
            .iter()
            .find(|(_, s, _)| *s == seqno)
            .map(|(sid, _, _)| *sid))
    }

    fn secure_log_segment_set_signature(
        &self,
        segment_id: u64,
        signature: &[u8],
        signer_identity: &str,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let row = inner
            .secure_log_segments
            .iter_mut()
            .find(|s| s.segment_id == Some(segment_id))
            .ok_or_else(|| anyhow::anyhow!("segment not found: {}", segment_id))?;
        row.signature = Some(signature.to_vec());
        row.signer_identity = Some(signer_identity.to_string());
        Ok(())
    }

    fn witness_log_insert(&self, row: &WitnessLogRow) -> anyhow::Result<u64> {
        let mut inner = self.inner.lock().unwrap();
        let id = inner.next_witness_id;
        inner.next_witness_id += 1;
        let mut stored = row.clone();
        stored.id = Some(id);
        inner.witness_log.push(stored);
        Ok(id as u64)
    }

    fn witness_log_latest(&self, stream_id: &str) -> anyhow::Result<Option<WitnessLogRow>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .witness_log
            .iter()
            .filter(|r| r.stream_id == stream_id)
            .max_by_key(|r| r.id)
            .cloned())
    }

    fn witness_log_list(&self, stream_id: &str) -> anyhow::Result<Vec<WitnessLogRow>> {
        let inner = self.inner.lock().unwrap();
        let mut rows: Vec<_> = inner
            .witness_log
            .iter()
            .filter(|r| r.stream_id == stream_id)
            .cloned()
            .collect();
        rows.sort_by_key(|r| r.id);
        Ok(rows)
    }

    fn witness_log_stream_ids(&self) -> anyhow::Result<Vec<String>> {
        let inner = self.inner.lock().unwrap();
        let mut seen = std::collections::HashSet::new();
        let mut ids: Vec<String> = inner
            .witness_log
            .iter()
            .filter_map(|r| {
                if seen.insert(r.stream_id.clone()) {
                    Some(r.stream_id.clone())
                } else {
                    None
                }
            })
            .collect();
        ids.sort();
        Ok(ids)
    }

    fn witness_log_gc(
        &self,
        stream_id: Option<&str>,
        keep_latest: Option<usize>,
        older_than_rfc3339: Option<&str>,
    ) -> anyhow::Result<usize> {
        let mut inner = self.inner.lock().unwrap();

        // Determine which streams to process.
        let streams: Vec<String> = if let Some(sid) = stream_id {
            vec![sid.to_string()]
        } else {
            let mut seen = std::collections::HashSet::new();
            inner
                .witness_log
                .iter()
                .filter_map(|r| {
                    if seen.insert(r.stream_id.clone()) {
                        Some(r.stream_id.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        let mut deleted = 0usize;

        for sid in &streams {
            // IDs to keep per keep_latest.
            let keep_ids: std::collections::HashSet<Option<i64>> = if let Some(k) = keep_latest {
                inner
                    .witness_log
                    .iter()
                    .filter(|r| &r.stream_id == sid)
                    .map(|r| r.id)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .take(k)
                    .collect()
            } else {
                std::collections::HashSet::new()
            };

            inner.witness_log.retain(|r| {
                if &r.stream_id != sid {
                    return true; // different stream, keep
                }
                // Keep if in the keep_latest set.
                if !keep_ids.is_empty() && keep_ids.contains(&r.id) {
                    return true;
                }
                // Keep if newer than the cutoff.
                if let Some(cutoff) = older_than_rfc3339 {
                    if r.received_at_rfc3339.as_str() >= cutoff {
                        return true;
                    }
                } else if keep_ids.is_empty() {
                    // Neither cutoff nor keep_latest — nothing to do.
                    return true;
                }
                deleted += 1;
                false
            });
        }

        Ok(deleted)
    }

    fn secure_log_stream_upsert(&self, row: &SecureLogStreamRow) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(existing) = inner
            .secure_log_streams
            .iter_mut()
            .find(|r| r.name == row.name)
        {
            existing.tier = row.tier.clone();
            existing.description = row.description.clone();
            existing.deprecated_at_rfc3339 = row.deprecated_at_rfc3339.clone();
        } else {
            inner.secure_log_streams.push(row.clone());
        }
        Ok(())
    }

    fn secure_log_stream_get(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<SecureLogStreamRow>> {
        let inner = self.inner.lock().unwrap();
        Ok(inner
            .secure_log_streams
            .iter()
            .find(|r| r.name == name)
            .cloned())
    }

    fn secure_log_stream_list(&self) -> anyhow::Result<Vec<SecureLogStreamRow>> {
        let inner = self.inner.lock().unwrap();
        let mut rows = inner.secure_log_streams.clone();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(rows)
    }

    fn secure_log_stream_set_tier(&self, name: &str, tier: &str) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let row = inner
            .secure_log_streams
            .iter_mut()
            .find(|r| r.name == name)
            .ok_or_else(|| anyhow::anyhow!("stream not found: {}", name))?;
        row.tier = tier.to_string();
        Ok(())
    }

    fn secure_log_stream_deprecate(
        &self,
        name: &str,
        deprecated_at_rfc3339: &str,
    ) -> anyhow::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        let row = inner
            .secure_log_streams
            .iter_mut()
            .find(|r| r.name == name)
            .ok_or_else(|| anyhow::anyhow!("stream not found: {}", name))?;
        row.deprecated_at_rfc3339 = Some(deprecated_at_rfc3339.to_string());
        Ok(())
    }
}
