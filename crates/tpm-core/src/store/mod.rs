pub mod migrations;
pub mod schema;

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{ObjectPath, Profile, TpmObject};

/// Persistent metadata store backed by SQLite.
pub struct Store {
    conn: Connection,
}

impl Store {
    /// Open a store at the given path, creating it if necessary.
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory store (for tests).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Run all pending migrations.
    pub fn migrate(&self) -> anyhow::Result<()> {
        // Ensure migrations table exists
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS migrations (
                version INTEGER PRIMARY KEY,
                applied TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )?;

        let current: i64 = self
            .conn
            .query_row("SELECT COALESCE(MAX(version), 0) FROM migrations", [], |r| {
                r.get(0)
            })?;

        for &(version, sql) in migrations::MIGRATIONS {
            if version > current {
                self.conn.execute_batch(sql)?;
                self.conn.execute(
                    "INSERT INTO migrations (version) VALUES (?1)",
                    params![version],
                )?;
            }
        }

        Ok(())
    }

    // -- Objects --

    pub fn insert_object(&self, obj: &TpmObject) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO objects (id, path, kind, algorithm, policy_id, handle_blob, created_at, metadata)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                obj.id.to_string(),
                obj.path.as_str(),
                serde_json::to_string(&obj.kind)?.trim_matches('"'),
                serde_json::to_string(&obj.algorithm)?.trim_matches('"'),
                obj.policy_id.map(|id| id.to_string()),
                obj.handle_blob,
                obj.created_at.to_rfc3339(),
                obj.metadata.to_string(),
            ],
        )?;
        Ok(())
    }

    pub fn get_object(&self, path: &ObjectPath) -> anyhow::Result<Option<TpmObject>> {
        self.conn
            .query_row(
                "SELECT id, path, kind, algorithm, policy_id, handle_blob, created_at, metadata
                 FROM objects WHERE path = ?1",
                params![path.as_str()],
                |row| {
                    Ok(RawObjectRow {
                        id: row.get(0)?,
                        path: row.get(1)?,
                        kind: row.get(2)?,
                        algorithm: row.get(3)?,
                        policy_id: row.get(4)?,
                        handle_blob: row.get(5)?,
                        created_at: row.get(6)?,
                        metadata: row.get(7)?,
                    })
                },
            )
            .optional()?
            .map(|r| r.into_object())
            .transpose()
    }

    pub fn list_objects(&self) -> anyhow::Result<Vec<TpmObject>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, path, kind, algorithm, policy_id, handle_blob, created_at, metadata
             FROM objects ORDER BY path",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RawObjectRow {
                id: row.get(0)?,
                path: row.get(1)?,
                kind: row.get(2)?,
                algorithm: row.get(3)?,
                policy_id: row.get(4)?,
                handle_blob: row.get(5)?,
                created_at: row.get(6)?,
                metadata: row.get(7)?,
            })
        })?;
        let mut objects = Vec::new();
        for row in rows {
            objects.push(row?.into_object()?);
        }
        Ok(objects)
    }

    pub fn delete_object(&self, path: &ObjectPath) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM objects WHERE path = ?1", params![path.as_str()])?;
        Ok(count > 0)
    }

    // -- Profiles --

    pub fn insert_profile(&self, profile: &Profile) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO profiles (name, default_algorithm, default_policy, is_active)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                profile.name,
                serde_json::to_string(&profile.default_algorithm)?.trim_matches('"'),
                profile.default_policy,
                profile.is_active as i32,
            ],
        )?;
        Ok(())
    }

    pub fn get_active_profile(&self) -> anyhow::Result<Option<Profile>> {
        self.conn
            .query_row(
                "SELECT name, default_algorithm, default_policy, is_active
                 FROM profiles WHERE is_active = 1 LIMIT 1",
                [],
                |row| {
                    Ok(RawProfileRow {
                        name: row.get(0)?,
                        default_algorithm: row.get(1)?,
                        default_policy: row.get(2)?,
                        is_active: row.get(3)?,
                    })
                },
            )
            .optional()?
            .map(|r| r.into_profile())
            .transpose()
    }

    pub fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
        let mut stmt = self.conn.prepare(
            "SELECT name, default_algorithm, default_policy, is_active
             FROM profiles ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RawProfileRow {
                name: row.get(0)?,
                default_algorithm: row.get(1)?,
                default_policy: row.get(2)?,
                is_active: row.get(3)?,
            })
        })?;
        let mut profiles = Vec::new();
        for row in rows {
            profiles.push(row?.into_profile()?);
        }
        Ok(profiles)
    }

    pub fn set_active_profile(&self, name: &str) -> anyhow::Result<()> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE profiles SET is_active = 0", [])?;
        let count = tx.execute(
            "UPDATE profiles SET is_active = 1 WHERE name = ?1",
            params![name],
        )?;
        if count == 0 {
            anyhow::bail!("profile not found: {}", name);
        }
        tx.commit()?;
        Ok(())
    }

    // -- Policies --

    pub fn insert_policy(&self, policy: &crate::model::Policy) -> anyhow::Result<()> {
        let rules_json = serde_json::to_string(&policy.rules)?;
        self.conn.execute(
            "INSERT INTO policies (id, name, rules) VALUES (?1, ?2, ?3)",
            params![policy.id.to_string(), policy.name, rules_json],
        )?;
        Ok(())
    }

    pub fn get_policy(&self, name: &str) -> anyhow::Result<Option<crate::model::Policy>> {
        self.conn
            .query_row(
                "SELECT id, name, rules FROM policies WHERE name = ?1",
                params![name],
                |row| {
                    Ok(RawPolicyRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        rules: row.get(2)?,
                    })
                },
            )
            .optional()?
            .map(|r| r.into_policy())
            .transpose()
    }

    pub fn get_policy_by_id(
        &self,
        id: &uuid::Uuid,
    ) -> anyhow::Result<Option<crate::model::Policy>> {
        self.conn
            .query_row(
                "SELECT id, name, rules FROM policies WHERE id = ?1",
                params![id.to_string()],
                |row| {
                    Ok(RawPolicyRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        rules: row.get(2)?,
                    })
                },
            )
            .optional()?
            .map(|r| r.into_policy())
            .transpose()
    }

    pub fn list_policies(&self) -> anyhow::Result<Vec<crate::model::Policy>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id, name, rules FROM policies ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            Ok(RawPolicyRow {
                id: row.get(0)?,
                name: row.get(1)?,
                rules: row.get(2)?,
            })
        })?;
        let mut policies = Vec::new();
        for row in rows {
            policies.push(row?.into_policy()?);
        }
        Ok(policies)
    }

    pub fn delete_policy(&self, name: &str) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM policies WHERE name = ?1", params![name])?;
        Ok(count > 0)
    }

    // -- NV Indices --

    pub fn insert_nv_index(&self, name: &str, nv_index: u32, size: usize) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO nv_indices (name, nv_index, size) VALUES (?1, ?2, ?3)",
            params![name, nv_index, size as i64],
        )?;
        Ok(())
    }

    pub fn get_nv_index(&self, name: &str) -> anyhow::Result<Option<(u32, usize)>> {
        Ok(self
            .conn
            .query_row(
                "SELECT nv_index, size FROM nv_indices WHERE name = ?1",
                params![name],
                |row| {
                    let idx: u32 = row.get(0)?;
                    let size: i64 = row.get(1)?;
                    Ok((idx, size as usize))
                },
            )
            .optional()?)
    }

    pub fn list_nv_indices(&self) -> anyhow::Result<Vec<(String, u32, usize)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name, nv_index, size FROM nv_indices ORDER BY name")?;
        let rows = stmt.query_map([], |row| {
            let name: String = row.get(0)?;
            let idx: u32 = row.get(1)?;
            let size: i64 = row.get(2)?;
            Ok((name, idx, size as usize))
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn nv_write_data(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE nv_indices SET data = ?2 WHERE name = ?1",
            params![name, data],
        )?;
        if count == 0 {
            anyhow::bail!("NV index not found: {}", name);
        }
        Ok(())
    }

    pub fn nv_read_data(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT data FROM nv_indices WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?)
    }

    pub fn delete_nv_index(&self, name: &str) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM nv_indices WHERE name = ?1", params![name])?;
        Ok(count > 0)
    }

    // -- PCR Baselines --

    pub fn save_pcr_baseline(
        &self,
        name: &str,
        bank: &str,
        values: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO pcr_baselines (name, bank, pcr_values) VALUES (?1, ?2, ?3)",
            params![name, bank, values.to_string()],
        )?;
        Ok(())
    }

    pub fn get_pcr_baseline(
        &self,
        name: &str,
    ) -> anyhow::Result<Option<(String, serde_json::Value)>> {
        self.conn
            .query_row(
                "SELECT bank, pcr_values FROM pcr_baselines WHERE name = ?1",
                params![name],
                |row| {
                    let bank: String = row.get(0)?;
                    let values_str: String = row.get(1)?;
                    Ok((bank, values_str))
                },
            )
            .optional()?
            .map(|(bank, values_str)| {
                let values: serde_json::Value = serde_json::from_str(&values_str)?;
                Ok((bank, values))
            })
            .transpose()
    }

    pub fn list_pcr_baselines(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM pcr_baselines ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    // -- Audit --

    pub fn log_action(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (action, object_path, details) VALUES (?1, ?2, ?3)",
            params![action, object_path, details.to_string()],
        )?;
        Ok(())
    }

    pub fn list_audit_log(
        &self,
        filter_object: Option<&str>,
        filter_action: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<AuditEntry>> {
        let mut sql = String::from(
            "SELECT id, timestamp, action, object_path, details FROM audit_log WHERE 1=1",
        );
        let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

        if let Some(obj) = filter_object {
            sql.push_str(" AND object_path = ?");
            param_values.push(Box::new(obj.to_string()));
        }
        if let Some(act) = filter_action {
            sql.push_str(" AND action LIKE ?");
            param_values.push(Box::new(format!("%{}%", act)));
        }
        sql.push_str(" ORDER BY id DESC LIMIT ?");
        param_values.push(Box::new(limit as i64));

        let params_ref: Vec<&dyn rusqlite::types::ToSql> =
            param_values.iter().map(|p| p.as_ref()).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params_ref.as_slice(), |row| {
            Ok(AuditEntry {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                action: row.get(2)?,
                object_path: row.get(3)?,
                details: row.get(4)?,
            })
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Count objects in the store.
    pub fn object_count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
        Ok(count as usize)
    }
}

/// An entry from the audit log.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: String,
    pub action: String,
    pub object_path: Option<String>,
    pub details: String,
}

// Internal row types for deserialization from SQLite

struct RawPolicyRow {
    id: String,
    name: String,
    rules: String,
}

impl RawPolicyRow {
    fn into_policy(self) -> anyhow::Result<crate::model::Policy> {
        Ok(crate::model::Policy {
            id: self.id.parse()?,
            name: self.name,
            rules: serde_json::from_str(&self.rules)?,
        })
    }
}

struct RawObjectRow {
    id: String,
    path: String,
    kind: String,
    algorithm: String,
    policy_id: Option<String>,
    handle_blob: Option<Vec<u8>>,
    created_at: String,
    metadata: String,
}

impl RawObjectRow {
    fn into_object(self) -> anyhow::Result<TpmObject> {
        Ok(TpmObject {
            id: self.id.parse()?,
            path: ObjectPath::new(&self.path)?,
            kind: serde_json::from_value(serde_json::Value::String(self.kind))?,
            algorithm: serde_json::from_value(serde_json::Value::String(self.algorithm))?,
            policy_id: self.policy_id.map(|s| s.parse()).transpose()?,
            handle_blob: self.handle_blob,
            created_at: chrono::DateTime::parse_from_rfc3339(&self.created_at)?.to_utc(),
            metadata: serde_json::from_str(&self.metadata)?,
        })
    }
}

struct RawProfileRow {
    name: String,
    default_algorithm: String,
    default_policy: Option<String>,
    is_active: i32,
}

impl RawProfileRow {
    fn into_profile(self) -> anyhow::Result<Profile> {
        Ok(Profile {
            name: self.name,
            default_algorithm: serde_json::from_value(serde_json::Value::String(
                self.default_algorithm,
            ))?,
            default_policy: self.default_policy,
            is_active: self.is_active != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use uuid::Uuid;

    use super::*;
    use crate::model::{Algorithm, ObjectKind};

    fn make_test_object(path: &str) -> TpmObject {
        TpmObject {
            id: Uuid::new_v4(),
            path: ObjectPath::new(path).unwrap(),
            kind: ObjectKind::SigningKey,
            algorithm: Algorithm::EccP256,
            policy_id: None,
            handle_blob: None,
            created_at: Utc::now(),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn insert_and_get_object() {
        let store = Store::open_memory().unwrap();
        let obj = make_test_object("signing/test");
        store.insert_object(&obj).unwrap();

        let path = ObjectPath::new("signing/test").unwrap();
        let fetched = store.get_object(&path).unwrap().unwrap();
        assert_eq!(fetched.id, obj.id);
        assert_eq!(fetched.path, obj.path);
        assert_eq!(fetched.kind, obj.kind);
        assert_eq!(fetched.algorithm, obj.algorithm);
    }

    #[test]
    fn list_objects() {
        let store = Store::open_memory().unwrap();
        store.insert_object(&make_test_object("a/one")).unwrap();
        store.insert_object(&make_test_object("b/two")).unwrap();
        let objects = store.list_objects().unwrap();
        assert_eq!(objects.len(), 2);
        assert_eq!(objects[0].path.as_str(), "a/one");
        assert_eq!(objects[1].path.as_str(), "b/two");
    }

    #[test]
    fn delete_object() {
        let store = Store::open_memory().unwrap();
        store.insert_object(&make_test_object("to-delete")).unwrap();
        let path = ObjectPath::new("to-delete").unwrap();
        assert!(store.delete_object(&path).unwrap());
        assert!(store.get_object(&path).unwrap().is_none());
        assert!(!store.delete_object(&path).unwrap());
    }

    #[test]
    fn profile_lifecycle() {
        let store = Store::open_memory().unwrap();
        let default = Profile::builtin_default();
        store.insert_profile(&default).unwrap();

        let active = store.get_active_profile().unwrap().unwrap();
        assert_eq!(active.name, "default");

        let ci = Profile {
            name: "ci-signer".to_string(),
            default_algorithm: Algorithm::Rsa2048,
            default_policy: None,
            is_active: false,
        };
        store.insert_profile(&ci).unwrap();
        store.set_active_profile("ci-signer").unwrap();

        let active = store.get_active_profile().unwrap().unwrap();
        assert_eq!(active.name, "ci-signer");
    }

    #[test]
    fn audit_log() {
        let store = Store::open_memory().unwrap();
        store
            .log_action("key.create", Some("signing/test"), &serde_json::json!({"alg": "ecc_p256"}))
            .unwrap();
    }

    #[test]
    fn migration_idempotent() {
        let store = Store::open_memory().unwrap();
        store.migrate().unwrap();
        store.migrate().unwrap();
    }
}
