//! SQLite-backed store implementation.
//!
//! Only available when the `sqlite` feature is enabled (default on native targets).

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use crate::model::{ObjectPath, Policy, Profile, TpmObject};

use super::migrations;
use super::traits::{AuditEntry, StoreBackend};

/// SQLite-backed store.
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
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

    /// Open an in-memory SQLite store (for tests).
    pub fn open_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA foreign_keys=ON;")?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> anyhow::Result<()> {
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
}

impl StoreBackend for SqliteStore {
    fn insert_object(&self, obj: &TpmObject) -> anyhow::Result<()> {
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

    fn get_object(&self, path: &ObjectPath) -> anyhow::Result<Option<TpmObject>> {
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

    fn list_objects(&self) -> anyhow::Result<Vec<TpmObject>> {
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

    fn delete_object(&self, path: &ObjectPath) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM objects WHERE path = ?1", params![path.as_str()])?;
        Ok(count > 0)
    }

    fn rename_object(&self, old_path: &ObjectPath, new_path: &ObjectPath) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE objects SET path = ?2 WHERE path = ?1",
            params![old_path.as_str(), new_path.as_str()],
        )?;
        if count == 0 {
            anyhow::bail!("object not found: {}", old_path);
        }
        Ok(())
    }

    fn set_object_state(&self, path: &ObjectPath, state: &str) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE objects SET state = ?2 WHERE path = ?1",
            params![path.as_str(), state],
        )?;
        if count == 0 {
            anyhow::bail!("object not found: {}", path);
        }
        Ok(())
    }

    fn touch_object(&self, path: &ObjectPath) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE objects SET last_used_at = datetime('now') WHERE path = ?1",
            params![path.as_str()],
        )?;
        Ok(())
    }

    fn object_count(&self) -> anyhow::Result<usize> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    fn insert_profile(&self, profile: &Profile) -> anyhow::Result<()> {
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

    fn get_active_profile(&self) -> anyhow::Result<Option<Profile>> {
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

    fn list_profiles(&self) -> anyhow::Result<Vec<Profile>> {
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

    fn set_active_profile(&self, name: &str) -> anyhow::Result<()> {
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

    fn insert_policy(&self, policy: &Policy) -> anyhow::Result<()> {
        let rules_json = serde_json::to_string(&policy.rules)?;
        self.conn.execute(
            "INSERT INTO policies (id, name, rules) VALUES (?1, ?2, ?3)",
            params![policy.id.to_string(), policy.name, rules_json],
        )?;
        Ok(())
    }

    fn get_policy(&self, name: &str) -> anyhow::Result<Option<Policy>> {
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

    fn get_policy_by_id(&self, id: &uuid::Uuid) -> anyhow::Result<Option<Policy>> {
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

    fn list_policies(&self) -> anyhow::Result<Vec<Policy>> {
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

    fn delete_policy(&self, name: &str) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM policies WHERE name = ?1", params![name])?;
        Ok(count > 0)
    }

    fn insert_nv_index(&self, name: &str, nv_index: u32, size: usize) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO nv_indices (name, nv_index, size) VALUES (?1, ?2, ?3)",
            params![name, nv_index, size as i64],
        )?;
        Ok(())
    }

    fn get_nv_index(&self, name: &str) -> anyhow::Result<Option<(u32, usize)>> {
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

    fn list_nv_indices(&self) -> anyhow::Result<Vec<(String, u32, usize)>> {
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

    fn nv_write_data(&self, name: &str, data: &[u8]) -> anyhow::Result<()> {
        let count = self.conn.execute(
            "UPDATE nv_indices SET data = ?2 WHERE name = ?1",
            params![name, data],
        )?;
        if count == 0 {
            anyhow::bail!("NV index not found: {}", name);
        }
        Ok(())
    }

    fn nv_read_data(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        Ok(self
            .conn
            .query_row(
                "SELECT data FROM nv_indices WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )
            .optional()?)
    }

    fn delete_nv_index(&self, name: &str) -> anyhow::Result<bool> {
        let count = self
            .conn
            .execute("DELETE FROM nv_indices WHERE name = ?1", params![name])?;
        Ok(count > 0)
    }

    fn save_pcr_baseline(
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

    fn get_pcr_baseline(&self, name: &str) -> anyhow::Result<Option<(String, serde_json::Value)>> {
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

    fn list_pcr_baselines(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT name FROM pcr_baselines ORDER BY name")?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    fn log_action(
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

    fn log_action_with_correlation(
        &self,
        action: &str,
        object_path: Option<&str>,
        details: &serde_json::Value,
        correlation_id: &str,
    ) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO audit_log (action, object_path, details, correlation_id) VALUES (?1, ?2, ?3, ?4)",
            params![action, object_path, details.to_string(), correlation_id],
        )?;
        Ok(())
    }

    fn list_audit_log(
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
}

// Internal row types for SQLite deserialization

struct RawPolicyRow {
    id: String,
    name: String,
    rules: String,
}

impl RawPolicyRow {
    fn into_policy(self) -> anyhow::Result<Policy> {
        Ok(Policy {
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
