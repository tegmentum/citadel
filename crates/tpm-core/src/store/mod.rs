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
}

// Internal row types for deserialization from SQLite

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
