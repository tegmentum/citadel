/// SQL for migration version 1.
pub const V1: &str = r#"
CREATE TABLE IF NOT EXISTS migrations (
    version  INTEGER PRIMARY KEY,
    applied  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE objects (
    id          TEXT PRIMARY KEY,
    path        TEXT NOT NULL UNIQUE,
    kind        TEXT NOT NULL,
    algorithm   TEXT NOT NULL,
    policy_id   TEXT,
    handle_blob BLOB,
    created_at  TEXT NOT NULL,
    metadata    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE policies (
    id    TEXT PRIMARY KEY,
    name  TEXT NOT NULL UNIQUE,
    rules TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE profiles (
    name              TEXT PRIMARY KEY,
    default_algorithm TEXT NOT NULL DEFAULT 'ecc_p256',
    default_policy    TEXT,
    is_active         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL DEFAULT (datetime('now')),
    action     TEXT NOT NULL,
    object_path TEXT,
    details    TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX idx_objects_path ON objects(path);
CREATE INDEX idx_audit_timestamp ON audit_log(timestamp);
"#;

/// SQL for migration version 2: PCR baselines and NV index tracking.
/// Also adds correlation_id to audit_log.
pub const V2: &str = r#"
CREATE TABLE pcr_baselines (
    name        TEXT PRIMARY KEY,
    bank        TEXT NOT NULL,
    pcr_values  TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE nv_indices (
    name       TEXT PRIMARY KEY,
    nv_index   INTEGER NOT NULL UNIQUE,
    size       INTEGER NOT NULL,
    data       BLOB,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"#;

/// SQL for migration version 3: object state and correlation IDs.
pub const V3: &str = r#"
ALTER TABLE objects ADD COLUMN state TEXT NOT NULL DEFAULT 'active';
ALTER TABLE objects ADD COLUMN last_used_at TEXT;
ALTER TABLE audit_log ADD COLUMN correlation_id TEXT;
"#;
