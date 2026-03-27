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
