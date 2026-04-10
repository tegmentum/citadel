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

/// SQL for migration version 4: approval requests.
pub const V4: &str = r#"
CREATE TABLE approvals (
    id           TEXT PRIMARY KEY,
    operation    TEXT NOT NULL,
    target       TEXT,
    requester    TEXT NOT NULL,
    reason       TEXT,
    status       TEXT NOT NULL DEFAULT 'pending',
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at  TEXT,
    resolved_by  TEXT
);
"#;

/// SQL for migration version 5: identity composite resources.
pub const V5: &str = r#"
CREATE TABLE identities (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL UNIQUE,
    key_object_id   TEXT NOT NULL REFERENCES objects(id) ON DELETE RESTRICT,
    policy_id       TEXT REFERENCES policies(id),
    usage           TEXT NOT NULL,
    subject         TEXT,
    certificate_pem TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now')),
    rotated_from    TEXT
);
CREATE INDEX idx_identities_key ON identities(key_object_id);
"#;

/// SQL for migration version 6: tamper-evident secure log.
///
/// The `secure_log` table is append-only: writes go through
/// [`SecureLog::append`](crate::secure_log::SecureLog::append) which
/// computes the chain hash from the previous entry. There is no
/// `UPDATE` path. Deletion is possible at the SQL layer (enforcement
/// is via the hash chain itself, not via SQLite constraints), but any
/// deletion is detectable because the chain will no longer verify.
///
/// `seqno` is workspace-unique: a single instance handles multiple
/// streams by partitioning on `stream_id`, but sequence numbers are
/// assigned globally and are monotonic across streams.
pub const V6: &str = r#"
CREATE TABLE secure_log (
    seqno             INTEGER PRIMARY KEY,
    stream_id         TEXT NOT NULL,
    session_id        TEXT NOT NULL,
    boot_id           TEXT NOT NULL,
    timestamp         TEXT NOT NULL,
    event_type        TEXT NOT NULL,
    severity          TEXT NOT NULL,
    producer          TEXT NOT NULL,
    payload_encoding  TEXT NOT NULL,
    payload           BLOB NOT NULL,
    prev_entry_hash   BLOB NOT NULL,
    entry_hash        BLOB NOT NULL
);
CREATE INDEX idx_secure_log_stream  ON secure_log(stream_id, seqno);
CREATE INDEX idx_secure_log_type    ON secure_log(event_type);
"#;

/// SQL for migration version 7: Merkle-sealed segments.
///
/// A segment is a closed, append-only window of log entries for a
/// single stream. Its `merkle_root` is a Merkle tree over the
/// entries' `entry_hash` values in ascending seqno order. Signature
/// columns are populated in Phase 3; Phase 2 writes only the
/// structural fields. `segment_entries` records which entries
/// belong to a segment so inclusion proofs can be reconstructed
/// later without rescanning `secure_log`.
pub const V7: &str = r#"
CREATE TABLE secure_log_segments (
    segment_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id            TEXT NOT NULL,
    seq_start            INTEGER NOT NULL,
    seq_end              INTEGER NOT NULL,
    merkle_root          BLOB NOT NULL,
    last_entry_hash      BLOB NOT NULL,
    prev_checkpoint_hash BLOB NOT NULL,
    closed_at            TEXT NOT NULL,
    signature            BLOB,
    signer_identity      TEXT
);
CREATE INDEX idx_secure_log_segments_stream
    ON secure_log_segments(stream_id, segment_id);

CREATE TABLE secure_log_segment_entries (
    segment_id   INTEGER NOT NULL REFERENCES secure_log_segments(segment_id),
    seqno        INTEGER NOT NULL,
    leaf_index   INTEGER NOT NULL,
    PRIMARY KEY (segment_id, seqno)
);
CREATE INDEX idx_secure_log_segment_entries_seqno
    ON secure_log_segment_entries(seqno);
"#;

/// SQL for migration version 8: persistent witness log.
///
/// A witness service (tpmd's `/v1/audit/witness` endpoint) stores
/// received checkpoint heads in this append-only table. Each row
/// is one accepted submission. The equivocation check is done at
/// insert time by the service: if the same `(stream_id, segment_id)`
/// has been seen before with a different `checkpoint_hash`, the
/// submission is rejected and no row is written.
pub const V8: &str = r#"
CREATE TABLE witness_log (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    stream_id            TEXT NOT NULL,
    segment_id           INTEGER NOT NULL,
    seq_start            INTEGER NOT NULL,
    seq_end              INTEGER NOT NULL,
    checkpoint_hash_hex  TEXT NOT NULL,
    signature_hex        TEXT NOT NULL,
    signer_identity      TEXT NOT NULL,
    received_at          TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX idx_witness_log_stream
    ON witness_log(stream_id, segment_id);
"#;

/// SQL for migration version 9: named secure log streams.
///
/// The `secure_log_streams` table holds per-stream metadata:
/// confidentiality tier, description, and creation time. Entries
/// in `secure_log` reference a stream by string name; rows here
/// declare the stream's policy. A default `"default"` stream is
/// created by the migration so existing deployments keep working
/// without any CLI step.
///
/// Confidentiality tiers:
///   - `public`            : payloads stored in plaintext.
///   - `protected`         : payloads auto-encrypted.
///   - `highly-restricted` : auto-encrypted + producer/severity
///                           hashed rather than recorded literally.
pub const V9: &str = r#"
CREATE TABLE secure_log_streams (
    name        TEXT PRIMARY KEY,
    tier        TEXT NOT NULL DEFAULT 'public',
    description TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO secure_log_streams (name, tier, description)
VALUES ('default', 'public', 'Default stream created automatically at init.');
"#;

/// SQL for migration version 10: soft-deletable streams.
///
/// Streams are never hard-deleted: the row stays so the chain hash
/// links through its entries remain interpretable, and so forensic
/// review after an incident can still see "this stream existed, and
/// was deprecated on X". The `deprecated_at` column is NULL for
/// active streams and a timestamp for deprecated ones. A deprecated
/// stream rejects new appends.
pub const V10: &str = r#"
ALTER TABLE secure_log_streams ADD COLUMN deprecated_at TEXT;
"#;
