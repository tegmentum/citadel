use super::schema;

/// All migrations in order.
///
/// Secure-log migrations (formerly V6–V10) now live in the
/// `secure-log-sqlite` crate, which manages its own schema versions
/// in `_secure_log_migrations`.
pub const MIGRATIONS: &[(i64, &str)] = &[
    (1, schema::V1),
    (2, schema::V2),
    (3, schema::V3),
    (4, schema::V4),
    (5, schema::V5),
    (6, schema::V6),
];
