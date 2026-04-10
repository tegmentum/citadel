use super::schema;

/// All migrations in order.
pub const MIGRATIONS: &[(i64, &str)] = &[
    (1, schema::V1),
    (2, schema::V2),
    (3, schema::V3),
    (4, schema::V4),
    (5, schema::V5),
    (6, schema::V6),
    (7, schema::V7),
    (8, schema::V8),
    (9, schema::V9),
    (10, schema::V10),
];
