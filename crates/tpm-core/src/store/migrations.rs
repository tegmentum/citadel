use super::schema;

/// All migrations in order.
pub const MIGRATIONS: &[(i64, &str)] = &[(1, schema::V1), (2, schema::V2), (3, schema::V3)];
