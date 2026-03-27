use super::schema;

/// All migrations in order.
pub const MIGRATIONS: &[(i64, &str)] = &[(1, schema::V1)];
