use super::{DiagCode, Diagnostic};

/// A TPM error that carries a structured diagnostic.
///
/// This allows commands to return rich, explainable errors that
/// the CLI/TUI can render with full context.
#[derive(Debug)]
pub struct TpmError {
    pub diagnostic: Diagnostic,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl TpmError {
    pub fn new(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostic,
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    /// Render the diagnostic and print it to stderr.
    pub fn emit(&self) {
        eprintln!("{}", self.diagnostic.render_text());
    }
}

impl std::fmt::Display for TpmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.diagnostic.code, self.diagnostic.message)
    }
}

impl std::error::Error for TpmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn std::error::Error + 'static))
    }
}

// -- Convenience constructors for common errors --

impl TpmError {
    pub fn object_not_found(path: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0004, format!("object not found: {}", path))
                .with_cause(format!(
                    "no object with path '{}' exists in the workspace",
                    path
                ))
                .with_suggestion("run `tpm object list` to see all objects")
                .with_suggestion("run `tpm key list` to see available keys".to_string())
                .with_context("path", path),
        )
    }

    pub fn object_already_exists(path: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0007, format!("object already exists: {}", path))
                .with_suggestion(format!("run `tpm key show {}` to inspect it", path))
                .with_suggestion("choose a different name or delete the existing object first")
                .with_context("path", path),
        )
    }

    pub fn policy_not_found(name: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0400, format!("policy not found: {}", name))
                .with_suggestion("run `tpm policy list` to see available policies")
                .with_suggestion(format!(
                    "create it with `tpm policy create {} --pcr 7,11`",
                    name
                ))
                .with_context("policy", name),
        )
    }

    pub fn invalid_path(path: &str, reason: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0003, format!("invalid object path: {}", path))
                .with_cause(reason.to_string())
                .with_suggestion("paths must be alphanumeric segments separated by '/'")
                .with_suggestion("example: signing/release, secret/db/prod")
                .with_context("path", path),
        )
    }

    pub fn type_mismatch(path: &str, expected: &str, actual: &str) -> Self {
        Self::new(
            Diagnostic::error(
                DiagCode::E0100,
                format!("object '{}' is a {}, not a {}", path, actual, expected),
            )
            .with_cause(format!(
                "the operation requires a {} but '{}' is a {}",
                expected, path, actual
            ))
            .with_context("path", path)
            .with_context("expected", expected)
            .with_context("actual", actual),
        )
    }

    pub fn nv_not_found(name: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0501, format!("NV index not found: {}", name))
                .with_suggestion("run `tpm nv list` to see defined indices")
                .with_suggestion(format!(
                    "define it with `tpm nv define {} --size <bytes>`",
                    name
                ))
                .with_context("name", name),
        )
    }

    pub fn baseline_not_found(name: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0601, format!("baseline not found: {}", name))
                .with_suggestion("run `tpm pcr baseline list` to see saved baselines")
                .with_suggestion(format!(
                    "save one with `tpm pcr baseline save {} --index 0,7,11`",
                    name
                ))
                .with_context("baseline", name),
        )
    }

    pub fn identity_not_found(name: &str) -> Self {
        Self::new(
            Diagnostic::error(DiagCode::E0900, format!("identity not found: {}", name))
                .with_suggestion("run `tpm identity list` to see available identities")
                .with_suggestion(format!(
                    "create it with `tpm identity init {} --usage generic`",
                    name
                ))
                .with_context("identity", name),
        )
    }

    pub fn identity_missing_key(name: &str, key_id: &str) -> Self {
        Self::new(
            Diagnostic::error(
                DiagCode::E0901,
                format!("identity '{}' references missing key", name),
            )
            .with_cause(format!(
                "the underlying key object (id={}) is no longer in the store",
                key_id
            ))
            .with_suggestion("run `tpm repair scan` to detect orphan identities")
            .with_suggestion(format!(
                "rotate the identity with `tpm identity rotate {}` to regenerate its key",
                name
            ))
            .with_context("identity", name)
            .with_context("key_id", key_id),
        )
    }

    pub fn backend_failed(operation: &str, cause: &str) -> Self {
        Self::new(
            Diagnostic::error(
                DiagCode::E0300,
                format!("backend operation failed: {}", operation),
            )
            .with_cause(cause.to_string())
            .with_suggestion("run `tpm doctor` to check backend health")
            .with_suggestion("run `tpm status` to verify backend connectivity"),
        )
    }
}
