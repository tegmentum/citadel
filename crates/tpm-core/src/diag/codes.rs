/// Stable diagnostic error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagCode {
    // Transport / environment (0001-0099)
    /// TPM device not found or unreachable.
    E0001,
    /// TPM device busy or locked.
    E0002,
    /// Permission denied accessing TPM device.
    E0010,
    /// Unsupported backend or TCTI.
    E0011,

    // Object model (0100-0199)
    /// Invalid object path format.
    E0003,
    /// Named object not found in store.
    E0004,
    /// Object already exists.
    E0007,
    /// Object type mismatch.
    E0100,
    /// Parent object missing.
    E0101,
    /// Handle blob missing or corrupt.
    E0102,

    // Store (0200-0299)
    /// Store migration failed.
    E0005,
    /// Store integrity error.
    E0200,

    // Backend (0300-0399)
    /// Backend unavailable.
    E0006,
    /// Backend operation failed.
    E0300,
    /// Unsupported algorithm.
    E0301,

    // Policy / auth (0400-0499)
    /// Policy mismatch.
    E0008,
    /// Authorization failed.
    E0009,
    /// Policy not found.
    E0400,
    /// Unsatisfiable policy.
    E0401,

    // NV (0500-0599)
    /// NV index already defined.
    E0500,
    /// NV index not found.
    E0501,
    /// NV data exceeds index size.
    E0502,
    /// NV index not yet written.
    E0503,

    // Attestation (0600-0699)
    /// PCR mismatch.
    E0600,
    /// Baseline not found.
    E0601,

    // Repair (0700-0799)
    /// Workspace drift detected.
    E0700,

    // Internal (9000-9999)
    /// Internal invariant violation.
    E9001,
}

impl DiagCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::E0001 => "TPM0001",
            Self::E0002 => "TPM0002",
            Self::E0003 => "TPM0003",
            Self::E0004 => "TPM0004",
            Self::E0005 => "TPM0005",
            Self::E0006 => "TPM0006",
            Self::E0007 => "TPM0007",
            Self::E0008 => "TPM0008",
            Self::E0009 => "TPM0009",
            Self::E0010 => "TPM0010",
            Self::E0011 => "TPM0011",
            Self::E0100 => "TPM0100",
            Self::E0101 => "TPM0101",
            Self::E0102 => "TPM0102",
            Self::E0200 => "TPM0200",
            Self::E0300 => "TPM0300",
            Self::E0301 => "TPM0301",
            Self::E0400 => "TPM0400",
            Self::E0401 => "TPM0401",
            Self::E0500 => "TPM0500",
            Self::E0501 => "TPM0501",
            Self::E0502 => "TPM0502",
            Self::E0503 => "TPM0503",
            Self::E0600 => "TPM0600",
            Self::E0601 => "TPM0601",
            Self::E0700 => "TPM0700",
            Self::E9001 => "TPM9001",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            Self::E0001 => "TPM device not found",
            Self::E0002 => "TPM device busy",
            Self::E0003 => "invalid object path",
            Self::E0004 => "object not found",
            Self::E0005 => "store migration failed",
            Self::E0006 => "backend unavailable",
            Self::E0007 => "object already exists",
            Self::E0008 => "policy mismatch",
            Self::E0009 => "authorization failed",
            Self::E0010 => "permission denied",
            Self::E0011 => "unsupported backend",
            Self::E0100 => "object type mismatch",
            Self::E0101 => "parent object missing",
            Self::E0102 => "handle blob missing",
            Self::E0200 => "store integrity error",
            Self::E0300 => "backend operation failed",
            Self::E0301 => "unsupported algorithm",
            Self::E0400 => "policy not found",
            Self::E0401 => "unsatisfiable policy",
            Self::E0500 => "NV index already defined",
            Self::E0501 => "NV index not found",
            Self::E0502 => "NV data exceeds index size",
            Self::E0503 => "NV index not yet written",
            Self::E0600 => "PCR mismatch",
            Self::E0601 => "baseline not found",
            Self::E0700 => "workspace drift detected",
            Self::E9001 => "internal invariant violation",
        }
    }

    /// Whether this error is safe to retry.
    pub fn retryable(&self) -> bool {
        matches!(self, Self::E0002)
    }

    /// Severity classification.
    pub fn default_severity(&self) -> super::Severity {
        match self {
            Self::E9001 => super::Severity::Error,
            Self::E0700 | Self::E0503 => super::Severity::Warning,
            _ => super::Severity::Error,
        }
    }
}

impl std::fmt::Display for DiagCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
