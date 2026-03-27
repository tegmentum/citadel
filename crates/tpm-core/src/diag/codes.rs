/// Stable diagnostic error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagCode {
    /// TPM device not found or unreachable.
    E0001,
    /// TPM device busy or locked.
    E0002,
    /// Invalid object path format.
    E0003,
    /// Named object not found in store.
    E0004,
    /// Store migration failed.
    E0005,
    /// Backend unavailable.
    E0006,
    /// Object already exists.
    E0007,
    /// Policy mismatch.
    E0008,
    /// Authorization failed.
    E0009,
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
            Self::E9001 => "internal invariant violation",
        }
    }
}

impl std::fmt::Display for DiagCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
