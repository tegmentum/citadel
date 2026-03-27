use serde::{Deserialize, Serialize};

use super::DiagCode;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

/// A structured diagnostic report.
#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub code: DiagCode,
    pub severity: Severity,
    pub message: String,
    pub causes: Vec<String>,
    pub suggestions: Vec<String>,
    pub context: Vec<(String, String)>,
}

impl Diagnostic {
    pub fn error(code: DiagCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Error,
            message: message.into(),
            causes: Vec::new(),
            suggestions: Vec::new(),
            context: Vec::new(),
        }
    }

    pub fn warning(code: DiagCode, message: impl Into<String>) -> Self {
        Self {
            code,
            severity: Severity::Warning,
            message: message.into(),
            causes: Vec::new(),
            suggestions: Vec::new(),
            context: Vec::new(),
        }
    }

    pub fn with_cause(mut self, cause: impl Into<String>) -> Self {
        self.causes.push(cause.into());
        self
    }

    pub fn with_suggestion(mut self, suggestion: impl Into<String>) -> Self {
        self.suggestions.push(suggestion.into());
        self
    }

    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.push((key.into(), value.into()));
        self
    }

    /// Render as human-readable text in rustc-style format.
    pub fn render_text(&self) -> String {
        let severity_label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        };

        let mut out = format!("{}[{}]: {}\n", severity_label, self.code, self.message);

        if !self.causes.is_empty() {
            out.push('\n');
            out.push_str("  causes:\n");
            for cause in &self.causes {
                out.push_str(&format!("    - {}\n", cause));
            }
        }

        if !self.context.is_empty() {
            out.push('\n');
            let max_key = self.context.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
            for (key, value) in &self.context {
                out.push_str(&format!("  {:width$}  {}\n", key, value, width = max_key));
            }
        }

        if !self.suggestions.is_empty() {
            out.push('\n');
            out.push_str("  next steps:\n");
            for (i, suggestion) in self.suggestions.iter().enumerate() {
                out.push_str(&format!("    {}. {}\n", i + 1, suggestion));
            }
        }

        out
    }

    /// Render as JSON.
    pub fn render_json(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code.as_str(),
            "severity": self.severity,
            "message": self.message,
            "causes": self.causes,
            "suggestions": self.suggestions,
            "context": self.context.iter()
                .map(|(k, v)| serde_json::json!({ "key": k, "value": v }))
                .collect::<Vec<_>>(),
        })
    }
}
