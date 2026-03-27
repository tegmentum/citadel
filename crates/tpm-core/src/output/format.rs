use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Yaml,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            _ => Err(format!("unknown format: '{}' (expected text, json, yaml)", s)),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::Yaml => write!(f, "yaml"),
        }
    }
}

/// Trait for types that have a human-readable text representation.
pub trait TextRenderable {
    fn render_text(&self) -> String;
}

/// Render a value in the requested format.
///
/// For `Text`, uses the `TextRenderable` implementation.
/// For `Json` and `Yaml`, uses `Serialize`.
pub fn render<T: Serialize + TextRenderable>(value: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => value.render_text(),
        OutputFormat::Json => serde_json::to_string_pretty(value).unwrap_or_default(),
        OutputFormat::Yaml => serde_yaml::to_string(value).unwrap_or_default(),
    }
}
