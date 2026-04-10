use serde::Serialize;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OutputFormat {
    #[default]
    Text,
    Json,
    Yaml,
    Dot,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "yaml" => Ok(Self::Yaml),
            "dot" => Ok(Self::Dot),
            _ => Err(format!(
                "unknown format: '{}' (expected text, json, yaml, dot)",
                s
            )),
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Text => write!(f, "text"),
            Self::Json => write!(f, "json"),
            Self::Yaml => write!(f, "yaml"),
            Self::Dot => write!(f, "dot"),
        }
    }
}

/// Trait for types that have a human-readable text representation.
pub trait TextRenderable {
    fn render_text(&self) -> String;
}

/// Trait for types that can be rendered as Graphviz DOT format.
pub trait DotRenderable {
    fn render_dot(&self) -> String;
}

/// Render a value in the requested format.
///
/// For `Text`, uses the `TextRenderable` implementation.
/// For `Json` and `Yaml`, uses `Serialize`.
/// `Dot` is handled by a separate `render_graph` function since not all
/// types implement `DotRenderable`.
pub fn render<T: Serialize + TextRenderable>(value: &T, format: OutputFormat) -> String {
    match format {
        OutputFormat::Text => value.render_text(),
        OutputFormat::Json => serde_json::to_string_pretty(value).unwrap_or_default(),
        OutputFormat::Yaml => serde_yaml::to_string(value).unwrap_or_default(),
        OutputFormat::Dot => value.render_text(), // fall back to text for non-graph types
    }
}

/// Render a value that supports graph output in the requested format.
pub fn render_graph<T: Serialize + TextRenderable + DotRenderable>(
    value: &T,
    format: OutputFormat,
) -> String {
    match format {
        OutputFormat::Text => value.render_text(),
        OutputFormat::Json => serde_json::to_string_pretty(value).unwrap_or_default(),
        OutputFormat::Yaml => serde_yaml::to_string(value).unwrap_or_default(),
        OutputFormat::Dot => value.render_dot(),
    }
}
