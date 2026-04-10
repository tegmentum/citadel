pub mod dsl;
pub mod manifest;

pub use dsl::{PolicyDefinition, PolicyRequirement};
pub use manifest::{
    try_parse_manifest, Manifest, ManifestIdentity, ManifestKey, ManifestMetadata, ManifestProfile,
    ManifestSecret, ManifestSpec,
};

/// Result of parsing a YAML document that may be either a single
/// PolicyDefinition or a full Manifest.
pub enum ParsedPolicyDocument {
    Single(PolicyDefinition),
    Manifest(Manifest),
}

/// Autodetect and parse a YAML string as either a Manifest or a PolicyDefinition.
///
/// Try Manifest first (looks for `apiVersion`), fall back to PolicyDefinition.
pub fn from_any_yaml(text: &str) -> Result<ParsedPolicyDocument, serde_yaml::Error> {
    if let Some(m) = try_parse_manifest(text) {
        return Ok(ParsedPolicyDocument::Manifest(m));
    }
    Ok(ParsedPolicyDocument::Single(
        PolicyDefinition::from_yaml(text)?,
    ))
}
