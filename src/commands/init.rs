use tpm_core::backend::TpmBackend;
use tpm_core::model::Profile;
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

#[derive(Serialize)]
struct InitResult {
    store_path: String,
    backend_type: String,
    profile: String,
    already_initialized: bool,
}

impl TextRenderable for InitResult {
    fn render_text(&self) -> String {
        if self.already_initialized {
            format!(
                "workspace already initialized\n  store:   {}\n  backend: {}\n  profile: {}\n",
                self.store_path, self.backend_type, self.profile
            )
        } else {
            format!(
                "workspace initialized\n  store:   {}\n  backend: {}\n  profile: {}\n",
                self.store_path, self.backend_type, self.profile
            )
        }
    }
}

pub fn run(
    store: &Store,
    backend: &dyn TpmBackend,
    store_path: &std::path::Path,
    profile_name: Option<&str>,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let status = backend.status()?;

    let profiles = store.list_profiles()?;
    let already_initialized = !profiles.is_empty();

    if profiles.is_empty() {
        let profile = match profile_name {
            Some(name) => Profile {
                name: name.to_string(),
                ..Profile::builtin_default()
            },
            None => Profile::builtin_default(),
        };
        store.insert_profile(&profile)?;
        store.log_action(
            "workspace.init",
            None,
            &serde_json::json!({"profile": &profile.name}),
        )?;
    }

    let active = store
        .get_active_profile()?
        .map(|p| p.name)
        .unwrap_or_else(|| "(none)".to_string());

    let result = InitResult {
        store_path: store_path.display().to_string(),
        backend_type: status.backend_type,
        profile: active,
        already_initialized,
    };

    println!("{}", render(&result, format));
    Ok(())
}
