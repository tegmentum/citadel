use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- profile list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let profiles = store.list_profiles()?;

    let listing = ProfileListing {
        profiles: profiles
            .iter()
            .map(|p| ProfileSummary {
                name: p.name.clone(),
                default_algorithm: p.default_algorithm.to_string(),
                active: p.is_active,
            })
            .collect(),
    };

    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct ProfileListing {
    profiles: Vec<ProfileSummary>,
}

#[derive(Serialize)]
struct ProfileSummary {
    name: String,
    default_algorithm: String,
    active: bool,
}

impl TextRenderable for ProfileListing {
    fn render_text(&self) -> String {
        if self.profiles.is_empty() {
            return "No profiles configured.\n".to_string();
        }
        let mut out = String::new();
        for p in &self.profiles {
            let marker = if p.active { " *" } else { "" };
            out.push_str(&format!(
                "  {}{}\n    algorithm: {}\n",
                p.name, marker, p.default_algorithm
            ));
        }
        out
    }
}

// -- profile show --

pub fn show(store: &Store, name: Option<&str>, format: OutputFormat) -> anyhow::Result<()> {
    let profile = match name {
        Some(n) => {
            let all = store.list_profiles()?;
            all.into_iter().find(|p| p.name == n)
        }
        None => store.get_active_profile()?,
    };

    match profile {
        Some(p) => {
            let detail = ProfileDetail {
                name: p.name,
                default_algorithm: p.default_algorithm.to_string(),
                default_policy: p.default_policy,
                active: p.is_active,
            };
            println!("{}", render(&detail, format));
        }
        None => {
            println!("No profile found.");
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct ProfileDetail {
    name: String,
    default_algorithm: String,
    default_policy: Option<String>,
    active: bool,
}

impl TextRenderable for ProfileDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("name:       {}\n", self.name));
        out.push_str(&format!("algorithm:  {}\n", self.default_algorithm));
        out.push_str(&format!(
            "policy:     {}\n",
            self.default_policy.as_deref().unwrap_or("(none)")
        ));
        out.push_str(&format!(
            "active:     {}\n",
            if self.active { "yes" } else { "no" }
        ));
        out
    }
}

// -- profile set --

pub fn set(store: &Store, name: &str) -> anyhow::Result<()> {
    store.set_active_profile(name)?;
    println!("active profile set to: {}", name);
    Ok(())
}
