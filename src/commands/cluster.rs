//! `citadel cluster ...` — operator queries against the Citadel control-plane
//! HTTP API. Plain-HTTP passthrough (no JSON model duplicated here): fetch the
//! endpoint and print the body, so the CLI stays in step with the API.

use anyhow::Context;

use crate::app::ClusterCommand;

pub fn run(cmd: ClusterCommand) -> anyhow::Result<()> {
    match cmd {
        ClusterCommand::Status { endpoint } => get(&endpoint, "/v1/mesh/health"),
        ClusterCommand::Nodes { endpoint } => get(&endpoint, "/v1/nodes"),
        ClusterCommand::Metrics { endpoint } => get(&endpoint, "/metrics"),
    }
}

/// GET `base + path` from the control plane and print the body.
fn get(base: &str, path: &str) -> anyhow::Result<()> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let body = ureq::get(&url)
        .call()
        .with_context(|| format!("querying the control plane at {url}"))?
        .into_string()
        .context("reading the response body")?;
    print!("{body}");
    if !body.ends_with('\n') {
        println!();
    }
    Ok(())
}
