//! Dependency graph CLI command.

use tpm_core::output::format::render_graph;
use tpm_core::output::OutputFormat;
use tpm_core::service::build_graph;
use tpm_core::store::Store;

pub fn show(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let graph = build_graph(store)?;
    println!("{}", render_graph(&graph, format));
    Ok(())
}
