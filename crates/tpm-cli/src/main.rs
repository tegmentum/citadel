mod app;
mod commands;

use std::io::IsTerminal;

use clap::Parser;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use app::{Cli, Command, KeyCommand, ProfileCommand};

fn default_store_path() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(dir).join("tpm").join("tpm.db")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("tpm")
            .join("tpm.db")
    } else {
        std::path::PathBuf::from("tpm.db")
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    if cli.verbose {
                        "tpm=debug".into()
                    } else {
                        "tpm=warn".into()
                    }
                }),
        )
        .with_writer(std::io::stderr)
        .init();

    match cli.command {
        Some(cmd) => {
            let store_path = cli.store_path.unwrap_or_else(default_store_path);
            let store = Store::open(&store_path)?;
            let backend = MockBackend::new();

            match cmd {
                Command::Status => commands::status::run(&store, &backend, cli.format),
                Command::Doctor => commands::doctor::run(&store, &backend, cli.format),
                Command::Key(key_cmd) => match key_cmd {
                    KeyCommand::Create { path, algorithm } => {
                        commands::key::create(&store, &backend, &path, &algorithm, cli.format)
                    }
                    KeyCommand::List => commands::key::list(&store, cli.format),
                    KeyCommand::Show { path } => {
                        commands::key::show(&store, &path, cli.format)
                    }
                    KeyCommand::Sign {
                        path,
                        input,
                        output,
                    } => commands::key::sign(
                        &store,
                        &backend,
                        &path,
                        &input,
                        output.as_ref(),
                        cli.format,
                    ),
                },
                Command::Profile(prof_cmd) => match prof_cmd {
                    ProfileCommand::List => commands::profile::list(&store, cli.format),
                    ProfileCommand::Show { name } => {
                        commands::profile::show(&store, name.as_deref(), cli.format)
                    }
                    ProfileCommand::Set { name } => commands::profile::set(&store, &name),
                },
            }
        }
        None => {
            if std::io::stdout().is_terminal() {
                tpm_tui::run()
            } else {
                Cli::parse_from(["tpm", "--help"]);
                Ok(())
            }
        }
    }
}
