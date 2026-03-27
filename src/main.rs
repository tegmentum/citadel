mod app;
mod commands;

use std::io::IsTerminal;

use clap::Parser;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use app::{
    Cli, Command, DaemonCommand, KeyCommand, NvCommand, ObjectCommand, PcrBaselineCommand,
    PcrCommand, PolicyCommand, ProfileCommand, RepairCommand, SecretCommand,
};

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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
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
                Command::Init { profile } => commands::init::run(
                    &store,
                    &backend,
                    &store_path,
                    profile.as_deref(),
                    cli.format,
                ),
                Command::Status => commands::status::run(&store, &backend, cli.format),
                Command::Doctor => commands::doctor::run(&store, &backend, cli.format),
                Command::Key(key_cmd) => match key_cmd {
                    KeyCommand::Create {
                        path,
                        algorithm,
                        policy,
                    } => commands::key::create(
                        &store,
                        &backend,
                        &path,
                        &algorithm,
                        policy.as_deref(),
                        cli.format,
                    ),
                    KeyCommand::List => commands::key::list(&store, cli.format),
                    KeyCommand::Show { path } => commands::key::show(&store, &path, cli.format),
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
                    KeyCommand::Delete { path } => {
                        commands::key::delete(&store, &path, cli.format)
                    }
                    KeyCommand::ExportPub { path, key_format } => {
                        commands::key::export_pub(&store, &path, &key_format, cli.format)
                    }
                },
                Command::Secret(sec_cmd) => match sec_cmd {
                    SecretCommand::Seal {
                        name,
                        input,
                        policy,
                    } => commands::secret::seal(
                        &store,
                        &backend,
                        &name,
                        &input,
                        policy.as_deref(),
                        cli.format,
                    ),
                    SecretCommand::Unseal { name, output } => commands::secret::unseal(
                        &store,
                        &backend,
                        &name,
                        output.as_deref(),
                        cli.format,
                    ),
                    SecretCommand::List => commands::secret::list(&store, cli.format),
                },
                Command::Nv(nv_cmd) => match nv_cmd {
                    NvCommand::Define { name, size } => {
                        commands::nv::define(&store, &backend, &name, size, cli.format)
                    }
                    NvCommand::Write { name, input } => {
                        commands::nv::write(&store, &backend, &name, &input)
                    }
                    NvCommand::Read { name, output } => {
                        commands::nv::read(&store, &backend, &name, output.as_deref(), cli.format)
                    }
                    NvCommand::List => commands::nv::list(&store, cli.format),
                    NvCommand::Delete { name } => {
                        commands::nv::delete(&store, &backend, &name)
                    }
                },
                Command::Pcr(pcr_cmd) => match pcr_cmd {
                    PcrCommand::Show { bank, index } => {
                        commands::pcr::show(&backend, &bank, &index, cli.format)
                    }
                    PcrCommand::Baseline(bl_cmd) => match bl_cmd {
                        PcrBaselineCommand::Save { name, bank, index } => {
                            commands::pcr::baseline_save(
                                &store, &backend, &name, &bank, &index, cli.format,
                            )
                        }
                        PcrBaselineCommand::Diff { name } => {
                            commands::pcr::baseline_diff(&store, &backend, &name, cli.format)
                        }
                        PcrBaselineCommand::List => {
                            commands::pcr::baseline_list(&store, cli.format)
                        }
                    },
                },
                Command::Policy(pol_cmd) => match pol_cmd {
                    PolicyCommand::Create {
                        name,
                        pcr,
                        pcr_bank,
                        password,
                    } => commands::policy::create(
                        &store, &name, &pcr, &pcr_bank, password, cli.format,
                    ),
                    PolicyCommand::List => commands::policy::list(&store, cli.format),
                    PolicyCommand::Show { name } => {
                        commands::policy::show(&store, &name, cli.format)
                    }
                    PolicyCommand::Explain { name } => {
                        commands::policy::explain(&store, &name, cli.format)
                    }
                    PolicyCommand::Delete { name } => commands::policy::delete(&store, &name),
                },
                Command::Object(obj_cmd) => match obj_cmd {
                    ObjectCommand::List => commands::object::list(&store, cli.format),
                    ObjectCommand::Tree => commands::object::tree(&store, cli.format),
                },
                Command::Profile(prof_cmd) => match prof_cmd {
                    ProfileCommand::List => commands::profile::list(&store, cli.format),
                    ProfileCommand::Show { name } => {
                        commands::profile::show(&store, name.as_deref(), cli.format)
                    }
                    ProfileCommand::Set { name } => commands::profile::set(&store, &name),
                },
                Command::Repair(rep_cmd) => match rep_cmd {
                    RepairCommand::Scan => {
                        commands::repair::scan(&store, &backend, cli.format)
                    }
                    RepairCommand::Plan => {
                        commands::repair::plan(&store, &backend, cli.format)
                    }
                    RepairCommand::Apply => {
                        commands::repair::apply(&store, &backend, cli.format)
                    }
                },
                Command::Explain { concept } => commands::explain::run(&concept),
                Command::Daemon(daemon_cmd) => match daemon_cmd {
                    DaemonCommand::Run { listen } => {
                        eprintln!("daemon: starting on {} (not yet implemented)", listen);
                        std::process::exit(1);
                    }
                    DaemonCommand::Status => {
                        eprintln!("daemon: status check (not yet implemented)");
                        std::process::exit(1);
                    }
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
