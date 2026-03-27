mod app;
mod commands;
mod plan;

use std::io::IsTerminal;

use clap::Parser;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use app::{
    AttestCommand, Cli, Command, DaemonCommand, GcCommand, KeyCommand, LogCommand, NvCommand,
    ObjectCommand, PcrBaselineCommand, PcrCommand, PolicyCommand, ProfileCommand, RecoverCommand,
    RepairCommand, SecretCommand, SimulatorCommand, TemplateCommand, WorkspaceCommand,
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

fn create_backend(name: &str) -> anyhow::Result<Box<dyn tpm_core::backend::TpmBackend>> {
    match name {
        "mock" => Ok(Box::new(MockBackend::new())),
        #[cfg(feature = "tpm-hw")]
        "device" => Ok(Box::new(tpm_core::backend::HardwareBackend::new_device()?)),
        #[cfg(not(feature = "tpm-hw"))]
        "device" => {
            anyhow::bail!(
                "hardware TPM backend not available: rebuild with --features tpm-hw\n\
                 This requires the tpm2-tss development libraries to be installed."
            )
        }
        // swtpm uses the hardware backend with socket TCTI when tpm-hw is enabled
        // Without tpm-hw, it uses mock backend with swtpm status check
        #[cfg(feature = "tpm-hw")]
        "swtpm" => {
            let mgr = tpm_core::backend::SwtpmManager::new(None);
            if !mgr.is_running() {
                anyhow::bail!(
                    "swtpm is not running.\n\
                     Start it with: tpm simulator start"
                );
            }
            let tcti = tss_esapi::tcti_ldr::TctiNameConf::Swtpm(
                tss_esapi::tcti_ldr::SwtpmConfig::default(),
            );
            Ok(Box::new(tpm_core::backend::HardwareBackend::new_with_tcti(tcti)))
        }
        #[cfg(not(feature = "tpm-hw"))]
        "swtpm" => {
            // Without tpm-hw, we can still check swtpm status but use mock backend
            let mgr = tpm_core::backend::SwtpmManager::new(None);
            if !mgr.is_running() {
                anyhow::bail!(
                    "swtpm is not running.\n\
                     Start it with: tpm simulator start\n\
                     Note: for full swtpm integration, rebuild with --features tpm-hw"
                );
            }
            eprintln!(
                "note: using mock backend (for real swtpm operations, rebuild with --features tpm-hw)"
            );
            Ok(Box::new(MockBackend::new()))
        }
        other => {
            anyhow::bail!(
                "unknown backend: '{}'\navailable backends: mock, device, swtpm",
                other
            )
        }
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
            let backend: Box<dyn tpm_core::backend::TpmBackend> =
                create_backend(&cli.backend)?;

            match cmd {
                Command::Init { profile } => commands::init::run(
                    &store,
                    backend.as_ref(),
                    &store_path,
                    profile.as_deref(),
                    cli.format,
                ),
                Command::Status => commands::status::run(&store, backend.as_ref(), cli.format),
                Command::Doctor => commands::doctor::run(&store, backend.as_ref(), cli.format),
                Command::Capabilities => {
                    commands::capabilities::run(backend.as_ref(), cli.format)
                }
                Command::Debug { output } => commands::capabilities::debug_bundle(
                    backend.as_ref(),
                    &store,
                    &store_path,
                    &output,
                ),
                Command::Key(key_cmd) => match key_cmd {
                    KeyCommand::Create {
                        path,
                        algorithm,
                        policy,
                    } => commands::key::create(
                        &store,
                        backend.as_ref(),
                        &path,
                        &algorithm,
                        policy.as_deref(),
                        cli.format,
                        cli.plan,
                    ),
                    KeyCommand::List => commands::key::list(&store, cli.format),
                    KeyCommand::Show { path } => commands::key::show(&store, &path, cli.format),
                    KeyCommand::Sign {
                        path,
                        input,
                        output,
                    } => commands::key::sign(
                        &store,
                        backend.as_ref(),
                        &path,
                        &input,
                        output.as_ref(),
                        cli.format,
                    ),
                    KeyCommand::Delete { path } => {
                        commands::key::delete(&store, &path, cli.format)
                    }
                    KeyCommand::ExportPub {
                        path,
                        key_format,
                        target,
                    } => commands::key::export_pub(
                        &store,
                        &path,
                        &key_format,
                        target.as_deref(),
                        cli.format,
                    ),
                    KeyCommand::Rotate { path } => {
                        commands::key::rotate(&store, backend.as_ref(), &path, cli.format)
                    }
                },
                Command::Attest(att_cmd) => match att_cmd {
                    AttestCommand::AkCreate { name, algorithm } => {
                        commands::attest::ak_create(
                            &store,
                            backend.as_ref(),
                            &name,
                            &algorithm,
                            cli.format,
                        )
                    }
                    AttestCommand::Quote {
                        ak,
                        bank,
                        pcr,
                        nonce,
                        output,
                    } => commands::attest::quote(
                        &store,
                        backend.as_ref(),
                        &ak,
                        &bank,
                        &pcr,
                        nonce.as_deref(),
                        output.as_deref(),
                        cli.format,
                    ),
                    AttestCommand::Verify { quote, nonce } => commands::attest::verify(
                        backend.as_ref(),
                        &quote,
                        nonce.as_deref(),
                        cli.format,
                    ),
                },
                Command::Secret(sec_cmd) => match sec_cmd {
                    SecretCommand::Seal {
                        name,
                        input,
                        policy,
                    } => commands::secret::seal(
                        &store,
                        backend.as_ref(),
                        &name,
                        &input,
                        policy.as_deref(),
                        cli.format,
                    ),
                    SecretCommand::Unseal { name, output } => commands::secret::unseal(
                        &store,
                        backend.as_ref(),
                        &name,
                        output.as_deref(),
                        cli.format,
                    ),
                    SecretCommand::List => commands::secret::list(&store, cli.format),
                },
                Command::Nv(nv_cmd) => match nv_cmd {
                    NvCommand::Define { name, size } => {
                        commands::nv::define(&store, backend.as_ref(), &name, size, cli.format)
                    }
                    NvCommand::Write { name, input } => {
                        commands::nv::write(&store, backend.as_ref(), &name, &input)
                    }
                    NvCommand::Read { name, output } => {
                        commands::nv::read(&store, backend.as_ref(), &name, output.as_deref(), cli.format)
                    }
                    NvCommand::List => commands::nv::list(&store, cli.format),
                    NvCommand::Delete { name } => {
                        commands::nv::delete(&store, backend.as_ref(), &name)
                    }
                },
                Command::Pcr(pcr_cmd) => match pcr_cmd {
                    PcrCommand::Show { bank, index } => {
                        commands::pcr::show(backend.as_ref(), &bank, &index, cli.format)
                    }
                    PcrCommand::Baseline(bl_cmd) => match bl_cmd {
                        PcrBaselineCommand::Save { name, bank, index } => {
                            commands::pcr::baseline_save(
                                &store, backend.as_ref(), &name, &bank, &index, cli.format,
                            )
                        }
                        PcrBaselineCommand::Diff { name } => {
                            commands::pcr::baseline_diff(&store, backend.as_ref(), &name, cli.format)
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
                    PolicyCommand::Compile { file } => {
                        commands::policy::compile(&store, &file, cli.format)
                    }
                    PolicyCommand::Test { name } => {
                        commands::policy::test_policy(&store, backend.as_ref(), &name, cli.format)
                    }
                },
                Command::Object(obj_cmd) => match obj_cmd {
                    ObjectCommand::List => commands::object::list(&store, cli.format),
                    ObjectCommand::Tree => commands::object::tree(&store, cli.format),
                    ObjectCommand::Dependents { path } => {
                        commands::object::dependents(&store, &path, cli.format)
                    }
                    ObjectCommand::Rename { from, to } => {
                        commands::object::rename(&store, &from, &to, cli.format)
                    }
                    ObjectCommand::Retire { path } => commands::object::retire(&store, &path),
                    ObjectCommand::Activate { path } => {
                        commands::object::activate(&store, &path)
                    }
                },
                Command::Gc(gc_cmd) => match gc_cmd {
                    GcCommand::Plan => commands::object::gc_plan(&store, cli.format),
                    GcCommand::Apply => commands::object::gc_apply(&store, cli.format),
                },
                Command::Recover(rec_cmd) => match rec_cmd {
                    RecoverCommand::List => commands::recover::list(cli.format),
                    RecoverCommand::Show { name } => {
                        commands::recover::show(&name, cli.format)
                    }
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
                        commands::repair::scan(&store, backend.as_ref(), cli.format)
                    }
                    RepairCommand::Plan => {
                        commands::repair::plan(&store, backend.as_ref(), cli.format)
                    }
                    RepairCommand::Apply => {
                        commands::repair::apply(&store, backend.as_ref(), cli.format)
                    }
                },
                Command::Log(log_cmd) => match log_cmd {
                    LogCommand::Show {
                        object,
                        action,
                        limit,
                    } => commands::log::list(
                        &store,
                        object.as_deref(),
                        action.as_deref(),
                        limit,
                        cli.format,
                    ),
                },
                Command::Template(tmpl_cmd) => match tmpl_cmd {
                    TemplateCommand::List => commands::template::list(cli.format),
                    TemplateCommand::Show { name } => {
                        commands::template::show(&name, cli.format)
                    }
                },
                Command::Simulator(sim_cmd) => match sim_cmd {
                    SimulatorCommand::Start { state_dir } => {
                        commands::simulator::start(state_dir.as_deref(), cli.format)
                    }
                    SimulatorCommand::Stop { state_dir } => {
                        commands::simulator::stop(state_dir.as_deref())
                    }
                    SimulatorCommand::Status { state_dir } => {
                        commands::simulator::status(state_dir.as_deref(), cli.format)
                    }
                },
                Command::Workspace(ws_cmd) => match ws_cmd {
                    WorkspaceCommand::Info => {
                        commands::workspace::info(&store, &store_path, cli.format)
                    }
                    WorkspaceCommand::Export { output } => {
                        commands::workspace::export(&store, &output, cli.format)
                    }
                    WorkspaceCommand::Import { input } => {
                        commands::workspace::import(&store, &input, cli.format)
                    }
                },
                Command::Explain { concept } => commands::explain::run(&concept),
                Command::Daemon(daemon_cmd) => match daemon_cmd {
                    DaemonCommand::Run { listen } => {
                        println!("starting tpmd on {}...", listen);
                        println!("use the tpmd binary directly for the daemon process:");
                        println!("  TPMD_LISTEN={} tpmd", listen);
                        Ok(())
                    }
                    DaemonCommand::Status => {
                        // Try to connect to daemon
                        let addr =
                            std::env::var("TPMD_LISTEN").unwrap_or_else(|_| "127.0.0.1:7701".into());
                        match std::net::TcpStream::connect_timeout(
                            &addr.parse().unwrap_or_else(|_| {
                                std::net::SocketAddr::from(([127, 0, 0, 1], 7701))
                            }),
                            std::time::Duration::from_secs(2),
                        ) {
                            Ok(_) => println!("daemon reachable at {}", addr),
                            Err(_) => println!("daemon not reachable at {}", addr),
                        }
                        Ok(())
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
