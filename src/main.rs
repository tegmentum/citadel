mod app;
mod commands;
mod plan;

use clap::CommandFactory;

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
        #[cfg(feature = "vtpm")]
        "vtpm" => {
            // Look for the WASM component in standard locations
            let component_path = std::env::var("TPM_VTPM_COMPONENT")
                .map(std::path::PathBuf::from)
                .or_else(|_| {
                    // Check common locations
                    let candidates = [
                        std::path::PathBuf::from("tpm-ephemeral.component.wasm"),
                        dirs_home().join(".local/share/tpm/tpm-ephemeral.component.wasm"),
                    ];
                    candidates
                        .iter()
                        .find(|p| p.exists())
                        .cloned()
                        .ok_or(())
                })
                .map_err(|_| {
                    anyhow::anyhow!(
                        "vTPM WASM component not found.\n\
                         Set TPM_VTPM_COMPONENT to the path of tpm-ephemeral.component.wasm\n\
                         or place it in ~/.local/share/tpm/"
                    )
                })?;
            Ok(Box::new(tpm_core::backend::VtpmBackend::new(&component_path)?))
        }
        #[cfg(not(feature = "vtpm"))]
        "vtpm" => {
            anyhow::bail!(
                "vTPM backend not available: rebuild with --features vtpm\n\
                 This embeds a libtpms-based virtual TPM via wasmtime."
            )
        }
        other => {
            anyhow::bail!(
                "unknown backend: '{}'\navailable backends: mock, device, swtpm, vtpm",
                other
            )
        }
    }
}

fn check_constraints(
    cmd: &Command,
    constraints: &tpm_core::model::ProfileConstraints,
) -> anyhow::Result<()> {
    // Map command to operation name and extract relevant fields
    let (operation, path, algorithm) = match cmd {
        Command::Key(KeyCommand::Create { path, algorithm, .. }) => {
            ("key.create", Some(path.as_str()), Some(algorithm.as_str()))
        }
        Command::Key(KeyCommand::Delete { path }) => ("key.delete", Some(path.as_str()), None),
        Command::Key(KeyCommand::Sign { path, .. }) => ("key.sign", Some(path.as_str()), None),
        Command::Key(KeyCommand::Rotate { path }) => ("key.rotate", Some(path.as_str()), None),
        Command::Secret(SecretCommand::Seal { name, .. }) => {
            ("secret.seal", Some(name.as_str()), None)
        }
        _ => return Ok(()),
    };

    // Check forbidden operations
    constraints.check_operation(operation).map_err(|e| anyhow::anyhow!(e))?;

    // Check path restrictions
    if let Some(p) = path {
        constraints.check_path(p).map_err(|e| anyhow::anyhow!(e))?;
    }

    // Check algorithm restrictions
    if let Some(a) = algorithm {
        constraints.check_algorithm(a).map_err(|e| anyhow::anyhow!(e))?;
    }

    Ok(())
}

fn generate_completions(shell: &str) -> anyhow::Result<()> {
    let mut cmd = Cli::command();
    let shell = match shell.to_lowercase().as_str() {
        "bash" => clap_complete::Shell::Bash,
        "zsh" => clap_complete::Shell::Zsh,
        "fish" => clap_complete::Shell::Fish,
        "elvish" => clap_complete::Shell::Elvish,
        "powershell" | "pwsh" => clap_complete::Shell::PowerShell,
        other => anyhow::bail!(
            "unknown shell: '{}'\navailable: bash, zsh, fish, elvish, powershell",
            other
        ),
    };
    clap_complete::generate(shell, &mut cmd, "tpm", &mut std::io::stdout());
    Ok(())
}

#[allow(dead_code)]
fn dirs_home() -> std::path::PathBuf {
    std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
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

    // --json is shorthand for --format json
    let format = if cli.json {
        tpm_core::output::OutputFormat::Json
    } else {
        cli.format
    };

    match cli.command {
        Some(Command::Completions { shell }) => {
            return generate_completions(&shell);
        }
        Some(cmd) => {
            let store_path = cli.store_path.unwrap_or_else(default_store_path);
            let store = Store::open(&store_path)?;
            let backend: Box<dyn tpm_core::backend::TpmBackend> =
                create_backend(&cli.backend)?;

            // Check profile constraints before dispatching
            if let Some(profile) = store.get_active_profile()? {
                check_constraints(&cmd, &profile.constraints)?;
            }

            match cmd {
                Command::Init { profile } => commands::init::run(
                    &store,
                    backend.as_ref(),
                    &store_path,
                    profile.as_deref(),
                    format,
                ),
                Command::Status => commands::status::run(&store, backend.as_ref(), format),
                Command::Doctor => commands::doctor::run(&store, backend.as_ref(), format),
                Command::Capabilities => {
                    commands::capabilities::run(backend.as_ref(), format)
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
                        format,
                        cli.plan,
                    ),
                    KeyCommand::List => commands::key::list(&store, format),
                    KeyCommand::Show { path } => commands::key::show(&store, &path, format),
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
                        format,
                    ),
                    KeyCommand::Delete { path } => {
                        commands::key::delete(&store, &path, format)
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
                        format,
                    ),
                    KeyCommand::Rotate { path } => {
                        commands::key::rotate(&store, backend.as_ref(), &path, format)
                    }
                },
                Command::Attest(att_cmd) => match att_cmd {
                    AttestCommand::AkCreate { name, algorithm } => {
                        commands::attest::ak_create(
                            &store,
                            backend.as_ref(),
                            &name,
                            &algorithm,
                            format,
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
                        format,
                    ),
                    AttestCommand::Verify { quote, nonce } => commands::attest::verify(
                        backend.as_ref(),
                        &quote,
                        nonce.as_deref(),
                        format,
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
                        format,
                    ),
                    SecretCommand::Unseal { name, output } => commands::secret::unseal(
                        &store,
                        backend.as_ref(),
                        &name,
                        output.as_deref(),
                        format,
                    ),
                    SecretCommand::List => commands::secret::list(&store, format),
                },
                Command::Nv(nv_cmd) => match nv_cmd {
                    NvCommand::Define { name, size } => {
                        commands::nv::define(&store, backend.as_ref(), &name, size, format)
                    }
                    NvCommand::Write { name, input } => {
                        commands::nv::write(&store, backend.as_ref(), &name, &input)
                    }
                    NvCommand::Read { name, output } => {
                        commands::nv::read(&store, backend.as_ref(), &name, output.as_deref(), format)
                    }
                    NvCommand::List => commands::nv::list(&store, format),
                    NvCommand::Delete { name } => {
                        commands::nv::delete(&store, backend.as_ref(), &name)
                    }
                },
                Command::Pcr(pcr_cmd) => match pcr_cmd {
                    PcrCommand::Show { bank, index } => {
                        commands::pcr::show(backend.as_ref(), &bank, &index, format)
                    }
                    PcrCommand::Baseline(bl_cmd) => match bl_cmd {
                        PcrBaselineCommand::Save { name, bank, index } => {
                            commands::pcr::baseline_save(
                                &store, backend.as_ref(), &name, &bank, &index, format,
                            )
                        }
                        PcrBaselineCommand::Diff { name } => {
                            commands::pcr::baseline_diff(&store, backend.as_ref(), &name, format)
                        }
                        PcrBaselineCommand::List => {
                            commands::pcr::baseline_list(&store, format)
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
                        &store, &name, &pcr, &pcr_bank, password, format,
                    ),
                    PolicyCommand::List => commands::policy::list(&store, format),
                    PolicyCommand::Show { name } => {
                        commands::policy::show(&store, &name, format)
                    }
                    PolicyCommand::Explain { name } => {
                        commands::policy::explain(&store, &name, format)
                    }
                    PolicyCommand::Delete { name } => commands::policy::delete(&store, &name),
                    PolicyCommand::Compile { file } => {
                        commands::policy::compile(&store, &file, format)
                    }
                    PolicyCommand::Test { name } => {
                        commands::policy::test_policy(&store, backend.as_ref(), &name, format)
                    }
                },
                Command::Object(obj_cmd) => match obj_cmd {
                    ObjectCommand::List => commands::object::list(&store, format),
                    ObjectCommand::Tree => commands::object::tree(&store, format),
                    ObjectCommand::Dependents { path } => {
                        commands::object::dependents(&store, &path, format)
                    }
                    ObjectCommand::Rename { from, to } => {
                        commands::object::rename(&store, &from, &to, format)
                    }
                    ObjectCommand::Retire { path } => commands::object::retire(&store, &path),
                    ObjectCommand::Activate { path } => {
                        commands::object::activate(&store, &path)
                    }
                },
                Command::Gc(gc_cmd) => match gc_cmd {
                    GcCommand::Plan => commands::object::gc_plan(&store, format),
                    GcCommand::Apply => commands::object::gc_apply(&store, format),
                },
                Command::Recover(rec_cmd) => match rec_cmd {
                    RecoverCommand::List => commands::recover::list(format),
                    RecoverCommand::Show { name } => {
                        commands::recover::show(&name, format)
                    }
                },
                Command::Profile(prof_cmd) => match prof_cmd {
                    ProfileCommand::List => commands::profile::list(&store, format),
                    ProfileCommand::Show { name } => {
                        commands::profile::show(&store, name.as_deref(), format)
                    }
                    ProfileCommand::Set { name } => commands::profile::set(&store, &name),
                },
                Command::Repair(rep_cmd) => match rep_cmd {
                    RepairCommand::Scan => {
                        commands::repair::scan(&store, backend.as_ref(), format)
                    }
                    RepairCommand::Plan => {
                        commands::repair::plan(&store, backend.as_ref(), format)
                    }
                    RepairCommand::Apply => {
                        commands::repair::apply(&store, backend.as_ref(), format)
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
                        format,
                    ),
                },
                Command::Template(tmpl_cmd) => match tmpl_cmd {
                    TemplateCommand::List => commands::template::list(format),
                    TemplateCommand::Show { name } => {
                        commands::template::show(&name, format)
                    }
                },
                Command::Simulator(sim_cmd) => match sim_cmd {
                    SimulatorCommand::Start { state_dir } => {
                        commands::simulator::start(state_dir.as_deref(), format)
                    }
                    SimulatorCommand::Stop { state_dir } => {
                        commands::simulator::stop(state_dir.as_deref())
                    }
                    SimulatorCommand::Status { state_dir } => {
                        commands::simulator::status(state_dir.as_deref(), format)
                    }
                },
                Command::Workspace(ws_cmd) => match ws_cmd {
                    WorkspaceCommand::Info => {
                        commands::workspace::info(&store, &store_path, format)
                    }
                    WorkspaceCommand::Export { output } => {
                        commands::workspace::export(&store, &output, format)
                    }
                    WorkspaceCommand::Import { input } => {
                        commands::workspace::import(&store, &input, format)
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
                Command::Completions { .. } => unreachable!("handled above"),
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
