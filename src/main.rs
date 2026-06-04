mod app;
mod commands;
mod plan;
#[cfg(feature = "vtpm")]
mod vtpm_bridge;

use clap::CommandFactory;

use std::io::IsTerminal;

use clap::Parser;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use app::{
    AttestCommand, AuditChainCommand, AuditCommand, AuditKeyCommand, AuditSegmentsCommand,
    AuditStreamsCommand, AuditWitnessCommand, Cli, Command, DaemonCommand, GcCommand,
    IdentityCommand, KeyCommand,
    LogCommand, MeasureCommand, NvCommand, ObjectCommand, PcrBaselineCommand, PcrCommand,
    PolicyCommand,
    ProfileCommand, RecoverCommand, RepairCommand, SecretCommand, TemplateCommand,
    VtpmCommand, VtpmCredentialCommand, WorkspaceCommand,
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
        "auto" => auto_detect_backend(),
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
        #[cfg(feature = "tpm-hw")]
        "swtpm" => {
            // Honor TPM_SWTPM_TCTI for full flexibility (e.g.
            //   swtpm:host=localhost,port=2321
            //   swtpm:path=/tmp/swtpm.sock
            // ). Otherwise use the swtpm default (TCP on localhost:2321).
            let backend = if let Ok(tcti) = std::env::var("TPM_SWTPM_TCTI") {
                tpm_core::backend::HardwareBackend::new_from_tcti_str(&tcti)?
            } else if let Ok(path) = std::env::var("TPM_SWTPM_SOCKET") {
                tpm_core::backend::HardwareBackend::new_swtpm_unix(&path)
            } else {
                let host = std::env::var("TPM_SWTPM_HOST")
                    .unwrap_or_else(|_| "localhost".to_string());
                let port = std::env::var("TPM_SWTPM_PORT")
                    .ok()
                    .and_then(|p| p.parse::<u16>().ok())
                    .unwrap_or(2321);
                tpm_core::backend::HardwareBackend::new_swtpm_tcp(&host, port)?
            };
            Ok(Box::new(backend))
        }
        #[cfg(not(feature = "tpm-hw"))]
        "swtpm" => {
            anyhow::bail!(
                "swtpm backend not available: rebuild with --features tpm-hw\n\
                 swtpm support uses the same tss-esapi client as the hardware backend.\n\
                 Set TPM_SWTPM_TCTI, TPM_SWTPM_SOCKET, or TPM_SWTPM_HOST/PORT to configure."
            )
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
            Ok(Box::new(vtpm_bridge::VtpmBackend::new(&component_path)?))
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
                "unknown backend: '{}'\navailable backends: auto, mock, device, swtpm, vtpm",
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

fn auto_detect_backend() -> anyhow::Result<Box<dyn tpm_core::backend::TpmBackend>> {
    // 1. Try real hardware TPM
    #[cfg(feature = "tpm-hw")]
    {
        if std::path::Path::new("/dev/tpmrm0").exists() {
            match tpm_core::backend::HardwareBackend::new_device() {
                Ok(backend) => {
                    if let Ok(status) = backend.status() {
                        if status.available {
                            tracing::info!("auto-detected hardware TPM at /dev/tpmrm0");
                            return Ok(Box::new(backend));
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    // 2. Try swtpm (explicit opt-in via env vars, or default TCP socket)
    #[cfg(feature = "tpm-hw")]
    {
        use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
        use std::time::Duration;

        // Explicit config: always honor if set.
        let explicit = std::env::var("TPM_SWTPM_TCTI")
            .ok()
            .or_else(|| std::env::var("TPM_SWTPM_SOCKET").ok())
            .or_else(|| std::env::var("TPM_SWTPM_HOST").ok())
            .or_else(|| std::env::var("TPM_SWTPM_PORT").ok());

        let should_probe = explicit.is_some() || {
            // Otherwise probe localhost:2321 with a short timeout so we
            // don't slow down the default (no-swtpm) path noticeably.
            "localhost:2321"
                .to_socket_addrs()
                .ok()
                .and_then(|mut it| it.next())
                .and_then(|addr: SocketAddr| {
                    TcpStream::connect_timeout(&addr, Duration::from_millis(75)).ok()
                })
                .is_some()
        };

        if should_probe {
            match create_backend("swtpm") {
                Ok(backend) => {
                    if let Ok(status) = backend.status() {
                        if status.available {
                            tracing::info!("auto-detected swtpm");
                            return Ok(backend);
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }

    // 3. Try vTPM (libtpms WASM component)
    #[cfg(feature = "vtpm")]
    {
        let candidates = [
            std::env::var("TPM_VTPM_COMPONENT")
                .map(std::path::PathBuf::from)
                .ok(),
            Some(dirs_home().join(".local/share/tpm/tpm-ephemeral.component.wasm")),
            Some(std::path::PathBuf::from("tpm-ephemeral.component.wasm")),
        ];
        for candidate in candidates.iter().flatten() {
            if candidate.exists() {
                match vtpm_bridge::VtpmBackend::new(candidate) {
                    Ok(backend) => {
                        tracing::info!("auto-detected vTPM at {}", candidate.display());
                        return Ok(Box::new(backend));
                    }
                    Err(_) => {}
                }
            }
        }
    }

    // 3. Fall back to mock
    tracing::info!("no TPM detected, using mock backend");
    Ok(Box::new(MockBackend::new()))
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
                Command::Apply { file, force } => commands::apply::apply_cmd(
                    &store,
                    backend.as_ref(),
                    &file,
                    force,
                    cli.plan,
                    format,
                ),
                Command::Diff { file } => {
                    commands::apply::diff_cmd(&store, &file, format)
                }
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
                    PcrCommand::Extend {
                        bank,
                        index,
                        input,
                        value,
                    } => commands::pcr::extend(
                        backend.as_ref(),
                        &bank,
                        index,
                        input.as_deref(),
                        value.as_deref(),
                        format,
                    ),
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
                    PolicyCommand::Fragility { name } => {
                        commands::policy::fragility(&store, &name, format)
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
                Command::Workspace(ws_cmd) => match ws_cmd {
                    WorkspaceCommand::Info => {
                        commands::workspace::info(&store, &store_path, format)
                    }
                    WorkspaceCommand::Export { output } => {
                        commands::workspace::export(&store, &output, format)
                    }
                    WorkspaceCommand::Import { input } => {
                        commands::workspace::import(&store, backend.as_ref(), &input, format)
                    }
                },
                Command::Explain { concept } => commands::explain::run(&concept),
                Command::Audit(audit_cmd) => match audit_cmd {
                    AuditCommand::Append {
                        event,
                        severity,
                        producer,
                        payload_file,
                        payload,
                        stream,
                        encrypt,
                    } => commands::audit::append(
                        &store_path,
                        backend.as_ref(),
                        &stream,
                        &event,
                        &severity,
                        &producer,
                        payload.as_deref(),
                        payload_file.as_deref(),
                        encrypt,
                        format,
                    ),
                    AuditCommand::Show { seqno, decrypt } => commands::audit::show(
                        &store_path,
                        backend.as_ref(),
                        seqno,
                        decrypt,
                        format,
                    ),
                    AuditCommand::Key(key_cmd) => match key_cmd {
                        AuditKeyCommand::Init { out, plaintext } => {
                            commands::audit::key_init(
                                &store_path,
                                backend.as_ref(),
                                Some(&out),
                                plaintext,
                            )
                        }
                        AuditKeyCommand::Show => commands::audit::key_show(&store_path),
                    },
                    AuditCommand::Streams(streams_cmd) => match streams_cmd {
                        AuditStreamsCommand::List => {
                            commands::audit::streams_list(&store_path, format)
                        }
                        AuditStreamsCommand::Create {
                            name,
                            tier,
                            description,
                        } => commands::audit::streams_create(
                            &store_path,
                            &name,
                            &tier,
                            description.as_deref(),
                            format,
                        ),
                        AuditStreamsCommand::Show { name } => {
                            commands::audit::streams_show(&store_path, &name, format)
                        }
                        AuditStreamsCommand::SetTier { name, tier } => {
                            commands::audit::streams_set_tier(
                                &store_path,
                                &name,
                                &tier,
                                format,
                            )
                        }
                        AuditStreamsCommand::Delete { name } => {
                            commands::audit::streams_delete(&store_path, &name, format)
                        }
                    },
                    AuditCommand::Head { stream } => {
                        commands::audit::head(&store_path, &stream, format)
                    }
                    AuditCommand::Chain(chain_cmd) => match chain_cmd {
                        AuditChainCommand::Verify { from, to, stream } => {
                            commands::audit::chain_verify(&store_path, &stream, from, to, format)
                        }
                    },
                    AuditCommand::Segments(seg_cmd) => match seg_cmd {
                        AuditSegmentsCommand::Close { stream } => {
                            commands::audit::segments_close(&store_path, &stream, format)
                        }
                        AuditSegmentsCommand::List { stream } => {
                            commands::audit::segments_list(&store_path, &stream, format)
                        }
                        AuditSegmentsCommand::Show { segment_id } => {
                            commands::audit::segments_show(&store_path, segment_id, format)
                        }
                    },
                    AuditCommand::Prove { seqno } => {
                        commands::audit::prove(&store_path, seqno, format)
                    }
                    AuditCommand::Sign {
                        segment_id,
                        identity,
                        require_baseline,
                    } => commands::audit::sign(
                        &store_path,
                        backend.as_ref(),
                        segment_id,
                        &identity,
                        require_baseline.as_deref(),
                        format,
                    ),
                    AuditCommand::Verify { stream } => {
                        commands::audit::verify(&store_path, backend.as_ref(), &stream, format)
                    }
                    AuditCommand::Publish { stream } => {
                        commands::audit::publish(&store_path, &stream, format)
                    }
                    AuditCommand::Rollback { stream } => commands::audit::rollback_check(
                        &store_path,
                        backend.as_ref(),
                        &stream,
                        format,
                    ),
                    AuditCommand::Witness(w_cmd) => match w_cmd {
                        AuditWitnessCommand::List { stream } => {
                            commands::audit::witness_list(&store_path, &stream, format)
                        }
                        AuditWitnessCommand::Latest { stream } => {
                            commands::audit::witness_latest(&store_path, &stream, format)
                        }
                        AuditWitnessCommand::Record { input } => {
                            commands::audit::witness_record(&store_path, &input, format)
                        }
                        AuditWitnessCommand::Gc {
                            stream,
                            keep_latest,
                            older_than,
                            dry_run,
                        } => commands::audit::witness_gc(
                            &store_path,
                            &stream,
                            keep_latest,
                            older_than.as_deref(),
                            dry_run,
                            format,
                        ),
                    },
                },
                Command::Measure(measure_cmd) => match measure_cmd {
                    MeasureCommand::File {
                        artifact,
                        kind,
                        bank,
                        pcr,
                    } => commands::measure::file(
                        &store_path,
                        backend.as_ref(),
                        &artifact,
                        &kind,
                        &bank,
                        pcr,
                        format,
                    ),
                    MeasureCommand::Ima { from } => commands::measure::ima(
                        &store_path,
                        backend.as_ref(),
                        from.as_deref(),
                        format,
                    ),
                    MeasureCommand::Checkpoint => {
                        commands::measure::checkpoint(&store_path, format)
                    }
                    MeasureCommand::Sign {
                        segment_id,
                        identity,
                        require_baseline,
                    } => commands::measure::sign(
                        &store_path,
                        backend.as_ref(),
                        segment_id,
                        &identity,
                        require_baseline.as_deref(),
                        format,
                    ),
                    MeasureCommand::Verify { seqno } => {
                        commands::measure::verify(&store_path, seqno, format)
                    }
                    MeasureCommand::List => commands::measure::list(&store_path, format),
                },
                Command::Graph => commands::graph::show(&store, format),
                Command::Identity(id_cmd) => match id_cmd {
                    IdentityCommand::Init {
                        name,
                        usage,
                        algorithm,
                        policy,
                        subject,
                        key_path,
                    } => commands::identity::init(
                        &store,
                        backend.as_ref(),
                        &name,
                        &usage,
                        &algorithm,
                        policy.as_deref(),
                        subject.as_deref(),
                        key_path.as_deref(),
                        format,
                    ),
                    IdentityCommand::Show { name } => {
                        commands::identity::show(&store, &name, format)
                    }
                    IdentityCommand::List => commands::identity::list(&store, format),
                    IdentityCommand::Rotate { name } => {
                        commands::identity::rotate(&store, backend.as_ref(), &name, format)
                    }
                    IdentityCommand::Delete { name, cascade } => {
                        commands::identity::delete(&store, &name, cascade)
                    }
                },
                Command::Vtpm(vtpm_cmd) => match vtpm_cmd {
                    VtpmCommand::Provision {
                        hw_backend,
                        out,
                        label,
                    } => commands::vtpm::provision(
                        &hw_backend,
                        out.as_deref(),
                        label.as_deref(),
                        format,
                    ),
                    VtpmCommand::Credential(cred_cmd) => match cred_cmd {
                        VtpmCredentialCommand::Show { path } => {
                            commands::vtpm::show(path.as_deref(), format)
                        }
                        VtpmCredentialCommand::Verify { hw_backend, path } => {
                            commands::vtpm::verify(&hw_backend, path.as_deref(), format)
                        }
                    },
                },
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
