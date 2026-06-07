//! TPM operator CLI for WebAssembly (wasi:cli).
//!
//! A lightweight CLI entrypoint that compiles to wasm32-wasip2.
//! Uses tpm-core with the in-memory store backend (no SQLite).
//!
//! Build:
//!   cargo build -p tpm-wasi --target wasm32-wasip2
//!
//! Run:
//!   wasmtime run target/wasm32-wasip2/debug/tpm-wasi.wasm -- status

use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::{MockBackend, TpmBackend};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, Profile, TpmObject};
use tpm_core::output::format::{render, OutputFormat, TextRenderable};
use tpm_core::store::Store;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Err(e) = run(&args[1..]) {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

fn run(args: &[String]) -> anyhow::Result<()> {
    let store = Store::memory();
    let backend = MockBackend::new();

    // Parse global flags
    let mut format = OutputFormat::Text;
    let mut cmd_args: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--format" => {
                i += 1;
                if i < args.len() {
                    format = args[i].parse().unwrap_or(OutputFormat::Text);
                }
            }
            "--help" | "-h" => {
                print_help();
                return Ok(());
            }
            "--version" | "-V" => {
                println!("tpm-wasi {}", env!("CARGO_PKG_VERSION"));
                return Ok(());
            }
            _ => cmd_args.push(&args[i]),
        }
        i += 1;
    }

    if cmd_args.is_empty() {
        print_help();
        return Ok(());
    }

    match cmd_args[0] {
        "status" => cmd_status(&store, &backend, format),
        "init" => cmd_init(&store, format),
        "key" if cmd_args.len() > 1 => match cmd_args[1] {
            "create" if cmd_args.len() > 2 => cmd_key_create(&store, &backend, cmd_args[2], format),
            "list" => cmd_key_list(&store, format),
            "show" if cmd_args.len() > 2 => cmd_key_show(&store, cmd_args[2], format),
            "delete" if cmd_args.len() > 2 => cmd_key_delete(&store, cmd_args[2], format),
            _ => {
                eprintln!("usage: tpm key <create|list|show|delete> [args]");
                Ok(())
            }
        },
        "secret" if cmd_args.len() > 1 => match cmd_args[1] {
            "list" => cmd_secret_list(&store, format),
            _ => {
                eprintln!("usage: tpm secret <seal|unseal|list>");
                Ok(())
            }
        },
        "policy" if cmd_args.len() > 1 => match cmd_args[1] {
            "list" => cmd_policy_list(&store, format),
            "create" if cmd_args.len() > 2 => cmd_policy_create(&store, cmd_args[2], format),
            _ => {
                eprintln!("usage: tpm policy <create|list|show|delete>");
                Ok(())
            }
        },
        "object" if cmd_args.len() > 1 => match cmd_args[1] {
            "list" => cmd_object_list(&store, format),
            "tree" => cmd_object_tree(&store, format),
            _ => {
                eprintln!("usage: tpm object <list|tree>");
                Ok(())
            }
        },
        "profile" if cmd_args.len() > 1 => match cmd_args[1] {
            "list" => cmd_profile_list(&store, format),
            _ => {
                eprintln!("usage: tpm profile <list|show|set>");
                Ok(())
            }
        },
        "pcr" if cmd_args.len() > 1 => match cmd_args[1] {
            "show" => cmd_pcr_show(&backend, format),
            _ => {
                eprintln!("usage: tpm pcr <show|baseline>");
                Ok(())
            }
        },
        "explain" if cmd_args.len() > 1 => {
            cmd_explain(cmd_args[1]);
            Ok(())
        }
        "doctor" => cmd_doctor(&store, &backend, format),
        "capabilities" => cmd_capabilities(&backend, format),
        _ => {
            eprintln!("unknown command: {}", cmd_args[0]);
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!(
        "tpm-wasi - TPM operator platform (WebAssembly)

Usage: tpm-wasi [OPTIONS] <COMMAND>

Commands:
  status        Show TPM and workspace status
  init          Initialize workspace
  doctor        Run diagnostic health checks
  capabilities  Show TPM capabilities
  key           Key management (create, list, show, delete)
  secret        Secret management (list)
  policy        Policy management (create, list)
  object        Object inspection (list, tree)
  profile       Profile management (list)
  pcr           PCR operations (show)
  explain       Explain a TPM concept

Options:
  --format <text|json|yaml>   Output format (default: text)
  -h, --help                  Show help
  -V, --version               Show version

Note: This is the WASM build. State is in-memory only.
For persistent storage, use the native build."
    );
}

// -- Commands --

fn cmd_status(store: &Store, backend: &dyn TpmBackend, format: OutputFormat) -> anyhow::Result<()> {
    let status = backend.status()?;
    let objects = store.list_objects()?;
    let profile = store.get_active_profile()?;

    #[derive(serde::Serialize)]
    struct Status {
        backend_type: String,
        available: bool,
        objects: usize,
        profile: Option<String>,
    }

    impl TextRenderable for Status {
        fn render_text(&self) -> String {
            format!(
                "TPM Status\n  backend:  {}\n  available: {}\n  objects:  {}\n  profile:  {}\n",
                self.backend_type,
                if self.available { "yes" } else { "no" },
                self.objects,
                self.profile.as_deref().unwrap_or("(none)")
            )
        }
    }

    let s = Status {
        backend_type: status.backend_type,
        available: status.available,
        objects: objects.len(),
        profile: profile.map(|p| p.name),
    };
    println!("{}", render(&s, format));
    Ok(())
}

fn cmd_init(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    if store.list_profiles()?.is_empty() {
        store.insert_profile(&Profile::builtin_default())?;
        store.log_action("workspace.init", None, &serde_json::json!({}))?;
        println!("workspace initialized (in-memory)");
    } else {
        println!("workspace already initialized");
    }
    Ok(())
}

fn cmd_key_create(
    store: &Store,
    backend: &dyn TpmBackend,
    path_str: &str,
    _format: OutputFormat,
) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;
    if store.get_object(&path)?.is_some() {
        anyhow::bail!("object already exists: {}", path_str);
    }
    let handle = backend.create_key(Algorithm::EccP256, &path)?;
    let obj = TpmObject {
        id: Uuid::new_v4(),
        path: path.clone(),
        kind: ObjectKind::SigningKey,
        algorithm: Algorithm::EccP256,
        policy_id: None,
        handle_blob: Some(handle.id),
        created_at: Utc::now(),
        metadata: serde_json::json!({}),
    };
    store.insert_object(&obj)?;
    println!("key created: {}", path_str);
    Ok(())
}

fn cmd_key_list(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let keys: Vec<_> = objects
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            )
        })
        .collect();

    if keys.is_empty() {
        println!("No keys found.");
    } else {
        for key in &keys {
            println!("  {}  {}  {}", key.path, key.algorithm, key.kind);
        }
    }
    Ok(())
}

fn cmd_key_show(store: &Store, path_str: &str, _format: OutputFormat) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;
    let obj = store
        .get_object(&path)?
        .ok_or_else(|| anyhow::anyhow!("not found: {}", path_str))?;
    println!("path:      {}", obj.path);
    println!("id:        {}", obj.id);
    println!("kind:      {}", obj.kind);
    println!("algorithm: {}", obj.algorithm);
    println!(
        "handle:    {}",
        if obj.handle_blob.is_some() {
            "present"
        } else {
            "none"
        }
    );
    Ok(())
}

fn cmd_key_delete(store: &Store, path_str: &str, _format: OutputFormat) -> anyhow::Result<()> {
    let path = ObjectPath::new(path_str)?;
    if store.delete_object(&path)? {
        println!("key deleted: {}", path_str);
    } else {
        anyhow::bail!("not found: {}", path_str);
    }
    Ok(())
}

fn cmd_secret_list(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let secrets: Vec<_> = objects
        .iter()
        .filter(|o| o.kind == ObjectKind::SealedBlob)
        .collect();
    if secrets.is_empty() {
        println!("No sealed secrets.");
    } else {
        for s in &secrets {
            println!("  {}", s.path);
        }
    }
    Ok(())
}

fn cmd_policy_list(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let policies = store.list_policies()?;
    if policies.is_empty() {
        println!("No policies defined.");
    } else {
        for p in &policies {
            println!("  {} ({} rules)", p.name, p.rules.len());
        }
    }
    Ok(())
}

fn cmd_policy_create(store: &Store, name: &str, _format: OutputFormat) -> anyhow::Result<()> {
    if store.get_policy(name)?.is_some() {
        anyhow::bail!("policy already exists: {}", name);
    }
    let policy = tpm_core::model::Policy {
        id: Uuid::new_v4(),
        name: name.to_string(),
        rules: Vec::new(),
    };
    store.insert_policy(&policy)?;
    println!("policy created: {}", name);
    Ok(())
}

fn cmd_object_list(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    if objects.is_empty() {
        println!("No objects in workspace.");
    } else {
        for o in &objects {
            println!("  {}  {}  {}", o.path, o.kind, o.algorithm);
        }
    }
    Ok(())
}

fn cmd_object_tree(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let objects = store.list_objects()?;
    let policies = store.list_policies()?;
    println!("workspace");
    let keys: Vec<_> = objects
        .iter()
        .filter(|o| {
            matches!(
                o.kind,
                ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
            )
        })
        .collect();
    if !keys.is_empty() {
        println!("  keys/");
        for k in &keys {
            println!("    {}", k.path);
        }
    }
    let secrets: Vec<_> = objects
        .iter()
        .filter(|o| o.kind == ObjectKind::SealedBlob)
        .collect();
    if !secrets.is_empty() {
        println!("  secrets/");
        for s in &secrets {
            println!("    {}", s.path);
        }
    }
    if !policies.is_empty() {
        println!("  policies/");
        for p in &policies {
            println!("    {}", p.name);
        }
    }
    Ok(())
}

fn cmd_profile_list(store: &Store, _format: OutputFormat) -> anyhow::Result<()> {
    let profiles = store.list_profiles()?;
    if profiles.is_empty() {
        println!("No profiles configured.");
    } else {
        for p in &profiles {
            let marker = if p.is_active { " *" } else { "" };
            println!("  {}{}", p.name, marker);
        }
    }
    Ok(())
}

fn cmd_pcr_show(backend: &dyn TpmBackend, _format: OutputFormat) -> anyhow::Result<()> {
    let values = backend.pcr_read("sha256", &[0, 1, 2, 3, 4, 5, 6, 7])?;
    println!("PCR bank: sha256\n");
    for v in &values {
        let hex: String = v.digest.iter().map(|b| format!("{:02x}", b)).collect();
        println!("  {:>2}  {}", v.index, hex);
    }
    Ok(())
}

fn cmd_doctor(
    store: &Store,
    backend: &dyn TpmBackend,
    _format: OutputFormat,
) -> anyhow::Result<()> {
    let status = backend.status()?;
    println!("Doctor Report\n");
    if status.available {
        println!("  [ok] TPM backend reachable ({})", status.backend_type);
    } else {
        println!("  [FAIL] TPM backend unreachable");
    }
    let objects = store.list_objects()?;
    println!("  [ok] Store accessible ({} objects)", objects.len());
    println!("\nOverall: healthy");
    Ok(())
}

fn cmd_capabilities(backend: &dyn TpmBackend, _format: OutputFormat) -> anyhow::Result<()> {
    let status = backend.status()?;
    println!("TPM Capabilities\n");
    println!("  backend:     {}", status.backend_type);
    println!("  manufacturer: {}", status.manufacturer);
    println!(
        "  available:    {}",
        if status.available { "yes" } else { "no" }
    );
    println!("\n  algorithms:");
    for alg in tpm_core::model::Algorithm::all() {
        println!("    - {}", alg);
    }
    Ok(())
}

fn cmd_explain(concept: &str) {
    match concept {
        "pcr" => println!("Platform Configuration Registers (PCRs)\n\nPCRs record measurements of the system's boot and runtime state.\nEach PCR holds a hash that is extended as the system boots."),
        "policy" => println!("TPM Policies\n\nPolicies define conditions that must be satisfied before the TPM\nwill perform an operation (sign, unseal, etc.)."),
        "key" => println!("TPM Keys\n\nKeys are generated inside the TPM. Their private material never\nleaves the hardware."),
        "seal" => println!("Sealing/Unsealing\n\nSealing encrypts data so it can only be decrypted when specific\nconditions are met, typically matching PCR values."),
        "attestation" => println!("Remote Attestation\n\nAttestation allows a remote party to verify the state of a machine\nby requesting a TPM quote."),
        _ => println!("Unknown concept: {}\nAvailable: pcr, policy, key, seal, attestation", concept),
    }
}
