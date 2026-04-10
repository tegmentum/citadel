use uuid::Uuid;

use tpm_core::model::{Policy, PolicyRule};
use tpm_core::output::format::{render, TextRenderable};
use tpm_core::output::OutputFormat;
use tpm_core::store::Store;

use serde::Serialize;

// -- policy create --

pub fn create(
    store: &Store,
    name: &str,
    pcr_indices: &[u32],
    pcr_bank: &str,
    require_password: bool,
    format: OutputFormat,
) -> anyhow::Result<()> {
    if store.get_policy(name)?.is_some() {
        anyhow::bail!("policy already exists: {}", name);
    }

    let mut rules = Vec::new();
    if !pcr_indices.is_empty() {
        rules.push(PolicyRule::PcrMatch {
            bank: pcr_bank.to_string(),
            indices: pcr_indices.to_vec(),
        });
    }
    if require_password {
        rules.push(PolicyRule::Password);
    }

    let policy = Policy {
        id: Uuid::new_v4(),
        name: name.to_string(),
        rules,
    };

    store.insert_policy(&policy)?;
    store.log_action(
        "policy.create",
        None,
        &serde_json::json!({"name": name}),
    )?;

    let result = PolicyCreated {
        name: policy.name,
        id: policy.id.to_string(),
        rule_count: policy.rules.len(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct PolicyCreated {
    name: String,
    id: String,
    rule_count: usize,
}

impl TextRenderable for PolicyCreated {
    fn render_text(&self) -> String {
        format!(
            "policy created: {}\n  id: {}\n  rules: {}\n",
            self.name, self.id, self.rule_count
        )
    }
}

// -- policy list --

pub fn list(store: &Store, format: OutputFormat) -> anyhow::Result<()> {
    let policies = store.list_policies()?;

    let listing = PolicyListing {
        policies: policies
            .iter()
            .map(|p| PolicySummary {
                name: p.name.clone(),
                rule_count: p.rules.len(),
                rules: p
                    .rules
                    .iter()
                    .map(|r| match r {
                        PolicyRule::PcrMatch { bank, indices } => {
                            format!("pcr {}:{}", bank, indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","))
                        }
                        PolicyRule::Password => "password".to_string(),
                    })
                    .collect(),
            })
            .collect(),
    };

    println!("{}", render(&listing, format));
    Ok(())
}

#[derive(Serialize)]
struct PolicyListing {
    policies: Vec<PolicySummary>,
}

#[derive(Serialize)]
struct PolicySummary {
    name: String,
    rule_count: usize,
    rules: Vec<String>,
}

impl TextRenderable for PolicyListing {
    fn render_text(&self) -> String {
        if self.policies.is_empty() {
            return "No policies defined.\n".to_string();
        }
        let mut out = String::new();
        for p in &self.policies {
            out.push_str(&format!("  {}\n", p.name));
            for rule in &p.rules {
                out.push_str(&format!("    - {}\n", rule));
            }
        }
        out
    }
}

// -- policy show --

pub fn show(store: &Store, name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let policy = store
        .get_policy(name)?
        .ok_or_else(|| anyhow::anyhow!("policy not found: {}", name))?;

    let detail = PolicyDetail {
        name: policy.name,
        id: policy.id.to_string(),
        rules: policy
            .rules
            .iter()
            .map(|r| match r {
                PolicyRule::PcrMatch { bank, indices } => PolicyRuleDetail {
                    rule_type: "pcr_match".to_string(),
                    description: format!(
                        "PCR bank {} indices {}",
                        bank,
                        indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                    ),
                },
                PolicyRule::Password => PolicyRuleDetail {
                    rule_type: "password".to_string(),
                    description: "requires auth value".to_string(),
                },
            })
            .collect(),
    };

    println!("{}", render(&detail, format));
    Ok(())
}

#[derive(Serialize)]
struct PolicyDetail {
    name: String,
    id: String,
    rules: Vec<PolicyRuleDetail>,
}

#[derive(Serialize)]
struct PolicyRuleDetail {
    rule_type: String,
    description: String,
}

impl TextRenderable for PolicyDetail {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("name:  {}\n", self.name));
        out.push_str(&format!("id:    {}\n", self.id));
        out.push_str("rules:\n");
        if self.rules.is_empty() {
            out.push_str("  (none)\n");
        }
        for rule in &self.rules {
            out.push_str(&format!("  - [{}] {}\n", rule.rule_type, rule.description));
        }
        out
    }
}

// -- policy delete --

pub fn delete(store: &Store, name: &str) -> anyhow::Result<()> {
    if store.delete_policy(name)? {
        println!("policy deleted: {}", name);
    } else {
        anyhow::bail!("policy not found: {}", name);
    }
    Ok(())
}

// -- policy explain --

pub fn explain(store: &Store, name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let policy = store
        .get_policy(name)?
        .ok_or_else(|| anyhow::anyhow!("policy not found: {}", name))?;

    let explanation = PolicyExplanation {
        name: policy.name.clone(),
        summary: format!(
            "policy '{}' requires {} condition(s) to be satisfied",
            policy.name,
            policy.rules.len()
        ),
        requirements: policy
            .rules
            .iter()
            .map(|r| match r {
                PolicyRule::PcrMatch { bank, indices } => {
                    format!(
                        "Platform state (PCR) check: the {} PCR bank values at indices {} must match \
                         the expected digest. This ties the operation to a specific boot/platform state.",
                        bank,
                        indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(", ")
                    )
                }
                PolicyRule::Password => {
                    "Password/auth value: the caller must provide the correct authorization value. \
                     This is a knowledge-based factor separate from platform state."
                        .to_string()
                }
            })
            .collect(),
        usage_hint: format!(
            "attach this policy to a key: tpm key create <path> --policy {}",
            policy.name
        ),
    };

    println!("{}", render(&explanation, format));
    Ok(())
}

#[derive(Serialize)]
struct PolicyExplanation {
    name: String,
    summary: String,
    requirements: Vec<String>,
    usage_hint: String,
}

impl TextRenderable for PolicyExplanation {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("{}\n\n", self.summary));
        out.push_str("requirements:\n");
        for (i, req) in self.requirements.iter().enumerate() {
            out.push_str(&format!("  {}. {}\n\n", i + 1, req));
        }
        out.push_str(&format!("hint: {}\n", self.usage_hint));
        out
    }
}

// -- policy compile --

pub fn compile(
    store: &Store,
    file: &std::path::Path,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let text = std::fs::read_to_string(file)?;
    let parsed = tpm_core::policy::from_any_yaml(&text)?;
    let def = match parsed {
        tpm_core::policy::ParsedPolicyDocument::Single(d) => d,
        tpm_core::policy::ParsedPolicyDocument::Manifest(_) => {
            anyhow::bail!(
                "this file is a Workspace Manifest — use `tpm apply --file {}` instead",
                file.display()
            );
        }
    };

    // Validate
    let issues = def.validate();
    if !issues.is_empty() {
        eprintln!("validation errors in {}:\n", file.display());
        for issue in &issues {
            eprintln!("  error: {}", issue);
        }
        anyhow::bail!("{} validation error(s) in policy file", issues.len());
    }

    // Check for existing policy with same name
    if store.get_policy(&def.name)?.is_some() {
        anyhow::bail!(
            "policy '{}' already exists. Delete it first or use a different name.",
            def.name
        );
    }

    let rules = def.compile();

    let policy = Policy {
        id: Uuid::new_v4(),
        name: def.name.clone(),
        rules: rules.clone(),
    };

    store.insert_policy(&policy)?;
    store.log_action(
        "policy.compile",
        None,
        &serde_json::json!({
            "name": &def.name,
            "source": file.display().to_string(),
            "rule_count": rules.len(),
        }),
    )?;

    let result = CompileResult {
        name: def.name,
        source: file.display().to_string(),
        rule_count: rules.len(),
        rules: rules
            .iter()
            .map(|r| match r {
                PolicyRule::PcrMatch { bank, indices } => format!(
                    "pcr {}:{}",
                    bank,
                    indices
                        .iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                PolicyRule::Password => "password".to_string(),
            })
            .collect(),
        id: policy.id.to_string(),
    };
    println!("{}", render(&result, format));
    Ok(())
}

#[derive(Serialize)]
struct CompileResult {
    name: String,
    source: String,
    rule_count: usize,
    rules: Vec<String>,
    id: String,
}

impl TextRenderable for CompileResult {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "policy compiled: {} (from {})\n",
            self.name, self.source
        ));
        out.push_str(&format!("  id: {}\n", self.id));
        out.push_str(&format!("  rules: {}\n", self.rule_count));
        for rule in &self.rules {
            out.push_str(&format!("    - {}\n", rule));
        }
        out
    }
}

// -- policy test --

pub fn test_policy(
    store: &Store,
    backend: &dyn tpm_core::backend::TpmBackend,
    name: &str,
    format: OutputFormat,
) -> anyhow::Result<()> {
    let policy = store
        .get_policy(name)?
        .ok_or_else(|| anyhow::anyhow!("policy not found: {}", name))?;

    let mut results = Vec::new();

    for rule in &policy.rules {
        match rule {
            PolicyRule::PcrMatch { bank, indices } => {
                match backend.pcr_read(bank, indices) {
                    Ok(values) => {
                        results.push(TestResult {
                            rule: format!(
                                "pcr {}:{}",
                                bank,
                                indices
                                    .iter()
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            ),
                            satisfied: true,
                            detail: format!("read {} PCR values successfully", values.len()),
                        });
                    }
                    Err(e) => {
                        results.push(TestResult {
                            rule: format!("pcr {}:{}", bank, indices.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")),
                            satisfied: false,
                            detail: format!("failed to read PCRs: {}", e),
                        });
                    }
                }
            }
            PolicyRule::Password => {
                results.push(TestResult {
                    rule: "password".to_string(),
                    satisfied: true,
                    detail: "auth value would be prompted at operation time".to_string(),
                });
            }
        }
    }

    let all_satisfied = results.iter().all(|r| r.satisfied);

    let report = TestReport {
        policy_name: name.to_string(),
        results,
        all_satisfied,
    };
    println!("{}", render(&report, format));
    Ok(())
}

#[derive(Serialize)]
struct TestResult {
    rule: String,
    satisfied: bool,
    detail: String,
}

#[derive(Serialize)]
struct TestReport {
    policy_name: String,
    results: Vec<TestResult>,
    all_satisfied: bool,
}

impl TextRenderable for TestReport {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("testing policy: {}\n\n", self.policy_name));
        for r in &self.results {
            let icon = if r.satisfied { "ok" } else { "FAIL" };
            out.push_str(&format!("  [{}] {}\n", icon, r.rule));
            out.push_str(&format!("        {}\n", r.detail));
        }
        out.push_str(&format!(
            "\nresult: {}\n",
            if self.all_satisfied {
                "all requirements satisfiable"
            } else {
                "SOME REQUIREMENTS CANNOT BE SATISFIED"
            }
        ));
        out
    }
}

// -- policy fragility --

pub fn fragility(store: &Store, name: &str, format: OutputFormat) -> anyhow::Result<()> {
    let policy = store
        .get_policy(name)?
        .ok_or_else(|| anyhow::anyhow!("policy not found: {}", name))?;

    let report = tpm_core::service::rate_policy(&policy);

    let out = FragilityOutput {
        policy: name.to_string(),
        overall: report.overall.to_string(),
        per_pcr: report
            .per_pcr
            .iter()
            .map(|p| PcrFragilityOut {
                bank: p.bank.clone(),
                index: p.index,
                rating: p.rating.to_string(),
                reason: p.reason.clone(),
            })
            .collect(),
        notes: report.notes.clone(),
    };

    println!("{}", render(&out, format));
    Ok(())
}

#[derive(Serialize)]
struct FragilityOutput {
    policy: String,
    overall: String,
    per_pcr: Vec<PcrFragilityOut>,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct PcrFragilityOut {
    bank: String,
    index: u32,
    rating: String,
    reason: String,
}

impl TextRenderable for FragilityOutput {
    fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("policy: {}\n", self.policy));
        out.push_str(&format!("overall: {}\n\n", self.overall));

        if self.per_pcr.is_empty() {
            out.push_str("  (no PCR requirements)\n");
        } else {
            out.push_str("per-PCR:\n");
            for p in &self.per_pcr {
                out.push_str(&format!(
                    "  {}:{:<3} [{:<6}] {}\n",
                    p.bank, p.index, p.rating, p.reason
                ));
            }
        }

        if !self.notes.is_empty() {
            out.push_str("\nnotes:\n");
            for note in &self.notes {
                out.push_str(&format!("  - {}\n", note));
            }
        }

        out
    }
}
