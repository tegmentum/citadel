//! CLI-side plan renderer. Types live in tpm_core::service::plan.

pub use tpm_core::service::plan::{PlannedAction, Risk};

/// Print a plan instead of executing.
pub fn show_plan(actions: &[PlannedAction]) {
    println!("plan: {} action(s) would be performed\n", actions.len());
    for (i, action) in actions.iter().enumerate() {
        println!("  {}. {}", i + 1, action.action);
        if let Some(ref target) = action.target {
            println!("     target:     {}", target);
        }
        for (key, value) in &action.details {
            println!("     {:<11}{}", format!("{}:", key), value);
        }
        println!("     risk:       {}", action.risk);
        println!(
            "     reversible: {}",
            if action.reversible { "yes" } else { "no" }
        );
        println!();
    }
    println!("no changes made (--plan mode)");
}
