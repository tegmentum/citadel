/// Describes a planned operation for --plan mode.
pub struct PlannedAction {
    pub action: String,
    pub target: Option<String>,
    pub details: Vec<(String, String)>,
    pub risk: Risk,
    pub reversible: bool,
}

#[allow(dead_code)]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for Risk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
        }
    }
}

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
