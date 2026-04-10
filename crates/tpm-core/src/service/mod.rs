//! Service layer: composition orchestration over model/store/backend.
//!
//! The service layer is the seam between CLI/TUI/daemon presentation code
//! and the core domain logic. CLI commands should delegate orchestration
//! to these services and keep only argument parsing, rendering, and
//! plan-mode presentation.

pub mod fragility;
pub mod graph;
pub mod identity;
pub mod keys;
pub mod plan;
pub mod reconcile;

pub use fragility::{rate_policy, FragilityRating, FragilityReport, PcrFragility};
pub use graph::{build_graph, DependencyGraph, GraphEdge, GraphNode, NodeKind};
pub use identity::{
    delete_identity as delete_identity_svc, init_identity, rotate_identity, InitIdentitySpec,
};
pub use keys::{create_key, CreateKeySpec};
pub use plan::{PlannedAction, Risk};
pub use reconcile::{apply as apply_manifest, diff as diff_manifest, ApplyReport};
