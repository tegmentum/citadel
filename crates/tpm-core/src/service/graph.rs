//! Dependency graph over workspace resources.
//!
//! Builds a `DependencyGraph` from the store contents: keys, policies,
//! identities, secrets, and the references between them. Used by
//! `tpm graph` for visualization and (in the future) by the reconciler
//! to detect orphans and cycles.

use serde::Serialize;

use crate::output::format::{DotRenderable, TextRenderable};
use crate::store::Store;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Key,
    Policy,
    Identity,
    Secret,
    Profile,
}

impl NodeKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Policy => "policy",
            Self::Identity => "identity",
            Self::Secret => "secret",
            Self::Profile => "profile",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphNode {
    pub id: String,
    pub label: String,
    pub kind: NodeKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub label: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DependencyGraph {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

/// Build a dependency graph from the store.
pub fn build_graph(store: &Store) -> anyhow::Result<DependencyGraph> {
    let mut graph = DependencyGraph::default();

    // Policies first (they're referenced by others)
    for pol in store.list_policies()? {
        let id = format!("policy:{}", pol.name);
        graph.nodes.push(GraphNode {
            id,
            label: pol.name.clone(),
            kind: NodeKind::Policy,
        });
    }

    // Keys and secrets
    let objects = store.list_objects()?;
    for obj in &objects {
        let (kind, id) = match obj.kind {
            crate::model::ObjectKind::SigningKey
            | crate::model::ObjectKind::StorageKey
            | crate::model::ObjectKind::AttestationKey => {
                (NodeKind::Key, format!("key:{}", obj.path))
            }
            crate::model::ObjectKind::SealedBlob => {
                (NodeKind::Secret, format!("secret:{}", obj.path))
            }
            _ => continue,
        };
        graph.nodes.push(GraphNode {
            id: id.clone(),
            label: obj.path.to_string(),
            kind,
        });

        // Edge: key/secret -> policy (if attached)
        if let Some(pid) = obj.policy_id {
            if let Some(pol) = store.get_policy_by_id(&pid)? {
                graph.edges.push(GraphEdge {
                    from: id.clone(),
                    to: format!("policy:{}", pol.name),
                    label: "uses".to_string(),
                });
            }
        }
    }

    // Identities
    for ident in store.list_identities()? {
        let id = format!("identity:{}", ident.name);
        graph.nodes.push(GraphNode {
            id: id.clone(),
            label: format!("{} [{}]", ident.name, ident.usage),
            kind: NodeKind::Identity,
        });

        // Edge: identity -> key
        if let Some(key_obj) = objects.iter().find(|o| o.id == ident.key_object_id) {
            graph.edges.push(GraphEdge {
                from: id.clone(),
                to: format!("key:{}", key_obj.path),
                label: "signs with".to_string(),
            });
        }

        // Edge: identity -> policy
        if let Some(pid) = ident.policy_id {
            if let Some(pol) = store.get_policy_by_id(&pid)? {
                graph.edges.push(GraphEdge {
                    from: id,
                    to: format!("policy:{}", pol.name),
                    label: "gated by".to_string(),
                });
            }
        }
    }

    Ok(graph)
}

impl TextRenderable for DependencyGraph {
    fn render_text(&self) -> String {
        if self.nodes.is_empty() {
            return "(empty workspace)\n".to_string();
        }
        let mut out = String::new();
        out.push_str("dependency graph\n");

        for kind in &[
            NodeKind::Identity,
            NodeKind::Key,
            NodeKind::Secret,
            NodeKind::Policy,
        ] {
            let filtered: Vec<_> = self
                .nodes
                .iter()
                .filter(|n| n.kind.as_str() == kind.as_str())
                .collect();
            if filtered.is_empty() {
                continue;
            }
            out.push_str(&format!("\n  {}s/\n", kind.as_str()));
            for node in &filtered {
                out.push_str(&format!("    - {}\n", node.label));
                for edge in self.edges.iter().filter(|e| e.from == node.id) {
                    let target_label = self
                        .nodes
                        .iter()
                        .find(|n| n.id == edge.to)
                        .map(|n| n.label.clone())
                        .unwrap_or_else(|| edge.to.clone());
                    out.push_str(&format!("        {} -> {}\n", edge.label, target_label));
                }
            }
        }
        out
    }
}

impl DotRenderable for DependencyGraph {
    fn render_dot(&self) -> String {
        let mut out = String::from("digraph tpm {\n");
        out.push_str("  rankdir=LR;\n");
        out.push_str("  node [shape=box, style=rounded];\n\n");

        for node in &self.nodes {
            let shape = match node.kind {
                NodeKind::Key => "box",
                NodeKind::Policy => "hexagon",
                NodeKind::Identity => "doubleoctagon",
                NodeKind::Secret => "folder",
                NodeKind::Profile => "ellipse",
            };
            let escaped_label = node.label.replace('"', "\\\"");
            out.push_str(&format!(
                "  \"{}\" [label=\"{}\", shape={}];\n",
                node.id, escaped_label, shape
            ));
        }

        out.push('\n');
        for edge in &self.edges {
            let escaped_label = edge.label.replace('"', "\\\"");
            out.push_str(&format!(
                "  \"{}\" -> \"{}\" [label=\"{}\"];\n",
                edge.from, edge.to, escaped_label
            ));
        }
        out.push_str("}\n");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::MockBackend;
    use crate::service::identity::{init_identity, InitIdentitySpec};
    use crate::service::keys::{create_key, CreateKeySpec};

    #[test]
    fn empty_store_produces_empty_graph() {
        let store = Store::memory();
        let g = build_graph(&store).unwrap();
        assert!(g.nodes.is_empty());
        assert!(g.edges.is_empty());
    }

    #[test]
    fn identity_key_edge_is_emitted() {
        let store = Store::memory();
        let backend = MockBackend::new();
        init_identity(
            &store,
            &backend,
            InitIdentitySpec {
                name: "svc",
                usage: crate::model::IdentityUsage::CodeSigning,
                algorithm: "ecc-p256",
                policy_name: None,
                subject: None,
                key_path: None,
            },
        )
        .unwrap();
        let g = build_graph(&store).unwrap();
        assert!(g.nodes.iter().any(|n| matches!(n.kind, NodeKind::Identity)));
        assert!(g.nodes.iter().any(|n| matches!(n.kind, NodeKind::Key)));
        assert!(g.edges.iter().any(|e| e.label == "signs with"));
    }

    #[test]
    fn dot_output_contains_digraph() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let _ = create_key(
            &store,
            &backend,
            CreateKeySpec {
                path: "signing/k",
                algorithm: "ecc-p256",
                policy_name: None,
            },
        )
        .unwrap();
        let g = build_graph(&store).unwrap();
        let dot = g.render_dot();
        assert!(dot.contains("digraph tpm"));
        assert!(dot.contains("->") || !g.edges.is_empty() || dot.contains("key:signing/k"));
    }

    #[test]
    fn identity_to_policy_edge() {
        let store = Store::memory();
        let backend = MockBackend::new();
        let policy = crate::model::Policy {
            id: uuid::Uuid::new_v4(),
            name: "boot".to_string(),
            rules: vec![],
        };
        store.insert_policy(&policy).unwrap();

        init_identity(
            &store,
            &backend,
            InitIdentitySpec {
                name: "gated",
                usage: crate::model::IdentityUsage::Tls,
                algorithm: "ecc-p256",
                policy_name: Some("boot"),
                subject: None,
                key_path: None,
            },
        )
        .unwrap();
        let g = build_graph(&store).unwrap();
        assert!(g.edges.iter().any(|e| e.label == "gated by"));
    }
}
