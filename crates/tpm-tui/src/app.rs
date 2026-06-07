use chrono::Utc;
use uuid::Uuid;

use tpm_core::backend::{BackendStatus, TpmBackend};
use tpm_core::model::{Algorithm, ObjectKind, ObjectPath, Policy, TpmObject};
use tpm_core::store::{AuditEntry, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    ObjectList,
    ObjectDetail,
    PolicyList,
    AuditLog,
}

/// Modal overlay states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Modal {
    None,
    /// Text input for creating a key. Holds the current input buffer.
    CreateKey {
        input: String,
    },
    /// Confirmation to delete the selected object.
    ConfirmDelete {
        path: String,
    },
    /// Status message shown briefly after an action.
    Message {
        text: String,
    },
}

pub struct App {
    pub screen: Screen,
    pub previous_screen: Screen,
    pub should_quit: bool,
    pub modal: Modal,
    pub status: Option<BackendStatus>,
    pub objects: Vec<TpmObject>,
    pub policies: Vec<Policy>,
    pub audit_entries: Vec<AuditEntry>,
    pub active_profile: Option<String>,
    pub health_posture: String,
    pub health_score: u8,
    pub selected_index: usize,
    pub command_preview: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Dashboard,
            previous_screen: Screen::Dashboard,
            should_quit: false,
            modal: Modal::None,
            status: None,
            objects: Vec::new(),
            policies: Vec::new(),
            audit_entries: Vec::new(),
            active_profile: None,
            health_posture: "unknown".to_string(),
            health_score: 0,
            selected_index: 0,
            command_preview: None,
        }
    }

    pub fn refresh(&mut self, store: &Store, backend: &dyn TpmBackend) {
        self.status = backend.status().ok();
        self.objects = store.list_objects().unwrap_or_default();
        self.policies = store.list_policies().unwrap_or_default();
        self.audit_entries = store.list_audit_log(None, None, 100).unwrap_or_default();
        self.active_profile = store.get_active_profile().ok().flatten().map(|p| p.name);
        self.compute_health();
        self.update_command_preview();
    }

    pub fn next_screen(&mut self) {
        self.previous_screen = self.screen;
        self.screen = match self.screen {
            Screen::Dashboard => Screen::ObjectList,
            Screen::ObjectList => Screen::PolicyList,
            Screen::PolicyList => Screen::AuditLog,
            Screen::AuditLog => Screen::Dashboard,
            Screen::ObjectDetail => Screen::ObjectList,
        };
        self.selected_index = 0;
        self.update_command_preview();
    }

    pub fn go_back(&mut self) {
        if self.modal != Modal::None {
            self.modal = Modal::None;
            return;
        }
        if self.screen == Screen::ObjectDetail {
            self.screen = self.previous_screen;
        }
        self.update_command_preview();
    }

    pub fn enter_detail(&mut self) {
        if self.screen == Screen::ObjectList && !self.objects.is_empty() {
            self.previous_screen = self.screen;
            self.screen = Screen::ObjectDetail;
            self.update_command_preview();
        }
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
            self.update_command_preview();
        }
    }

    pub fn move_down(&mut self) {
        let max = self.current_list_len().saturating_sub(1);
        if self.selected_index < max {
            self.selected_index += 1;
            self.update_command_preview();
        }
    }

    fn current_list_len(&self) -> usize {
        match self.screen {
            Screen::ObjectList | Screen::ObjectDetail => self.objects.len(),
            Screen::PolicyList => self.policies.len(),
            Screen::AuditLog => self.audit_entries.len(),
            Screen::Dashboard => 0,
        }
    }

    pub fn selected_object(&self) -> Option<&TpmObject> {
        self.objects.get(self.selected_index)
    }

    // -- Modal actions --

    pub fn start_create_key(&mut self) {
        self.modal = Modal::CreateKey {
            input: String::new(),
        };
    }

    pub fn start_delete(&mut self) {
        if let Some(obj) = self.selected_object() {
            self.modal = Modal::ConfirmDelete {
                path: obj.path.to_string(),
            };
        }
    }

    pub fn modal_input_char(&mut self, c: char) {
        if let Modal::CreateKey { ref mut input } = self.modal {
            input.push(c);
        }
    }

    pub fn modal_input_backspace(&mut self) {
        if let Modal::CreateKey { ref mut input } = self.modal {
            input.pop();
        }
    }

    pub fn execute_create_key(&mut self, store: &Store, backend: &dyn TpmBackend) {
        if let Modal::CreateKey { ref input } = self.modal {
            let path_str = input.trim().to_string();
            if path_str.is_empty() {
                self.modal = Modal::Message {
                    text: "path cannot be empty".to_string(),
                };
                return;
            }

            match ObjectPath::new(&path_str) {
                Ok(path) => {
                    if store.get_object(&path).ok().flatten().is_some() {
                        self.modal = Modal::Message {
                            text: format!("already exists: {}", path_str),
                        };
                        return;
                    }
                    match backend.create_key(Algorithm::EccP256, &path) {
                        Ok(handle) => {
                            let obj = TpmObject {
                                id: Uuid::new_v4(),
                                path,
                                kind: ObjectKind::SigningKey,
                                algorithm: Algorithm::EccP256,
                                policy_id: None,
                                handle_blob: Some(handle.id),
                                created_at: Utc::now(),
                                metadata: serde_json::json!({"created_via": "tui"}),
                            };
                            if store.insert_object(&obj).is_ok() {
                                store
                                    .log_action(
                                        "key.create",
                                        Some(&path_str),
                                        &serde_json::json!({"via": "tui"}),
                                    )
                                    .ok();
                                self.modal = Modal::Message {
                                    text: format!("key created: {}", path_str),
                                };
                                self.refresh(store, backend);
                            } else {
                                self.modal = Modal::Message {
                                    text: "failed to store key".to_string(),
                                };
                            }
                        }
                        Err(e) => {
                            self.modal = Modal::Message {
                                text: format!("backend error: {}", e),
                            };
                        }
                    }
                }
                Err(e) => {
                    self.modal = Modal::Message {
                        text: format!("invalid path: {}", e),
                    };
                }
            }
        }
    }

    pub fn execute_delete(&mut self, store: &Store, backend: &dyn TpmBackend) {
        if let Modal::ConfirmDelete { ref path } = self.modal {
            let path_str = path.clone();
            match ObjectPath::new(&path_str) {
                Ok(obj_path) => {
                    if store.delete_object(&obj_path).unwrap_or(false) {
                        store
                            .log_action(
                                "object.delete",
                                Some(&path_str),
                                &serde_json::json!({"via": "tui"}),
                            )
                            .ok();
                        self.modal = Modal::Message {
                            text: format!("deleted: {}", path_str),
                        };
                        self.refresh(store, backend);
                        // Adjust selection
                        if self.selected_index > 0 && self.selected_index >= self.objects.len() {
                            self.selected_index = self.objects.len().saturating_sub(1);
                        }
                    } else {
                        self.modal = Modal::Message {
                            text: format!("not found: {}", path_str),
                        };
                    }
                }
                Err(e) => {
                    self.modal = Modal::Message {
                        text: format!("error: {}", e),
                    };
                }
            }
        }
    }

    fn compute_health(&mut self) {
        let mut score: i32 = 100;
        let available = self.status.as_ref().map(|s| s.available).unwrap_or(false);
        if !available {
            score -= 40;
        }
        if self.active_profile.is_none() {
            score -= 10;
        }
        let orphans = self
            .objects
            .iter()
            .filter(|o| {
                matches!(
                    o.kind,
                    ObjectKind::SigningKey | ObjectKind::StorageKey | ObjectKind::AttestationKey
                ) && o.handle_blob.is_none()
            })
            .count();
        if orphans > 0 {
            score -= 15;
        }
        self.health_score = score.max(0) as u8;
        self.health_posture = match self.health_score {
            90..=100 => "healthy",
            70..=89 => "degraded",
            40..=69 => "warning",
            _ => "critical",
        }
        .to_string();
    }

    fn update_command_preview(&mut self) {
        self.command_preview = match self.screen {
            Screen::ObjectList => self
                .selected_object()
                .map(|o| format!("tpm key show {}", o.path)),
            Screen::ObjectDetail => self
                .selected_object()
                .map(|o| format!("tpm key show {} --format json", o.path)),
            Screen::PolicyList => self
                .policies
                .get(self.selected_index)
                .map(|p| format!("tpm policy show {}", p.name)),
            Screen::AuditLog => Some("tpm log show".to_string()),
            Screen::Dashboard => Some("tpm status".to_string()),
        };
    }
}
