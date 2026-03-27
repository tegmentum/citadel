use tpm_core::backend::{BackendStatus, TpmBackend};
use tpm_core::model::{Policy, TpmObject};
use tpm_core::store::{AuditEntry, Store};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    ObjectList,
    ObjectDetail,
    PolicyList,
    AuditLog,
}

pub struct App {
    pub screen: Screen,
    pub previous_screen: Screen,
    pub should_quit: bool,
    pub status: Option<BackendStatus>,
    pub objects: Vec<TpmObject>,
    pub policies: Vec<Policy>,
    pub audit_entries: Vec<AuditEntry>,
    pub active_profile: Option<String>,
    pub selected_index: usize,
    pub command_preview: Option<String>,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Dashboard,
            previous_screen: Screen::Dashboard,
            should_quit: false,
            status: None,
            objects: Vec::new(),
            policies: Vec::new(),
            audit_entries: Vec::new(),
            active_profile: None,
            selected_index: 0,
            command_preview: None,
        }
    }

    pub fn refresh(&mut self, store: &Store, backend: &dyn TpmBackend) {
        self.status = backend.status().ok();
        self.objects = store.list_objects().unwrap_or_default();
        self.policies = store.list_policies().unwrap_or_default();
        self.audit_entries = store.list_audit_log(None, None, 100).unwrap_or_default();
        self.active_profile = store
            .get_active_profile()
            .ok()
            .flatten()
            .map(|p| p.name);
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

    fn update_command_preview(&mut self) {
        self.command_preview = match self.screen {
            Screen::ObjectList => self.selected_object().map(|o| {
                format!("tpm key show {}", o.path)
            }),
            Screen::ObjectDetail => self.selected_object().map(|o| {
                format!("tpm key show {} --format json", o.path)
            }),
            Screen::PolicyList => self.policies.get(self.selected_index).map(|p| {
                format!("tpm policy show {}", p.name)
            }),
            Screen::AuditLog => Some("tpm log show".to_string()),
            Screen::Dashboard => Some("tpm status".to_string()),
        };
    }
}
