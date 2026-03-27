use tpm_core::backend::{BackendStatus, TpmBackend};
use tpm_core::model::TpmObject;
use tpm_core::store::Store;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    ObjectList,
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub status: Option<BackendStatus>,
    pub objects: Vec<TpmObject>,
    pub active_profile: Option<String>,
    pub selected_index: usize,
}

impl App {
    pub fn new() -> Self {
        Self {
            screen: Screen::Dashboard,
            should_quit: false,
            status: None,
            objects: Vec::new(),
            active_profile: None,
            selected_index: 0,
        }
    }

    pub fn refresh(&mut self, store: &Store, backend: &dyn TpmBackend) {
        self.status = backend.status().ok();
        self.objects = store.list_objects().unwrap_or_default();
        self.active_profile = store
            .get_active_profile()
            .ok()
            .flatten()
            .map(|p| p.name);
    }

    pub fn next_screen(&mut self) {
        self.screen = match self.screen {
            Screen::Dashboard => Screen::ObjectList,
            Screen::ObjectList => Screen::Dashboard,
        };
        self.selected_index = 0;
    }

    pub fn move_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn move_down(&mut self) {
        let max = if self.objects.is_empty() {
            0
        } else {
            self.objects.len() - 1
        };
        if self.selected_index < max {
            self.selected_index += 1;
        }
    }
}
