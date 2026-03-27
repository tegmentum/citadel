use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};

/// Poll for a key event with timeout.
pub fn poll_key(timeout: Duration) -> anyhow::Result<Option<KeyEvent>> {
    if event::poll(timeout)? {
        if let Event::Key(key) = event::read()? {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// Map a key event to an action (normal mode).
pub fn key_to_action(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Back,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
        KeyCode::Tab => Action::NextScreen,
        KeyCode::Char('1') => Action::GoToDashboard,
        KeyCode::Char('2') => Action::GoToObjects,
        KeyCode::Char('3') => Action::GoToPolicies,
        KeyCode::Char('4') => Action::GoToAuditLog,
        KeyCode::Char('j') | KeyCode::Down => Action::Down,
        KeyCode::Char('k') | KeyCode::Up => Action::Up,
        KeyCode::Enter => Action::Enter,
        KeyCode::Char('r') => Action::Refresh,
        KeyCode::Char('n') => Action::CreateKey,
        KeyCode::Char('d') | KeyCode::Delete => Action::DeleteSelected,
        _ => Action::None,
    }
}

/// Map a key event in modal input mode.
pub fn key_to_modal_action(key: KeyEvent) -> ModalAction {
    match key.code {
        KeyCode::Esc => ModalAction::Cancel,
        KeyCode::Enter => ModalAction::Confirm,
        KeyCode::Backspace => ModalAction::Backspace,
        KeyCode::Char(c) => ModalAction::Input(c),
        _ => ModalAction::None,
    }
}

/// Map a key event in confirmation modal.
pub fn key_to_confirm_action(key: KeyEvent) -> ConfirmAction {
    match key.code {
        KeyCode::Char('y') | KeyCode::Char('Y') => ConfirmAction::Yes,
        KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => ConfirmAction::No,
        _ => ConfirmAction::None,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    Back,
    NextScreen,
    GoToDashboard,
    GoToObjects,
    GoToPolicies,
    GoToAuditLog,
    Up,
    Down,
    Enter,
    Refresh,
    CreateKey,
    DeleteSelected,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModalAction {
    Cancel,
    Confirm,
    Backspace,
    Input(char),
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmAction {
    Yes,
    No,
    None,
}
