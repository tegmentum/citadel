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

/// Map a key event to an action.
pub fn key_to_action(key: KeyEvent) -> Action {
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Action::Back,
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => Action::Quit,
        KeyCode::Tab => Action::NextScreen,
        KeyCode::Char('1') => Action::GoToDashboard,
        KeyCode::Char('2') => Action::GoToObjects,
        KeyCode::Char('3') => Action::GoToPolicies,
        KeyCode::Char('j') | KeyCode::Down => Action::Down,
        KeyCode::Char('k') | KeyCode::Up => Action::Up,
        KeyCode::Enter => Action::Enter,
        KeyCode::Char('r') => Action::Refresh,
        _ => Action::None,
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
    Up,
    Down,
    Enter,
    Refresh,
    None,
}
