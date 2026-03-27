pub mod app;
pub mod event;
pub mod views;

use std::io;
use std::time::Duration;

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;

use tpm_core::backend::MockBackend;
use tpm_core::store::Store;

use app::{App, Screen};
use event::{key_to_action, poll_key, Action};

fn default_store_path() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("XDG_DATA_HOME") {
        std::path::PathBuf::from(dir).join("tpm").join("tpm.db")
    } else if let Ok(home) = std::env::var("HOME") {
        std::path::PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("tpm")
            .join("tpm.db")
    } else {
        std::path::PathBuf::from("tpm.db")
    }
}

pub fn run() -> anyhow::Result<()> {
    let store_path = std::env::var("TPM_STORE_PATH")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| default_store_path());

    let store = Store::open(&store_path)?;
    let backend = MockBackend::new();

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let term_backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(term_backend)?;

    let mut app = App::new();
    app.refresh(&store, &backend);

    let result = run_loop(&mut terminal, &mut app, &store, &backend);

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut App,
    store: &Store,
    backend: &dyn tpm_core::backend::TpmBackend,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|frame| {
            match app.screen {
                Screen::Dashboard => views::dashboard::render(frame, app),
                Screen::ObjectList => views::object_list::render(frame, app),
            }
        })?;

        if let Some(key) = poll_key(Duration::from_millis(250))? {
            match key_to_action(key) {
                Action::Quit => {
                    app.should_quit = true;
                    break;
                }
                Action::NextScreen => app.next_screen(),
                Action::GoToDashboard => {
                    app.screen = Screen::Dashboard;
                    app.selected_index = 0;
                }
                Action::GoToObjects => {
                    app.screen = Screen::ObjectList;
                    app.selected_index = 0;
                }
                Action::Up => app.move_up(),
                Action::Down => app.move_down(),
                Action::Refresh => app.refresh(store, backend),
                Action::None => {}
            }
        }
    }
    Ok(())
}
