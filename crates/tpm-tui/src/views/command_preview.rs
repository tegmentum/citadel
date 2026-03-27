use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(ref cmd) = app.command_preview {
        let preview = Paragraph::new(Line::from(vec![
            Span::styled(" $ ", Style::default().fg(Color::DarkGray)),
            Span::styled(cmd.as_str(), Style::default().fg(Color::Green)),
        ]));
        frame.render_widget(preview, area);
    }
}
