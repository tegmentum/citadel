use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(frame.area());

    let content = if let Some(obj) = app.selected_object() {
        let policy_display = if obj.policy_id.is_some() {
            "attached"
        } else {
            "(none)"
        };

        vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("  path:       ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    obj.path.as_str(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("  id:         ", Style::default().fg(Color::DarkGray)),
                Span::raw(obj.id.to_string()),
            ]),
            Line::from(vec![
                Span::styled("  kind:       ", Style::default().fg(Color::DarkGray)),
                Span::raw(obj.kind.to_string()),
            ]),
            Line::from(vec![
                Span::styled("  algorithm:  ", Style::default().fg(Color::DarkGray)),
                Span::raw(obj.algorithm.to_string()),
            ]),
            Line::from(vec![
                Span::styled("  policy:     ", Style::default().fg(Color::DarkGray)),
                Span::raw(policy_display),
            ]),
            Line::from(vec![
                Span::styled("  created:    ", Style::default().fg(Color::DarkGray)),
                Span::raw(obj.created_at.format("%Y-%m-%d %H:%M:%S UTC").to_string()),
            ]),
            Line::from(vec![
                Span::styled("  handle:     ", Style::default().fg(Color::DarkGray)),
                if obj.handle_blob.is_some() {
                    Span::styled("present", Style::default().fg(Color::Green))
                } else {
                    Span::styled("none", Style::default().fg(Color::Yellow))
                },
            ]),
        ]
    } else {
        vec![Line::from("  (no object selected)")]
    };

    let detail = Paragraph::new(content).block(
        Block::default()
            .title(" Object Detail ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(detail, chunks[0]);

    // Keybindings
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" Esc", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" back  "),
        Span::styled("Ctrl-c", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit  "),
        Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" refresh"),
    ]))
    .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, chunks[1]);
}
