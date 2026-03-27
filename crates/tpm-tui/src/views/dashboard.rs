use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),
            Constraint::Length(6),
            Constraint::Min(1),
        ])
        .split(area);

    // TPM Status block
    let status_lines = if let Some(ref status) = app.status {
        vec![
            Line::from(vec![
                Span::styled("  backend:      ", Style::default().fg(Color::DarkGray)),
                Span::raw(&status.backend_type),
            ]),
            Line::from(vec![
                Span::styled("  manufacturer: ", Style::default().fg(Color::DarkGray)),
                Span::raw(&status.manufacturer),
            ]),
            Line::from(vec![
                Span::styled("  firmware:     ", Style::default().fg(Color::DarkGray)),
                Span::raw(&status.firmware_version),
            ]),
            Line::from(vec![
                Span::styled("  available:    ", Style::default().fg(Color::DarkGray)),
                if status.available {
                    Span::styled("yes", Style::default().fg(Color::Green))
                } else {
                    Span::styled("no", Style::default().fg(Color::Red))
                },
            ]),
        ]
    } else {
        vec![Line::from(Span::styled(
            "  (unable to query backend)",
            Style::default().fg(Color::Red),
        ))]
    };

    let status_block = Paragraph::new(status_lines).block(
        Block::default()
            .title(" TPM Status ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(status_block, chunks[0]);

    // Workspace summary
    let profile_display = app
        .active_profile
        .as_deref()
        .unwrap_or("(none)");

    let health_color = match app.health_posture.as_str() {
        "healthy" => Color::Green,
        "degraded" => Color::Yellow,
        "warning" => Color::Magenta,
        _ => Color::Red,
    };

    let workspace_lines = vec![
        Line::from(vec![
            Span::styled("  health:    ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                format!("{} ({}/100)", app.health_posture, app.health_score),
                Style::default().fg(health_color),
            ),
        ]),
        Line::from(vec![
            Span::styled("  objects:   ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.objects.len().to_string()),
        ]),
        Line::from(vec![
            Span::styled("  policies:  ", Style::default().fg(Color::DarkGray)),
            Span::raw(app.policies.len().to_string()),
        ]),
        Line::from(vec![
            Span::styled("  profile:   ", Style::default().fg(Color::DarkGray)),
            Span::raw(profile_display),
        ]),
    ];

    let workspace_block = Paragraph::new(workspace_lines).block(
        Block::default()
            .title(" Workspace ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    frame.render_widget(workspace_block, chunks[1]);

    // Keybindings
    let help = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit  "),
        Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" switch view  "),
        Span::styled("1", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" dashboard  "),
        Span::styled("2", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" objects  "),
        Span::styled("3", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" policies  "),
        Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" refresh"),
    ]))
    .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, chunks[2]);
}
