use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);

    if app.audit_entries.is_empty() {
        let empty = Paragraph::new("  No audit log entries. Operations will be recorded here.")
            .block(
                Block::default()
                    .title(" Audit Log ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        frame.render_widget(empty, chunks[0]);
    } else {
        let header = Row::new(vec![
            Cell::from("Time"),
            Cell::from("Action"),
            Cell::from("Object"),
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let rows: Vec<Row> = app
            .audit_entries
            .iter()
            .enumerate()
            .map(|(i, entry)| {
                let style = if i == app.selected_index {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default()
                };
                Row::new(vec![
                    Cell::from(
                        entry
                            .timestamp
                            .get(..19)
                            .unwrap_or(&entry.timestamp)
                            .to_string(),
                    ),
                    Cell::from(entry.action.clone()),
                    Cell::from(entry.object_path.clone().unwrap_or_default()),
                ])
                .style(style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(30),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(" Audit Log ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        frame.render_widget(table, chunks[0]);
    }

    let help = Paragraph::new(Line::from(vec![
        Span::styled(" q", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" quit  "),
        Span::styled("Tab", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" switch view  "),
        Span::styled("j/k", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" navigate  "),
        Span::styled("r", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(" refresh"),
    ]))
    .block(Block::default().borders(Borders::TOP));
    frame.render_widget(help, chunks[1]);
}
