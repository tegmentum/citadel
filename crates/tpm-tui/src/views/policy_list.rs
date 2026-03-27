use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use tpm_core::model::PolicyRule;

use crate::app::App;

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);

    if app.policies.is_empty() {
        let empty = Paragraph::new("  No policies. Use `tpm policy create <name> --pcr 7,11` to get started.")
            .block(
                Block::default()
                    .title(" Policies ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Cyan)),
            );
        frame.render_widget(empty, chunks[0]);
    } else {
        let header = Row::new(vec![
            Cell::from("Name"),
            Cell::from("Rules"),
            Cell::from("Details"),
        ])
        .style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );

        let rows: Vec<Row> = app
            .policies
            .iter()
            .enumerate()
            .map(|(i, pol)| {
                let style = if i == app.selected_index {
                    Style::default().fg(Color::Black).bg(Color::Cyan)
                } else {
                    Style::default()
                };

                let rule_summary: String = pol
                    .rules
                    .iter()
                    .map(|r| match r {
                        PolicyRule::PcrMatch { bank, indices } => {
                            format!(
                                "pcr {}:{}",
                                bank,
                                indices
                                    .iter()
                                    .map(|i| i.to_string())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            )
                        }
                        PolicyRule::Password => "password".to_string(),
                    })
                    .collect::<Vec<_>>()
                    .join(", ");

                Row::new(vec![
                    Cell::from(pol.name.clone()),
                    Cell::from(pol.rules.len().to_string()),
                    Cell::from(rule_summary),
                ])
                .style(style)
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Percentage(30),
                Constraint::Percentage(15),
                Constraint::Percentage(55),
            ],
        )
        .header(header)
        .block(
            Block::default()
                .title(" Policies ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        );

        frame.render_widget(table, chunks[0]);
    }

    // Keybindings
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
