use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::app::{App, Modal};

pub fn render(frame: &mut Frame, app: &App) {
    match &app.modal {
        Modal::None => {}
        Modal::CreateKey { input } => {
            let area = centered_rect(50, 7, frame.area());
            frame.render_widget(Clear, area);

            let lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled("  path: ", Style::default().fg(Color::DarkGray)),
                    Span::styled(
                        format!("{}_", input),
                        Style::default()
                            .fg(Color::White)
                            .add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  Enter", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" create  "),
                    Span::styled("Esc", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" cancel"),
                ]),
            ];

            let popup = Paragraph::new(lines).block(
                Block::default()
                    .title(" Create Key (ecc-p256) ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)),
            );
            frame.render_widget(popup, area);
        }
        Modal::ConfirmDelete { path } => {
            let area = centered_rect(50, 7, frame.area());
            frame.render_widget(Clear, area);

            let lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::raw("  delete "),
                    Span::styled(
                        path.as_str(),
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("?"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  y", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" yes  "),
                    Span::styled("n", Style::default().add_modifier(Modifier::BOLD)),
                    Span::raw(" no"),
                ]),
            ];

            let popup = Paragraph::new(lines).block(
                Block::default()
                    .title(" Confirm Delete ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            );
            frame.render_widget(popup, area);
        }
        Modal::Message { text } => {
            let area = centered_rect(50, 5, frame.area());
            frame.render_widget(Clear, area);

            let lines = vec![
                Line::from(""),
                Line::from(format!("  {}", text)),
                Line::from(""),
            ];

            let popup = Paragraph::new(lines).block(
                Block::default()
                    .title(" Info ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            frame.render_widget(popup, area);
        }
    }
}

fn centered_rect(percent_x: u16, height: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Fill(1),
            Constraint::Length(height),
            Constraint::Fill(1),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}
