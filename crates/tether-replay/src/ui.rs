//! Ratatui rendering for the replay TUI.
//!
//! Draws the three-pane layout:
//! - Left (30%): Timeline list of events
//! - Center (50%): Event detail panel
//! - Right (20%): Verdict badge with color coding
//!
//! Color scheme:
//! - Green: Allow verdicts
//! - Yellow: Warn verdicts
//! - Red: Block verdicts

use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::app::{App, VerdictCategory};

/// Render the full TUI frame.
pub fn render(frame: &mut Frame, app: &App) {
    // Create the three-pane layout
    let outer_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Main content
            Constraint::Length(2), // Status bar
        ])
        .split(frame.area());

    let main_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(30), // Timeline
            Constraint::Percentage(50), // Detail
            Constraint::Percentage(20), // Verdict
        ])
        .split(outer_chunks[0]);

    render_timeline(frame, app, main_chunks[0]);
    render_detail(frame, app, main_chunks[1]);
    render_verdict(frame, app, main_chunks[2]);
    render_status_bar(frame, app, outer_chunks[1]);
}

/// Render the timeline pane (left).
fn render_timeline(frame: &mut Frame, app: &App, area: Rect) {
    let events = app.filtered_events();
    let items: Vec<ListItem> = events
        .iter()
        .enumerate()
        .map(|(i, event)| {
            let category = VerdictCategory::from_decision(&event.decision);
            let marker = match category {
                VerdictCategory::Allow => Style::default().fg(Color::Green),
                VerdictCategory::Warn => Style::default().fg(Color::Yellow),
                VerdictCategory::Block => Style::default().fg(Color::Red),
            };

            let tool = event.tool_name.as_deref().unwrap_or("-");
            let time = if event.ts.len() > 19 {
                &event.ts[11..19] // HH:MM:SS
            } else {
                &event.ts
            };

            let line = format!("{:>3} {} {} {}", i + 1, time, category.label(), tool);
            ListItem::new(line).style(marker)
        })
        .collect();

    let title = format!(
        " Timeline [{}/{}] filter:{} ",
        app.filtered_count(),
        app.total_count(),
        app.filter.label()
    );

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol(">> ");

    let mut state = ListState::default();
    state.select(Some(app.selected_index()));
    frame.render_stateful_widget(list, area, &mut state);
}

/// Render the detail pane (center).
fn render_detail(frame: &mut Frame, app: &App, area: Rect) {
    let content = match app.selected_event() {
        Some(event) => {
            let tool = event.tool_name.as_deref().unwrap_or("<none>");
            let scanners_pretty =
                serde_json::to_string_pretty(&event.scanners).unwrap_or_else(|_| "{}".to_string());

            format!(
                "Event ID: {}\n\
                 Timestamp: {}\n\
                 Agent: {}\n\
                 Stage: {}\n\
                 Tool: {}\n\
                 Decision: {}\n\
                 Duration: {}us\n\
                 Input Hash: {}\n\
                 \n\
                 --- Scanner Results ---\n\
                 {}",
                event.id,
                event.ts,
                event.agent,
                event.stage,
                tool,
                event.decision,
                event.duration_us,
                event.input_hash,
                scanners_pretty,
            )
        }
        None => "No event selected".to_string(),
    };

    let detail = Paragraph::new(content)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Event Detail ")
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(detail, area);
}

/// Render the verdict badge pane (right).
fn render_verdict(frame: &mut Frame, app: &App, area: Rect) {
    let (label, color, description) = match app.selected_event() {
        Some(event) => {
            let category = VerdictCategory::from_decision(&event.decision);
            match category {
                VerdictCategory::Allow => (
                    "ALLOW",
                    Color::Green,
                    "Action permitted.\nNo threats detected.",
                ),
                VerdictCategory::Warn => (
                    " WARN ",
                    Color::Yellow,
                    "Action permitted\nwith advisory.\nReview recommended.",
                ),
                VerdictCategory::Block => (
                    "BLOCK",
                    Color::Red,
                    "Action denied.\nThreat detected\nor policy violation.",
                ),
            }
        }
        None => ("  -  ", Color::DarkGray, "No event selected."),
    };

    // Build the verdict display with a large badge
    let badge_text = format!(
        "\n\n\n  {}\n\n\n  {}",
        label,
        description.replace('\n', "\n  ")
    );

    let verdict = Paragraph::new(badge_text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Verdict ")
                .border_style(Style::default().fg(color)),
        )
        .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Left);

    frame.render_widget(verdict, area);
}

/// Render the status bar at the bottom.
fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let status_text = if let Some(ref msg) = app.status {
        msg.clone()
    } else {
        format!(
            " Session: {} | j/k:nav  g/G:first/last  a/w/b:filter  *:all  e:export  q:quit",
            app.session_id
        )
    };

    let status =
        Paragraph::new(status_text).style(Style::default().bg(Color::DarkGray).fg(Color::White));

    frame.render_widget(status, area);
}
