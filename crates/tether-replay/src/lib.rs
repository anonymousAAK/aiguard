//! Session replay TUI for tether.
//!
//! Provides a three-pane terminal interface for reviewing audit events:
//! - Left pane: Timeline of events with navigation
//! - Center pane: Event detail (tool name, command, scanner results)
//! - Right pane: Verdict badge with color coding

pub mod app;
pub mod events;
pub mod ui;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::prelude::*;
use std::io;

use crate::app::{App, AppAction};

/// Run the replay TUI for a given session.
pub fn run_replay(session_id: &str, db_path: &str) -> Result<()> {
    let events = events::load_events(db_path, session_id)?;
    if events.is_empty() {
        anyhow::bail!("No events found for session '{session_id}'");
    }

    let mut app = App::new(events, session_id.to_string());
    run_tui(&mut app)
}

/// Run the replay TUI for the most recent session.
pub fn run_replay_last(db_path: &str) -> Result<()> {
    let session_id = events::most_recent_session(db_path)?
        .ok_or_else(|| anyhow::anyhow!("No sessions found in the audit log"))?;

    let events = events::load_events(db_path, &session_id)?;
    if events.is_empty() {
        anyhow::bail!("No events found for session '{session_id}'");
    }

    let mut app = App::new(events, session_id);
    run_tui(&mut app)
}

/// Run the TUI event loop.
fn run_tui(app: &mut App) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = event_loop(&mut terminal, app);

    // Restore terminal state regardless of result
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Main event loop: draw, read key, handle action, repeat.
fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    loop {
        terminal.draw(|frame| {
            ui::render(frame, app);
        })?;

        if let Event::Key(key) = event::read()? {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            let action = match key.code {
                KeyCode::Char('q') | KeyCode::Esc => AppAction::Quit,
                KeyCode::Char('j') | KeyCode::Down => AppAction::NextEvent,
                KeyCode::Char('k') | KeyCode::Up => AppAction::PrevEvent,
                KeyCode::Char('g') => AppAction::FirstEvent,
                KeyCode::Char('G') => AppAction::LastEvent,
                KeyCode::Char('e') => AppAction::Export,
                KeyCode::Char('/') => AppAction::ToggleFilter,
                KeyCode::Char('a') => AppAction::FilterAllow,
                KeyCode::Char('w') => AppAction::FilterWarn,
                KeyCode::Char('b') => AppAction::FilterBlock,
                KeyCode::Char('*') => AppAction::FilterAll,
                _ => AppAction::None,
            };

            match action {
                AppAction::Quit => break,
                AppAction::Export => {
                    app.export_jsonl()?;
                }
                other => app.handle_action(other),
            }
        }
    }

    Ok(())
}
