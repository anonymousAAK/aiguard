//! Replay TUI application state.
//!
//! Manages the three-pane layout state:
//! - Left: Timeline (event list with j/k navigation)
//! - Center: Event detail (tool name, command, scanner results)
//! - Right: Verdict badge (ALLOW/WARN/BLOCK with color)

use std::fs::OpenOptions;
use std::io::Write as IoWrite;

use aiguard_core::AuditEvent;

/// Actions that can be triggered by key presses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAction {
    None,
    Quit,
    NextEvent,
    PrevEvent,
    FirstEvent,
    LastEvent,
    Export,
    ToggleFilter,
    FilterAllow,
    FilterWarn,
    FilterBlock,
    FilterAll,
}

/// Filter for which decision types to show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionFilter {
    All,
    Allow,
    Warn,
    Block,
}

impl DecisionFilter {
    /// Check if an event's decision matches this filter.
    pub fn matches(&self, decision: &str) -> bool {
        match self {
            DecisionFilter::All => true,
            DecisionFilter::Allow => decision == "allow" || decision == "allow_with_context",
            DecisionFilter::Warn => decision == "allow_with_context" || decision == "ask",
            DecisionFilter::Block => decision == "block" || decision == "mutate",
        }
    }

    /// Display label for the current filter.
    pub fn label(&self) -> &'static str {
        match self {
            DecisionFilter::All => "ALL",
            DecisionFilter::Allow => "ALLOW",
            DecisionFilter::Warn => "WARN",
            DecisionFilter::Block => "BLOCK",
        }
    }
}

/// The replay TUI application state.
pub struct App {
    /// All events for the session (unfiltered).
    all_events: Vec<AuditEvent>,
    /// Indices into `all_events` that match the current filter.
    filtered_indices: Vec<usize>,
    /// Current selection index into `filtered_indices`.
    selected: usize,
    /// Session identifier.
    pub session_id: String,
    /// Current decision filter.
    pub filter: DecisionFilter,
    /// Status message (shown at bottom).
    pub status: Option<String>,
}

impl App {
    /// Create a new app with the given events and session id.
    pub fn new(events: Vec<AuditEvent>, session_id: String) -> Self {
        let filtered_indices: Vec<usize> = (0..events.len()).collect();
        Self {
            all_events: events,
            filtered_indices,
            selected: 0,
            session_id,
            filter: DecisionFilter::All,
            status: None,
        }
    }

    /// Get the currently filtered events.
    pub fn filtered_events(&self) -> Vec<&AuditEvent> {
        self.filtered_indices
            .iter()
            .map(|&i| &self.all_events[i])
            .collect()
    }

    /// Get the currently selected event, if any.
    pub fn selected_event(&self) -> Option<&AuditEvent> {
        self.filtered_indices
            .get(self.selected)
            .map(|&i| &self.all_events[i])
    }

    /// Get the current selection index.
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Total number of filtered events.
    pub fn filtered_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Total number of events (unfiltered).
    pub fn total_count(&self) -> usize {
        self.all_events.len()
    }

    /// Handle an action from key input.
    pub fn handle_action(&mut self, action: AppAction) {
        match action {
            AppAction::NextEvent => {
                if !self.filtered_indices.is_empty()
                    && self.selected < self.filtered_indices.len() - 1
                {
                    self.selected += 1;
                }
            }
            AppAction::PrevEvent => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
            }
            AppAction::FirstEvent => {
                self.selected = 0;
            }
            AppAction::LastEvent => {
                if !self.filtered_indices.is_empty() {
                    self.selected = self.filtered_indices.len() - 1;
                }
            }
            AppAction::FilterAllow => {
                self.set_filter(DecisionFilter::Allow);
            }
            AppAction::FilterWarn => {
                self.set_filter(DecisionFilter::Warn);
            }
            AppAction::FilterBlock => {
                self.set_filter(DecisionFilter::Block);
            }
            AppAction::FilterAll | AppAction::ToggleFilter => {
                self.set_filter(DecisionFilter::All);
            }
            AppAction::None | AppAction::Quit | AppAction::Export => {}
        }
        self.status = None;
    }

    /// Export filtered events to a JSONL file.
    pub fn export_jsonl(&mut self) -> anyhow::Result<()> {
        let filename = format!("aiguard-replay-{}.jsonl", self.session_id);
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&filename)?;

        let events = self.filtered_events();
        for event in &events {
            let line = serde_json::to_string(event)?;
            writeln!(file, "{line}")?;
        }

        self.status = Some(format!("Exported {} events to {filename}", events.len()));
        Ok(())
    }

    /// Recompute filtered indices based on the current filter.
    fn set_filter(&mut self, filter: DecisionFilter) {
        self.filter = filter;
        self.filtered_indices = self
            .all_events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filter.matches(&e.decision))
            .map(|(i, _)| i)
            .collect();
        self.selected = 0;
    }
}

/// Classify a decision string into a verdict category for display.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictCategory {
    Allow,
    Warn,
    Block,
}

impl VerdictCategory {
    /// Classify a decision label string.
    pub fn from_decision(decision: &str) -> Self {
        match decision {
            "allow" => Self::Allow,
            "allow_with_context" | "ask" => Self::Warn,
            "block" | "mutate" => Self::Block,
            _ => Self::Warn,
        }
    }

    /// Display label.
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "ALLOW",
            Self::Warn => "WARN",
            Self::Block => "BLOCK",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_events() -> Vec<AuditEvent> {
        vec![
            AuditEvent {
                id: "evt-1".into(),
                ts: "2025-01-01T00:00:00Z".into(),
                session_id: "sess-1".into(),
                agent: "codex".into(),
                stage: "pre_tool".into(),
                tool_name: Some("bash".into()),
                decision: "allow".into(),
                scanners: serde_json::json!({}),
                duration_us: 100,
                input_hash: "abc".into(),
                payload: None,
            },
            AuditEvent {
                id: "evt-2".into(),
                ts: "2025-01-01T00:00:01Z".into(),
                session_id: "sess-1".into(),
                agent: "codex".into(),
                stage: "pre_tool".into(),
                tool_name: Some("write_file".into()),
                decision: "block".into(),
                scanners: serde_json::json!({"prompt_injection": {"type": "block"}}),
                duration_us: 250,
                input_hash: "def".into(),
                payload: None,
            },
            AuditEvent {
                id: "evt-3".into(),
                ts: "2025-01-01T00:00:02Z".into(),
                session_id: "sess-1".into(),
                agent: "codex".into(),
                stage: "post_tool".into(),
                tool_name: Some("bash".into()),
                decision: "allow_with_context".into(),
                scanners: serde_json::json!({}),
                duration_us: 50,
                input_hash: "ghi".into(),
                payload: None,
            },
        ]
    }

    #[test]
    fn navigation_works() {
        let mut app = App::new(sample_events(), "sess-1".into());
        assert_eq!(app.selected_index(), 0);

        app.handle_action(AppAction::NextEvent);
        assert_eq!(app.selected_index(), 1);

        app.handle_action(AppAction::NextEvent);
        assert_eq!(app.selected_index(), 2);

        // Can't go past the end
        app.handle_action(AppAction::NextEvent);
        assert_eq!(app.selected_index(), 2);

        app.handle_action(AppAction::PrevEvent);
        assert_eq!(app.selected_index(), 1);

        app.handle_action(AppAction::FirstEvent);
        assert_eq!(app.selected_index(), 0);

        app.handle_action(AppAction::LastEvent);
        assert_eq!(app.selected_index(), 2);
    }

    #[test]
    fn filter_block_shows_only_blocks() {
        let mut app = App::new(sample_events(), "sess-1".into());
        app.handle_action(AppAction::FilterBlock);
        assert_eq!(app.filtered_count(), 1);
        let evt = app.selected_event().unwrap();
        assert_eq!(evt.decision, "block");
    }

    #[test]
    fn filter_allow_shows_allows_and_context() {
        let mut app = App::new(sample_events(), "sess-1".into());
        app.handle_action(AppAction::FilterAllow);
        // "allow" matches, "allow_with_context" matches
        assert_eq!(app.filtered_count(), 2);
    }

    #[test]
    fn filter_all_shows_everything() {
        let mut app = App::new(sample_events(), "sess-1".into());
        app.handle_action(AppAction::FilterBlock);
        assert_eq!(app.filtered_count(), 1);
        app.handle_action(AppAction::FilterAll);
        assert_eq!(app.filtered_count(), 3);
    }

    #[test]
    fn verdict_category_classification() {
        assert_eq!(
            VerdictCategory::from_decision("allow"),
            VerdictCategory::Allow
        );
        assert_eq!(
            VerdictCategory::from_decision("block"),
            VerdictCategory::Block
        );
        assert_eq!(
            VerdictCategory::from_decision("mutate"),
            VerdictCategory::Block
        );
        assert_eq!(
            VerdictCategory::from_decision("allow_with_context"),
            VerdictCategory::Warn
        );
    }
}
