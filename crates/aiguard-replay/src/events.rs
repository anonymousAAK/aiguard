//! Event loading from SQLite for the replay TUI.
//!
//! Loads audit events from aiguard-core's AuditLog database and supports
//! filtering by session and decision type.

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use aiguard_core::AuditEvent;

/// Load all events for a given session from the SQLite database.
pub fn load_events(db_path: &str, session_id: &str) -> Result<Vec<AuditEvent>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt = conn.prepare(
        "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                scanners, duration_us, input_hash, payload
         FROM events
         WHERE session_id = ?1
         ORDER BY ts ASC",
    )?;

    let rows = stmt.query_map(params![session_id], |row| {
        Ok(RawEventRow {
            id: row.get(0)?,
            ts: row.get(1)?,
            session_id: row.get(2)?,
            agent: row.get(3)?,
            stage: row.get(4)?,
            tool_name: row.get(5)?,
            decision: row.get(6)?,
            scanners: row.get(7)?,
            duration_us: row.get::<_, i64>(8)? as u64,
            input_hash: row.get(9)?,
            payload: row.get(10)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        let raw = row?;
        events.push(raw_to_audit_event(raw)?);
    }

    Ok(events)
}

/// Load events filtered by decision type.
pub fn load_events_by_decision(
    db_path: &str,
    session_id: &str,
    decision: &str,
) -> Result<Vec<AuditEvent>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt = conn.prepare(
        "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                scanners, duration_us, input_hash, payload
         FROM events
         WHERE session_id = ?1 AND decision = ?2
         ORDER BY ts ASC",
    )?;

    let rows = stmt.query_map(params![session_id, decision], |row| {
        Ok(RawEventRow {
            id: row.get(0)?,
            ts: row.get(1)?,
            session_id: row.get(2)?,
            agent: row.get(3)?,
            stage: row.get(4)?,
            tool_name: row.get(5)?,
            decision: row.get(6)?,
            scanners: row.get(7)?,
            duration_us: row.get::<_, i64>(8)? as u64,
            input_hash: row.get(9)?,
            payload: row.get(10)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        let raw = row?;
        events.push(raw_to_audit_event(raw)?);
    }

    Ok(events)
}

/// Get the most recent session ID from the database.
pub fn most_recent_session(db_path: &str) -> Result<Option<String>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt =
        conn.prepare("SELECT DISTINCT session_id FROM events ORDER BY ts DESC LIMIT 1")?;

    let session = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .next()
        .transpose()?;

    Ok(session)
}

/// List all distinct session IDs, ordered by most recent first.
pub fn list_sessions(db_path: &str) -> Result<Vec<SessionSummary>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt = conn.prepare(
        "SELECT session_id, MIN(ts) as first_ts, MAX(ts) as last_ts,
                COUNT(*) as event_count, agent
         FROM events
         GROUP BY session_id
         ORDER BY last_ts DESC",
    )?;

    let rows = stmt.query_map([], |row| {
        Ok(SessionSummary {
            session_id: row.get(0)?,
            first_ts: row.get(1)?,
            last_ts: row.get(2)?,
            event_count: row.get(3)?,
            agent: row.get(4)?,
        })
    })?;

    let mut sessions = Vec::new();
    for row in rows {
        sessions.push(row?);
    }

    Ok(sessions)
}

/// Get a single event by ID.
pub fn get_event(db_path: &str, event_id: &str) -> Result<Option<AuditEvent>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt = conn.prepare(
        "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                scanners, duration_us, input_hash, payload
         FROM events
         WHERE id = ?1",
    )?;

    let event = stmt
        .query_map(params![event_id], |row| {
            Ok(RawEventRow {
                id: row.get(0)?,
                ts: row.get(1)?,
                session_id: row.get(2)?,
                agent: row.get(3)?,
                stage: row.get(4)?,
                tool_name: row.get(5)?,
                decision: row.get(6)?,
                scanners: row.get(7)?,
                duration_us: row.get::<_, i64>(8)? as u64,
                input_hash: row.get(9)?,
                payload: row.get(10)?,
            })
        })?
        .next()
        .transpose()?;

    match event {
        Some(raw) => Ok(Some(raw_to_audit_event(raw)?)),
        None => Ok(None),
    }
}

/// Get recent events (for `aiguard log tail`).
pub fn tail_events(db_path: &str, limit: usize) -> Result<Vec<AuditEvent>> {
    let conn = Connection::open(db_path)
        .with_context(|| format!("Failed to open audit database at {db_path}"))?;

    let mut stmt = conn.prepare(
        "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                scanners, duration_us, input_hash, payload
         FROM events
         ORDER BY ts DESC
         LIMIT ?1",
    )?;

    let rows = stmt.query_map(params![limit as i64], |row| {
        Ok(RawEventRow {
            id: row.get(0)?,
            ts: row.get(1)?,
            session_id: row.get(2)?,
            agent: row.get(3)?,
            stage: row.get(4)?,
            tool_name: row.get(5)?,
            decision: row.get(6)?,
            scanners: row.get(7)?,
            duration_us: row.get::<_, i64>(8)? as u64,
            input_hash: row.get(9)?,
            payload: row.get(10)?,
        })
    })?;

    let mut events = Vec::new();
    for row in rows {
        let raw = row?;
        events.push(raw_to_audit_event(raw)?);
    }

    // Reverse to get chronological order
    events.reverse();
    Ok(events)
}

/// Summary of a session for listing.
#[derive(Debug, Clone)]
pub struct SessionSummary {
    pub session_id: String,
    pub first_ts: String,
    pub last_ts: String,
    pub event_count: i64,
    pub agent: String,
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct RawEventRow {
    id: String,
    ts: String,
    session_id: String,
    agent: String,
    stage: String,
    tool_name: Option<String>,
    decision: String,
    scanners: String,
    duration_us: u64,
    input_hash: String,
    payload: Option<Vec<u8>>,
}

fn raw_to_audit_event(raw: RawEventRow) -> Result<AuditEvent> {
    let scanners: serde_json::Value = serde_json::from_str(&raw.scanners)
        .unwrap_or(serde_json::Value::Object(serde_json::Map::new()));

    // Decompress payload if present (zstd compressed)
    let payload = match raw.payload {
        Some(compressed) if !compressed.is_empty() => {
            match zstd::decode_all(compressed.as_slice()) {
                Ok(decompressed) => Some(decompressed),
                Err(_) => Some(compressed), // Fallback: maybe it wasn't compressed
            }
        }
        _ => None,
    };

    Ok(AuditEvent {
        id: raw.id,
        ts: raw.ts,
        session_id: raw.session_id,
        agent: raw.agent,
        stage: raw.stage,
        tool_name: raw.tool_name,
        decision: raw.decision,
        scanners,
        duration_us: raw.duration_us,
        input_hash: raw.input_hash,
        payload,
    })
}
