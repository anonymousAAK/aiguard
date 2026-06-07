use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};

use chrono::{NaiveDate, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Result, TetherError};
use crate::policy::LoggingConfig;

// ---------------------------------------------------------------------------
// AuditEvent
// ---------------------------------------------------------------------------

/// A single auditable event recorded by the policy engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier (UUID v4).
    pub id: String,

    /// ISO-8601 timestamp.
    pub ts: String,

    /// Session identifier.
    pub session_id: String,

    /// Agent name (e.g. "claude_code", "codex").
    pub agent: String,

    /// Lifecycle stage (e.g. "pre_tool", "post_tool").
    pub stage: String,

    /// Tool name, if applicable.
    pub tool_name: Option<String>,

    /// Final decision label.
    pub decision: String,

    /// Per-scanner verdicts serialized as JSON.
    pub scanners: serde_json::Value,

    /// Wall-clock duration of the evaluation in microseconds.
    pub duration_us: u64,

    /// SHA-256 hash of the input payload.
    pub input_hash: String,

    /// Raw payload (will be zstd-compressed when stored in SQLite).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Vec<u8>>,
}

impl AuditEvent {
    /// Compute the SHA-256 hex digest of an arbitrary byte slice.
    pub fn hash_input(data: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// AuditLog
// ---------------------------------------------------------------------------

/// Dual-write audit log: SQLite database + daily JSONL files.
pub struct AuditLog {
    conn: Connection,
    audit_dir: PathBuf,
    retention_days: u32,
}

impl std::fmt::Debug for AuditLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditLog")
            .field("audit_dir", &self.audit_dir)
            .field("retention_days", &self.retention_days)
            .finish_non_exhaustive()
    }
}

impl AuditLog {
    /// Open (or create) the audit log from the logging configuration.
    ///
    /// This creates the SQLite database, runs migrations, and ensures the
    /// JSONL audit directory exists.
    pub fn open(config: &LoggingConfig) -> Result<Self> {
        let sqlite_path = expand_tilde(&config.sqlite_path);
        let audit_dir = expand_tilde(&config.audit_dir);

        // Ensure parent directories exist.
        if let Some(parent) = Path::new(&sqlite_path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::create_dir_all(&audit_dir)?;

        let conn = Connection::open(&sqlite_path)?;
        let log = Self {
            conn,
            audit_dir: PathBuf::from(audit_dir),
            retention_days: config.retention_days,
        };
        log.migrate()?;
        Ok(log)
    }

    /// Open an in-memory audit log (for testing).
    pub fn open_in_memory() -> Result<Self> {
        let dir = std::env::temp_dir().join("aiguard-audit-test");
        fs::create_dir_all(&dir)?;
        let conn = Connection::open_in_memory()?;
        let log = Self {
            conn,
            audit_dir: dir,
            retention_days: 90,
        };
        log.migrate()?;
        Ok(log)
    }

    /// Run schema migrations.
    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS events (
                id          TEXT PRIMARY KEY,
                ts          TEXT NOT NULL,
                session_id  TEXT NOT NULL,
                agent       TEXT NOT NULL,
                stage       TEXT NOT NULL,
                tool_name   TEXT,
                decision    TEXT NOT NULL,
                scanners    TEXT NOT NULL,
                duration_us INTEGER NOT NULL,
                input_hash  TEXT NOT NULL,
                payload     BLOB
            );

            CREATE INDEX IF NOT EXISTS idx_events_session_ts
                ON events (session_id, ts);

            CREATE INDEX IF NOT EXISTS idx_events_decision_non_allow
                ON events (decision)
                WHERE decision != 'allow';
            ",
        )?;
        Ok(())
    }

    /// Record an audit event to both SQLite and the JSONL file.
    pub fn log_event(&self, event: &AuditEvent) -> Result<()> {
        self.write_sqlite(event)?;
        self.write_jsonl(event)?;
        Ok(())
    }

    /// Write the event to SQLite, compressing the payload with zstd.
    fn write_sqlite(&self, event: &AuditEvent) -> Result<()> {
        let compressed_payload: Option<Vec<u8>> = event
            .payload
            .as_ref()
            .map(|p| {
                zstd::encode_all(p.as_slice(), 3)
                    .map_err(|e| TetherError::Compression(e.to_string()))
            })
            .transpose()?;

        let scanners_json = serde_json::to_string(&event.scanners)?;

        self.conn.execute(
            "INSERT OR REPLACE INTO events
                (id, ts, session_id, agent, stage, tool_name, decision,
                 scanners, duration_us, input_hash, payload)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.id,
                event.ts,
                event.session_id,
                event.agent,
                event.stage,
                event.tool_name,
                event.decision,
                scanners_json,
                event.duration_us as i64,
                event.input_hash,
                compressed_payload,
            ],
        )?;
        Ok(())
    }

    /// Append the event as a single JSON line to today's JSONL file.
    fn write_jsonl(&self, event: &AuditEvent) -> Result<()> {
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let path = self.audit_dir.join(format!("{today}.jsonl"));

        let mut file = OpenOptions::new().create(true).append(true).open(&path)?;

        let line = serde_json::to_string(event)?;
        writeln!(file, "{line}")?;
        Ok(())
    }

    /// Query all events for a given session, ordered by timestamp.
    pub fn query_session(&self, session_id: &str) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                    scanners, duration_us, input_hash, payload
             FROM events
             WHERE session_id = ?1
             ORDER BY ts ASC",
        )?;

        let rows = stmt.query_map(params![session_id], |row| {
            Ok(RawRow {
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

        rows.map(|r| r.map_err(TetherError::from).and_then(raw_to_event))
            .collect()
    }

    /// Query events by decision type (e.g. "block", "mutate").
    pub fn query_by_decision(&self, decision: &str) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, ts, session_id, agent, stage, tool_name, decision,
                    scanners, duration_us, input_hash, payload
             FROM events
             WHERE decision = ?1
             ORDER BY ts DESC",
        )?;

        let rows = stmt.query_map(params![decision], |row| {
            Ok(RawRow {
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

        rows.map(|r| r.map_err(TetherError::from).and_then(raw_to_event))
            .collect()
    }

    /// Delete events older than `retention_days` from both SQLite and JSONL.
    pub fn prune(&self) -> Result<u64> {
        let cutoff = Utc::now() - chrono::Duration::days(i64::from(self.retention_days));
        let cutoff_str = cutoff.format("%Y-%m-%dT%H:%M:%S").to_string();

        // Prune SQLite
        let deleted = self
            .conn
            .execute("DELETE FROM events WHERE ts < ?1", params![cutoff_str])?
            as u64;

        // Prune old JSONL files
        let cutoff_date = cutoff.date_naive();
        self.prune_jsonl_files(cutoff_date)?;

        Ok(deleted)
    }

    /// Remove JSONL files whose date is before the cutoff.
    fn prune_jsonl_files(&self, cutoff: NaiveDate) -> Result<()> {
        let entries = fs::read_dir(&self.audit_dir)?;
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            // Files are named YYYY-MM-DD.jsonl
            if let Some(date_str) = name_str.strip_suffix(".jsonl") {
                if let Ok(date) = NaiveDate::parse_from_str(date_str, "%Y-%m-%d") {
                    if date < cutoff {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        }
        Ok(())
    }

    /// Decompress a zstd-compressed payload blob.
    pub fn decompress_payload(compressed: &[u8]) -> Result<Vec<u8>> {
        zstd::decode_all(compressed).map_err(|e| TetherError::Compression(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Intermediate row type for SQLite mapping.
struct RawRow {
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

fn raw_to_event(row: RawRow) -> Result<AuditEvent> {
    let scanners: serde_json::Value = serde_json::from_str(&row.scanners)?;

    // Decompress payload if present.
    let payload = row
        .payload
        .map(|compressed| AuditLog::decompress_payload(&compressed))
        .transpose()?;

    Ok(AuditEvent {
        id: row.id,
        ts: row.ts,
        session_id: row.session_id,
        agent: row.agent,
        stage: row.stage,
        tool_name: row.tool_name,
        decision: row.decision,
        scanners,
        duration_us: row.duration_us,
        input_hash: row.input_hash,
        payload,
    })
}

/// Expand a leading `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = directories::UserDirs::new() {
            return home.home_dir().join(rest).to_string_lossy().into_owned();
        }
    }
    path.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_event() -> AuditEvent {
        AuditEvent {
            id: uuid::Uuid::new_v4().to_string(),
            ts: Utc::now().to_rfc3339(),
            session_id: "test-session-1".into(),
            agent: "codex".into(),
            stage: "pre_tool".into(),
            tool_name: Some("bash".into()),
            decision: "allow".into(),
            scanners: serde_json::json!({"prompt_injection": "pass"}),
            duration_us: 1234,
            input_hash: AuditEvent::hash_input(b"echo hello"),
            payload: Some(b"echo hello".to_vec()),
        }
    }

    #[test]
    fn round_trip_in_memory() {
        let log = AuditLog::open_in_memory().unwrap();
        let event = sample_event();
        log.log_event(&event).unwrap();

        let events = log.query_session("test-session-1").unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, event.id);
        assert_eq!(events[0].agent, "codex");
        // Payload should be decompressed back to the original.
        assert_eq!(events[0].payload.as_deref(), Some(b"echo hello".as_ref()));
    }

    #[test]
    fn query_by_decision_works() {
        let log = AuditLog::open_in_memory().unwrap();

        let mut allow_event = sample_event();
        allow_event.decision = "allow".into();
        log.log_event(&allow_event).unwrap();

        let mut block_event = sample_event();
        block_event.id = uuid::Uuid::new_v4().to_string();
        block_event.decision = "block".into();
        log.log_event(&block_event).unwrap();

        let blocks = log.query_by_decision("block").unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].decision, "block");
    }

    #[test]
    fn hash_input_deterministic() {
        let h1 = AuditEvent::hash_input(b"hello");
        let h2 = AuditEvent::hash_input(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex is 64 chars
    }
}
