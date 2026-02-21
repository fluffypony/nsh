use rusqlite::{Connection, params};

use crate::memory::types::DecayReport;

pub fn run_decay(
    conn: &Connection,
    fade_after_days: u32,
    expire_after_days: u32,
) -> anyhow::Result<DecayReport> {
    let mut report = DecayReport::default();

    let expire_cutoff = format!("-{} days", expire_after_days);

    // Episodic: expire by occurred_at
    report.episodic_deleted = conn.execute(
        "DELETE FROM episodic_memory WHERE occurred_at < datetime('now', ?)",
        params![expire_cutoff],
    )? as usize;

    // Semantic: expire by updated_at
    report.semantic_deleted = conn.execute(
        "DELETE FROM semantic_memory WHERE updated_at < datetime('now', ?) AND access_count < 3",
        params![expire_cutoff],
    )? as usize;

    // Procedural: expire by updated_at
    report.procedural_deleted = conn.execute(
        "DELETE FROM procedural_memory WHERE updated_at < datetime('now', ?) AND access_count < 3",
        params![expire_cutoff],
    )? as usize;

    // Resource: expire by updated_at
    report.resource_deleted = conn.execute(
        "DELETE FROM resource_memory WHERE updated_at < datetime('now', ?)",
        params![expire_cutoff],
    )? as usize;

    // Knowledge: expire by updated_at (only low sensitivity)
    report.knowledge_deleted = conn.execute(
        "DELETE FROM knowledge_vault WHERE updated_at < datetime('now', ?) AND sensitivity = 'low'",
        params![expire_cutoff],
    )? as usize;

    // Record last decay time
    conn.execute(
        "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_decay_at', datetime('now'))",
        [],
    )?;

    Ok(report)
}

pub fn get_fade_cutoff(conn: &Connection, fade_after_days: u32) -> anyhow::Result<String> {
    let cutoff: String = conn.query_row(
        "SELECT datetime('now', ? || ' days')",
        params![-(fade_after_days as i64)],
        |r| r.get(0),
    )?;
    Ok(cutoff)
}

pub fn should_run_decay(conn: &Connection) -> bool {
    let last: Option<String> = conn
        .query_row(
            "SELECT value FROM memory_config WHERE key = 'last_decay_at'",
            [],
            |r| r.get(0),
        )
        .ok();

    match last {
        Some(ts) if !ts.is_empty() => {
            // Run if last decay was more than 24 hours ago
            let should: bool = conn
                .query_row(
                    "SELECT datetime('now', '-24 hours') > ?",
                    params![ts],
                    |r| r.get(0),
                )
                .unwrap_or(true);
            should
        }
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::schema::create_memory_tables;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();
        conn
    }

    #[test]
    fn run_decay_empty_db() {
        let conn = setup();
        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(report.episodic_deleted, 0);
        assert_eq!(report.semantic_deleted, 0);
    }

    #[test]
    fn should_run_decay_initially_true() {
        let conn = setup();
        assert!(should_run_decay(&conn));
    }

    #[test]
    fn should_run_decay_after_recent_run() {
        let conn = setup();
        run_decay(&conn, 30, 90).unwrap();
        assert!(!should_run_decay(&conn));
    }

    #[test]
    fn get_fade_cutoff_returns_date() {
        let conn = setup();
        let cutoff = get_fade_cutoff(&conn, 30).unwrap();
        assert!(!cutoff.is_empty());
    }
}
