use rusqlite::{Connection, params};

use crate::memory::types::DecayReport;

pub fn run_decay(
    conn: &Connection,
    _fade_after_days: u32,
    expire_after_days: u32,
) -> anyhow::Result<DecayReport> {
    let mut report = DecayReport::default();

    let expire_cutoff = format!("-{expire_after_days} days");

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

    #[test]
    fn decay_expires_old_episodic() {
        let conn = setup();
        // Insert an episodic event with a very old timestamp
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_OLD', 'command_execution', 'user', 'old event', 'old', datetime('now', '-100 days'))",
            [],
        ).unwrap();
        // Insert a recent one
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_NEW', 'command_execution', 'user', 'new event', 'new', datetime('now'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.episodic_deleted, 1,
            "old episodic event should be deleted"
        );

        // The recent one should survive
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM episodic_memory", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn decay_preserves_high_access_semantic() {
        let conn = setup();
        // Insert a semantic item with old update time but high access count
        conn.execute(
            "INSERT INTO semantic_memory (id, name, category, summary, search_keywords, access_count, updated_at)
             VALUES ('sem_HI', 'important fact', 'general', 'very important', 'important', 10, datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.semantic_deleted, 0,
            "high-access semantic items should be preserved"
        );
    }

    #[test]
    fn decay_expires_low_access_semantic() {
        let conn = setup();
        // Insert a semantic item with old update time and low access count
        conn.execute(
            "INSERT INTO semantic_memory (id, name, category, summary, search_keywords, access_count, updated_at)
             VALUES ('sem_LO', 'trivial fact', 'general', 'not important', 'trivial', 1, datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.semantic_deleted, 1,
            "low-access old semantic items should be deleted"
        );
    }

    #[test]
    fn decay_preserves_high_access_procedural() {
        let conn = setup();
        conn.execute(
            "INSERT INTO procedural_memory (id, entry_type, trigger_pattern, summary, steps, search_keywords, access_count, updated_at)
             VALUES ('proc_HI', 'workflow', 'deploy', 'deploy flow', '[]', 'deploy', 5, datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.procedural_deleted, 0,
            "high-access procedural items should be preserved"
        );
    }

    #[test]
    fn decay_expires_low_access_procedural() {
        let conn = setup();
        conn.execute(
            "INSERT INTO procedural_memory (id, entry_type, trigger_pattern, summary, steps, search_keywords, access_count, updated_at)
             VALUES ('proc_LO', 'workflow', 'test', 'test flow', '[]', 'test', 0, datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.procedural_deleted, 1,
            "low-access old procedural items should be deleted"
        );
    }

    #[test]
    fn decay_expires_old_resource() {
        let conn = setup();
        conn.execute(
            "INSERT INTO resource_memory (id, resource_type, title, summary, search_keywords, updated_at)
             VALUES ('res_OLD', 'file', 'old file', 'old', 'old', datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.resource_deleted, 1,
            "old resource items should be deleted"
        );
    }

    #[test]
    fn decay_preserves_recent_resource() {
        let conn = setup();
        conn.execute(
            "INSERT INTO resource_memory (id, resource_type, title, summary, search_keywords, updated_at)
             VALUES ('res_NEW', 'file', 'new file', 'new', 'new', datetime('now'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(report.resource_deleted, 0);
    }

    #[test]
    fn decay_expires_low_sensitivity_knowledge() {
        let conn = setup();
        conn.execute(
            "INSERT INTO knowledge_vault (id, entry_type, caption, secret_value, sensitivity, search_keywords, updated_at)
             VALUES ('kv_LOW', 'cred', 'old low secret', 'enc', 'low', 'test', datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.knowledge_deleted, 1,
            "old low-sensitivity knowledge should be deleted"
        );
    }

    #[test]
    fn decay_preserves_medium_sensitivity_knowledge() {
        let conn = setup();
        conn.execute(
            "INSERT INTO knowledge_vault (id, entry_type, caption, secret_value, sensitivity, search_keywords, updated_at)
             VALUES ('kv_MED', 'cred', 'medium secret', 'enc', 'medium', 'test', datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.knowledge_deleted, 0,
            "medium/high sensitivity knowledge should be preserved"
        );
    }

    #[test]
    fn decay_preserves_high_sensitivity_knowledge() {
        let conn = setup();
        conn.execute(
            "INSERT INTO knowledge_vault (id, entry_type, caption, secret_value, sensitivity, search_keywords, updated_at)
             VALUES ('kv_HI', 'cred', 'high secret', 'enc', 'high', 'test', datetime('now', '-100 days'))",
            [],
        ).unwrap();

        let report = run_decay(&conn, 30, 90).unwrap();
        assert_eq!(
            report.knowledge_deleted, 0,
            "high sensitivity knowledge should be preserved"
        );
    }

    #[test]
    fn decay_records_last_decay_timestamp() {
        let conn = setup();
        run_decay(&conn, 30, 90).unwrap();

        let last: String = conn
            .query_row(
                "SELECT value FROM memory_config WHERE key = 'last_decay_at'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!last.is_empty(), "last_decay_at should be set");
    }

    #[test]
    fn decay_custom_expire_days() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_OLD2', 'command_execution', 'user', 'old', 'old', datetime('now', '-10 days'))",
            [],
        ).unwrap();

        // With expire_after_days=5, the 10-day-old event should be deleted
        let report = run_decay(&conn, 3, 5).unwrap();
        assert_eq!(report.episodic_deleted, 1);
    }

    #[test]
    fn fade_cutoff_changes_with_days() {
        let conn = setup();
        let cutoff_30 = get_fade_cutoff(&conn, 30).unwrap();
        let cutoff_60 = get_fade_cutoff(&conn, 60).unwrap();
        // 60-day cutoff should be earlier than 30-day cutoff
        assert!(
            cutoff_60 < cutoff_30,
            "60-day cutoff should be earlier than 30-day"
        );
    }

    #[test]
    fn should_run_decay_false_after_recent() {
        let conn = setup();
        // Mark as recently run
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_decay_at', datetime('now'))",
            [],
        ).unwrap();
        assert!(
            !should_run_decay(&conn),
            "should not run decay if recently run"
        );
    }

    #[test]
    fn should_run_decay_true_when_old() {
        let conn = setup();
        // Mark as run 2 days ago
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_decay_at', datetime('now', '-48 hours'))",
            [],
        ).unwrap();
        assert!(
            should_run_decay(&conn),
            "should run decay if last run > 24 hours ago"
        );
    }
}
