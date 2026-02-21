use rusqlite::{Connection, params};

pub fn find_merge_candidate(
    conn: &Connection,
    new_summary: &str,
    time_window_secs: i64,
) -> anyhow::Result<Option<String>> {
    let mut stmt = conn.prepare(
        "SELECT id, summary FROM episodic_memory
         WHERE occurred_at >= datetime('now', ? || ' seconds')
         ORDER BY occurred_at DESC
         LIMIT 20",
    )?;

    let neg = format!("-{time_window_secs}");
    let rows: Vec<(String, String)> = stmt
        .query_map(params![neg], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .filter_map(|r| r.ok())
        .collect();

    for (id, existing_summary) in &rows {
        let similarity = strsim::jaro_winkler(new_summary, existing_summary);
        if similarity > 0.85 {
            return Ok(Some(id.clone()));
        }
    }

    Ok(None)
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
    fn no_candidate_empty_db() {
        let conn = setup();
        let result = find_merge_candidate(&conn, "ran cargo build", 30).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn finds_similar_recent() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_TEST', 'command_execution', 'user', 'Ran cargo build successfully', 'cargo build', datetime('now'))",
            [],
        ).unwrap();

        let result = find_merge_candidate(&conn, "Ran cargo build successfully with output", 30).unwrap();
        assert_eq!(result, Some("ep_TEST".to_string()));
    }

    #[test]
    fn rejects_dissimilar() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_TEST', 'command_execution', 'user', 'Installed npm packages', 'npm install', datetime('now'))",
            [],
        ).unwrap();

        let result = find_merge_candidate(&conn, "Ran cargo build", 30).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn finds_exact_match() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_EXACT', 'command_execution', 'user', 'Ran cargo build', 'cargo build', datetime('now'))",
            [],
        ).unwrap();

        let result = find_merge_candidate(&conn, "Ran cargo build", 30).unwrap();
        assert_eq!(result, Some("ep_EXACT".to_string()), "exact match should be found");
    }

    #[test]
    fn similarity_threshold_boundary() {
        let conn = setup();
        // Insert a moderately similar string
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_SIM', 'command_execution', 'user', 'Compiled the Rust application', 'rust compile', datetime('now'))",
            [],
        ).unwrap();

        // Very different string should not match (Jaro-Winkler < 0.85)
        let result = find_merge_candidate(&conn, "Deployed Docker container to production", 30).unwrap();
        assert!(result.is_none(), "dissimilar strings should not match");
    }

    #[test]
    fn time_window_excludes_old() {
        let conn = setup();
        // Insert an event from 60 seconds ago
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_OLD', 'command_execution', 'user', 'Ran cargo build', 'cargo build', datetime('now', '-60 seconds'))",
            [],
        ).unwrap();

        // With a 30-second window, the 60-second-old event should not be found
        let result = find_merge_candidate(&conn, "Ran cargo build", 30).unwrap();
        assert!(result.is_none(), "events outside time window should not match");
    }

    #[test]
    fn picks_most_recent_match() {
        let conn = setup();
        // Insert two similar events at different times
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_OLDER', 'command_execution', 'user', 'Ran cargo build successfully', 'cargo build', datetime('now', '-10 seconds'))",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_NEWER', 'command_execution', 'user', 'Ran cargo build successfully', 'cargo build', datetime('now', '-5 seconds'))",
            [],
        ).unwrap();

        // The query is sorted DESC by occurred_at, so most recent should be checked first
        let result = find_merge_candidate(&conn, "Ran cargo build successfully with output", 30).unwrap();
        assert_eq!(result, Some("ep_NEWER".to_string()), "should pick most recent match");
    }

    #[test]
    fn handles_special_characters() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_SPEC', 'command_execution', 'user', 'Ran `cargo build` with --release flag', 'cargo build', datetime('now'))",
            [],
        ).unwrap();

        let result = find_merge_candidate(&conn, "Ran `cargo build` with --release flag successfully", 30).unwrap();
        assert_eq!(result, Some("ep_SPEC".to_string()));
    }

    #[test]
    fn empty_summary_no_match() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_EMPTY', 'command_execution', 'user', '', 'test', datetime('now'))",
            [],
        ).unwrap();

        let result = find_merge_candidate(&conn, "Ran cargo build", 30).unwrap();
        assert!(result.is_none(), "empty summaries should not match");
    }

    #[test]
    fn large_time_window() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_WIDE', 'command_execution', 'user', 'Ran cargo build', 'cargo', datetime('now', '-300 seconds'))",
            [],
        ).unwrap();

        // With a 600-second window, the 300-second-old event should be found
        let result = find_merge_candidate(&conn, "Ran cargo build", 600).unwrap();
        assert_eq!(result, Some("ep_WIDE".to_string()));
    }

    #[test]
    fn jaro_winkler_slightly_different() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords, occurred_at)
             VALUES ('ep_CLOSE', 'command_execution', 'user', 'Ran cargo build (exit 0)', 'cargo', datetime('now'))",
            [],
        ).unwrap();

        // Slight variation should still match (Jaro-Winkler > 0.85)
        let result = find_merge_candidate(&conn, "Ran cargo build (exit 1)", 30).unwrap();
        assert!(result.is_some(), "slight variations should still match with Jaro-Winkler > 0.85");
    }
}
