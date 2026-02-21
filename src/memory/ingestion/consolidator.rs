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

    let neg = format!("-{}", time_window_secs);
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
}
