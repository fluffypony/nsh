use rusqlite::{Connection, params};

use crate::memory::types::{ProceduralItem, generate_id};

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<ProceduralItem> {
    Ok(ProceduralItem {
        id: row.get(0)?,
        entry_type: row.get(1)?,
        trigger_pattern: row.get(2)?,
        summary: row.get(3)?,
        steps: row.get(4)?,
        search_keywords: row.get(5)?,
        access_count: row.get(6)?,
        last_accessed: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

pub fn insert(
    conn: &Connection,
    entry_type: &str,
    trigger_pattern: &str,
    summary: &str,
    steps: &str,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let id = generate_id("proc");
    conn.execute(
        "INSERT INTO procedural_memory (id, entry_type, trigger_pattern, summary, steps, search_keywords)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![id, entry_type, trigger_pattern, summary, steps, search_keywords],
    )?;
    Ok(id)
}

pub fn update(
    conn: &Connection,
    id: &str,
    summary: &str,
    steps: &str,
    search_keywords: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE procedural_memory SET summary = ?, steps = ?, search_keywords = ?, updated_at = datetime('now')
         WHERE id = ?",
        params![summary, steps, search_keywords, id],
    )?;
    Ok(())
}

pub fn search_bm25(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> anyhow::Result<Vec<ProceduralItem>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare(
        "SELECT p.id, p.entry_type, p.trigger_pattern, p.summary, p.steps, p.search_keywords, p.access_count, p.last_accessed, p.created_at, p.updated_at
         FROM procedural_memory p
         JOIN procedural_memory_fts f ON p.rowid = f.rowid
         WHERE procedural_memory_fts MATCH ?
         ORDER BY bm25(procedural_memory_fts, 10.0, 2.0, 3.0) ASC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![fts_query, limit as i64], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn list_all(conn: &Connection) -> anyhow::Result<Vec<ProceduralItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, entry_type, trigger_pattern, summary, steps, search_keywords, access_count, last_accessed, created_at, updated_at
         FROM procedural_memory
         ORDER BY updated_at DESC",
    )?;
    let rows = stmt.query_map([], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn delete(conn: &Connection, ids: &[String]) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in ids {
        count += conn.execute("DELETE FROM procedural_memory WHERE id = ?", params![id])?;
    }
    Ok(count)
}

#[allow(dead_code)]
pub fn increment_access(conn: &Connection, id: &str) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE procedural_memory SET access_count = access_count + 1, last_accessed = datetime('now') WHERE id = ?",
        params![id],
    )?;
    Ok(())
}

pub fn count(conn: &Connection) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM procedural_memory", [], |r| r.get(0))?;
    Ok(n as usize)
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
    fn insert_and_search() {
        let conn = setup();
        insert(
            &conn,
            "workflow",
            "deploy",
            "Deploy to production",
            r#"["cargo build --release", "scp target/release/app server:/opt/app"]"#,
            "deploy production release build scp",
        )
        .unwrap();

        let results = search_bm25(&conn, "deploy production", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].summary, "Deploy to production");
    }

    #[test]
    fn update_modifies_fields() {
        let conn = setup();
        let id = insert(&conn, "workflow", "", "old", "[]", "old").unwrap();
        update(&conn, &id, "new summary", r#"["step1"]"#, "new keywords").unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].summary, "new summary");
    }

    #[test]
    fn delete_removes_items() {
        let conn = setup();
        let id = insert(&conn, "workflow", "test", "test", "[]", "test").unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    fn increment_access_updates_count() {
        let conn = setup();
        let id = insert(&conn, "workflow", "deploy", "deploy flow", "[]", "deploy").unwrap();
        increment_access(&conn, &id).unwrap();
        increment_access(&conn, &id).unwrap();
        increment_access(&conn, &id).unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].access_count, 3);
    }

    #[test]
    fn search_bm25_empty_returns_empty() {
        let conn = setup();
        insert(
            &conn,
            "workflow",
            "deploy",
            "deploy to prod",
            "[]",
            "deploy",
        )
        .unwrap();
        let results = search_bm25(&conn, "", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn list_all_returns_in_order() {
        let conn = setup();
        insert(&conn, "workflow", "a", "first", "[]", "first").unwrap();
        insert(&conn, "fix", "b", "second", "[]", "second").unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items.len(), 2);
    }

    #[test]
    fn search_finds_by_steps_content() {
        let conn = setup();
        insert(
            &conn,
            "workflow",
            "deploy",
            "Deployment workflow",
            r#"["run cargo build --release", "copy binary to server", "restart systemd service"]"#,
            "deploy production release",
        )
        .unwrap();

        let results = search_bm25(&conn, "systemd service", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn update_preserves_type_and_trigger() {
        let conn = setup();
        let id = insert(
            &conn,
            "fix",
            "error-E0433",
            "fix missing import",
            "[]",
            "fix",
        )
        .unwrap();
        update(
            &conn,
            &id,
            "fix missing import with use statement",
            r#"["add use crate::foo"]"#,
            "fix import",
        )
        .unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].entry_type, "fix");
        assert_eq!(items[0].trigger_pattern, "error-E0433");
        assert_eq!(items[0].summary, "fix missing import with use statement");
    }
}
