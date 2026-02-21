use rusqlite::{Connection, params};

use crate::memory::types::{SemanticItem, generate_id};

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<SemanticItem> {
    Ok(SemanticItem {
        id: row.get(0)?,
        name: row.get(1)?,
        category: row.get(2)?,
        summary: row.get(3)?,
        details: row.get(4)?,
        search_keywords: row.get(5)?,
        access_count: row.get(6)?,
        last_accessed: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

pub fn insert_or_update(
    conn: &Connection,
    name: &str,
    category: &str,
    summary: &str,
    details: Option<&str>,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM semantic_memory WHERE name = ?",
            params![name],
            |r| r.get(0),
        )
        .ok();

    if let Some(id) = existing {
        conn.execute(
            "UPDATE semantic_memory SET summary = ?, details = ?, search_keywords = ?, category = ?, updated_at = datetime('now')
             WHERE id = ?",
            params![summary, details, search_keywords, category, id],
        )?;
        Ok(id)
    } else {
        let id = generate_id("sem");
        conn.execute(
            "INSERT INTO semantic_memory (id, name, category, summary, details, search_keywords)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![id, name, category, summary, details, search_keywords],
        )?;
        Ok(id)
    }
}

pub fn search_bm25(conn: &Connection, query: &str, limit: usize) -> anyhow::Result<Vec<SemanticItem>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare(
        "SELECT s.id, s.name, s.category, s.summary, s.details, s.search_keywords, s.access_count, s.last_accessed, s.created_at, s.updated_at
         FROM semantic_memory s
         JOIN semantic_memory_fts f ON s.rowid = f.rowid
         WHERE semantic_memory_fts MATCH ?
         ORDER BY bm25(semantic_memory_fts, 10.0, 5.0, 1.0, 3.0) ASC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![fts_query, limit as i64], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

#[allow(dead_code)]
pub fn list_recent(conn: &Connection, limit: usize) -> anyhow::Result<Vec<SemanticItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, category, summary, details, search_keywords, access_count, last_accessed, created_at, updated_at
         FROM semantic_memory
         ORDER BY updated_at DESC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![limit as i64], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn list_all(conn: &Connection) -> anyhow::Result<Vec<SemanticItem>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, category, summary, details, search_keywords, access_count, last_accessed, created_at, updated_at
         FROM semantic_memory
         ORDER BY name",
    )?;
    let rows = stmt.query_map([], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn update_by_id(
    conn: &Connection,
    id: &str,
    summary: &str,
    details: Option<&str>,
    search_keywords: &str,
) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE semantic_memory SET summary = ?, details = ?, search_keywords = ?, updated_at = datetime('now')
         WHERE id = ?",
        params![summary, details, search_keywords, id],
    )?;
    Ok(())
}

pub fn delete(conn: &Connection, ids: &[String]) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in ids {
        count += conn.execute("DELETE FROM semantic_memory WHERE id = ?", params![id])?;
    }
    Ok(count)
}

pub fn increment_access(conn: &Connection, id: &str) -> anyhow::Result<()> {
    conn.execute(
        "UPDATE semantic_memory SET access_count = access_count + 1, last_accessed = datetime('now') WHERE id = ?",
        params![id],
    )?;
    Ok(())
}

pub fn count(conn: &Connection) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM semantic_memory", [], |r| r.get(0))?;
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
        insert_or_update(
            &conn,
            "Rust project structure",
            "knowledge",
            "The project uses Cargo workspaces with multiple crates",
            None,
            "rust cargo workspace crate project structure",
        )
        .unwrap();

        let results = search_bm25(&conn, "cargo workspace", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Rust project structure");
    }

    #[test]
    fn insert_or_update_deduplicates() {
        let conn = setup();
        let id1 = insert_or_update(&conn, "fact", "general", "old", None, "fact").unwrap();
        let id2 = insert_or_update(&conn, "fact", "general", "new", None, "fact").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(count(&conn).unwrap(), 1);

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].summary, "new");
    }

    #[test]
    fn increment_access_updates_count() {
        let conn = setup();
        let id = insert_or_update(&conn, "item", "general", "test", None, "test").unwrap();
        increment_access(&conn, &id).unwrap();
        increment_access(&conn, &id).unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].access_count, 2);
    }

    #[test]
    fn delete_removes_items() {
        let conn = setup();
        let id = insert_or_update(&conn, "fact", "general", "test", None, "test").unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    fn list_recent_ordered_by_updated_at() {
        let conn = setup();
        insert_or_update(&conn, "first", "general", "first fact", None, "first").unwrap();
        insert_or_update(&conn, "second", "general", "second fact", None, "second").unwrap();

        let items = list_recent(&conn, 10).unwrap();
        assert_eq!(items.len(), 2);
        // Most recently updated should come first
    }

    #[test]
    fn update_by_id_modifies_fields() {
        let conn = setup();
        let id = insert_or_update(&conn, "fact", "general", "old summary", None, "old").unwrap();
        update_by_id(&conn, &id, "new summary", Some("new details"), "new keywords").unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].summary, "new summary");
        assert_eq!(items[0].details.as_ref().unwrap(), "new details");
        assert_eq!(items[0].search_keywords, "new keywords");
    }

    #[test]
    fn search_bm25_empty_query() {
        let conn = setup();
        insert_or_update(&conn, "fact", "general", "test", None, "test").unwrap();
        let results = search_bm25(&conn, "", 10).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn insert_or_update_preserves_category_on_update() {
        let conn = setup();
        insert_or_update(&conn, "fact", "tools", "original", None, "fact").unwrap();
        insert_or_update(&conn, "fact", "knowledge", "updated", None, "fact").unwrap();

        let items = list_all(&conn).unwrap();
        assert_eq!(items[0].category, "knowledge", "category should be updated");
        assert_eq!(items[0].summary, "updated");
    }

    #[test]
    fn search_finds_by_name() {
        let conn = setup();
        insert_or_update(&conn, "Docker compose setup", "tools", "Uses docker-compose for local dev", None, "docker compose").unwrap();

        let results = search_bm25(&conn, "Docker", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "Docker compose setup");
    }

    #[test]
    fn multiple_facts_searchable() {
        let conn = setup();
        insert_or_update(&conn, "Rust toolchain", "tools", "Uses Rust 2024 edition", None, "rust toolchain").unwrap();
        insert_or_update(&conn, "Python environment", "tools", "Uses Python 3.12 with venv", None, "python venv").unwrap();

        let rust = search_bm25(&conn, "rust", 10).unwrap();
        assert_eq!(rust.len(), 1);
        assert_eq!(rust[0].name, "Rust toolchain");

        let python = search_bm25(&conn, "python", 10).unwrap();
        assert_eq!(python.len(), 1);
        assert_eq!(python[0].name, "Python environment");
    }
}
