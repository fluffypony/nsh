use rusqlite::{Connection, params};

use crate::memory::types::{ResourceItem, generate_id};

fn row_to_item(row: &rusqlite::Row<'_>) -> rusqlite::Result<ResourceItem> {
    Ok(ResourceItem {
        id: row.get(0)?,
        resource_type: row.get(1)?,
        file_path: row.get(2)?,
        file_hash: row.get(3)?,
        title: row.get(4)?,
        summary: row.get(5)?,
        content: row.get(6)?,
        search_keywords: row.get(7)?,
        created_at: row.get(8)?,
        updated_at: row.get(9)?,
    })
}

pub fn insert(
    conn: &Connection,
    resource_type: &str,
    file_path: Option<&str>,
    file_hash: Option<&str>,
    title: &str,
    summary: &str,
    content: Option<&str>,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let id = generate_id("res");
    conn.execute(
        "INSERT INTO resource_memory (id, resource_type, file_path, file_hash, title, summary, content, search_keywords)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![id, resource_type, file_path, file_hash, title, summary, content, search_keywords],
    )?;
    Ok(id)
}

pub fn upsert_by_path(
    conn: &Connection,
    resource_type: &str,
    file_path: &str,
    file_hash: &str,
    title: &str,
    summary: &str,
    content: Option<&str>,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let existing: Option<String> = conn
        .query_row(
            "SELECT id FROM resource_memory WHERE file_path = ?",
            params![file_path],
            |r| r.get(0),
        )
        .ok();

    if let Some(id) = existing {
        conn.execute(
            "UPDATE resource_memory SET file_hash = ?, title = ?, summary = ?, content = ?, search_keywords = ?, updated_at = datetime('now')
             WHERE id = ?",
            params![file_hash, title, summary, content, search_keywords, id],
        )?;
        Ok(id)
    } else {
        insert(conn, resource_type, Some(file_path), Some(file_hash), title, summary, content, search_keywords)
    }
}

pub fn search_bm25(conn: &Connection, query: &str, limit: usize) -> anyhow::Result<Vec<ResourceItem>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }
    let mut stmt = conn.prepare(
        "SELECT r.id, r.resource_type, r.file_path, r.file_hash, r.title, r.summary, r.content, r.search_keywords, r.created_at, r.updated_at
         FROM resource_memory r
         JOIN resource_memory_fts f ON r.rowid = f.rowid
         WHERE resource_memory_fts MATCH ?
         ORDER BY bm25(resource_memory_fts, 10.0, 5.0, 1.0, 3.0) ASC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![fts_query, limit as i64], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn get_for_cwd(conn: &Connection, cwd: &str, limit: usize) -> anyhow::Result<Vec<ResourceItem>> {
    let pattern = format!("{cwd}%");
    let mut stmt = conn.prepare(
        "SELECT id, resource_type, file_path, file_hash, title, summary, content, search_keywords, created_at, updated_at
         FROM resource_memory
         WHERE file_path LIKE ?
         ORDER BY updated_at DESC
         LIMIT ?",
    )?;
    let rows = stmt.query_map(params![pattern, limit as i64], row_to_item)?;
    Ok(rows.filter_map(|r| r.ok()).collect())
}

pub fn exists_with_hash(conn: &Connection, path: &str, hash: &str) -> anyhow::Result<bool> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM resource_memory WHERE file_path = ? AND file_hash = ?",
            params![path, hash],
            |r| r.get(0),
        )
        .unwrap_or(false);
    Ok(exists)
}

pub fn delete(conn: &Connection, ids: &[String]) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in ids {
        count += conn.execute("DELETE FROM resource_memory WHERE id = ?", params![id])?;
    }
    Ok(count)
}

pub fn count(conn: &Connection) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM resource_memory", [], |r| r.get(0))?;
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
            "config",
            Some("/home/user/.gitconfig"),
            Some("abc123"),
            "Git config",
            "Git configuration with aliases and settings",
            Some("[alias]\nco = checkout"),
            "git config alias checkout",
        )
        .unwrap();

        let results = search_bm25(&conn, "git config", 10).unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn upsert_by_path_updates() {
        let conn = setup();
        let id1 = upsert_by_path(&conn, "file", "/tmp/test", "hash1", "Test", "Old", None, "test").unwrap();
        let id2 = upsert_by_path(&conn, "file", "/tmp/test", "hash2", "Test", "New", None, "test").unwrap();
        assert_eq!(id1, id2);
        assert_eq!(count(&conn).unwrap(), 1);
    }

    #[test]
    fn exists_with_hash_works() {
        let conn = setup();
        insert(&conn, "file", Some("/tmp/f"), Some("h1"), "t", "s", None, "k").unwrap();
        assert!(exists_with_hash(&conn, "/tmp/f", "h1").unwrap());
        assert!(!exists_with_hash(&conn, "/tmp/f", "h2").unwrap());
    }

    #[test]
    fn get_for_cwd_filters() {
        let conn = setup();
        insert(&conn, "file", Some("/home/user/project/Cargo.toml"), None, "Cargo", "manifest", None, "cargo").unwrap();
        insert(&conn, "file", Some("/other/path/file"), None, "Other", "other", None, "other").unwrap();

        let results = get_for_cwd(&conn, "/home/user/project", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "Cargo");
    }
}
