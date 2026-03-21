use rusqlite::{Connection, params};

use crate::memory::types::{KnowledgeEntry, Sensitivity, generate_id};

pub struct KnowledgeWrite<'a> {
    pub entry_type: &'a str,
    pub caption: &'a str,
    pub secret_value: &'a str,
    pub sensitivity: Sensitivity,
    pub search_keywords: &'a str,
}

pub fn store(conn: &Connection, write: &KnowledgeWrite<'_>) -> anyhow::Result<String> {
    insert(
        conn,
        write.entry_type,
        write.caption,
        write.secret_value,
        write.sensitivity,
        write.search_keywords,
    )
}

fn insert(
    conn: &Connection,
    entry_type: &str,
    caption: &str,
    secret_value: &str,
    sensitivity: Sensitivity,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let encrypted = super::knowledge_crypto::encrypt_secret(secret_value)?;
    let id = generate_id("kv");
    conn.execute(
        "INSERT INTO knowledge_vault (id, entry_type, caption, secret_value, sensitivity, search_keywords)
         VALUES (?, ?, ?, ?, ?, ?)",
        params![id, entry_type, caption, encrypted, sensitivity.as_str(), search_keywords],
    )?;
    Ok(id)
}

pub fn search_bm25(
    conn: &Connection,
    query: &str,
    limit: usize,
    max_sensitivity: Sensitivity,
) -> anyhow::Result<Vec<KnowledgeEntry>> {
    let fts_query = crate::memory::search::fts::build_fts5_query(query);
    if fts_query.is_empty() {
        return Ok(vec![]);
    }

    let allowed: Vec<&str> = match max_sensitivity {
        Sensitivity::Low => vec!["low"],
        Sensitivity::Medium => vec!["low", "medium"],
        Sensitivity::High => vec!["low", "medium", "high"],
    };

    let placeholders: Vec<String> = allowed.iter().map(|_| "?".to_string()).collect();
    let sql = format!(
        "SELECT k.id, k.entry_type, k.caption, '' as secret_value, k.sensitivity, k.search_keywords, k.created_at, k.updated_at
         FROM knowledge_vault k
         JOIN knowledge_vault_fts f ON k.rowid = f.rowid
         WHERE knowledge_vault_fts MATCH ?1
         AND k.sensitivity IN ({})
         ORDER BY bm25(knowledge_vault_fts, 10.0, 3.0) ASC
         LIMIT ?{}",
        placeholders.join(", "),
        allowed.len() + 2
    );

    let mut stmt = conn.prepare(&sql)?;
    let mut param_idx = 1;
    stmt.raw_bind_parameter(param_idx, &fts_query)?;
    param_idx += 1;
    for s in &allowed {
        stmt.raw_bind_parameter(param_idx, s)?;
        param_idx += 1;
    }
    stmt.raw_bind_parameter(param_idx, limit as i64)?;

    let mut results = Vec::new();
    let mut rows = stmt.raw_query();
    while let Some(row) = rows.next()? {
        results.push(KnowledgeEntry {
            id: row.get(0)?,
            entry_type: row.get(1)?,
            caption: row.get(2)?,
            secret_value: String::new(), // never return encrypted value in search
            sensitivity: Sensitivity::parse(&row.get::<_, String>(4)?)?,
            search_keywords: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        });
    }
    Ok(results)
}

pub fn list_all(conn: &Connection) -> anyhow::Result<Vec<KnowledgeEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, entry_type, caption, '' as secret_value, sensitivity, search_keywords, created_at, updated_at
         FROM knowledge_vault
         ORDER BY created_at DESC",
    )?;
    let mut results = Vec::new();
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        results.push(KnowledgeEntry {
            id: row.get(0)?,
            entry_type: row.get(1)?,
            caption: row.get(2)?,
            secret_value: String::new(),
            sensitivity: Sensitivity::parse(&row.get::<_, String>(4)?)?,
            search_keywords: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        });
    }
    Ok(results)
}

/// Retrieve and decrypt a single secret by ID.
pub fn retrieve_secret(conn: &Connection, id: &str) -> anyhow::Result<String> {
    let encrypted: String = conn.query_row(
        "SELECT secret_value FROM knowledge_vault WHERE id = ?",
        params![id],
        |r| r.get(0),
    )?;
    super::knowledge_crypto::decrypt_secret(&encrypted)
}

pub fn delete(conn: &Connection, ids: &[String]) -> anyhow::Result<usize> {
    let mut count = 0;
    for id in ids {
        count += conn.execute("DELETE FROM knowledge_vault WHERE id = ?", params![id])?;
    }
    Ok(count)
}

pub fn count(conn: &Connection) -> anyhow::Result<usize> {
    let n: i64 = conn.query_row("SELECT COUNT(*) FROM knowledge_vault", [], |r| r.get(0))?;
    Ok(n as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::schema::create_memory_tables;
    use serial_test::serial;

    fn setup() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        create_memory_tables(&conn).unwrap();
        conn
    }

    #[test]
    #[serial]
    fn encrypt_decrypt_roundtrip() {
        let original = "my-secret-api-key-12345";
        let encrypted = super::super::knowledge_crypto::encrypt_secret(original).unwrap();
        assert_ne!(encrypted, original);
        let decrypted = super::super::knowledge_crypto::decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    #[serial]
    fn insert_and_retrieve_secret() {
        let conn = setup();
        let id = insert(
            &conn,
            "api_key",
            "OpenRouter API key",
            "sk-or-test-12345",
            Sensitivity::High,
            "openrouter api key",
        )
        .unwrap();

        let secret = retrieve_secret(&conn, &id).unwrap();
        assert_eq!(secret, "sk-or-test-12345");
    }

    #[test]
    #[serial]
    fn search_never_returns_secret_value() {
        let conn = setup();
        insert(
            &conn,
            "credential",
            "Database password for staging",
            "super-secret-password",
            Sensitivity::Medium,
            "database password staging",
        )
        .unwrap();

        let results = search_bm25(&conn, "database password", 10, Sensitivity::Medium).unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].secret_value.is_empty());
        assert_eq!(results[0].caption, "Database password for staging");
    }

    #[test]
    #[serial]
    fn search_filters_by_sensitivity() {
        let conn = setup();
        insert(
            &conn,
            "cred",
            "Low secret",
            "val",
            Sensitivity::Low,
            "low test",
        )
        .unwrap();
        insert(
            &conn,
            "cred",
            "High secret",
            "val",
            Sensitivity::High,
            "high test",
        )
        .unwrap();

        let low_only = search_bm25(&conn, "test", 10, Sensitivity::Low).unwrap();
        assert_eq!(low_only.len(), 1);
        assert_eq!(low_only[0].caption, "Low secret");

        let all = search_bm25(&conn, "test", 10, Sensitivity::High).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    #[serial]
    fn delete_removes_entries() {
        let conn = setup();
        let id = insert(
            &conn,
            "cred",
            "test secret",
            "value",
            Sensitivity::Low,
            "test",
        )
        .unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    #[serial]
    fn multiple_secrets_independent() {
        let conn = setup();
        let id1 = insert(
            &conn,
            "api_key",
            "GitHub token",
            "ghp_abc123",
            Sensitivity::High,
            "github token",
        )
        .unwrap();
        let id2 = insert(
            &conn,
            "password",
            "DB password",
            "supersecret",
            Sensitivity::Medium,
            "database password",
        )
        .unwrap();

        assert_ne!(id1, id2);
        assert_eq!(count(&conn).unwrap(), 2);

        let secret1 = retrieve_secret(&conn, &id1).unwrap();
        let secret2 = retrieve_secret(&conn, &id2).unwrap();
        assert_eq!(secret1, "ghp_abc123");
        assert_eq!(secret2, "supersecret");
    }

    #[test]
    #[serial]
    fn encrypt_different_each_time() {
        // Same plaintext should produce different ciphertext due to random nonce
        let enc1 = super::super::knowledge_crypto::encrypt_secret("test-value").unwrap();
        let enc2 = super::super::knowledge_crypto::encrypt_secret("test-value").unwrap();
        assert_ne!(enc1, enc2, "encryption should use random nonce");

        // But both should decrypt to the same value
        let dec1 = super::super::knowledge_crypto::decrypt_secret(&enc1).unwrap();
        let dec2 = super::super::knowledge_crypto::decrypt_secret(&enc2).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, "test-value");
    }

    #[test]
    #[serial]
    fn encrypt_empty_string() {
        let encrypted = super::super::knowledge_crypto::encrypt_secret("").unwrap();
        let decrypted = super::super::knowledge_crypto::decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    #[serial]
    fn encrypt_long_secret() {
        let long_secret = "a".repeat(10000);
        let encrypted = super::super::knowledge_crypto::encrypt_secret(&long_secret).unwrap();
        let decrypted = super::super::knowledge_crypto::decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, long_secret);
    }

    #[test]
    #[serial]
    fn encrypt_special_characters() {
        let special = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
        let encrypted = super::super::knowledge_crypto::encrypt_secret(special).unwrap();
        let decrypted = super::super::knowledge_crypto::decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, special);
    }

    #[test]
    #[serial]
    fn encrypt_unicode() {
        let unicode = "密码 пароль パスワード 🔑🔐";
        let encrypted = super::super::knowledge_crypto::encrypt_secret(unicode).unwrap();
        let decrypted = super::super::knowledge_crypto::decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, unicode);
    }

    #[test]
    #[serial]
    fn decrypt_invalid_hex_fails() {
        let result = super::super::knowledge_crypto::decrypt_secret("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn decrypt_too_short_fails() {
        let result = super::super::knowledge_crypto::decrypt_secret("aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    #[serial]
    fn search_bm25_empty_query() {
        let conn = setup();
        insert(&conn, "cred", "test", "val", Sensitivity::Low, "test").unwrap();
        let results = search_bm25(&conn, "", 10, Sensitivity::High).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    #[serial]
    fn sensitivity_low_only_excludes_medium_high() {
        let conn = setup();
        insert(
            &conn,
            "cred",
            "Low item",
            "val",
            Sensitivity::Low,
            "shared keyword",
        )
        .unwrap();
        insert(
            &conn,
            "cred",
            "Medium item",
            "val",
            Sensitivity::Medium,
            "shared keyword",
        )
        .unwrap();
        insert(
            &conn,
            "cred",
            "High item",
            "val",
            Sensitivity::High,
            "shared keyword",
        )
        .unwrap();

        let results = search_bm25(&conn, "shared keyword", 10, Sensitivity::Low).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caption, "Low item");
    }

    #[test]
    #[serial]
    fn sensitivity_medium_includes_low_and_medium() {
        let conn = setup();
        insert(
            &conn,
            "cred",
            "Low item",
            "val",
            Sensitivity::Low,
            "shared keyword",
        )
        .unwrap();
        insert(
            &conn,
            "cred",
            "Medium item",
            "val",
            Sensitivity::Medium,
            "shared keyword",
        )
        .unwrap();
        insert(
            &conn,
            "cred",
            "High item",
            "val",
            Sensitivity::High,
            "shared keyword",
        )
        .unwrap();

        let results = search_bm25(&conn, "shared keyword", 10, Sensitivity::Medium).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    #[serial]
    fn retrieve_nonexistent_fails() {
        let conn = setup();
        let result = retrieve_secret(&conn, "kv_NONEXIST");
        assert!(result.is_err());
    }
}
