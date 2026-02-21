use rusqlite::{Connection, params};

use crate::memory::types::{KnowledgeEntry, Sensitivity, generate_id};

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<KnowledgeEntry> {
    Ok(KnowledgeEntry {
        id: row.get(0)?,
        entry_type: row.get(1)?,
        caption: row.get(2)?,
        secret_value: row.get(3)?,
        sensitivity: Sensitivity::from_str(&row.get::<_, String>(4)?),
        search_keywords: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

pub fn insert(
    conn: &Connection,
    entry_type: &str,
    caption: &str,
    secret_value: &str,
    sensitivity: Sensitivity,
    search_keywords: &str,
) -> anyhow::Result<String> {
    let encrypted = encrypt_secret(secret_value)?;
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
            sensitivity: Sensitivity::from_str(&row.get::<_, String>(4)?),
            search_keywords: row.get(5)?,
            created_at: row.get(6)?,
            updated_at: row.get(7)?,
        });
    }
    Ok(results)
}

pub fn retrieve_secret(conn: &Connection, id: &str) -> anyhow::Result<String> {
    let encrypted: String = conn.query_row(
        "SELECT secret_value FROM knowledge_vault WHERE id = ?",
        params![id],
        |r| r.get(0),
    )?;
    decrypt_secret(&encrypted)
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

// ── Encryption helpers ──

fn get_or_create_key() -> anyhow::Result<[u8; 32]> {
    let key_path = crate::config::Config::nsh_dir().join("vault.key");
    if key_path.exists() {
        let bytes = std::fs::read(&key_path)?;
        if bytes.len() < 32 {
            anyhow::bail!("vault.key is too short (expected 32 bytes)");
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[..32]);
        Ok(key)
    } else {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&key_path)?;
            file.write_all(&key)?;
        }
        #[cfg(not(unix))]
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&key_path)?;
            file.write_all(&key)?;
            // Mark as read-only to prevent accidental modification
            let mut perms = std::fs::metadata(&key_path)?.permissions();
            perms.set_readonly(true);
            std::fs::set_permissions(&key_path, perms)?;
            // On Windows, hide the key file
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                // Set FILE_ATTRIBUTE_HIDDEN via attrib command (available on all Windows)
                let _ = std::process::Command::new("attrib")
                    .args(["+H", &key_path.to_string_lossy()])
                    .output();
            }
        }
        Ok(key)
    }
}

fn encrypt_secret(plaintext: &str) -> anyhow::Result<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, AeadCore, OsRng}};
    let key = get_or_create_key()?;
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(hex::encode(&combined))
}

fn decrypt_secret(hex_data: &str) -> anyhow::Result<String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
    let key = get_or_create_key()?;
    let data = hex::decode(hex_data)?;
    if data.len() < 12 {
        anyhow::bail!("encrypted data too short");
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("cipher init: {e}"))?;
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
    Ok(String::from_utf8(plaintext)?)
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
    fn encrypt_decrypt_roundtrip() {
        let original = "my-secret-api-key-12345";
        let encrypted = encrypt_secret(original).unwrap();
        assert_ne!(encrypted, original);
        let decrypted = decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
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
    fn search_filters_by_sensitivity() {
        let conn = setup();
        insert(&conn, "cred", "Low secret", "val", Sensitivity::Low, "low test").unwrap();
        insert(&conn, "cred", "High secret", "val", Sensitivity::High, "high test").unwrap();

        let low_only = search_bm25(&conn, "test", 10, Sensitivity::Low).unwrap();
        assert_eq!(low_only.len(), 1);
        assert_eq!(low_only[0].caption, "Low secret");

        let all = search_bm25(&conn, "test", 10, Sensitivity::High).unwrap();
        assert_eq!(all.len(), 2);
    }

    #[test]
    fn delete_removes_entries() {
        let conn = setup();
        let id = insert(&conn, "cred", "test secret", "value", Sensitivity::Low, "test").unwrap();
        assert_eq!(count(&conn).unwrap(), 1);
        delete(&conn, &[id]).unwrap();
        assert_eq!(count(&conn).unwrap(), 0);
    }

    #[test]
    fn multiple_secrets_independent() {
        let conn = setup();
        let id1 = insert(&conn, "api_key", "GitHub token", "ghp_abc123", Sensitivity::High, "github token").unwrap();
        let id2 = insert(&conn, "password", "DB password", "supersecret", Sensitivity::Medium, "database password").unwrap();

        assert_ne!(id1, id2);
        assert_eq!(count(&conn).unwrap(), 2);

        let secret1 = retrieve_secret(&conn, &id1).unwrap();
        let secret2 = retrieve_secret(&conn, &id2).unwrap();
        assert_eq!(secret1, "ghp_abc123");
        assert_eq!(secret2, "supersecret");
    }

    #[test]
    fn encrypt_different_each_time() {
        // Same plaintext should produce different ciphertext due to random nonce
        let enc1 = encrypt_secret("test-value").unwrap();
        let enc2 = encrypt_secret("test-value").unwrap();
        assert_ne!(enc1, enc2, "encryption should use random nonce");

        // But both should decrypt to the same value
        let dec1 = decrypt_secret(&enc1).unwrap();
        let dec2 = decrypt_secret(&enc2).unwrap();
        assert_eq!(dec1, dec2);
        assert_eq!(dec1, "test-value");
    }

    #[test]
    fn encrypt_empty_string() {
        let encrypted = encrypt_secret("").unwrap();
        let decrypted = decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn encrypt_long_secret() {
        let long_secret = "a".repeat(10000);
        let encrypted = encrypt_secret(&long_secret).unwrap();
        let decrypted = decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, long_secret);
    }

    #[test]
    fn encrypt_special_characters() {
        let special = "p@$$w0rd!#%^&*()_+-=[]{}|;':\",./<>?";
        let encrypted = encrypt_secret(special).unwrap();
        let decrypted = decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, special);
    }

    #[test]
    fn encrypt_unicode() {
        let unicode = "密码 пароль パスワード 🔑🔐";
        let encrypted = encrypt_secret(unicode).unwrap();
        let decrypted = decrypt_secret(&encrypted).unwrap();
        assert_eq!(decrypted, unicode);
    }

    #[test]
    fn decrypt_invalid_hex_fails() {
        let result = decrypt_secret("not_valid_hex!");
        assert!(result.is_err());
    }

    #[test]
    fn decrypt_too_short_fails() {
        let result = decrypt_secret("aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    fn search_bm25_empty_query() {
        let conn = setup();
        insert(&conn, "cred", "test", "val", Sensitivity::Low, "test").unwrap();
        let results = search_bm25(&conn, "", 10, Sensitivity::High).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn sensitivity_low_only_excludes_medium_high() {
        let conn = setup();
        insert(&conn, "cred", "Low item", "val", Sensitivity::Low, "shared keyword").unwrap();
        insert(&conn, "cred", "Medium item", "val", Sensitivity::Medium, "shared keyword").unwrap();
        insert(&conn, "cred", "High item", "val", Sensitivity::High, "shared keyword").unwrap();

        let results = search_bm25(&conn, "shared keyword", 10, Sensitivity::Low).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].caption, "Low item");
    }

    #[test]
    fn sensitivity_medium_includes_low_and_medium() {
        let conn = setup();
        insert(&conn, "cred", "Low item", "val", Sensitivity::Low, "shared keyword").unwrap();
        insert(&conn, "cred", "Medium item", "val", Sensitivity::Medium, "shared keyword").unwrap();
        insert(&conn, "cred", "High item", "val", Sensitivity::High, "shared keyword").unwrap();

        let results = search_bm25(&conn, "shared keyword", 10, Sensitivity::Medium).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn retrieve_nonexistent_fails() {
        let conn = setup();
        let result = retrieve_secret(&conn, "kv_NONEXIST");
        assert!(result.is_err());
    }
}
