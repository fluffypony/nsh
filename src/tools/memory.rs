pub fn execute_remember(
    input: &serde_json::Value,
    query: &str,
    db: &crate::db::Db,
    session_id: &str,
) -> anyhow::Result<()> {
    let key = input["key"].as_str().unwrap_or("");
    let value = input["value"].as_str().unwrap_or("");
    if key.is_empty() || value.is_empty() {
        anyhow::bail!("remember: 'key' and 'value' are required");
    }
    let (id, was_update) = db.upsert_memory(key, value)?;
    let action = if was_update { "updated" } else { "stored" };
    eprintln!("\x1b[32m✓ Memory #{id} {action}: {key} = {value}\x1b[0m");
    crate::audit::audit_log(
        session_id,
        &format!("remember: {key}"),
        "remember",
        value,
        "safe",
    );
    db.insert_conversation(
        session_id,
        query,
        "remember",
        &format!("{key} = {value}"),
        Some(&format!("Memory #{id} {action}")),
        false,
        false,
    )
    .ok();
    Ok(())
}

pub fn execute_forget(input: &serde_json::Value, db: &crate::db::Db) -> anyhow::Result<()> {
    let id = input["id"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("forget_memory: 'id' is required"))?;
    if db.delete_memory(id)? {
        eprintln!("\x1b[32m✓ Memory #{id} forgotten\x1b[0m");
    } else {
        eprintln!("\x1b[33mMemory #{id} not found\x1b[0m");
    }
    Ok(())
}

pub fn execute_update(input: &serde_json::Value, db: &crate::db::Db) -> anyhow::Result<()> {
    let id = input["id"]
        .as_i64()
        .ok_or_else(|| anyhow::anyhow!("update_memory: 'id' is required"))?;
    let key = input["key"].as_str();
    let value = input["value"].as_str();
    if key.is_none() && value.is_none() {
        anyhow::bail!("update_memory: at least 'key' or 'value' must be provided");
    }
    if db.update_memory(id, key, value)? {
        eprintln!("\x1b[32m✓ Memory #{id} updated\x1b[0m");
    } else {
        eprintln!("\x1b[33mMemory #{id} not found\x1b[0m");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_db() -> crate::db::Db {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("s1", "/dev/pts/0", "zsh", 1234).unwrap();
        db
    }

    #[test]
    fn test_remember_happy_path() {
        let db = test_db();
        let input = json!({"key": "editor", "value": "vim"});
        let result = execute_remember(&input, "remember editor", &db, "s1");
        assert!(result.is_ok());
    }

    #[test]
    fn test_remember_empty_key() {
        let db = test_db();
        let input = json!({"key": "", "value": "vim"});
        let result = execute_remember(&input, "remember", &db, "s1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_remember_empty_value() {
        let db = test_db();
        let input = json!({"key": "editor", "value": ""});
        let result = execute_remember(&input, "remember", &db, "s1");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("required"));
    }

    #[test]
    fn test_forget_happy_path() {
        let db = test_db();
        let input = json!({"key": "editor", "value": "vim"});
        execute_remember(&input, "remember editor", &db, "s1").unwrap();

        let forget_input = json!({"id": 1});
        let result = execute_forget(&forget_input, &db);
        assert!(result.is_ok());
    }

    #[test]
    fn test_forget_missing_id() {
        let db = test_db();
        let input = json!({});
        let result = execute_forget(&input, &db);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'id' is required"));
    }

    #[test]
    fn test_forget_nonexistent_id() {
        let db = test_db();
        let input = json!({"id": 9999});
        let result = execute_forget(&input, &db);
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_happy_path() {
        let db = test_db();
        let input = json!({"key": "editor", "value": "vim"});
        execute_remember(&input, "remember editor", &db, "s1").unwrap();

        let update_input = json!({"id": 1, "value": "emacs"});
        let result = execute_update(&update_input, &db);
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_missing_id() {
        let db = test_db();
        let input = json!({"key": "editor"});
        let result = execute_update(&input, &db);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("'id' is required"));
    }

    #[test]
    fn test_update_no_key_or_value() {
        let db = test_db();
        let input = json!({"id": 1});
        let result = execute_update(&input, &db);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("at least"));
    }

    #[test]
    fn test_update_nonexistent_id() {
        let db = test_db();
        let input = json!({"id": 9999, "value": "new_value"});
        let result = execute_update(&input, &db);
        assert!(result.is_ok());
    }
}
