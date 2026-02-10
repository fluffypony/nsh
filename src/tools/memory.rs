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
