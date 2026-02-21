//! Memory tool handlers for the persistent memory system.
//!
//! These functions encapsulate the logic for the five memory tools:
//! search_memory, core_memory_append, core_memory_rewrite, store_memory,
//! and retrieve_secret.

use crate::daemon_db::DbAccess;

/// Execute a search_memory tool call.
pub fn execute_search_memory(
    db: &dyn DbAccess,
    memory_type: &str,
    query: &str,
    limit: usize,
) -> Result<String, String> {
    let mt = if memory_type == "all" { None } else { Some(memory_type) };
    db.memory_search(query, mt, limit)
        .map_err(|e| format!("Memory search error: {e}"))
}

/// Execute a core_memory_append tool call.
pub fn execute_core_memory_append(
    db: &dyn DbAccess,
    label: &str,
    content: &str,
) -> Result<String, String> {
    db.memory_core_append(label, content)
        .map(|()| format!("Appended to core memory '{label}'"))
        .map_err(|e| format!("Error: {e}"))
}

/// Execute a core_memory_rewrite tool call.
pub fn execute_core_memory_rewrite(
    db: &dyn DbAccess,
    label: &str,
    content: &str,
) -> Result<String, String> {
    db.memory_core_rewrite(label, content)
        .map(|()| format!("Rewrote core memory block '{label}'"))
        .map_err(|e| format!("Error: {e}"))
}

/// Execute a store_memory tool call.
pub fn execute_store_memory(
    db: &dyn DbAccess,
    memory_type: &str,
    data: &serde_json::Value,
) -> Result<String, String> {
    db.memory_store(memory_type, &data.to_string())
        .map(|id| format!("Stored in {memory_type} memory (id: {id})"))
        .map_err(|e| format!("Error: {e}"))
}

/// Execute a retrieve_secret tool call.
pub fn execute_retrieve_secret(
    db: &dyn DbAccess,
    caption_query: &str,
) -> Result<String, String> {
    db.memory_retrieve_secret(caption_query)
        .map_err(|e| format!("Secret retrieval error: {e}"))
}
