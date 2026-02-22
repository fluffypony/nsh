//! Memory tool handlers for the persistent memory system.
//!
//! These functions encapsulate the logic for the five memory tools:
//! search_memory, core_memory_append, core_memory_rewrite, store_memory,
//! and retrieve_secret.

use crate::daemon_db::DbAccess;

fn validate_store_memory_input(memory_type: &str, data: &serde_json::Value) -> Result<(), String> {
    let obj = data
        .as_object()
        .ok_or_else(|| "store_memory 'data' must be a JSON object".to_string())?;
    match memory_type {
        "semantic" => {
            for req in ["name", "category", "summary", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj.get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    return Err(format!("Semantic memory missing required field '{req}'"));
                }
            }
        }
        "procedural" => {
            for req in ["entry_type", "summary", "steps", "search_keywords"] {
                if !obj.contains_key(req) {
                    return Err(format!("Procedural memory missing required field '{req}'"));
                }
            }
            if !obj.get("steps").map(|v| v.is_array()).unwrap_or(false) {
                return Err("Procedural memory 'steps' must be an array".into());
            }
        }
        "resource" => {
            for req in ["resource_type", "title", "summary", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj.get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    return Err(format!("Resource memory missing required field '{req}'"));
                }
            }
        }
        "knowledge" => {
            for req in ["entry_type", "caption", "secret_value", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj.get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    return Err(format!("Knowledge memory missing required field '{req}'"));
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Execute a search_memory tool call.
pub fn execute_search_memory(
    db: &dyn DbAccess,
    memory_type: &str,
    query: &str,
    limit: usize,
) -> Result<String, String> {
    let mt = if memory_type == "all" {
        None
    } else {
        Some(memory_type)
    };
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
    // Validate minimal schema up front to avoid noisy daemon errors
    validate_store_memory_input(memory_type, data)?;
    db.memory_store(memory_type, &data.to_string())
        .map(|id| format!("Stored in {memory_type} memory (id: {id})"))
        .map_err(|e| format!("Error: {e}"))
}

/// Execute a retrieve_secret tool call.
pub fn execute_retrieve_secret(db: &dyn DbAccess, caption_query: &str) -> Result<String, String> {
    db.memory_retrieve_secret(caption_query)
        .map_err(|e| format!("Secret retrieval error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn validate_semantic_ok() {
        let data = json!({
            "name": "Humanizer",
            "category": "tool",
            "summary": "CLI to humanize ls -lR output",
            "search_keywords": "humanizer ls pretty"
        });
        assert!(validate_store_memory_input("semantic", &data).is_ok());
    }

    #[test]
    fn validate_semantic_missing_field() {
        let data = json!({ "name": "X" });
        let err = validate_store_memory_input("semantic", &data).unwrap_err();
        assert!(err.contains("missing required field"));
    }

    #[test]
    fn validate_procedural_steps_must_be_array() {
        let data = json!({
            "entry_type": "workflow",
            "summary": "Deploy",
            "steps": "not an array",
            "search_keywords": "deploy"
        });
        let err = validate_store_memory_input("procedural", &data).unwrap_err();
        assert!(err.contains("steps"));
    }

    #[test]
    fn validate_resource_ok() {
        let data = json!({
            "resource_type": "doc",
            "title": "README",
            "summary": "Important notes",
            "search_keywords": "readme doc"
        });
        assert!(validate_store_memory_input("resource", &data).is_ok());
    }

    #[test]
    fn validate_knowledge_ok() {
        let data = json!({
            "entry_type": "token",
            "caption": "API token",
            "secret_value": "abc123",
            "search_keywords": "token api"
        });
        assert!(validate_store_memory_input("knowledge", &data).is_ok());
    }
}
