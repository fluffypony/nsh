//! Memory tool handlers for the persistent memory system.
//!
//! These functions encapsulate the logic for the five memory tools:
//! search_memory, core_memory_append, core_memory_rewrite, store_memory,
//! and retrieve_secret.

use anyhow::{bail, ensure, Context};

use crate::daemon_db::DbAccess;
use crate::memory::types::{Actor, EventType, MemoryType, Sensitivity};

pub(crate) fn validate_store_memory_input(
    memory_type: MemoryType,
    data: &serde_json::Value,
) -> anyhow::Result<()> {
    let obj = data
        .as_object()
        .context("store_memory 'data' must be a JSON object")?;
    match memory_type {
        MemoryType::Semantic => {
            for req in ["name", "category", "summary", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj
                        .get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    bail!("Semantic memory missing required field '{req}'");
                }
            }
        }
        MemoryType::Procedural => {
            for req in ["entry_type", "summary", "steps", "search_keywords"] {
                if !obj.contains_key(req) {
                    bail!("Procedural memory missing required field '{req}'");
                }
            }
            ensure!(
                obj.get("steps").map(|v| v.is_array()).unwrap_or(false),
                "Procedural memory 'steps' must be an array"
            );
        }
        MemoryType::Resource => {
            for req in ["resource_type", "title", "summary", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj
                        .get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    bail!("Resource memory missing required field '{req}'");
                }
            }
        }
        MemoryType::Knowledge => {
            for req in ["entry_type", "caption", "secret_value", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj
                        .get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    bail!("Knowledge memory missing required field '{req}'");
                }
            }
            let sensitivity = obj
                .get("sensitivity")
                .and_then(|v| v.as_str())
                .unwrap_or("medium");
            Sensitivity::parse(sensitivity)
                .context("Knowledge memory has invalid sensitivity")?;
        }
        MemoryType::Core => {
            bail!(
                "store_memory does not support 'core'; use core_memory_append/core_memory_rewrite"
            );
        }
        MemoryType::Episodic => {
            for req in ["event_type", "actor", "summary", "search_keywords"] {
                if !obj.contains_key(req)
                    || obj
                        .get(req)
                        .and_then(|v| v.as_str())
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(true)
                {
                    bail!("Episodic memory missing required field '{req}'");
                }
            }
            let event_type = obj.get("event_type").and_then(|v| v.as_str()).unwrap();
            EventType::parse(event_type).context("Episodic memory has invalid event_type")?;
            let actor = obj.get("actor").and_then(|v| v.as_str()).unwrap();
            Actor::parse(actor).context("Episodic memory has invalid actor")?;
        }
    }
    Ok(())
}

pub fn execute_search_memory(
    db: &dyn DbAccess,
    memory_type: &str,
    query: &str,
    limit: usize,
) -> anyhow::Result<String> {
    let mt = if memory_type == "all" {
        None
    } else {
        Some(MemoryType::parse(memory_type)?)
    };
    db.memory_search(query, mt, limit)
        .context("Memory search error")
}

pub fn execute_core_memory_append(
    db: &dyn DbAccess,
    label: &str,
    content: &str,
) -> anyhow::Result<String> {
    db.memory_core_append(label, content)
        .map(|()| format!("Appended to core memory '{label}'"))
        .context("core_memory_append failed")
}

pub fn execute_core_memory_rewrite(
    db: &dyn DbAccess,
    label: &str,
    content: &str,
) -> anyhow::Result<String> {
    db.memory_core_rewrite(label, content)
        .map(|()| format!("Rewrote core memory block '{label}'"))
        .context("core_memory_rewrite failed")
}

pub fn execute_store_memory(
    db: &dyn DbAccess,
    memory_type: &str,
    data: &serde_json::Value,
) -> anyhow::Result<String> {
    let parsed_type = MemoryType::parse(memory_type)?;
    // Validate minimal schema up front to avoid noisy daemon errors
    validate_store_memory_input(parsed_type, data)?;
    db.memory_store(parsed_type, &data.to_string())
        .map(|id| format!("Stored in {memory_type} memory (id: {id})"))
        .context("store_memory failed")
}

pub fn execute_retrieve_secret(
    db: &dyn DbAccess,
    caption_query: &str,
    explicit_user_request: Option<&str>,
) -> anyhow::Result<String> {
    db.memory_retrieve_secret(caption_query, explicit_user_request)
        .context("Secret retrieval error")
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
        assert!(validate_store_memory_input(MemoryType::Semantic, &data).is_ok());
    }

    #[test]
    fn validate_semantic_missing_field() {
        let data = json!({ "name": "X" });
        let err = validate_store_memory_input(MemoryType::Semantic, &data).unwrap_err();
        assert!(err.to_string().contains("missing required field"));
    }

    #[test]
    fn validate_procedural_steps_must_be_array() {
        let data = json!({
            "entry_type": "workflow",
            "summary": "Deploy",
            "steps": "not an array",
            "search_keywords": "deploy"
        });
        let err = validate_store_memory_input(MemoryType::Procedural, &data).unwrap_err();
        assert!(err.to_string().contains("steps"));
    }

    #[test]
    fn validate_resource_ok() {
        let data = json!({
            "resource_type": "doc",
            "title": "README",
            "summary": "Important notes",
            "search_keywords": "readme doc"
        });
        assert!(validate_store_memory_input(MemoryType::Resource, &data).is_ok());
    }

    #[test]
    fn validate_knowledge_ok() {
        let data = json!({
            "entry_type": "token",
            "caption": "API token",
            "secret_value": "abc123",
            "search_keywords": "token api"
        });
        assert!(validate_store_memory_input(MemoryType::Knowledge, &data).is_ok());
    }

    #[test]
    fn validate_knowledge_invalid_sensitivity() {
        let data = json!({
            "entry_type": "token",
            "caption": "API token",
            "secret_value": "abc123",
            "sensitivity": "critical",
            "search_keywords": "token api"
        });
        let err = validate_store_memory_input(MemoryType::Knowledge, &data).unwrap_err();
        assert!(err.to_string().contains("invalid sensitivity"));
    }

    #[test]
    fn validate_episodic_ok() {
        let data = json!({
            "event_type": "command_execution",
            "actor": "user",
            "summary": "Ran cargo build",
            "search_keywords": "cargo build rust"
        });
        assert!(validate_store_memory_input(MemoryType::Episodic, &data).is_ok());
    }

    #[test]
    fn validate_episodic_missing_field() {
        let data = json!({ "summary": "Ran cargo build" });
        let err = validate_store_memory_input(MemoryType::Episodic, &data).unwrap_err();
        assert!(err.to_string().contains("missing required field"));
    }

    #[test]
    fn validate_episodic_invalid_event_type() {
        let data = json!({
            "event_type": "invalid_type",
            "actor": "user",
            "summary": "Ran cargo build",
            "search_keywords": "cargo build"
        });
        let err = validate_store_memory_input(MemoryType::Episodic, &data).unwrap_err();
        assert!(err.to_string().contains("invalid event_type"));
    }

    #[test]
    fn validate_episodic_invalid_actor() {
        let data = json!({
            "event_type": "command_execution",
            "actor": "robot",
            "summary": "Ran cargo build",
            "search_keywords": "cargo build"
        });
        let err = validate_store_memory_input(MemoryType::Episodic, &data).unwrap_err();
        assert!(err.to_string().contains("invalid actor"));
    }
}
