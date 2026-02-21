use crate::memory::types::RetrievedMemories;

pub fn build_memory_prompt(memories: &RetrievedMemories) -> String {
    let mut parts = Vec::new();

    let now = chrono::Utc::now().to_rfc3339();
    parts.push(format!("<memory_context timestamp=\"{now}\">"));

    // Keywords used for retrieval
    if !memories.keywords.is_empty() {
        parts.push(format!(
            "<search_keywords>{}</search_keywords>",
            memories.keywords.join(", ")
        ));
    }

    // Core memory (always present)
    if !memories.core.is_empty() {
        parts.push("<core_memory>".into());
        for block in &memories.core {
            let used = block.value.len();
            let limit = block.char_limit;
            let pct = if limit > 0 {
                (used as f64 / limit as f64 * 100.0) as u32
            } else {
                0
            };
            if !block.value.is_empty() {
                parts.push(format!(
                    "<{} characters=\"{}/{}\" ({}% full)>\n{}\n</{}>",
                    block.label, used, limit, pct, block.value, block.label
                ));
            }
        }
        parts.push("</core_memory>".into());
    }

    // Recent episodic
    if !memories.recent_episodic.is_empty() {
        parts.push("<episodic_memory type=\"recent\">".into());
        for ep in &memories.recent_episodic {
            let mut line = format!("[{}] {}", ep.occurred_at, ep.summary);
            if let Some(ref cmd) = ep.command {
                line.push_str(&format!(" (cmd: {})", cmd));
            }
            if let Some(exit) = ep.exit_code {
                if exit != 0 {
                    line.push_str(&format!(" [exit {}]", exit));
                }
            }
            parts.push(line);
        }
        parts.push("</episodic_memory>".into());
    }

    // Relevant episodic
    if !memories.relevant_episodic.is_empty() {
        parts.push("<episodic_memory type=\"relevant\">".into());
        for ep in &memories.relevant_episodic {
            let mut line = format!("[{}] {}", ep.occurred_at, ep.summary);
            if let Some(ref details) = ep.details {
                let preview = if details.len() > 200 {
                    format!("{}...", &details[..200])
                } else {
                    details.clone()
                };
                line.push_str(&format!("\n  {}", preview));
            }
            parts.push(line);
        }
        parts.push("</episodic_memory>".into());
    }

    // Semantic
    if !memories.semantic.is_empty() {
        parts.push("<semantic_memory>".into());
        for s in &memories.semantic {
            let mut line = format!("• {}: {}", s.name, s.summary);
            if let Some(ref details) = s.details {
                let preview = if details.len() > 200 {
                    format!("{}...", &details[..200])
                } else {
                    details.clone()
                };
                line.push_str(&format!("\n  {}", preview));
            }
            parts.push(line);
        }
        parts.push("</semantic_memory>".into());
    }

    // Procedural
    if !memories.procedural.is_empty() {
        parts.push("<procedural_memory>".into());
        for p in &memories.procedural {
            parts.push(format!("• {}", p.summary));
            // Show first 5 steps as preview
            if let Ok(steps) = serde_json::from_str::<Vec<String>>(&p.steps) {
                for (i, step) in steps.iter().take(5).enumerate() {
                    parts.push(format!("  {}. {}", i + 1, step));
                }
                if steps.len() > 5 {
                    parts.push(format!("  ... ({} more steps)", steps.len() - 5));
                }
            }
        }
        parts.push("</procedural_memory>".into());
    }

    // Resource
    if !memories.resource.is_empty() {
        parts.push("<resource_memory>".into());
        for r in &memories.resource {
            let mut line = format!("• {} ({})", r.title, r.resource_type);
            if let Some(ref path) = r.file_path {
                line.push_str(&format!(" [{}]", path));
            }
            parts.push(line);
            parts.push(format!("  {}", r.summary));
        }
        parts.push("</resource_memory>".into());
    }

    // Knowledge (captions only — redacted to prevent secret leakage)
    if !memories.knowledge.is_empty() {
        parts.push("<knowledge>".into());
        for k in &memories.knowledge {
            // Redact captions to prevent accidental secret leakage if
            // a caption inadvertently contains sensitive material
            let redacted_caption = {
                let redaction = crate::config::RedactionConfig::default();
                crate::redact::redact_secrets(&k.caption, &redaction)
            };
            parts.push(format!("• {} ({})", redacted_caption, k.sensitivity));
        }
        parts.push("</knowledge>".into());
    }

    parts.push("</memory_context>".into());

    parts.join("\n")
}

#[cfg(test)]
pub fn compile_core_memory(
    conn: &rusqlite::Connection,
) -> anyhow::Result<String> {
    crate::memory::store::core::compile_for_prompt(conn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::*;

    #[test]
    fn build_prompt_empty_memories() {
        let memories = RetrievedMemories::default();
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("<memory_context"));
        assert!(prompt.contains("</memory_context>"));
    }

    #[test]
    fn build_prompt_with_core() {
        let memories = RetrievedMemories {
            core: vec![CoreBlock {
                label: CoreLabel::Human,
                value: "Name: Alice".into(),
                char_limit: 5000,
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Name: Alice"));
        assert!(prompt.contains("<core_memory>"));
    }

    #[test]
    fn build_prompt_with_episodic() {
        let memories = RetrievedMemories {
            recent_episodic: vec![EpisodicEvent {
                id: "ep_TEST".into(),
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "Ran cargo build".into(),
                details: None,
                command: Some("cargo build".into()),
                exit_code: Some(0),
                working_dir: None,
                project_context: None,
                search_keywords: String::new(),
                occurred_at: "2025-01-01T00:00:00Z".into(),
                is_consolidated: false,
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Ran cargo build"));
        assert!(prompt.contains("cargo build"));
    }

    #[test]
    fn build_prompt_with_semantic() {
        let memories = RetrievedMemories {
            semantic: vec![SemanticItem {
                id: "sem_1".into(),
                name: "Rust project".into(),
                category: "tools".into(),
                summary: "Uses cargo workspaces".into(),
                details: Some("Detailed info about workspaces".into()),
                search_keywords: String::new(),
                access_count: 0,
                last_accessed: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Rust project"));
        assert!(prompt.contains("cargo workspaces"));
        assert!(prompt.contains("<semantic_memory>"));
    }

    #[test]
    fn build_prompt_with_procedural() {
        let memories = RetrievedMemories {
            procedural: vec![ProceduralItem {
                id: "proc_1".into(),
                entry_type: "workflow".into(),
                trigger_pattern: "deploy".into(),
                summary: "Deploy to production".into(),
                steps: r#"["build", "test", "deploy"]"#.into(),
                search_keywords: String::new(),
                access_count: 0,
                last_accessed: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Deploy to production"));
        assert!(prompt.contains("<procedural_memory>"));
        assert!(prompt.contains("1. build"));
    }

    #[test]
    fn build_prompt_with_resource() {
        let memories = RetrievedMemories {
            resource: vec![ResourceItem {
                id: "res_1".into(),
                resource_type: "config".into(),
                file_path: Some("/home/user/.gitconfig".into()),
                file_hash: None,
                title: "Git config".into(),
                summary: "Git configuration with aliases".into(),
                content: None,
                search_keywords: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Git config"));
        assert!(prompt.contains(".gitconfig"));
        assert!(prompt.contains("<resource_memory>"));
    }

    #[test]
    fn build_prompt_with_knowledge() {
        let memories = RetrievedMemories {
            knowledge: vec![KnowledgeEntry {
                id: "kv_1".into(),
                entry_type: "credential".into(),
                caption: "GitHub personal token".into(),
                secret_value: String::new(),
                sensitivity: Sensitivity::High,
                search_keywords: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("GitHub personal token"));
        assert!(prompt.contains("<knowledge>"));
        assert!(prompt.contains("high"));
    }

    #[test]
    fn build_prompt_with_keywords() {
        let memories = RetrievedMemories {
            keywords: vec!["rust".into(), "cargo".into(), "build".into()],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("rust, cargo, build"));
        assert!(prompt.contains("<search_keywords>"));
    }

    #[test]
    fn build_prompt_error_exit_code_shown() {
        let memories = RetrievedMemories {
            recent_episodic: vec![EpisodicEvent {
                id: "ep_ERR".into(),
                event_type: EventType::CommandError,
                actor: Actor::User,
                summary: "Compilation failed".into(),
                details: None,
                command: Some("cargo build".into()),
                exit_code: Some(101),
                working_dir: None,
                project_context: None,
                search_keywords: String::new(),
                occurred_at: "2025-01-01T00:00:00Z".into(),
                is_consolidated: false,
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("[exit 101]"), "non-zero exit code should be shown");
    }

    #[test]
    fn build_prompt_relevant_episodic_shows_details() {
        let memories = RetrievedMemories {
            relevant_episodic: vec![EpisodicEvent {
                id: "ep_REL".into(),
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "Deployed to staging".into(),
                details: Some("Deployed version 2.1.0 to staging environment".into()),
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: String::new(),
                occurred_at: "2025-01-01T00:00:00Z".into(),
                is_consolidated: false,
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("Deployed to staging"));
        assert!(prompt.contains("version 2.1.0"));
        assert!(prompt.contains("type=\"relevant\""));
    }

    #[test]
    fn build_prompt_truncates_long_details() {
        let memories = RetrievedMemories {
            relevant_episodic: vec![EpisodicEvent {
                id: "ep_LONG".into(),
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "test".into(),
                details: Some("x".repeat(500)),
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: String::new(),
                occurred_at: "2025-01-01T00:00:00Z".into(),
                is_consolidated: false,
            }],
            ..Default::default()
        };
        let prompt = build_memory_prompt(&memories);
        assert!(prompt.contains("..."), "long details should be truncated");
    }
}
