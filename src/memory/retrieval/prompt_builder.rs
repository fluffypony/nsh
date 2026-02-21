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
}
