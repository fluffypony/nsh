use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::types::{
    CoreBlock, EpisodicEvent, MemoryOp, ProceduralItem, SemanticItem, ShellEvent,
};

pub async fn extract_memory_ops(
    events: &[ShellEvent],
    core: &[CoreBlock],
    recent_episodic: &[EpisodicEvent],
    semantic: &[SemanticItem],
    procedural: &[ProceduralItem],
    llm: &dyn MemoryLlmClient,
) -> anyhow::Result<Vec<MemoryOp>> {
    let prompt = build_extraction_prompt(events, core, recent_episodic, semantic, procedural);
    let response = llm.complete_json(&prompt).await?;
    let ops = parse_extraction_response(&response)?;
    Ok(validate_keyword_presence(ops))
}

fn build_extraction_prompt(
    events: &[ShellEvent],
    core: &[CoreBlock],
    recent_episodic: &[EpisodicEvent],
    semantic: &[SemanticItem],
    procedural: &[ProceduralItem],
) -> String {
    let mut prompt = String::with_capacity(4096);

    prompt.push_str("Analyze these shell events and extract structured memory operations.\n\n");

    // Current memory state
    prompt.push_str("## Current Memory State\n\n");

    prompt.push_str("### Core Memory\n");
    for block in core {
        prompt.push_str(&format!(
            "- {}: {}\n",
            block.label,
            if block.value.is_empty() {
                "(empty)"
            } else {
                &block.value
            }
        ));
    }

    if !recent_episodic.is_empty() {
        prompt.push_str("\n### Recent Episodes (last 10)\n");
        for ep in recent_episodic.iter().take(10) {
            prompt.push_str(&format!("- [{}] {}\n", ep.event_type, ep.summary));
        }
    }

    if !semantic.is_empty() {
        prompt.push_str("\n### Known Facts\n");
        for s in semantic.iter().take(20) {
            prompt.push_str(&format!("- {}: {}\n", s.name, s.summary));
        }
    }

    if !procedural.is_empty() {
        prompt.push_str("\n### Known Procedures\n");
        for p in procedural.iter().take(10) {
            prompt.push_str(&format!("- {}\n", p.summary));
        }
    }

    // New events to process
    prompt.push_str("\n## New Events\n\n");
    for (i, event) in events.iter().enumerate() {
        prompt.push_str(&format!("### Event {}\n", i + 1));
        prompt.push_str(&format!("Type: {}\n", event.event_type.as_str()));
        if let Some(ref cmd) = event.command {
            let (redacted_cmd, _) = crate::memory::privacy::redact_secrets_for_memory(cmd);
            prompt.push_str(&format!("Command: {redacted_cmd}\n"));
        }
        if let Some(exit) = event.exit_code {
            prompt.push_str(&format!("Exit code: {exit}\n"));
        }
        if let Some(ref output) = event.output {
            let truncated = crate::memory::ingestion::output_truncator::truncate_output(
                output,
                event.exit_code,
                2000,
            );
            let (redacted, _) = crate::memory::privacy::redact_secrets_for_memory(&truncated);
            prompt.push_str(&format!("Output:\n```\n{redacted}\n```\n"));
        }
        if let Some(ref cwd) = event.working_dir {
            prompt.push_str(&format!("CWD: {cwd}\n"));
        }
        prompt.push('\n');
    }

    prompt.push_str(r#"
## Instructions

Respond with a JSON array of memory operations. Each operation must be one of:

- {"op": "CoreAppend", "label": "human|persona|environment", "content": "..."}
- {"op": "CoreRewrite", "label": "human|persona|environment", "content": "..."}
- {"op": "EpisodicInsert", "event": {"event_type": "...", "actor": "user|assistant|system", "summary": "...", "details": "...", "command": "...", "exit_code": N, "working_dir": "...", "project_context": "...", "search_keywords": "..."}}
- {"op": "SemanticInsert", "name": "...", "category": "...", "summary": "...", "details": "...", "search_keywords": "..."}
- {"op": "SemanticUpdate", "id": "...", "summary": "...", "details": "...", "search_keywords": "..."}
- {"op": "ProceduralInsert", "entry_type": "workflow|fix|pattern", "trigger_pattern": "...", "summary": "...", "steps": "[\"step1\",\"step2\"]", "search_keywords": "..."}
- {"op": "ResourceInsert", "resource_type": "file|config|doc", "file_path": "...", "file_hash": "...", "title": "...", "summary": "...", "content": "...", "search_keywords": "..."}
- {"op": "KnowledgeInsert", "entry_type": "credential|secret|key", "caption": "...", "secret_value": "...", "sensitivity": "low|medium|high", "search_keywords": "..."}
- {"op": "NoOp", "reason": "..."}

IMPORTANT:
- Every operation MUST include a "search_keywords" field with relevant terms for BM25 search.
- Do NOT duplicate information already in memory.
- Only create SemanticInsert for genuinely new facts not already captured.
- Prefer NoOp for routine, low-information commands (ls, cd, pwd, clear).
- For KnowledgeInsert, the caption should describe the secret WITHOUT revealing it.

Respond ONLY with the JSON array, no other text.
"#);

    prompt
}

fn parse_extraction_response(response: &str) -> anyhow::Result<Vec<MemoryOp>> {
    let trimmed = response.trim();
    let json_str = if let Some(start) = trimmed.find('[') {
        if let Some(end) = trimmed.rfind(']') {
            &trimmed[start..=end]
        } else {
            trimmed
        }
    } else {
        trimmed
    };

    match serde_json::from_str::<Vec<MemoryOp>>(json_str) {
        Ok(ops) => Ok(ops),
        Err(e) => {
            tracing::warn!("Failed to parse extraction response: {e}");
            Ok(vec![MemoryOp::NoOp {
                reason: format!("Parse error: {e}"),
            }])
        }
    }
}

pub fn validate_keyword_presence(ops: Vec<MemoryOp>) -> Vec<MemoryOp> {
    ops.into_iter()
        .map(|op| match op {
            MemoryOp::EpisodicInsert { mut event } => {
                if event.search_keywords.trim().is_empty() {
                    event.search_keywords = extract_fallback_keywords(&event.summary);
                }
                MemoryOp::EpisodicInsert { event }
            }
            MemoryOp::SemanticInsert {
                name,
                category,
                summary,
                details,
                search_keywords,
            } => {
                let kw = if search_keywords.trim().is_empty() {
                    extract_fallback_keywords(&summary)
                } else {
                    search_keywords
                };
                MemoryOp::SemanticInsert {
                    name,
                    category,
                    summary,
                    details,
                    search_keywords: kw,
                }
            }
            MemoryOp::ProceduralInsert {
                entry_type,
                trigger_pattern,
                summary,
                steps,
                search_keywords,
            } => {
                let kw = if search_keywords.trim().is_empty() {
                    extract_fallback_keywords(&summary)
                } else {
                    search_keywords
                };
                MemoryOp::ProceduralInsert {
                    entry_type,
                    trigger_pattern,
                    summary,
                    steps,
                    search_keywords: kw,
                }
            }
            other => other,
        })
        .collect()
}

pub fn extract_fallback_keywords(text: &str) -> String {
    const STOP_WORDS: &[&str] = &[
        "the", "a", "an", "is", "was", "are", "were", "be", "been", "being", "have", "has", "had",
        "do", "does", "did", "will", "would", "could", "should", "may", "might", "shall", "can",
        "to", "of", "in", "for", "on", "with", "at", "by", "from", "as", "into", "through",
        "during", "before", "after", "and", "but", "or", "nor", "not", "no", "so", "if", "then",
        "than", "that", "this", "these", "those", "it", "its", "i", "me", "my", "we", "our", "you",
        "your", "he", "she", "they",
    ];

    text.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|w| w.len() > 2 && !STOP_WORDS.contains(&w.to_lowercase().as_str()))
        .take(10)
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
pub fn extract_command_tags(command: &str) -> Vec<String> {
    let mut tags = Vec::new();
    let first = command.split_whitespace().next().unwrap_or("");
    let base = first.rsplit('/').next().unwrap_or(first);
    tags.push(base.to_string());

    let domain_keywords = [
        ("git", "version_control"),
        ("docker", "containerization"),
        ("kubectl", "kubernetes"),
        ("cargo", "rust"),
        ("npm", "nodejs"),
        ("pip", "python"),
        ("brew", "package_management"),
        ("systemctl", "systemd"),
        ("ssh", "remote_access"),
    ];

    for (cmd, domain) in &domain_keywords {
        if base == *cmd {
            tags.push(domain.to_string());
        }
    }

    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_fallback_keywords_filters_stop_words() {
        let result = extract_fallback_keywords("The quick brown fox jumps over the lazy dog");
        assert!(result.contains("quick"));
        assert!(result.contains("brown"));
        assert!(!result.contains("the"));
        assert!(!result.contains(" a "));
    }

    #[test]
    fn extract_command_tags_basic() {
        let tags = extract_command_tags("git push origin main");
        assert!(tags.contains(&"git".to_string()));
        assert!(tags.contains(&"version_control".to_string()));
    }

    #[test]
    fn parse_extraction_response_valid() {
        let response = r#"[{"op": "NoOp", "reason": "low signal"}]"#;
        let ops = parse_extraction_response(response).unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn parse_extraction_response_invalid_falls_back() {
        let response = "not valid json at all";
        let ops = parse_extraction_response(response).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(ops[0], MemoryOp::NoOp { .. }));
    }

    #[test]
    fn validate_adds_keywords_when_missing() {
        let ops = vec![MemoryOp::SemanticInsert {
            name: "test".into(),
            category: "general".into(),
            summary: "Cargo build system for Rust projects".into(),
            details: None,
            search_keywords: "".into(),
        }];
        let validated = validate_keyword_presence(ops);
        match &validated[0] {
            MemoryOp::SemanticInsert {
                search_keywords, ..
            } => {
                assert!(!search_keywords.is_empty());
                assert!(search_keywords.contains("Cargo"));
            }
            _ => panic!("expected SemanticInsert"),
        }
    }

    #[test]
    fn extract_fallback_keywords_short_words_filtered() {
        let result = extract_fallback_keywords("A is to be or");
        // All words are <= 2 chars or stop words
        assert!(result.is_empty());
    }

    #[test]
    fn extract_fallback_keywords_max_10() {
        let text = "word1 word2 word3 word4 word5 word6 word7 word8 word9 word10 word11 word12";
        let result = extract_fallback_keywords(text);
        let count = result.split_whitespace().count();
        assert!(count <= 10, "should take at most 10 keywords, got {count}");
    }

    #[test]
    fn extract_fallback_keywords_preserves_underscores() {
        let result = extract_fallback_keywords("my_function_name");
        assert!(result.contains("my_function_name"));
    }

    #[test]
    fn extract_fallback_keywords_preserves_dashes() {
        let result = extract_fallback_keywords("my-component-name");
        assert!(result.contains("my-component-name"));
    }

    #[test]
    fn extract_command_tags_git() {
        let tags = extract_command_tags("git push origin main");
        assert!(tags.contains(&"git".to_string()));
        assert!(tags.contains(&"version_control".to_string()));
    }

    #[test]
    fn extract_command_tags_docker() {
        let tags = extract_command_tags("docker build -t myapp .");
        assert!(tags.contains(&"docker".to_string()));
        assert!(tags.contains(&"containerization".to_string()));
    }

    #[test]
    fn extract_command_tags_kubectl() {
        let tags = extract_command_tags("kubectl get pods");
        assert!(tags.contains(&"kubectl".to_string()));
        assert!(tags.contains(&"kubernetes".to_string()));
    }

    #[test]
    fn extract_command_tags_cargo() {
        let tags = extract_command_tags("cargo test --release");
        assert!(tags.contains(&"cargo".to_string()));
        assert!(tags.contains(&"rust".to_string()));
    }

    #[test]
    fn extract_command_tags_npm() {
        let tags = extract_command_tags("npm install express");
        assert!(tags.contains(&"npm".to_string()));
        assert!(tags.contains(&"nodejs".to_string()));
    }

    #[test]
    fn extract_command_tags_pip() {
        let tags = extract_command_tags("pip install requests");
        assert!(tags.contains(&"pip".to_string()));
        assert!(tags.contains(&"python".to_string()));
    }

    #[test]
    fn extract_command_tags_ssh() {
        let tags = extract_command_tags("ssh user@host");
        assert!(tags.contains(&"ssh".to_string()));
        assert!(tags.contains(&"remote_access".to_string()));
    }

    #[test]
    fn extract_command_tags_brew() {
        let tags = extract_command_tags("brew install ripgrep");
        assert!(tags.contains(&"brew".to_string()));
        assert!(tags.contains(&"package_management".to_string()));
    }

    #[test]
    fn extract_command_tags_systemctl() {
        let tags = extract_command_tags("systemctl restart nginx");
        assert!(tags.contains(&"systemctl".to_string()));
        assert!(tags.contains(&"systemd".to_string()));
    }

    #[test]
    fn extract_command_tags_unknown_command() {
        let tags = extract_command_tags("myunknowncommand --flag");
        assert!(tags.contains(&"myunknowncommand".to_string()));
        assert_eq!(tags.len(), 1, "unknown command should only have base name");
    }

    #[test]
    fn extract_command_tags_full_path() {
        let tags = extract_command_tags("/usr/bin/git status");
        assert!(tags.contains(&"git".to_string()));
        assert!(tags.contains(&"version_control".to_string()));
    }

    #[test]
    fn validate_keyword_presence_procedural_empty_keywords() {
        let ops = vec![MemoryOp::ProceduralInsert {
            entry_type: "workflow".into(),
            trigger_pattern: "deploy".into(),
            summary: "Deploy to production server".into(),
            steps: r#"["build", "test"]"#.into(),
            search_keywords: "".into(),
        }];
        let validated = validate_keyword_presence(ops);
        match &validated[0] {
            MemoryOp::ProceduralInsert {
                search_keywords, ..
            } => {
                assert!(
                    !search_keywords.is_empty(),
                    "should fill in fallback keywords for procedural"
                );
                assert!(search_keywords.contains("Deploy"));
            }
            _ => panic!("expected ProceduralInsert"),
        }
    }

    #[test]
    fn validate_keyword_presence_episodic_empty_keywords() {
        let ops = vec![MemoryOp::EpisodicInsert {
            event: crate::memory::types::EpisodicEventCreate {
                event_type: crate::memory::types::EventType::CommandExecution,
                actor: crate::memory::types::Actor::User,
                summary: "Built the Rust project using cargo".into(),
                details: None,
                command: Some("cargo build".into()),
                exit_code: Some(0),
                working_dir: None,
                project_context: None,
                search_keywords: "   ".into(),
            },
        }];
        let validated = validate_keyword_presence(ops);
        match &validated[0] {
            MemoryOp::EpisodicInsert { event } => {
                assert!(
                    !event.search_keywords.trim().is_empty(),
                    "should fill in fallback keywords"
                );
                assert!(event.search_keywords.contains("Built"));
            }
            _ => panic!("expected EpisodicInsert"),
        }
    }

    #[test]
    fn validate_keyword_presence_preserves_existing() {
        let ops = vec![MemoryOp::SemanticInsert {
            name: "test".into(),
            category: "general".into(),
            summary: "Test summary".into(),
            details: None,
            search_keywords: "existing keywords here".into(),
        }];
        let validated = validate_keyword_presence(ops);
        match &validated[0] {
            MemoryOp::SemanticInsert {
                search_keywords, ..
            } => {
                assert_eq!(search_keywords, "existing keywords here");
            }
            _ => panic!("expected SemanticInsert"),
        }
    }

    #[test]
    fn validate_keyword_presence_noop_passthrough() {
        let ops = vec![MemoryOp::NoOp {
            reason: "test".into(),
        }];
        let validated = validate_keyword_presence(ops);
        assert!(matches!(&validated[0], MemoryOp::NoOp { .. }));
    }

    #[test]
    fn parse_extraction_response_with_surrounding_text() {
        let response = "Here is the output:\n[{\"op\": \"NoOp\", \"reason\": \"test\"}]\nDone!";
        let ops = parse_extraction_response(response).unwrap();
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn parse_extraction_response_multiple_ops() {
        let response = r#"[
            {"op": "EpisodicInsert", "event": {"event_type": "command_execution", "actor": "user", "summary": "test", "search_keywords": "test"}},
            {"op": "NoOp", "reason": "low signal"}
        ]"#;
        let ops = parse_extraction_response(response).unwrap();
        assert_eq!(ops.len(), 2);
    }

    #[test]
    fn parse_extraction_response_empty_array() {
        let response = "[]";
        let ops = parse_extraction_response(response).unwrap();
        assert!(ops.is_empty());
    }
}
