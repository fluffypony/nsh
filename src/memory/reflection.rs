use rusqlite::{Connection, params};

use crate::memory::types::MemoryOp;

// Reflection orchestration moved into MemorySystem::run_reflection to avoid holding locks across awaits

pub fn build_reflection_prompt(
    unconsolidated: &[crate::memory::types::EpisodicEvent],
    core: &[crate::memory::types::CoreBlock],
    semantic: &[crate::memory::types::SemanticItem],
    procedural: &[crate::memory::types::ProceduralItem],
) -> String {
    let mut prompt = String::with_capacity(4096);

    prompt.push_str("You are a memory consolidation agent. Review unconsolidated episodic events and extract higher-level knowledge.\n\n");

    prompt.push_str("## Current Core Memory\n");
    for block in core {
        let pct = if block.char_limit > 0 {
            (block.value.len() as f64 / block.char_limit as f64 * 100.0) as u32
        } else {
            0
        };
        prompt.push_str(&format!("- {} ({}% full): {}\n", block.label,  pct, if block.value.is_empty() { "(empty)" } else { &block.value }));
    }

    if !semantic.is_empty() {
        prompt.push_str("\n## Known Semantic Facts\n");
        for s in semantic.iter().take(30) {
            prompt.push_str(&format!("- [{}] {}: {}\n", s.id, s.name, s.summary));
        }
    }

    if !procedural.is_empty() {
        prompt.push_str("\n## Known Procedures\n");
        for p in procedural.iter().take(15) {
            prompt.push_str(&format!("- [{}] {}\n", p.id, p.summary));
        }
    }

    prompt.push_str("\n## Unconsolidated Events\n");
    for ep in unconsolidated {
        prompt.push_str(&format!(
            "- [{}] {} | {} | {}{}\n",
            ep.id,
            ep.occurred_at,
            ep.event_type,
            ep.summary,
            ep.command.as_ref().map(|c| format!(" (cmd: {})", c)).unwrap_or_default()
        ));
    }

    prompt.push_str(r#"
## Instructions

Analyze the unconsolidated events and produce a JSON array of memory operations:

1. **Compress verbose episodic events** into concise semantic facts
2. **Detect repeated command sequences** → promote to procedural memory
3. **Identify facts for core memory** (user preferences, environment info)
4. **Deduplicate** semantic entries about the same concept (use SemanticUpdate with existing ID)
5. **Condense core memory** if >80% capacity (use CoreRewrite)
6. **Generate search_keywords** for every new entry (space-separated relevant terms)

Available operations:
- {"op": "CoreAppend", "label": "...", "content": "..."}
- {"op": "CoreRewrite", "label": "...", "content": "..."}
- {"op": "SemanticInsert", "name": "...", "category": "...", "summary": "...", "details": "...", "search_keywords": "..."}
- {"op": "SemanticUpdate", "id": "...", "summary": "...", "details": "...", "search_keywords": "..."}
- {"op": "SemanticDelete", "ids": ["..."]}
- {"op": "ProceduralInsert", "entry_type": "...", "trigger_pattern": "...", "summary": "...", "steps": "[...]", "search_keywords": "..."}
- {"op": "EpisodicDelete", "ids": ["..."]}
- {"op": "NoOp", "reason": "..."}

Respond ONLY with the JSON array.
"#);

    prompt
}

pub fn parse_reflection_response(response: &str) -> Vec<MemoryOp> {
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
        Ok(ops) => crate::memory::ingestion::extractor::validate_keyword_presence(ops),
        Err(e) => {
            tracing::warn!("Failed to parse reflection response: {e}");
            vec![]
        }
    }
}

// Apply-op is handled by MemorySystem::apply_op

pub fn should_run_reflection(conn: &Connection, consolidation_threshold: usize) -> bool {
    // Check unconsolidated count
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM episodic_memory WHERE is_consolidated = 0",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    if count >= consolidation_threshold as i64 {
        return true;
    }

    // Check if last reflection was more than 24 hours ago
    let last: Option<String> = conn
        .query_row(
            "SELECT value FROM memory_config WHERE key = 'last_reflection_at'",
            [],
            |r| r.get(0),
        )
        .ok();

    match last {
        Some(ts) if !ts.is_empty() => {
            let overdue: bool = conn
                .query_row(
                    "SELECT datetime('now', '-24 hours') > ?",
                    params![ts],
                    |r| r.get(0),
                )
                .unwrap_or(false);
            overdue && count > 0
        }
        _ => count > 0,
    }
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
    fn should_run_reflection_empty_db() {
        let conn = setup();
        assert!(!should_run_reflection(&conn, 50));
    }

    #[test]
    fn should_run_reflection_with_events() {
        let conn = setup();
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
             VALUES ('ep_1', 'command_execution', 'user', 'test', 'test')",
            [],
        )
        .unwrap();
        // Under threshold but no prior reflection, so should run
        assert!(should_run_reflection(&conn, 50));
    }

    #[test]
    fn parse_reflection_response_valid() {
        let resp = r#"[{"op": "NoOp", "reason": "nothing to consolidate"}]"#;
        let ops = parse_reflection_response(resp);
        assert_eq!(ops.len(), 1);
    }

    #[test]
    fn parse_reflection_response_invalid() {
        let ops = parse_reflection_response("not json");
        assert!(ops.is_empty());
    }

    #[test]
    fn should_run_reflection_threshold_reached() {
        let conn = setup();
        // Insert enough unconsolidated events to meet the threshold
        for i in 0..50 {
            conn.execute(
                &format!(
                    "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
                     VALUES ('ep_{i}', 'command_execution', 'user', 'event {i}', 'test')"
                ),
                [],
            ).unwrap();
        }
        assert!(should_run_reflection(&conn, 50), "should run when threshold reached");
    }

    #[test]
    fn should_run_reflection_under_threshold_recent() {
        let conn = setup();
        // Insert a few events
        for i in 0..5 {
            conn.execute(
                &format!(
                    "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
                     VALUES ('ep_{i}', 'command_execution', 'user', 'event {i}', 'test')"
                ),
                [],
            ).unwrap();
        }
        // Mark reflection as recently run
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_reflection_at', datetime('now'))",
            [],
        ).unwrap();
        assert!(!should_run_reflection(&conn, 50), "should not run under threshold with recent reflection");
    }

    #[test]
    fn should_run_reflection_under_threshold_overdue() {
        let conn = setup();
        // Insert a few events
        conn.execute(
            "INSERT INTO episodic_memory (id, event_type, actor, summary, search_keywords)
             VALUES ('ep_1', 'command_execution', 'user', 'event', 'test')",
            [],
        ).unwrap();
        // Mark reflection as long ago
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_reflection_at', datetime('now', '-48 hours'))",
            [],
        ).unwrap();
        assert!(should_run_reflection(&conn, 50), "should run when overdue and has events");
    }

    #[test]
    fn parse_reflection_response_semantic_insert() {
        let resp = r#"[{"op": "SemanticInsert", "name": "Docker usage", "category": "tools", "summary": "Uses Docker for containerization", "search_keywords": "docker container"}]"#;
        let ops = parse_reflection_response(resp);
        assert_eq!(ops.len(), 1);
        assert!(matches!(&ops[0], MemoryOp::SemanticInsert { .. }));
    }

    #[test]
    fn parse_reflection_response_mixed_ops() {
        let resp = r#"[
            {"op": "SemanticInsert", "name": "fact", "category": "general", "summary": "test", "search_keywords": "test"},
            {"op": "EpisodicDelete", "ids": ["ep_1", "ep_2"]},
            {"op": "CoreAppend", "label": "human", "content": "prefers vim"}
        ]"#;
        let ops = parse_reflection_response(resp);
        assert_eq!(ops.len(), 3);
    }

    #[test]
    fn parse_reflection_adds_missing_keywords() {
        let resp = r#"[{"op": "SemanticInsert", "name": "fact", "category": "general", "summary": "Uses Docker for development workflow", "search_keywords": ""}]"#;
        let ops = parse_reflection_response(resp);
        match &ops[0] {
            MemoryOp::SemanticInsert { search_keywords, .. } => {
                assert!(!search_keywords.is_empty(), "should fill in fallback keywords");
            }
            _ => panic!("expected SemanticInsert"),
        }
    }
}
