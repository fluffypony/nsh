use crate::memory::types::RetrievedMemories;

pub fn enforce_budget(memories: &mut RetrievedMemories, budget_tokens: usize) {
    let mut current = estimate_tokens(memories);

    if current <= budget_tokens {
        return;
    }

    // Phase 1: Reduce resource content to summaries only
    for r in &mut memories.resource {
        r.content = None;
    }
    current = estimate_tokens(memories);
    if current <= budget_tokens {
        return;
    }

    // Phase 2: Reduce items per type
    memories.resource.truncate(3);
    memories.knowledge.truncate(3);
    memories.procedural.truncate(3);
    current = estimate_tokens(memories);
    if current <= budget_tokens {
        return;
    }

    // Phase 3: Aggressively truncate
    memories.recent_episodic.truncate(5);
    memories.relevant_episodic.truncate(5);
    memories.semantic.truncate(5);
    memories.resource.truncate(2);
}

pub fn estimate_tokens(memories: &RetrievedMemories) -> usize {
    let mut chars = 0;

    for block in &memories.core {
        chars += block.value.len() + 100; // overhead for XML tags
    }
    for ep in &memories.recent_episodic {
        chars += ep.summary.len() + ep.details.as_ref().map_or(0, |d| d.len()) + 50;
    }
    for ep in &memories.relevant_episodic {
        chars += ep.summary.len() + ep.details.as_ref().map_or(0, |d| d.len()) + 50;
    }
    for s in &memories.semantic {
        chars += s.name.len() + s.summary.len() + s.details.as_ref().map_or(0, |d| d.len()) + 50;
    }
    for p in &memories.procedural {
        chars += p.summary.len() + p.steps.len() + 50;
    }
    for r in &memories.resource {
        chars += r.title.len() + r.summary.len() + r.content.as_ref().map_or(0, |c| c.len()) + 50;
    }
    for k in &memories.knowledge {
        chars += k.caption.len() + 50;
    }

    // Rough estimate: 1 token ≈ 4 chars
    chars / 4
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{CoreBlock, CoreLabel, EpisodicEvent, EventType, Actor};

    #[test]
    fn estimate_tokens_basic() {
        let memories = RetrievedMemories {
            core: vec![CoreBlock {
                label: CoreLabel::Human,
                value: "a".repeat(400),
                char_limit: 5000,
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let tokens = estimate_tokens(&memories);
        assert!(tokens > 0);
        assert!(tokens < 200);
    }

    #[test]
    fn enforce_budget_truncates() {
        let mut memories = RetrievedMemories {
            recent_episodic: (0..20)
                .map(|i| EpisodicEvent {
                    id: format!("ep_{i}"),
                    event_type: EventType::CommandExecution,
                    actor: Actor::User,
                    summary: "x".repeat(200),
                    details: Some("y".repeat(500)),
                    command: None,
                    exit_code: None,
                    working_dir: None,
                    project_context: None,
                    search_keywords: String::new(),
                    occurred_at: String::new(),
                    is_consolidated: false,
                })
                .collect(),
            ..Default::default()
        };
        enforce_budget(&mut memories, 100);
        assert!(memories.recent_episodic.len() <= 5);
    }

    #[test]
    fn estimate_tokens_all_types() {
        let memories = RetrievedMemories {
            core: vec![CoreBlock {
                label: CoreLabel::Human,
                value: "test user".into(),
                char_limit: 5000,
                updated_at: String::new(),
            }],
            recent_episodic: vec![EpisodicEvent {
                id: "ep_1".into(),
                event_type: EventType::CommandExecution,
                actor: Actor::User,
                summary: "ran cargo build".into(),
                details: Some("full output".into()),
                command: None,
                exit_code: None,
                working_dir: None,
                project_context: None,
                search_keywords: String::new(),
                occurred_at: String::new(),
                is_consolidated: false,
            }],
            semantic: vec![crate::memory::types::SemanticItem {
                id: "sem_1".into(),
                name: "Rust project".into(),
                category: "tools".into(),
                summary: "Uses cargo".into(),
                details: None,
                search_keywords: String::new(),
                access_count: 0,
                last_accessed: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let tokens = estimate_tokens(&memories);
        assert!(tokens > 0);
    }

    #[test]
    fn enforce_budget_phase1_strips_resource_content() {
        let mut memories = RetrievedMemories {
            resource: vec![crate::memory::types::ResourceItem {
                id: "res_1".into(),
                resource_type: "file".into(),
                file_path: Some("/test".into()),
                file_hash: None,
                title: "test".into(),
                summary: "test".into(),
                content: Some("x".repeat(10000)),
                search_keywords: String::new(),
                created_at: String::new(),
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        enforce_budget(&mut memories, 100);
        // Resource content should be stripped
        assert!(memories.resource[0].content.is_none() || memories.resource.is_empty());
    }

    #[test]
    fn enforce_budget_does_nothing_under_budget() {
        let mut memories = RetrievedMemories {
            core: vec![CoreBlock {
                label: CoreLabel::Human,
                value: "short".into(),
                char_limit: 5000,
                updated_at: String::new(),
            }],
            ..Default::default()
        };
        let orig_core_len = memories.core.len();
        enforce_budget(&mut memories, 100000);
        assert_eq!(memories.core.len(), orig_core_len, "should not modify when under budget");
    }

    #[test]
    fn estimate_tokens_empty() {
        let memories = RetrievedMemories::default();
        assert_eq!(estimate_tokens(&memories), 0);
    }
}
