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
}
