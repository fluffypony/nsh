pub mod prompt_builder;
pub mod ranker;
pub mod topic_extractor;

use rusqlite::Connection;

use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::types::{InteractionMode, MemoryQueryContext, RetrievedMemories, Sensitivity};

pub fn needs_full_retrieval(mode: InteractionMode) -> bool {
    matches!(
        mode,
        InteractionMode::NaturalLanguage
            | InteractionMode::ErrorFix
            | InteractionMode::CodeGeneration
            | InteractionMode::AutonomousExecution
    )
}

#[allow(dead_code)]
pub async fn retrieve_for_query(
    conn: &Connection,
    ctx: &MemoryQueryContext,
    llm: Option<&dyn MemoryLlmClient>,
    fade_cutoff: Option<&str>,
) -> anyhow::Result<RetrievedMemories> {
    // Parse temporal expression from query to constrain time range
    let temporal_range =
        crate::memory::temporal::parse_temporal_expression(&ctx.query, chrono::Utc::now());
    // Use space separator to match SQLite's datetime() format: "YYYY-MM-DD HH:MM:SS"
    let since_str = temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
    let since_ref = since_str.as_deref();

    // Core memory is always loaded
    let core = crate::memory::store::core::get_all(conn)?;

    // Recent episodic
    let recent_episodic =
        crate::memory::store::episodic::list_recent(conn, 10, fade_cutoff, since_ref)?;

    // MIRIX: always fetch high-access semantic items (user preferences)
    let top_semantic =
        crate::memory::store::semantic::list_top_accessed(conn, 5).unwrap_or_default();

    // MIRIX: always fetch CWD-relevant resources
    let cwd_resources = if let Some(ref cwd) = ctx.cwd {
        crate::memory::store::resource::get_for_cwd(conn, cwd, 3).unwrap_or_default()
    } else {
        vec![]
    };

    let mut memories = RetrievedMemories {
        core,
        recent_episodic,
        semantic: top_semantic,
        resource: cwd_resources,
        ..Default::default()
    };

    if !needs_full_retrieval(ctx.interaction_mode) {
        return Ok(memories);
    }

    // Extract search topics
    let keywords = topic_extractor::extract(ctx, llm).await;
    memories.keywords = keywords.clone();

    if !keywords.is_empty() {
        let query_str = keywords.join(" ");

        // Search across memory types
        memories.relevant_episodic = crate::memory::store::episodic::search_bm25(
            conn,
            &query_str,
            10,
            fade_cutoff,
            since_ref,
        )?;

        // Merge BM25 semantic results with always-recalled top-accessed items
        let bm25_semantic =
            crate::memory::store::semantic::search_bm25(conn, &query_str, 10)?;
        for item in bm25_semantic {
            if !memories.semantic.iter().any(|existing| existing.id == item.id) {
                memories.semantic.push(item);
            }
        }

        memories.procedural =
            crate::memory::store::procedural::search_bm25(conn, &query_str, 5)?;

        // Merge BM25 resource results with always-recalled CWD resources
        let bm25_resources =
            crate::memory::store::resource::search_bm25(conn, &query_str, 5)?;
        for r in bm25_resources {
            if !memories.resource.iter().any(|existing| existing.id == r.id) {
                memories.resource.push(r);
            }
        }

        memories.knowledge = crate::memory::store::knowledge::search_bm25(
            conn,
            &query_str,
            5,
            Sensitivity::Medium,
        )?;
    }

    // Enforce budget first, then increment access counts only for
    // items that survive truncation (MIRIX: track what's actually shown)
    ranker::enforce_budget(&mut memories, 4000);
    for item in &memories.semantic {
        let _ = crate::memory::store::semantic::increment_access(conn, &item.id);
    }

    Ok(memories)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_full_retrieval_natural_language() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::NaturalLanguage
        ));
    }

    #[test]
    fn needs_full_retrieval_error_fix() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::ErrorFix
        ));
    }

    #[test]
    fn needs_full_retrieval_code_generation() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::CodeGeneration
        ));
    }

    #[test]
    fn needs_full_retrieval_autonomous() {
        assert!(needs_full_retrieval(
            crate::memory::types::InteractionMode::AutonomousExecution
        ));
    }

    #[test]
    fn does_not_need_full_retrieval_command_suggestion() {
        assert!(!needs_full_retrieval(
            crate::memory::types::InteractionMode::CommandSuggestion
        ));
    }
}
