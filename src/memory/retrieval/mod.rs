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

pub async fn retrieve_for_query(
    conn: &Connection,
    ctx: &MemoryQueryContext,
    llm: Option<&dyn MemoryLlmClient>,
    fade_cutoff: Option<&str>,
) -> anyhow::Result<RetrievedMemories> {
    let mut memories = RetrievedMemories::default();

    // Parse temporal expression from query to constrain time range
    let temporal_range = crate::memory::temporal::parse_temporal_expression(
        &ctx.query,
        chrono::Utc::now(),
    );
    let since_str = temporal_range.map(|(start, _)| start.format("%Y-%m-%dT%H:%M:%S").to_string());
    let since_ref = since_str.as_deref();

    // Core memory is always loaded
    memories.core = crate::memory::store::core::get_all(conn)?;

    // Recent episodic
    memories.recent_episodic =
        crate::memory::store::episodic::list_recent(conn, 10, fade_cutoff, since_ref)?;

    if !needs_full_retrieval(ctx.interaction_mode) {
        return Ok(memories);
    }

    // Extract search topics
    let keywords = topic_extractor::extract(ctx, llm).await;
    memories.keywords = keywords.clone();

    if keywords.is_empty() {
        return Ok(memories);
    }

    let query_str = keywords.join(" ");

    // Search across memory types
    memories.relevant_episodic =
        crate::memory::store::episodic::search_bm25(conn, &query_str, 10, fade_cutoff, since_ref)?;

    memories.semantic =
        crate::memory::store::semantic::search_bm25(conn, &query_str, 10)?;

    memories.procedural =
        crate::memory::store::procedural::search_bm25(conn, &query_str, 5)?;

    memories.resource =
        crate::memory::store::resource::search_bm25(conn, &query_str, 5)?;

    // Add CWD-relevant resources
    if let Some(ref cwd) = ctx.cwd {
        let cwd_resources =
            crate::memory::store::resource::get_for_cwd(conn, cwd, 3)?;
        for r in cwd_resources {
            if !memories.resource.iter().any(|existing| existing.id == r.id) {
                memories.resource.push(r);
            }
        }
    }

    memories.knowledge = crate::memory::store::knowledge::search_bm25(
        conn,
        &query_str,
        5,
        Sensitivity::Medium,
    )?;

    // Update access counts for retrieved semantic items
    for item in &memories.semantic {
        let _ = crate::memory::store::semantic::increment_access(conn, &item.id);
    }

    Ok(memories)
}
