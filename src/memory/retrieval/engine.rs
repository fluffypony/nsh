use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::types::{MemoryQueryContext, RetrievedMemories, Sensitivity};

pub struct MemoryRetrievalEngine<'a> {
    db: &'a Arc<Mutex<Connection>>,
    config: &'a crate::config::MemoryConfig,
}

impl<'a> MemoryRetrievalEngine<'a> {
    pub fn new(
        db: &'a Arc<Mutex<Connection>>,
        config: &'a crate::config::MemoryConfig,
    ) -> Self {
        Self { db, config }
    }

    pub async fn retrieve_for_query(
        &self,
        ctx: &MemoryQueryContext,
        llm: Option<&dyn MemoryLlmClient>,
    ) -> anyhow::Result<RetrievedMemories> {
        let temporal_range =
            crate::memory::temporal::parse_temporal_expression(&ctx.query, chrono::Utc::now());
        let since_str =
            temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        let (fade_cutoff, core, recent, top_semantic, cwd_resources) = {
            let conn = self.db.lock().unwrap();
            let fade_cutoff =
                crate::memory::decay::get_fade_cutoff(&conn, self.config.fade_after_days)?;
            let core = crate::memory::store::core::get_all(&conn)?;
            let recent =
                crate::memory::store::episodic::list_recent(&conn, 10, Some(&fade_cutoff), since_ref)?;
            let top_semantic =
                crate::memory::store::semantic::list_top_accessed(&conn, 5).unwrap_or_default();
            let cwd_resources = if let Some(cwd) = ctx.cwd.as_deref() {
                crate::memory::store::resource::get_for_cwd(&conn, cwd, 3).unwrap_or_default()
            } else {
                vec![]
            };
            (fade_cutoff, core, recent, top_semantic, cwd_resources)
        };

        let keywords = crate::memory::retrieval::topic_extractor::extract(ctx, llm).await;

        let conn = self.db.lock().unwrap();
        let mut memories = RetrievedMemories {
            keywords: keywords.clone(),
            core,
            recent_episodic: recent,
            semantic: top_semantic,
            resource: cwd_resources,
            ..Default::default()
        };

        if crate::memory::retrieval::needs_full_retrieval(ctx.interaction_mode)
            && !keywords.is_empty()
        {
            let query_str = keywords.join(" ");
            memories.relevant_episodic = crate::memory::store::episodic::search_bm25(
                &conn,
                &query_str,
                10,
                Some(&fade_cutoff),
                since_ref,
            )?;

            let bm25_semantic = crate::memory::store::semantic::search_bm25(&conn, &query_str, 10)?;
            for item in bm25_semantic {
                if !memories
                    .semantic
                    .iter()
                    .any(|existing| existing.id == item.id)
                {
                    memories.semantic.push(item);
                }
            }

            memories.procedural =
                crate::memory::store::procedural::search_bm25(&conn, &query_str, 5)?;

            let bm25_resources = crate::memory::store::resource::search_bm25(&conn, &query_str, 5)?;
            for resource in bm25_resources {
                if !memories
                    .resource
                    .iter()
                    .any(|existing| existing.id == resource.id)
                {
                    memories.resource.push(resource);
                }
            }

            memories.knowledge = crate::memory::store::knowledge::search_bm25(
                &conn,
                &query_str,
                5,
                Sensitivity::Medium,
            )?;
        }

        crate::memory::retrieval::ranker::enforce_budget(&mut memories, 4000);
        for item in &memories.semantic {
            let _ = crate::memory::store::semantic::increment_access(&conn, &item.id);
        }

        Ok(memories)
    }

    pub fn build_memory_prompt(&self, memories: &RetrievedMemories) -> String {
        let _ = self.config;
        crate::memory::retrieval::prompt_builder::build_memory_prompt(memories)
    }
}
