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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{InteractionMode, MemoryQueryContext};

    struct MockLlm {
        response: serde_json::Value,
    }

    #[async_trait::async_trait]
    impl MemoryLlmClient for MockLlm {
        async fn complete_json(&self, _prompt: &str) -> anyhow::Result<serde_json::Value> {
            Ok(self.response.clone())
        }
    }

    fn setup_memory() -> (Arc<Mutex<Connection>>, crate::config::MemoryConfig) {
        let conn = Connection::open_in_memory().unwrap();
        crate::memory::schema::create_memory_tables(&conn).unwrap();
        let db = Arc::new(Mutex::new(conn));
        let config = crate::config::MemoryConfig::default();
        (db, config)
    }

    fn make_query_ctx(query: &str, mode: InteractionMode) -> MemoryQueryContext {
        MemoryQueryContext {
            query: query.to_string(),
            cwd: Some("/home/user/project".into()),
            session_id: None,
            interaction_mode: mode,
            error_context: None,
        }
    }

    #[tokio::test]
    async fn retrieve_returns_core_memory_always() {
        let (db, config) = setup_memory();
        let engine = MemoryRetrievalEngine::new(&db, &config);

        let ctx = make_query_ctx("hello", InteractionMode::CommandSuggestion);
        let result = engine.retrieve_for_query(&ctx, None).await.unwrap();

        // Core memory (3 seeded blocks) should always be present
        assert_eq!(result.core.len(), 3);
    }

    #[tokio::test]
    async fn retrieve_command_suggestion_skips_full_retrieval() {
        let (db, config) = setup_memory();

        // Insert a semantic item to verify it's NOT returned via BM25 search
        {
            let conn = db.lock().unwrap();
            crate::memory::store::semantic::store(
                &conn,
                &crate::memory::store::semantic::SemanticWrite {
                    name: "test_fact",
                    category: "tools",
                    summary: "User uses cargo for builds",
                    details: None,
                    search_keywords: "cargo build rust",
                },
            )
            .unwrap();
        }

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("cargo build", InteractionMode::CommandSuggestion);
        let result = engine.retrieve_for_query(&ctx, None).await.unwrap();

        // CommandSuggestion does NOT trigger full retrieval
        assert!(result.relevant_episodic.is_empty());
        assert!(result.procedural.is_empty());
        assert!(result.knowledge.is_empty());
    }

    #[tokio::test]
    async fn retrieve_natural_language_performs_full_retrieval() {
        let (db, config) = setup_memory();

        // Insert data across multiple stores
        {
            let conn = db.lock().unwrap();
            let store = crate::memory::store::access::MemoryStoreAccess::new(&conn);

            store
                .apply_op(&crate::memory::types::MemoryOp::SemanticInsert {
                    name: "rust_project".into(),
                    category: "tools".into(),
                    summary: "This is a Rust project using cargo".into(),
                    details: None,
                    search_keywords: "rust cargo project".into(),
                })
                .unwrap();

            store
                .apply_op(&crate::memory::types::MemoryOp::EpisodicInsert {
                    event: crate::memory::types::EpisodicEventCreate {
                        event_type: crate::memory::types::EventType::CommandExecution,
                        actor: crate::memory::types::Actor::User,
                        summary: "ran cargo build".into(),
                        details: None,
                        command: Some("cargo build".into()),
                        exit_code: Some(0),
                        working_dir: Some("/home/user/project".into()),
                        project_context: None,
                        search_keywords: "cargo build rust".into(),
                    },
                })
                .unwrap();
        }

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("how do I build with cargo", InteractionMode::NaturalLanguage);

        let llm = MockLlm {
            response: serde_json::json!(["cargo", "build", "rust"]),
        };
        let result = engine
            .retrieve_for_query(&ctx, Some(&llm))
            .await
            .unwrap();

        // Should have core memory
        assert_eq!(result.core.len(), 3);
        // Should have recent episodic (the one we inserted)
        assert!(!result.recent_episodic.is_empty());
        // Should have semantic results from BM25
        assert!(!result.semantic.is_empty());
    }

    #[tokio::test]
    async fn retrieve_with_cwd_returns_resources() {
        let (db, config) = setup_memory();

        // Insert a resource tied to a CWD
        {
            let conn = db.lock().unwrap();
            crate::memory::store::resource::store(
                &conn,
                &crate::memory::store::resource::ResourceWrite {
                    resource_type: "file",
                    file_path: Some("/home/user/project/Cargo.toml"),
                    file_hash: None,
                    title: "Cargo.toml",
                    summary: "Rust project manifest",
                    content: Some("[package]\nname = \"nsh\""),
                    search_keywords: "cargo toml rust",
                },
            )
            .unwrap();
        }

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let mut ctx = make_query_ctx("what deps do we have", InteractionMode::NaturalLanguage);
        ctx.cwd = Some("/home/user/project".into());

        let result = engine.retrieve_for_query(&ctx, None).await.unwrap();

        assert!(
            !result.resource.is_empty(),
            "should retrieve resources for matching CWD"
        );
    }

    #[tokio::test]
    async fn retrieve_deduplicates_semantic_results() {
        let (db, config) = setup_memory();

        // Insert a semantic item with high access count (will be in top_semantic)
        {
            let conn = db.lock().unwrap();
            crate::memory::store::semantic::store(
                &conn,
                &crate::memory::store::semantic::SemanticWrite {
                    name: "cargo_tool",
                    category: "tools",
                    summary: "cargo is the Rust build tool",
                    details: None,
                    search_keywords: "cargo rust build tool",
                },
            )
            .unwrap();
            // Increment access count so it appears in top_accessed
            let items = crate::memory::store::semantic::list_all(&conn).unwrap();
            for item in &items {
                for _ in 0..10 {
                    crate::memory::store::semantic::increment_access(&conn, &item.id).unwrap();
                }
            }
        }

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("cargo build", InteractionMode::NaturalLanguage);

        let llm = MockLlm {
            response: serde_json::json!(["cargo", "build"]),
        };
        let result = engine
            .retrieve_for_query(&ctx, Some(&llm))
            .await
            .unwrap();

        // Verify no duplicate semantic IDs
        let ids: Vec<_> = result.semantic.iter().map(|s| &s.id).collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "semantic results should be deduplicated");
    }

    #[test]
    fn build_memory_prompt_produces_xml_tagged_output() {
        let (db, config) = setup_memory();
        let engine = MemoryRetrievalEngine::new(&db, &config);

        let memories = RetrievedMemories {
            core: vec![crate::memory::types::CoreBlock {
                label: crate::memory::types::CoreLabel::Human,
                value: "test user".into(),
                char_limit: 5000,
                updated_at: String::new(),
            }],
            ..Default::default()
        };

        let prompt = engine.build_memory_prompt(&memories);
        assert!(
            prompt.contains("<memory_context>") || prompt.contains("<core_memory>"),
            "prompt should contain XML memory tags"
        );
    }

    #[tokio::test]
    async fn retrieve_empty_db_returns_only_core() {
        let (db, config) = setup_memory();
        let engine = MemoryRetrievalEngine::new(&db, &config);

        let ctx = make_query_ctx("anything", InteractionMode::NaturalLanguage);
        let result = engine.retrieve_for_query(&ctx, None).await.unwrap();

        assert_eq!(result.core.len(), 3);
        assert!(result.recent_episodic.is_empty());
        assert!(result.relevant_episodic.is_empty());
        assert!(result.procedural.is_empty());
        assert!(result.knowledge.is_empty());
    }
}
