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

    /// Retrieve memories relevant to the given query context.
    ///
    /// Side effect: increments access counters on returned semantic items
    /// so the decay system can preserve frequently-accessed facts.
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
        crate::memory::retrieval::prompt_builder::build_memory_prompt(memories)
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::test_support::{setup_memory, MockLlm};
    use crate::memory::types::{InteractionMode, MemoryQueryContext, RetrievedMemories};

    use super::MemoryRetrievalEngine;

    use std::sync::{Arc, Mutex};
    use rusqlite::Connection;

    fn make_query_ctx(query: &str, mode: InteractionMode) -> MemoryQueryContext {
        MemoryQueryContext {
            query: query.to_string(),
            cwd: Some("/home/user/project".into()),
            session_id: None,
            interaction_mode: mode,
            error_context: None,
        }
    }

    /// Run a setup closure that needs the DB lock, outside of async context.
    fn with_db(db: &Arc<Mutex<Connection>>, f: impl FnOnce(&Connection)) {
        let conn = db.lock().unwrap();
        f(&conn);
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

        // Insert procedural data that would match BM25 if full retrieval ran
        with_db(&db, |conn| {
            let store = crate::memory::store::access::MemoryStoreAccess::new(conn);
            store
                .apply_op(&crate::memory::types::MemoryOp::ProceduralInsert {
                    entry_type: "workflow".into(),
                    trigger_pattern: "cargo build".into(),
                    summary: "How to build with cargo".into(),
                    steps: "[\"cargo build --release\"]".into(),
                    search_keywords: "cargo build rust release".into(),
                })
                .unwrap();
        });

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("cargo build", InteractionMode::CommandSuggestion);

        // Even with LLM providing keywords, full retrieval should NOT run
        let llm = MockLlm {
            response: serde_json::json!(["cargo", "build"]),
        };
        let result = engine
            .retrieve_for_query(&ctx, Some(&llm))
            .await
            .unwrap();

        // CommandSuggestion does NOT trigger full retrieval — BM25-only fields stay empty
        assert!(
            result.relevant_episodic.is_empty(),
            "relevant_episodic should be empty for CommandSuggestion"
        );
        assert!(
            result.procedural.is_empty(),
            "procedural should be empty for CommandSuggestion (data exists but BM25 shouldn't run)"
        );
        assert!(result.knowledge.is_empty());
    }

    #[tokio::test]
    async fn retrieve_natural_language_performs_bm25_search() {
        let (db, config) = setup_memory();

        // Insert data that will ONLY appear via BM25 search (not in baseline results)
        with_db(&db, |conn| {
            let store = crate::memory::store::access::MemoryStoreAccess::new(conn);

            // This procedural item is only retrievable via BM25 search
            store
                .apply_op(&crate::memory::types::MemoryOp::ProceduralInsert {
                    entry_type: "workflow".into(),
                    trigger_pattern: "deploy".into(),
                    summary: "Deploy process for production".into(),
                    steps: "[\"cargo build --release\", \"deploy to prod\"]".into(),
                    search_keywords: "deploy production release cargo".into(),
                })
                .unwrap();

            // Insert episodic events -- these should appear in relevant_episodic via BM25
            // Use 12+ events so some are beyond the recent-10 cutoff
            for i in 0..12 {
                store
                    .apply_op(&crate::memory::types::MemoryOp::EpisodicInsert {
                        event: crate::memory::types::EpisodicEventCreate {
                            event_type: crate::memory::types::EventType::CommandExecution,
                            actor: crate::memory::types::Actor::User,
                            summary: format!("ran command {i}"),
                            details: None,
                            command: Some(format!("echo {i}")),
                            exit_code: Some(0),
                            working_dir: Some("/home/user/project".into()),
                            project_context: None,
                            search_keywords: format!("echo number{i}"),
                        },
                    })
                    .unwrap();
            }

            // Insert a deploy-related episodic event that BM25 should find
            store
                .apply_op(&crate::memory::types::MemoryOp::EpisodicInsert {
                    event: crate::memory::types::EpisodicEventCreate {
                        event_type: crate::memory::types::EventType::CommandExecution,
                        actor: crate::memory::types::Actor::User,
                        summary: "deployed production build".into(),
                        details: None,
                        command: Some("cargo build --release && deploy".into()),
                        exit_code: Some(0),
                        working_dir: Some("/home/user/project".into()),
                        project_context: None,
                        search_keywords: "deploy production release cargo".into(),
                    },
                })
                .unwrap();
        });

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("how do I deploy to production", InteractionMode::NaturalLanguage);

        let llm = MockLlm {
            response: serde_json::json!(["deploy", "production", "release"]),
        };
        let result = engine
            .retrieve_for_query(&ctx, Some(&llm))
            .await
            .unwrap();

        assert_eq!(result.core.len(), 3);

        // BM25-specific fields: these are ONLY populated by the full retrieval branch
        assert!(
            !result.relevant_episodic.is_empty(),
            "relevant_episodic should be populated by BM25 search"
        );
        assert!(
            result
                .relevant_episodic
                .iter()
                .any(|e| e.summary.contains("deploy")),
            "BM25 should find the deploy-related episodic event"
        );
        assert!(
            !result.procedural.is_empty(),
            "procedural should be populated by BM25 search"
        );
        assert!(
            result
                .procedural
                .iter()
                .any(|p| p.summary.contains("Deploy")),
            "BM25 should find the deploy procedural workflow"
        );
    }

    #[tokio::test]
    async fn retrieve_with_cwd_returns_resources() {
        let (db, config) = setup_memory();

        // Insert a resource tied to a CWD
        with_db(&db, |conn| {
            crate::memory::store::resource::store(
                conn,
                &crate::memory::store::resource::ResourceWrite {
                    resource_type: "file",
                    file_path: Some("/home/user/project/Cargo.toml"),
                    file_hash: Some("abc123hash"),
                    title: "Cargo.toml",
                    summary: "Rust project manifest",
                    content: Some("[package]\nname = \"nsh\""),
                    search_keywords: "cargo toml rust",
                },
            )
            .unwrap();
        });

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
        with_db(&db, |conn| {
            crate::memory::store::semantic::store(
                conn,
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
            let items = crate::memory::store::semantic::list_all(conn).unwrap();
            for item in &items {
                for _ in 0..10 {
                    crate::memory::store::semantic::increment_access(conn, &item.id).unwrap();
                }
            }
        });

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

    #[tokio::test]
    async fn retrieve_enforces_budget_truncation() {
        let (db, config) = setup_memory();

        // Insert many episodic events with large details to blow the 4000-token budget
        with_db(&db, |conn| {
            let store = crate::memory::store::access::MemoryStoreAccess::new(conn);

            for i in 0..30 {
                store
                    .apply_op(&crate::memory::types::MemoryOp::EpisodicInsert {
                        event: crate::memory::types::EpisodicEventCreate {
                            event_type: crate::memory::types::EventType::CommandExecution,
                            actor: crate::memory::types::Actor::User,
                            summary: format!("executed deploy step {i} with verbose output"),
                            details: Some("x".repeat(500)),
                            command: Some(format!("deploy-step-{i}")),
                            exit_code: Some(0),
                            working_dir: Some("/home/user/project".into()),
                            project_context: None,
                            search_keywords: "deploy step verbose output".into(),
                        },
                    })
                    .unwrap();
            }

            // Add resources with large content
            for i in 0..10 {
                store
                    .apply_op(&crate::memory::types::MemoryOp::ResourceInsert {
                        resource_type: "file".into(),
                        file_path: Some(format!("/home/user/project/config{i}.toml")),
                        file_hash: Some(format!("hash{i}")),
                        title: format!("config{i}.toml"),
                        summary: "deploy configuration file".into(),
                        content: Some("y".repeat(2000)),
                        search_keywords: "deploy config toml".into(),
                    })
                    .unwrap();
            }
        });

        let engine = MemoryRetrievalEngine::new(&db, &config);
        let ctx = make_query_ctx("show me deploy details", InteractionMode::NaturalLanguage);

        let llm = MockLlm {
            response: serde_json::json!(["deploy", "step", "verbose"]),
        };
        let result = engine
            .retrieve_for_query(&ctx, Some(&llm))
            .await
            .unwrap();

        // Budget enforcement should truncate results to fit within 4000 tokens
        let token_estimate = crate::memory::retrieval::ranker::estimate_tokens(&result);
        assert!(
            token_estimate <= 4000,
            "budget enforcement should keep tokens <= 4000, got {token_estimate}"
        );

        // At least phase 2 or 3 should have kicked in: resource/episodic counts reduced
        let total_items = result.recent_episodic.len()
            + result.relevant_episodic.len()
            + result.resource.len();
        assert!(
            total_items < 40,
            "budget enforcement should have truncated items, got {total_items}"
        );
    }
}
