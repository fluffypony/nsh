use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::memory::ingestion::{self, IngestionBuffer};
use crate::memory::llm_adapter::MemoryLlmClient;
use crate::memory::store::access::MemoryStoreAccess;
use crate::memory::types::{MemoryOp, ShellEvent};

pub struct MemoryIngestionPipeline<'a> {
    db: &'a Arc<Mutex<Connection>>,
    config: &'a crate::config::MemoryConfig,
    buffer: &'a Mutex<IngestionBuffer>,
    ignore_patterns: &'a [String],
}

impl<'a> MemoryIngestionPipeline<'a> {
    pub fn new(
        db: &'a Arc<Mutex<Connection>>,
        config: &'a crate::config::MemoryConfig,
        buffer: &'a Mutex<IngestionBuffer>,
        ignore_patterns: &'a [String],
    ) -> Self {
        Self {
            db,
            config,
            buffer,
            ignore_patterns,
        }
    }

    pub fn record_event(&self, event: ShellEvent) {
        if self.config.incognito || !self.config.enabled {
            return;
        }

        if let Some(cwd) = event.working_dir.as_deref()
            && crate::memory::privacy::is_ignored_path(cwd, self.ignore_patterns)
        {
            return;
        }

        if let Some(output) = event.output.as_deref() {
            if crate::memory::privacy::is_password_prompt(output) {
                return;
            }
            if crate::memory::privacy::should_skip_output(output) {
                return;
            }
        }

        let mut buffer = self.buffer.lock().unwrap();
        let _ = buffer.push(event);
    }

    pub async fn flush_ingestion(&self, llm: &dyn MemoryLlmClient) -> anyhow::Result<()> {
        let events = {
            let mut buffer = self.buffer.lock().unwrap();
            if buffer.is_empty() {
                return Ok(());
            }
            buffer.flush()
        };
        self.ingest_batch(&events, llm).await?;
        Ok(())
    }

    pub async fn ingest_batch(
        &self,
        events: &[ShellEvent],
        llm: &dyn MemoryLlmClient,
    ) -> anyhow::Result<Vec<MemoryOp>> {
        let mut all_ops = Vec::new();
        let mut complex_events = Vec::new();

        for event in events {
            let decision = crate::memory::ingestion::router::route(event);
            if ingestion::can_fast_path(event) && decision.only_episodic() {
                let episodic = ingestion::fast_path_episodic(event);
                let merge_id = {
                    let conn = self.db.lock().unwrap();
                    ingestion::consolidator::find_merge_candidate(&conn, &episodic.summary, 30)?
                };
                let op = if let Some(target_id) = merge_id {
                    MemoryOp::EpisodicMerge {
                        target_id,
                        combined_summary: episodic.summary,
                        additional_details: episodic.details,
                        search_keywords: episodic.search_keywords,
                    }
                } else {
                    MemoryOp::EpisodicInsert { event: episodic }
                };
                let conn = self.db.lock().unwrap();
                MemoryStoreAccess::new(&conn).apply_op(&op)?;
                all_ops.push(op);
            } else {
                complex_events.push(event.clone());
            }
        }

        if !complex_events.is_empty() {
            let (core, recent, semantic, procedural) = {
                let conn = self.db.lock().unwrap();
                let core = crate::memory::store::core::get_all(&conn)?;
                let recent = crate::memory::store::episodic::list_recent(&conn, 10, None, None)?;
                let semantic = crate::memory::store::semantic::list_all(&conn)?;
                let procedural = crate::memory::store::procedural::list_all(&conn)?;
                (core, recent, semantic, procedural)
            };

            let ops = ingestion::extractor::extract_memory_ops(
                &complex_events,
                &core,
                &recent,
                &semantic,
                &procedural,
                llm,
            )
            .await?;

            let conn = self.db.lock().unwrap();
            let store = MemoryStoreAccess::new(&conn);
            for op in &ops {
                store.apply_op(op)?;
            }
            all_ops.extend(ops);
        }

        Ok(all_ops)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{ShellEvent, ShellEventType};

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

    fn make_event(cmd: &str, exit_code: i32) -> ShellEvent {
        crate::memory::ingestion::make_test_event(cmd, exit_code)
    }

    #[tokio::test]
    async fn ingest_batch_fast_path_produces_episodic_insert() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);
        let llm = MockLlm {
            response: serde_json::json!([]),
        };

        let events = vec![make_event("ls", 0)];
        let ops = pipeline.ingest_batch(&events, &llm).await.unwrap();

        assert_eq!(ops.len(), 1);
        assert!(
            matches!(&ops[0], MemoryOp::EpisodicInsert { .. }),
            "fast-path command should produce EpisodicInsert"
        );

        // Verify it was persisted to the DB
        let conn = db.lock().unwrap();
        let count = crate::memory::store::episodic::count(&conn).unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn ingest_batch_complex_event_routes_through_extractor() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);

        // MockLlm returns a SemanticInsert op for complex events
        let llm = MockLlm {
            response: serde_json::json!([{
                "op": "SemanticInsert",
                "name": "rust_project",
                "category": "tools",
                "summary": "User works on a Rust project",
                "details": null,
                "search_keywords": "rust cargo project"
            }]),
        };

        // UserInstruction events cannot be fast-pathed
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: Some("/home/user/project".into()),
            session_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            git_context: None,
            instruction: Some("I prefer dark mode".into()),
            file_path: None,
        };

        let ops = pipeline.ingest_batch(&[event], &llm).await.unwrap();

        assert!(
            !ops.is_empty(),
            "complex event should produce ops from extractor"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, MemoryOp::SemanticInsert { .. })),
            "should contain SemanticInsert from LLM extraction"
        );

        // Verify semantic item was persisted
        let conn = db.lock().unwrap();
        let count = crate::memory::store::semantic::count(&conn).unwrap();
        assert_eq!(count, 1);
    }

    #[tokio::test]
    async fn ingest_batch_mixed_events_splits_fast_and_complex() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);

        let llm = MockLlm {
            response: serde_json::json!([{
                "op": "NoOp",
                "reason": "no useful memory from this event"
            }]),
        };

        let events = vec![
            // Fast-path: simple command
            make_event("ls", 0),
            // Complex: user instruction
            ShellEvent {
                event_type: ShellEventType::UserInstruction,
                command: None,
                output: None,
                exit_code: None,
                working_dir: None,
                session_id: None,
                timestamp: chrono::Utc::now().to_rfc3339(),
                git_context: None,
                instruction: Some("How do I build this?".into()),
                file_path: None,
            },
        ];

        let ops = pipeline.ingest_batch(&events, &llm).await.unwrap();

        // Should have at least the fast-path EpisodicInsert + NoOp from extractor
        assert!(ops.len() >= 2);
        assert!(
            ops.iter()
                .any(|op| matches!(op, MemoryOp::EpisodicInsert { .. })),
            "fast-path event should produce EpisodicInsert"
        );
        assert!(
            ops.iter()
                .any(|op| matches!(op, MemoryOp::NoOp { .. })),
            "complex event should produce NoOp from mock"
        );
    }

    #[tokio::test]
    async fn flush_ingestion_empty_buffer_is_noop() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);
        let llm = MockLlm {
            response: serde_json::json!([]),
        };

        // Flushing empty buffer should succeed without touching DB
        pipeline.flush_ingestion(&llm).await.unwrap();

        let conn = db.lock().unwrap();
        let count = crate::memory::store::episodic::count(&conn).unwrap();
        assert_eq!(count, 0);
    }

    #[tokio::test]
    async fn flush_ingestion_drains_buffer_and_persists() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);
        let llm = MockLlm {
            response: serde_json::json!([]),
        };

        // Push events into buffer via record_event
        pipeline.record_event(make_event("pwd", 0));
        pipeline.record_event(make_event("whoami", 0));

        assert!(!buffer.lock().unwrap().is_empty());

        pipeline.flush_ingestion(&llm).await.unwrap();

        assert!(buffer.lock().unwrap().is_empty());

        // At least one episodic event should be persisted (the second may merge
        // with the first via Jaro-Winkler consolidation, so count >= 1)
        let conn = db.lock().unwrap();
        let count = crate::memory::store::episodic::count(&conn).unwrap();
        assert!(count >= 1, "should persist at least one episodic event, got {count}");
    }

    #[test]
    fn record_event_skipped_in_incognito_mode() {
        let (db, mut config) = setup_memory();
        config.incognito = true;
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);

        pipeline.record_event(make_event("ls", 0));

        assert!(buffer.lock().unwrap().is_empty());
    }

    #[test]
    fn record_event_skipped_when_disabled() {
        let (db, mut config) = setup_memory();
        config.enabled = false;
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);

        pipeline.record_event(make_event("ls", 0));

        assert!(buffer.lock().unwrap().is_empty());
    }

    #[test]
    fn record_event_skipped_for_ignored_path() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let ignore_patterns = vec!["/secret/*".to_string()];
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &ignore_patterns);

        let mut event = make_event("ls", 0);
        event.working_dir = Some("/secret/stuff".into());
        pipeline.record_event(event);

        assert!(buffer.lock().unwrap().is_empty());
    }

    #[test]
    fn record_event_buffers_normal_event() {
        let (db, config) = setup_memory();
        let buffer = Mutex::new(IngestionBuffer::new(15, 60));
        let pipeline = MemoryIngestionPipeline::new(&db, &config, &buffer, &[]);

        pipeline.record_event(make_event("ls", 0));

        assert_eq!(buffer.lock().unwrap().len(), 1);
    }
}
