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
