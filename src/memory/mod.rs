pub mod bootstrap;
pub mod decay;
pub mod id;
pub mod ingestion;
pub mod llm_adapter;
pub mod privacy;
pub mod reflection;
pub mod retrieval;
pub mod schema;
pub mod search;
pub mod store;
pub mod temporal;
pub mod types;

use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

pub use types::*;

pub struct MemorySystem {
    db: Arc<Mutex<Connection>>,
    config: crate::config::MemoryConfig,
    ingestion_buffer: std::sync::Mutex<ingestion::IngestionBuffer>,
    ignore_patterns: Vec<String>,
}

impl MemorySystem {
    #[cfg(test)]
    pub fn open_in_memory() -> anyhow::Result<Self> {
        let config = crate::config::MemoryConfig::default();
        let conn = Connection::open_in_memory()?;
        schema::create_memory_tables(&conn)?;
        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            ingestion_buffer: std::sync::Mutex::new(ingestion::IngestionBuffer::new(
                config.ingestion_buffer_size,
                config.ingestion_buffer_age_secs,
            )),
            config,
            ignore_patterns: Vec::new(),
        })
    }

    pub fn open(config: crate::config::MemoryConfig, db_path: std::path::PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;",
        )?;

        schema::create_memory_tables(&conn)?;

        let ignore_patterns = privacy::load_ignore_patterns();

        Ok(Self {
            db: Arc::new(Mutex::new(conn)),
            ingestion_buffer: std::sync::Mutex::new(ingestion::IngestionBuffer::new(
                config.ingestion_buffer_size,
                config.ingestion_buffer_age_secs,
            )),
            config,
            ignore_patterns,
        })
    }

    pub fn record_event(&self, event: ShellEvent) {
        if self.config.incognito || !self.config.enabled {
            return;
        }

        // Check ignored paths
        if let Some(ref cwd) = event.working_dir {
            if self.is_ignored_path(Path::new(cwd)) {
                return;
            }
        }

        // Skip password prompts
        if let Some(ref output) = event.output {
            if privacy::is_password_prompt(output) {
                return;
            }
            if privacy::should_skip_output(output) {
                return;
            }
        }

        let mut buffer = self.ingestion_buffer.lock().unwrap();
        let _should_flush = buffer.push(event);
        // Auto-flush is handled by the caller (daemon) via flush_ingestion()
    }

    pub async fn flush_ingestion(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<()> {
        let events = {
            let mut buffer = self.ingestion_buffer.lock().unwrap();
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
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<Vec<MemoryOp>> {
        let conn = self.db.lock().unwrap();
        let mut all_ops = Vec::new();

        // Separate fast-path and complex events
        let mut complex_events = Vec::new();

        for event in events {
            let decision = ingestion::router::route(event);
            if ingestion::can_fast_path(event) && decision.only_episodic() {
                let ep = ingestion::fast_path_episodic(event);
                // Check for merge candidates
                let merge_id = ingestion::consolidator::find_merge_candidate(
                    &conn,
                    &ep.summary,
                    30,
                )?;
                if let Some(id) = merge_id {
                    store::episodic::merge(
                        &conn,
                        &id,
                        &ep.summary,
                        ep.details.as_deref(),
                        &ep.search_keywords,
                    )?;
                    all_ops.push(MemoryOp::EpisodicMerge {
                        target_id: id,
                        combined_summary: ep.summary,
                        additional_details: ep.details,
                        search_keywords: ep.search_keywords,
                    });
                } else {
                    store::episodic::insert(&conn, &ep)?;
                    all_ops.push(MemoryOp::EpisodicInsert { event: ep });
                }
            } else {
                complex_events.push(event.clone());
            }
        }

        // Process complex events with LLM extraction
        if !complex_events.is_empty() {
            let core = store::core::get_all(&conn)?;
            let recent = store::episodic::list_recent(&conn, 10, None, None)?;
            let semantic = store::semantic::list_all(&conn)?;
            let procedural = store::procedural::list_all(&conn)?;

            // Drop the lock before async call
            drop(conn);

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
            for op in &ops {
                self.apply_op(&conn, op)?;
            }
            all_ops.extend(ops);
        }

        Ok(all_ops)
    }

    pub async fn retrieve_for_query(
        &self,
        ctx: &MemoryQueryContext,
        llm: Option<&dyn llm_adapter::MemoryLlmClient>,
    ) -> anyhow::Result<RetrievedMemories> {
        // Parse temporal expression from query to constrain time range
        let temporal_range = crate::memory::temporal::parse_temporal_expression(
            &ctx.query,
            chrono::Utc::now(),
        );
        // Use space separator to match SQLite's datetime() format: "YYYY-MM-DD HH:MM:SS"
        let since_str = temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        // Get fade cutoff and core/recent data while holding the lock briefly
        let (fade_cutoff, core, recent) = {
            let conn = self.db.lock().unwrap();
            let cutoff = decay::get_fade_cutoff(&conn, self.config.fade_after_days)?;
            let core = store::core::get_all(&conn)?;
            let recent = store::episodic::list_recent(&conn, 10, Some(&cutoff), since_ref)?;
            (cutoff, core, recent)
        };

        // Extract topics without holding the lock (may call LLM)
        let keywords = retrieval::topic_extractor::extract(ctx, llm).await;

        // Re-acquire lock for searches
        let conn = self.db.lock().unwrap();
        let mut memories = RetrievedMemories {
            keywords: keywords.clone(),
            core,
            recent_episodic: recent,
            ..Default::default()
        };

        if retrieval::needs_full_retrieval(ctx.interaction_mode) && !keywords.is_empty() {
            let query_str = keywords.join(" ");
            memories.relevant_episodic =
                store::episodic::search_bm25(&conn, &query_str, 10, Some(&fade_cutoff), since_ref)?;
            memories.semantic =
                store::semantic::search_bm25(&conn, &query_str, 10)?;
            memories.procedural =
                store::procedural::search_bm25(&conn, &query_str, 5)?;
            memories.resource =
                store::resource::search_bm25(&conn, &query_str, 5)?;

            if let Some(ref cwd) = ctx.cwd {
                let cwd_resources = store::resource::get_for_cwd(&conn, cwd, 3)?;
                for r in cwd_resources {
                    if !memories.resource.iter().any(|existing| existing.id == r.id) {
                        memories.resource.push(r);
                    }
                }
            }

            memories.knowledge = store::knowledge::search_bm25(
                &conn, &query_str, 5, Sensitivity::Medium,
            )?;

            for item in &memories.semantic {
                let _ = store::semantic::increment_access(&conn, &item.id);
            }
        }

        drop(conn);
        retrieval::ranker::enforce_budget(&mut memories, 4000);
        Ok(memories)
    }

    pub fn build_memory_prompt(&self, memories: &RetrievedMemories) -> String {
        retrieval::prompt_builder::build_memory_prompt(memories)
    }

    pub fn get_core_memory(&self) -> anyhow::Result<Vec<CoreBlock>> {
        let conn = self.db.lock().unwrap();
        store::core::get_all(&conn)
    }

    pub fn update_core_block(
        &self,
        label: CoreLabel,
        op: CoreOp,
        content: &str,
    ) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        match op {
            CoreOp::Append => store::core::append(&conn, label, content),
            CoreOp::Rewrite => store::core::rewrite(&conn, label, content),
        }
    }

    pub fn search(
        &self,
        query: &str,
        _memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<Vec<SearchResult>> {
        let conn = self.db.lock().unwrap();
        search::search_all(&conn, query, limit)
    }

    pub fn delete_memory(&self, memory_type: MemoryType, id: &str) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        let ids = vec![id.to_string()];
        match memory_type {
            MemoryType::Core => anyhow::bail!("Cannot delete core memory blocks"),
            MemoryType::Episodic => { store::episodic::delete(&conn, &ids)?; }
            MemoryType::Semantic => { store::semantic::delete(&conn, &ids)?; }
            MemoryType::Procedural => { store::procedural::delete(&conn, &ids)?; }
            MemoryType::Resource => { store::resource::delete(&conn, &ids)?; }
            MemoryType::Knowledge => { store::knowledge::delete(&conn, &ids)?; }
        }
        Ok(())
    }

    pub fn stats(&self) -> anyhow::Result<MemoryStats> {
        let conn = self.db.lock().unwrap();
        Ok(MemoryStats {
            core_count: 3,
            episodic_count: store::episodic::count(&conn)?,
            semantic_count: store::semantic::count(&conn)?,
            procedural_count: store::procedural::count(&conn)?,
            resource_count: store::resource::count(&conn)?,
            knowledge_count: store::knowledge::count(&conn)?,
        })
    }

    pub fn run_decay(&self) -> anyhow::Result<DecayReport> {
        let conn = self.db.lock().unwrap();
        decay::run_decay(&conn, self.config.fade_after_days, self.config.expire_after_days)
    }

    pub async fn run_reflection(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<ReflectionReport> {
        let conn = self.db.lock().unwrap();
        reflection::run_reflection(&conn, llm).await
    }

    pub async fn bootstrap_scan(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<BootstrapReport> {
        let conn = self.db.lock().unwrap();
        bootstrap::bootstrap_scan(&conn, llm).await
    }

    pub fn clear_all(&self) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute_batch(
            "DELETE FROM episodic_memory;
             DELETE FROM semantic_memory;
             DELETE FROM procedural_memory;
             DELETE FROM resource_memory;
             DELETE FROM knowledge_vault;
             UPDATE core_memory SET value = '', updated_at = datetime('now');
             DELETE FROM memory_config WHERE key IN ('last_decay_at', 'last_reflection_at', 'last_bootstrap_at');",
        )?;
        Ok(())
    }

    pub fn is_incognito(&self) -> bool {
        self.config.incognito
    }

    pub fn has_bootstrapped(&self) -> bool {
        let conn = self.db.lock().unwrap();
        bootstrap::has_bootstrapped(&conn)
    }

    pub fn should_run_reflection(&self) -> bool {
        let conn = self.db.lock().unwrap();
        reflection::should_run_reflection(&conn, self.config.consolidation_threshold)
    }

    pub fn should_run_decay(&self) -> bool {
        let conn = self.db.lock().unwrap();
        decay::should_run_decay(&conn)
    }

    pub fn set_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES (?, ?)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    pub fn should_flush_ingestion(&self) -> bool {
        self.ingestion_buffer.lock().unwrap().should_flush()
    }

    pub fn is_ignored_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        privacy::is_ignored_path(&path_str, &self.ignore_patterns)
    }

    pub fn resource_exists_with_hash(&self, path: &Path, hash: &str) -> anyhow::Result<bool> {
        let conn = self.db.lock().unwrap();
        store::resource::exists_with_hash(&conn, &path.to_string_lossy(), hash)
    }

    pub fn queue_resource_scan(&self, _path: std::path::PathBuf, _content: String, _hash: String) {
        // Resource scanning is deferred to the ingestion pipeline
        // Will be implemented when resource scanning is wired into the daemon
    }

    fn apply_op(&self, conn: &Connection, op: &MemoryOp) -> anyhow::Result<()> {
        match op {
            MemoryOp::CoreAppend { label, content } => {
                if let Some(l) = CoreLabel::from_str(label) {
                    store::core::append(conn, l, content)?;
                }
            }
            MemoryOp::CoreRewrite { label, content } => {
                if let Some(l) = CoreLabel::from_str(label) {
                    store::core::rewrite(conn, l, content)?;
                }
            }
            MemoryOp::EpisodicInsert { event } => {
                store::episodic::insert(conn, event)?;
            }
            MemoryOp::EpisodicMerge {
                target_id,
                combined_summary,
                additional_details,
                search_keywords,
            } => {
                store::episodic::merge(
                    conn,
                    target_id,
                    combined_summary,
                    additional_details.as_deref(),
                    search_keywords,
                )?;
            }
            MemoryOp::EpisodicDelete { ids } => {
                store::episodic::delete(conn, ids)?;
            }
            MemoryOp::SemanticInsert {
                name,
                category,
                summary,
                details,
                search_keywords,
            } => {
                store::semantic::insert_or_update(
                    conn,
                    name,
                    category,
                    summary,
                    details.as_deref(),
                    search_keywords,
                )?;
            }
            MemoryOp::SemanticUpdate {
                id,
                summary,
                details,
                search_keywords,
            } => {
                store::semantic::update_by_id(conn, id, summary, details.as_deref(), search_keywords)?;
            }
            MemoryOp::SemanticDelete { ids } => {
                store::semantic::delete(conn, ids)?;
            }
            MemoryOp::ProceduralInsert {
                entry_type,
                trigger_pattern,
                summary,
                steps,
                search_keywords,
            } => {
                store::procedural::insert(conn, entry_type, trigger_pattern, summary, steps, search_keywords)?;
            }
            MemoryOp::ProceduralUpdate {
                id,
                summary,
                steps,
                search_keywords,
            } => {
                store::procedural::update(conn, id, summary, steps, search_keywords)?;
            }
            MemoryOp::ProceduralDelete { ids } => {
                store::procedural::delete(conn, ids)?;
            }
            MemoryOp::ResourceInsert {
                resource_type,
                file_path,
                file_hash,
                title,
                summary,
                content,
                search_keywords,
            } => {
                store::resource::insert(
                    conn,
                    resource_type,
                    file_path.as_deref(),
                    file_hash.as_deref(),
                    title,
                    summary,
                    content.as_deref(),
                    search_keywords,
                )?;
            }
            MemoryOp::ResourceDelete { ids } => {
                store::resource::delete(conn, ids)?;
            }
            MemoryOp::KnowledgeInsert {
                entry_type,
                caption,
                secret_value,
                sensitivity,
                search_keywords,
            } => {
                store::knowledge::insert(
                    conn,
                    entry_type,
                    caption,
                    secret_value,
                    Sensitivity::from_str(sensitivity),
                    search_keywords,
                )?;
            }
            MemoryOp::KnowledgeDelete { ids } => {
                store::knowledge::delete(conn, ids)?;
            }
            MemoryOp::NoOp { .. } => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> crate::config::MemoryConfig {
        crate::config::MemoryConfig::default()
    }

    #[test]
    fn open_and_stats() {
        let mem = MemorySystem::open(test_config(), ":memory:".into()).unwrap();
        let stats = mem.stats().unwrap();
        assert_eq!(stats.core_count, 3);
        assert_eq!(stats.episodic_count, 0);
    }

    #[test]
    fn core_memory_operations() {
        let mem = MemorySystem::open(test_config(), ":memory:".into()).unwrap();
        mem.update_core_block(CoreLabel::Human, CoreOp::Append, "Name: Alice")
            .unwrap();
        let blocks = mem.get_core_memory().unwrap();
        let human = blocks.iter().find(|b| b.label == CoreLabel::Human).unwrap();
        assert_eq!(human.value, "Name: Alice");

        mem.update_core_block(CoreLabel::Human, CoreOp::Rewrite, "Name: Bob")
            .unwrap();
        let blocks = mem.get_core_memory().unwrap();
        let human = blocks.iter().find(|b| b.label == CoreLabel::Human).unwrap();
        assert_eq!(human.value, "Name: Bob");
    }

    #[test]
    fn incognito_skips_events() {
        let mut config = test_config();
        config.incognito = true;
        let mem = MemorySystem::open(config, ":memory:".into()).unwrap();
        assert!(mem.is_incognito());

        mem.record_event(ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some("cargo build".into()),
            output: None,
            exit_code: Some(0),
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        });

        let buffer = mem.ingestion_buffer.lock().unwrap();
        assert!(buffer.is_empty());
    }

    #[test]
    fn clear_all_resets() {
        let mem = MemorySystem::open(test_config(), ":memory:".into()).unwrap();
        mem.update_core_block(CoreLabel::Human, CoreOp::Append, "test")
            .unwrap();
        mem.clear_all().unwrap();
        let blocks = mem.get_core_memory().unwrap();
        let human = blocks.iter().find(|b| b.label == CoreLabel::Human).unwrap();
        assert!(human.value.is_empty());
    }

    #[test]
    fn decay_runs() {
        let mem = MemorySystem::open(test_config(), ":memory:".into()).unwrap();
        let report = mem.run_decay().unwrap();
        assert_eq!(report.episodic_deleted, 0);
    }

    #[test]
    fn memory_prompt_generation() {
        let mem = MemorySystem::open(test_config(), ":memory:".into()).unwrap();
        mem.update_core_block(CoreLabel::Human, CoreOp::Append, "Name: Test User")
            .unwrap();

        let memories = RetrievedMemories {
            core: mem.get_core_memory().unwrap(),
            ..Default::default()
        };
        let prompt = mem.build_memory_prompt(&memories);
        assert!(prompt.contains("Test User"));
        assert!(prompt.contains("<memory_context"));
    }
}
