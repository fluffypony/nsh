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

    pub fn open(
        config: crate::config::MemoryConfig,
        db_path: std::path::PathBuf,
    ) -> anyhow::Result<Self> {
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
        let mut all_ops = Vec::new();

        // Separate fast-path and complex events
        let mut complex_events = Vec::new();

        for event in events {
            let decision = ingestion::router::route(event);
            if ingestion::can_fast_path(event) && decision.only_episodic() {
                let ep = ingestion::fast_path_episodic(event);
                // Check for merge candidates
                let merge_id = {
                    let conn = self.db.lock().unwrap();
                    ingestion::consolidator::find_merge_candidate(&conn, &ep.summary, 30)?
                };
                if let Some(id) = merge_id {
                    {
                        let conn = self.db.lock().unwrap();
                        store::episodic::merge(
                            &conn,
                            &id,
                            &ep.summary,
                            ep.details.as_deref(),
                            &ep.search_keywords,
                        )?;
                    }
                    all_ops.push(MemoryOp::EpisodicMerge {
                        target_id: id,
                        combined_summary: ep.summary,
                        additional_details: ep.details,
                        search_keywords: ep.search_keywords,
                    });
                } else {
                    let conn = self.db.lock().unwrap();
                    store::episodic::insert(&conn, &ep)?;
                    all_ops.push(MemoryOp::EpisodicInsert { event: ep });
                }
            } else {
                complex_events.push(event.clone());
            }
        }

        // Process complex events with LLM extraction
        if !complex_events.is_empty() {
            // Collect inputs while holding DB lock in a limited scope, then drop before await
            let (core, recent, semantic, procedural) = {
                let conn = self.db.lock().unwrap();
                let core = store::core::get_all(&conn)?;
                let recent = store::episodic::list_recent(&conn, 10, None, None)?;
                let semantic = store::semantic::list_all(&conn)?;
                let procedural = store::procedural::list_all(&conn)?;
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
        let temporal_range =
            crate::memory::temporal::parse_temporal_expression(&ctx.query, chrono::Utc::now());
        // Use space separator to match SQLite's datetime() format: "YYYY-MM-DD HH:MM:SS"
        let since_str =
            temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        // Get fade cutoff and core/recent data while holding the lock briefly
        let (fade_cutoff, core, recent, top_semantic, cwd_resources) = {
            let conn = self.db.lock().unwrap();
            let cutoff = decay::get_fade_cutoff(&conn, self.config.fade_after_days)?;
            let core = store::core::get_all(&conn)?;
            let recent = store::episodic::list_recent(&conn, 10, Some(&cutoff), since_ref)?;
            // MIRIX: always fetch high-access semantic items (user preferences)
            let top_sem = store::semantic::list_top_accessed(&conn, 5).unwrap_or_default();
            // MIRIX: always fetch CWD-relevant resources
            let cwd_res = if let Some(ref cwd) = ctx.cwd {
                store::resource::get_for_cwd(&conn, cwd, 3).unwrap_or_default()
            } else {
                vec![]
            };
            (cutoff, core, recent, top_sem, cwd_res)
        };

        // Extract topics without holding the lock (may call LLM)
        let keywords = retrieval::topic_extractor::extract(ctx, llm).await;

        // Re-acquire lock for searches
        let conn = self.db.lock().unwrap();
        let mut memories = RetrievedMemories {
            keywords: keywords.clone(),
            core,
            recent_episodic: recent,
            // MIRIX: seed with always-recalled semantic items and CWD resources
            semantic: top_semantic,
            resource: cwd_resources,
            ..Default::default()
        };

        if retrieval::needs_full_retrieval(ctx.interaction_mode) && !keywords.is_empty() {
            let query_str = keywords.join(" ");
            memories.relevant_episodic =
                store::episodic::search_bm25(&conn, &query_str, 10, Some(&fade_cutoff), since_ref)?;

            // Merge BM25 semantic results with always-recalled top-accessed items
            let bm25_semantic = store::semantic::search_bm25(&conn, &query_str, 10)?;
            for item in bm25_semantic {
                if !memories.semantic.iter().any(|existing| existing.id == item.id) {
                    memories.semantic.push(item);
                }
            }

            memories.procedural = store::procedural::search_bm25(&conn, &query_str, 5)?;

            // Merge BM25 resource results with always-recalled CWD resources
            let bm25_resources = store::resource::search_bm25(&conn, &query_str, 5)?;
            for r in bm25_resources {
                if !memories.resource.iter().any(|existing| existing.id == r.id) {
                    memories.resource.push(r);
                }
            }

            memories.knowledge =
                store::knowledge::search_bm25(&conn, &query_str, 5, Sensitivity::Medium)?;
        }

        // Update access counts for all semantic items that will be shown
        for item in &memories.semantic {
            let _ = store::semantic::increment_access(&conn, &item.id);
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
            MemoryType::Episodic => {
                store::episodic::delete(&conn, &ids)?;
            }
            MemoryType::Semantic => {
                store::semantic::delete(&conn, &ids)?;
            }
            MemoryType::Procedural => {
                store::procedural::delete(&conn, &ids)?;
            }
            MemoryType::Resource => {
                store::resource::delete(&conn, &ids)?;
            }
            MemoryType::Knowledge => {
                store::knowledge::delete(&conn, &ids)?;
            }
        }
        Ok(())
    }

    pub fn export_all(&self) -> anyhow::Result<serde_json::Value> {
        let conn = self.db.lock().unwrap();
        let core = store::core::get_all(&conn)?;
        let episodic = store::episodic::list_all(&conn)?;
        let semantic = store::semantic::list_all(&conn)?;
        let procedural = store::procedural::list_all(&conn)?;
        let resource = store::resource::list_all(&conn)?;
        let knowledge = store::knowledge::list_all(&conn)?;

        Ok(serde_json::json!({
            "core": core,
            "episodic": episodic,
            "semantic": semantic,
            "procedural": procedural,
            "resource": resource,
            "knowledge": knowledge,
        }))
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
        let report = decay::run_decay(
            &conn,
            self.config.fade_after_days,
            self.config.expire_after_days,
        )?;
        // Telemetry counters and timestamps
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('last_decay_at', datetime('now')) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![],
        );
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('decay_runs', '1') \
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            rusqlite::params![],
        );
        Ok(report)
    }

    pub async fn run_reflection(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<ReflectionReport> {
        // Phase 1: snapshot state under lock
        let (unconsolidated, core, semantic, procedural) = {
            let conn = self.db.lock().unwrap();
            let uncon = crate::memory::store::episodic::list_unconsolidated(&conn, 100)?;
            if uncon.is_empty() {
                return Ok(ReflectionReport::default());
            }
            let core = crate::memory::store::core::get_all(&conn)?;
            let semantic = crate::memory::store::semantic::list_all(&conn)?;
            let procedural = crate::memory::store::procedural::list_all(&conn)?;
            (uncon, core, semantic, procedural)
        };

        // Phase 2: LLM call without holding the DB lock
        let prompt =
            reflection::build_reflection_prompt(&unconsolidated, &core, &semantic, &procedural);
        let response = llm.complete_json(&prompt).await?;
        let ops = reflection::parse_reflection_response(&response);

        // Phase 3: apply ops and mark consolidated under lock
        let mut report = ReflectionReport::default();
        let ids: Vec<String> = unconsolidated.iter().map(|e| e.id.clone()).collect();
        let conn = self.db.lock().unwrap();
        for op in &ops {
            if self.apply_op(&conn, op).is_ok() {
                report.ops_applied += 1;
            }
        }
        crate::memory::store::episodic::mark_consolidated(&conn, &ids)?;
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('last_reflection_at', datetime('now')) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![],
        );
        let _ = conn.execute(
            "INSERT INTO memory_config(key, value) VALUES('reflection_runs', '1') \
             ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + 1",
            rusqlite::params![],
        );
        Ok(report)
    }

    pub async fn bootstrap_scan(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<BootstrapReport> {
        // Implement without holding the DB lock across awaits
        let home = dirs::home_dir().unwrap_or_default();
        let config_files = [
            (".zshrc", "Zsh configuration"),
            (".bashrc", "Bash configuration"),
            (".bash_profile", "Bash profile"),
            (".profile", "Shell profile"),
            (".gitconfig", "Git configuration"),
            (".ssh/config", "SSH configuration"),
            (".cargo/config.toml", "Cargo configuration"),
            (".npmrc", "npm configuration"),
            (".docker/config.json", "Docker configuration"),
        ];

        let mut report = BootstrapReport::default();

        for (filename, description) in &config_files {
            let path = home.join(filename);
            if !path.exists() {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if content.len() > 50_000 {
                continue;
            }
            let (redacted, _) = crate::memory::privacy::redact_secrets_for_memory(&content);
            let prompt = format!(
                "Summarize this config file in 2-3 sentences. What tools, settings, and preferences does it reveal?\n\nFile: {filename} ({description})\n\n```\n{redacted}\n```\n\nAlso provide 5-10 search keywords as a space-separated string.\n\nRespond with JSON: {{\"summary\": \"...\", \"keywords\": \"...\"}}"
            );

            if let Ok(response) = llm.complete_json(&prompt).await {
                let (summary, keywords) =
                    crate::memory::bootstrap::parse_bootstrap_response(&response, description);
                let path_str = path.to_string_lossy().to_string();
                let hash = crate::memory::bootstrap::compute_hash(&content);
                let conn = self.db.lock().unwrap();
                crate::memory::store::resource::upsert_by_path(
                    &conn,
                    "config",
                    &path_str,
                    &hash,
                    description,
                    &summary,
                    None,
                    &keywords,
                )?;
                report.files_scanned += 1;
            }
        }

        // Detect installed tools for Environment core block
        let tools = crate::memory::bootstrap::detect_installed_tools();
        if !tools.is_empty() {
            let env_text = format!("Installed tools: {}", tools.join(", "));
            let conn = self.db.lock().unwrap();
            crate::memory::store::core::append(
                &conn,
                crate::memory::types::CoreLabel::Environment,
                &env_text,
            )?;
        }

        // Record bootstrap completion
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES ('last_bootstrap_at', datetime('now'))",
            [],
        )?;

        Ok(report)
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

    pub fn should_flush_ingestion(&self) -> bool {
        self.ingestion_buffer.lock().unwrap().should_flush()
    }

    #[cfg(test)]
    pub fn is_incognito(&self) -> bool {
        self.config.incognito
    }

    pub fn is_ignored_path(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        privacy::is_ignored_path(&path_str, &self.ignore_patterns)
    }

    #[cfg(test)]
    pub fn set_config(&self, key: &str, value: &str) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO memory_config (key, value) VALUES (?, ?)",
            rusqlite::params![key, value],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub fn resource_exists_with_hash(&self, path: &Path, hash: &str) -> anyhow::Result<bool> {
        let conn = self.db.lock().unwrap();
        crate::memory::store::resource::exists_with_hash(&conn, &path.to_string_lossy(), hash)
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
                store::semantic::update_by_id(
                    conn,
                    id,
                    summary,
                    details.as_deref(),
                    search_keywords,
                )?;
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
                store::procedural::insert(
                    conn,
                    entry_type,
                    trigger_pattern,
                    summary,
                    steps,
                    search_keywords,
                )?;
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
    use async_trait::async_trait;

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

    #[test]
    fn open_in_memory_works() {
        let mem = MemorySystem::open_in_memory().unwrap();
        let stats = mem.stats().unwrap();
        assert_eq!(stats.core_count, 3);
    }

    #[test]
    fn record_event_adds_to_buffer() {
        let mem = MemorySystem::open_in_memory().unwrap();
        mem.record_event(ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some("cargo build".into()),
            output: None,
            exit_code: Some(0),
            working_dir: Some("/home/user/project".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        });

        let buffer = mem.ingestion_buffer.lock().unwrap();
        assert_eq!(buffer.len(), 1, "event should be in buffer");
    }

    #[test]
    fn record_event_skips_password_prompts() {
        let mem = MemorySystem::open_in_memory().unwrap();
        mem.record_event(ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some("sudo command".into()),
            output: Some("Password:".into()),
            exit_code: Some(0),
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        });

        let buffer = mem.ingestion_buffer.lock().unwrap();
        assert!(
            buffer.is_empty(),
            "password prompt events should be skipped"
        );
    }

    #[test]
    fn record_event_skips_binary_output() {
        let mem = MemorySystem::open_in_memory().unwrap();
        mem.record_event(ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some("cat binary".into()),
            output: Some("hello\x00world".into()),
            exit_code: Some(0),
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        });

        let buffer = mem.ingestion_buffer.lock().unwrap();
        assert!(buffer.is_empty(), "binary output events should be skipped");
    }

    #[test]
    fn search_with_populated_data() {
        let mem = MemorySystem::open_in_memory().unwrap();
        // Insert a semantic item directly
        {
            let conn = mem.db.lock().unwrap();
            crate::memory::store::semantic::insert_or_update(
                &conn,
                "Rust toolchain",
                "tools",
                "Uses cargo for building",
                None,
                "rust cargo build",
            )
            .unwrap();
        }

        let results = mem.search("cargo", None, 10).unwrap();
        assert!(!results.is_empty(), "search should find the semantic entry");
    }

    #[test]
    fn delete_memory_works() {
        let mem = MemorySystem::open_in_memory().unwrap();
        let id = {
            let conn = mem.db.lock().unwrap();
            crate::memory::store::semantic::insert_or_update(
                &conn, "fact", "general", "test", None, "test",
            )
            .unwrap()
        };

        mem.delete_memory(MemoryType::Semantic, &id).unwrap();
        let stats = mem.stats().unwrap();
        assert_eq!(stats.semantic_count, 0);
    }

    #[test]
    fn delete_core_fails() {
        let mem = MemorySystem::open_in_memory().unwrap();
        let result = mem.delete_memory(MemoryType::Core, "human");
        assert!(result.is_err(), "deleting core memory should fail");
    }

    #[test]
    fn apply_op_all_types() {
        let mem = MemorySystem::open_in_memory().unwrap();
        let conn = mem.db.lock().unwrap();

        // Test CoreAppend
        mem.apply_op(
            &conn,
            &MemoryOp::CoreAppend {
                label: "human".into(),
                content: "likes Rust".into(),
            },
        )
        .unwrap();

        // Test CoreRewrite
        mem.apply_op(
            &conn,
            &MemoryOp::CoreRewrite {
                label: "persona".into(),
                content: "helpful assistant".into(),
            },
        )
        .unwrap();

        // Test SemanticInsert
        mem.apply_op(
            &conn,
            &MemoryOp::SemanticInsert {
                name: "test_fact".into(),
                category: "general".into(),
                summary: "a test fact".into(),
                details: None,
                search_keywords: "test fact".into(),
            },
        )
        .unwrap();

        // Test ProceduralInsert
        mem.apply_op(
            &conn,
            &MemoryOp::ProceduralInsert {
                entry_type: "workflow".into(),
                trigger_pattern: "deploy".into(),
                summary: "deploy flow".into(),
                steps: "[]".into(),
                search_keywords: "deploy".into(),
            },
        )
        .unwrap();

        // Test ResourceInsert
        mem.apply_op(
            &conn,
            &MemoryOp::ResourceInsert {
                resource_type: "file".into(),
                file_path: Some("/tmp/test".into()),
                file_hash: None,
                title: "test file".into(),
                summary: "test".into(),
                content: None,
                search_keywords: "test".into(),
            },
        )
        .unwrap();

        // Test NoOp
        mem.apply_op(
            &conn,
            &MemoryOp::NoOp {
                reason: "test".into(),
            },
        )
        .unwrap();

        // Verify everything was created
        let blocks = crate::memory::store::core::get_all(&conn).unwrap();
        let human = blocks.iter().find(|b| b.label == CoreLabel::Human).unwrap();
        assert!(human.value.contains("likes Rust"));

        let persona = blocks
            .iter()
            .find(|b| b.label == CoreLabel::Persona)
            .unwrap();
        assert_eq!(persona.value, "helpful assistant");

        assert_eq!(crate::memory::store::semantic::count(&conn).unwrap(), 1);
        assert_eq!(crate::memory::store::procedural::count(&conn).unwrap(), 1);
        assert_eq!(crate::memory::store::resource::count(&conn).unwrap(), 1);
    }

    #[test]
    fn set_config_stores_value() {
        let mem = MemorySystem::open_in_memory().unwrap();
        mem.set_config("test_key", "test_value").unwrap();

        let conn = mem.db.lock().unwrap();
        let val: String = conn
            .query_row(
                "SELECT value FROM memory_config WHERE key = 'test_key'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(val, "test_value");
    }

    #[test]
    fn should_flush_ingestion_initially_false() {
        let mem = MemorySystem::open_in_memory().unwrap();
        assert!(
            !mem.should_flush_ingestion(),
            "should not flush with empty buffer"
        );
    }

    #[test]
    fn has_bootstrapped_initially_false() {
        let mem = MemorySystem::open_in_memory().unwrap();
        assert!(!mem.has_bootstrapped());
    }

    #[test]
    fn clear_selective_by_type() {
        let mem = MemorySystem::open_in_memory().unwrap();

        // Add data to multiple types
        {
            let conn = mem.db.lock().unwrap();
            crate::memory::store::semantic::insert_or_update(
                &conn, "fact", "general", "test", None, "test",
            )
            .unwrap();
            crate::memory::store::episodic::insert(
                &conn,
                &crate::memory::types::EpisodicEventCreate {
                    event_type: crate::memory::types::EventType::CommandExecution,
                    actor: crate::memory::types::Actor::User,
                    summary: "test".into(),
                    details: None,
                    command: None,
                    exit_code: None,
                    working_dir: None,
                    project_context: None,
                    search_keywords: "test".into(),
                },
            )
            .unwrap();
        }

        let stats = mem.stats().unwrap();
        assert_eq!(stats.semantic_count, 1);
        assert_eq!(stats.episodic_count, 1);

        // clear_all should reset everything
        mem.clear_all().unwrap();
        let stats = mem.stats().unwrap();
        assert_eq!(stats.semantic_count, 0);
        assert_eq!(stats.episodic_count, 0);
    }

    #[test]
    fn resource_exists_with_hash_integration() {
        let mem = MemorySystem::open_in_memory().unwrap();
        {
            let conn = mem.db.lock().unwrap();
            crate::memory::store::resource::insert(
                &conn,
                "file",
                Some("/tmp/test"),
                Some("hash123"),
                "test",
                "test",
                None,
                "test",
            )
            .unwrap();
        }

        assert!(
            mem.resource_exists_with_hash(std::path::Path::new("/tmp/test"), "hash123")
                .unwrap()
        );
        assert!(
            !mem.resource_exists_with_hash(std::path::Path::new("/tmp/test"), "wrong_hash")
                .unwrap()
        );
    }

    #[test]
    fn disabled_memory_skips_events() {
        let mut config = test_config();
        config.enabled = false;
        let mem = MemorySystem::open(config, ":memory:".into()).unwrap();

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
        assert!(buffer.is_empty(), "disabled memory should skip events");
    }

    struct MockLlm;

    #[async_trait]
    impl crate::memory::llm_adapter::MemoryLlmClient for MockLlm {
        async fn complete_json(&self, _prompt: &str) -> anyhow::Result<String> {
            Ok(r#"[{"op":"SemanticInsert","name":"Project uses cargo","category":"project","summary":"User builds with cargo","details":null,"search_keywords":"cargo build project"} ]"#.to_string())
        }
        async fn complete(&self, _system: &str, _user: &str) -> anyhow::Result<String> {
            Ok(String::new())
        }
    }

    #[tokio::test]
    async fn reflection_promotes_semantic_and_marks_consolidated() {
        let mem = MemorySystem::open_in_memory().unwrap();
        {
            let conn = mem.db.lock().unwrap();
            crate::memory::store::episodic::insert(
                &conn,
                &crate::memory::types::EpisodicEventCreate {
                    event_type: crate::memory::types::EventType::CommandExecution,
                    actor: crate::memory::types::Actor::User,
                    summary: "Ran cargo build successfully".into(),
                    details: None,
                    command: Some("cargo build".into()),
                    exit_code: Some(0),
                    working_dir: None,
                    project_context: None,
                    search_keywords: "cargo build".into(),
                },
            )
            .unwrap();
        }

        let report = mem.run_reflection(&MockLlm).await.unwrap();
        assert!(report.ops_applied >= 1);

        let conn = mem.db.lock().unwrap();
        let sem_count = crate::memory::store::semantic::count(&conn).unwrap();
        assert!(sem_count >= 1);
        let uncon = crate::memory::store::episodic::list_unconsolidated(&conn, 10).unwrap();
        assert!(uncon.is_empty());
    }
}
