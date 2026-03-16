pub mod bootstrap;
pub mod decay;
pub mod id;
pub mod ingestion;
pub mod llm_adapter;
pub mod maintenance;
pub mod privacy;
pub mod reflection;
pub mod retrieval;
pub mod schema;
pub mod search;
pub mod store;
pub mod temporal;
#[cfg(test)]
pub(crate) mod test_support;
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
        self.ingestion_pipeline().record_event(event);
    }

    pub async fn flush_ingestion(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<()> {
        self.ingestion_pipeline().flush_ingestion(llm).await
    }

    pub async fn ingest_batch(
        &self,
        events: &[ShellEvent],
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<Vec<MemoryOp>> {
        self.ingestion_pipeline().ingest_batch(events, llm).await
    }

    /// Retrieve memories relevant to the given query context.
    ///
    /// Side effect: increments access counters on returned semantic items
    /// so the decay system can preserve frequently-accessed facts.
    pub async fn retrieve_for_query(
        &self,
        ctx: &MemoryQueryContext,
        llm: Option<&dyn llm_adapter::MemoryLlmClient>,
    ) -> anyhow::Result<RetrievedMemories> {
        self.retrieval_engine().retrieve_for_query(ctx, llm).await
    }

    pub fn build_memory_prompt(&self, memories: &RetrievedMemories) -> String {
        self.retrieval_engine().build_memory_prompt(memories)
    }

    pub fn core_memory(&self) -> anyhow::Result<Vec<CoreBlock>> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).core_memory()
    }

    pub fn update_core_block(
        &self,
        label: CoreLabel,
        op: CoreOp,
        content: &str,
    ) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).update_core_block(label, op, content)
    }

    pub fn search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<Vec<SearchResult>> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).search(query, memory_type, limit)
    }

    pub fn delete_memory(&self, memory_type: MemoryType, id: &str) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).delete_memory(memory_type, id)
    }

    pub fn export_all(&self) -> anyhow::Result<serde_json::Value> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).export_all()
    }

    pub fn stats(&self) -> anyhow::Result<MemoryStats> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).stats()
    }

    pub fn run_decay(&self) -> anyhow::Result<DecayReport> {
        self.maintenance().run_decay()
    }

    pub async fn run_reflection(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<ReflectionReport> {
        self.maintenance().run_reflection(llm).await
    }

    pub async fn bootstrap_scan(
        &self,
        llm: &dyn llm_adapter::MemoryLlmClient,
    ) -> anyhow::Result<BootstrapReport> {
        self.maintenance().bootstrap_scan(llm).await
    }

    pub fn clear_all(&self) -> anyhow::Result<()> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).clear_all()
    }

    pub fn has_bootstrapped(&self) -> bool {
        self.maintenance().has_bootstrapped()
    }

    pub fn should_run_reflection(&self) -> bool {
        self.maintenance().should_run_reflection()
    }

    pub fn should_run_decay(&self) -> bool {
        self.maintenance().should_run_decay()
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
        store::access::MemoryStoreAccess::new(&conn).set_config(key, value)
    }

    #[cfg(test)]
    pub fn resource_exists_with_hash(&self, path: &Path, hash: &str) -> anyhow::Result<bool> {
        let conn = self.db.lock().unwrap();
        store::access::MemoryStoreAccess::new(&conn).resource_exists_with_hash(path, hash)
    }

    fn apply_op(&self, conn: &Connection, op: &MemoryOp) -> anyhow::Result<()> {
        store::access::MemoryStoreAccess::new(conn).apply_op(op)
    }

    fn ingestion_pipeline(&self) -> ingestion::pipeline::MemoryIngestionPipeline<'_> {
        ingestion::pipeline::MemoryIngestionPipeline::new(
            &self.db,
            &self.config,
            &self.ingestion_buffer,
            &self.ignore_patterns,
        )
    }

    fn retrieval_engine(&self) -> retrieval::engine::MemoryRetrievalEngine<'_> {
        retrieval::engine::MemoryRetrievalEngine::new(&self.db, &self.config)
    }

    fn maintenance(&self) -> maintenance::MemoryMaintenance<'_> {
        maintenance::MemoryMaintenance::new(&self.db, &self.config)
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
        let blocks = mem.core_memory().unwrap();
        let human = blocks.iter().find(|b| b.label == CoreLabel::Human).unwrap();
        assert_eq!(human.value, "Name: Alice");

        mem.update_core_block(CoreLabel::Human, CoreOp::Rewrite, "Name: Bob")
            .unwrap();
        let blocks = mem.core_memory().unwrap();
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
        let blocks = mem.core_memory().unwrap();
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
            core: mem.core_memory().unwrap(),
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
            crate::memory::store::semantic::store(
                &conn,
                &crate::memory::store::semantic::SemanticWrite {
                    name: "Rust toolchain",
                    category: "tools",
                    summary: "Uses cargo for building",
                    details: None,
                    search_keywords: "rust cargo build",
                },
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
            crate::memory::store::semantic::store(
                &conn,
                &crate::memory::store::semantic::SemanticWrite {
                    name: "fact",
                    category: "general",
                    summary: "test",
                    details: None,
                    search_keywords: "test",
                },
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
            crate::memory::store::semantic::store(
                &conn,
                &crate::memory::store::semantic::SemanticWrite {
                    name: "fact",
                    category: "general",
                    summary: "test",
                    details: None,
                    search_keywords: "test",
                },
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
            crate::memory::store::resource::store(
                &conn,
                &crate::memory::store::resource::ResourceWrite {
                    resource_type: "file",
                    file_path: Some("/tmp/test"),
                    file_hash: Some("hash123"),
                    title: "test",
                    summary: "test",
                    content: None,
                    search_keywords: "test",
                },
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
        async fn complete_json(&self, _prompt: &str) -> anyhow::Result<serde_json::Value> {
            Ok(serde_json::json!([
                {
                    "op": "SemanticInsert",
                    "name": "Project uses cargo",
                    "category": "project",
                    "summary": "User builds with cargo",
                    "details": null,
                    "search_keywords": "cargo build project"
                }
            ]))
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
