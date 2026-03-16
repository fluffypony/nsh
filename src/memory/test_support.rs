use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::memory::llm_adapter::MemoryLlmClient;

/// A configurable mock LLM for memory subsystem tests.
pub(crate) struct MockLlm {
    pub(crate) response: serde_json::Value,
}

#[async_trait::async_trait]
impl MemoryLlmClient for MockLlm {
    async fn complete_json(&self, _prompt: &str) -> anyhow::Result<serde_json::Value> {
        Ok(self.response.clone())
    }
}

/// Create an in-memory database with memory tables initialized.
pub(crate) fn setup_memory() -> (Arc<Mutex<Connection>>, crate::config::MemoryConfig) {
    let conn = Connection::open_in_memory().unwrap();
    crate::memory::schema::create_memory_tables(&conn).unwrap();
    let db = Arc::new(Mutex::new(conn));
    let config = crate::config::MemoryConfig::default();
    (db, config)
}
