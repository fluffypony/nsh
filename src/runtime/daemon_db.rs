use anyhow::anyhow;

use crate::daemon::{DaemonRequest, DaemonResponse};
use crate::db::{
    CommandEntityMatch, CommandForSummary, CommandWithSummary, ConversationExchange, Db,
    HistoryMatch, OtherSessionSummary, ResourceMemoryWrite,
};
use crate::memory::types::{MemoryOp, MemoryType, Sensitivity};

pub trait DbAccess {
    fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<ConversationExchange>>;
    fn recent_commands_with_summaries(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandWithSummary>>;
    fn other_sessions_with_summaries(
        &self,
        session_id: &str,
        max_ttys: usize,
        summaries_per_tty: usize,
    ) -> anyhow::Result<Vec<OtherSessionSummary>>;
    fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>>;
    #[allow(clippy::too_many_arguments)]
    fn search_history_advanced(
        &self,
        fts_query: Option<&str>,
        regex_pattern: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        exit_code: Option<i32>,
        failed_only: bool,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<HistoryMatch>>;
    #[allow(clippy::too_many_arguments)]
    fn search_command_entities(
        &self,
        executable: Option<&str>,
        entity: Option<&str>,
        entity_type: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandEntityMatch>>;
    #[allow(clippy::too_many_arguments)]
    fn insert_conversation(
        &self,
        session_id: &str,
        query: &str,
        response_type: &str,
        response: &str,
        explanation: Option<&str>,
        executed: bool,
        pending: bool,
    ) -> anyhow::Result<i64>;
    fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()>;

    fn commands_needing_llm_summary(&self, limit: usize) -> anyhow::Result<Vec<CommandForSummary>>;
    fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool>;
    fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()>;

    // ── Memory system ──────────────────────────────────
    fn memory_retrieve_prompt(
        &self,
        ctx: &crate::memory::types::MemoryQueryContext,
    ) -> anyhow::Result<String>;
    fn memory_search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<String>;
    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()>;
    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()>;
    fn memory_store(&self, memory_type: MemoryType, data_json: &str) -> anyhow::Result<String>;
    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String>;
    // Note: event recording is routed via daemon requests from query flow; no direct trait use required.
}

macro_rules! forward_dbaccess_method {
    (fn $name:ident (&self $(, $arg:ident : $ty:ty )* $(,)? ) -> $return:ty;) => {
        fn $name(&self, $( $arg : $ty ),*) -> $return {
            crate::db::Db::$name(self, $( $arg ),*).map_err(Into::into)
        }
    };
}

impl DbAccess for Db {
    forward_dbaccess_method!(
        fn get_conversations(
            &self,
            session_id: &str,
            limit: usize,
        ) -> anyhow::Result<Vec<ConversationExchange>>;
    );
    forward_dbaccess_method!(
        fn recent_commands_with_summaries(
            &self,
            session_id: &str,
            limit: usize,
        ) -> anyhow::Result<Vec<CommandWithSummary>>;
    );
    forward_dbaccess_method!(
        fn other_sessions_with_summaries(
            &self,
            session_id: &str,
            max_ttys: usize,
            summaries_per_tty: usize,
        ) -> anyhow::Result<Vec<OtherSessionSummary>>;
    );
    forward_dbaccess_method!(
        fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>>;
    );
    forward_dbaccess_method!(
        fn search_history_advanced(
            &self,
            fts_query: Option<&str>,
            regex_pattern: Option<&str>,
            since: Option<&str>,
            until: Option<&str>,
            exit_code: Option<i32>,
            failed_only: bool,
            session_filter: Option<&str>,
            current_session: Option<&str>,
            limit: usize,
        ) -> anyhow::Result<Vec<HistoryMatch>>;
    );
    forward_dbaccess_method!(
        fn search_command_entities(
            &self,
            executable: Option<&str>,
            entity: Option<&str>,
            entity_type: Option<&str>,
            since: Option<&str>,
            until: Option<&str>,
            session_filter: Option<&str>,
            current_session: Option<&str>,
            limit: usize,
        ) -> anyhow::Result<Vec<CommandEntityMatch>>;
    );
    forward_dbaccess_method!(
        fn insert_conversation(
            &self,
            session_id: &str,
            query: &str,
            response_type: &str,
            response: &str,
            explanation: Option<&str>,
            executed: bool,
            pending: bool,
        ) -> anyhow::Result<i64>;
    );
    forward_dbaccess_method!(
        fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()>;
    );
    forward_dbaccess_method!(
        fn commands_needing_llm_summary(
            &self,
            limit: usize,
        ) -> anyhow::Result<Vec<CommandForSummary>>;
    );
    forward_dbaccess_method!(
        fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool>;
    );
    forward_dbaccess_method!(
        fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()>;
    );

    fn memory_retrieve_prompt(
        &self,
        _ctx: &crate::memory::types::MemoryQueryContext,
    ) -> anyhow::Result<String> {
        // Direct path: build a minimal prompt with core memory + top semantic.
        // Full retrieval is only available via the daemon, but MIRIX requires
        // that core memory and high-access user preferences are always present.
        let mut memories = crate::memory::types::RetrievedMemories::default();
        if let Ok(core) = self.get_core_memory() {
            memories.core = core;
        }
        if let Ok(top_sem) = self.list_top_accessed_semantic(5) {
            memories.semantic = top_sem;
        }
        let prompt = crate::memory::retrieval::prompt_builder::build_memory_prompt(&memories);
        Ok(prompt)
    }

    fn memory_search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<String> {
        let mut results = serde_json::Map::new();
        let should_search = |mt: MemoryType| memory_type.is_none() || memory_type == Some(mt);

        // Parse temporal expressions to constrain episodic search by time range
        let temporal_range =
            crate::memory::temporal::parse_temporal_expression(query, chrono::Utc::now());
        // Use space separator to match SQLite's datetime() format: "YYYY-MM-DD HH:MM:SS"
        let since_str =
            temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        if should_search(MemoryType::Episodic) {
            match self.search_episodic_fts_since(query, limit, None, since_ref) {
                Ok(items) => {
                    results.insert("episodic".into(), serde_json::to_value(&items)?);
                }
                Err(e) => {
                    tracing::debug!("memory_search episodic failed: {e}");
                }
            }
        }
        if should_search(MemoryType::Semantic) {
            match self.search_semantic_fts(query, limit) {
                Ok(items) => {
                    results.insert("semantic".into(), serde_json::to_value(&items)?);
                }
                Err(e) => {
                    tracing::debug!("memory_search semantic failed: {e}");
                }
            }
        }
        if should_search(MemoryType::Procedural) {
            match self.search_procedural_fts(query, limit) {
                Ok(items) => {
                    results.insert("procedural".into(), serde_json::to_value(&items)?);
                }
                Err(e) => {
                    tracing::debug!("memory_search procedural failed: {e}");
                }
            }
        }
        if should_search(MemoryType::Resource) {
            match self.search_resource_fts(query, limit) {
                Ok(items) => {
                    results.insert("resource".into(), serde_json::to_value(&items)?);
                }
                Err(e) => {
                    tracing::debug!("memory_search resource failed: {e}");
                }
            }
        }
        if should_search(MemoryType::Knowledge) {
            match self.search_knowledge_fts(query, limit, &["low", "medium"]) {
                Ok(items) => {
                    results.insert("knowledge".into(), serde_json::to_value(&items)?);
                }
                Err(e) => {
                    tracing::debug!("memory_search knowledge failed: {e}");
                }
            }
        }
        Ok(serde_json::to_string(&results)?)
    }

    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.append_core_block(label, content).map_err(Into::into)
    }

    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.update_core_block(label, content).map_err(Into::into)
    }

    fn memory_store(&self, memory_type: MemoryType, data_json: &str) -> anyhow::Result<String> {
        let data: serde_json::Value = serde_json::from_str(data_json)?;
        let op = memory_store_op(memory_type, data)?;
        let id_out = match op {
            MemoryOp::SemanticInsert {
                name,
                category,
                summary,
                details,
                search_keywords,
            } => self.store_semantic_memory(
                &name,
                &category,
                &summary,
                details.as_deref(),
                &search_keywords,
            )?,
            MemoryOp::ProceduralInsert {
                entry_type,
                trigger_pattern,
                summary,
                steps,
                search_keywords,
            } => self.store_procedural_memory(
                &entry_type,
                &trigger_pattern,
                &summary,
                &steps,
                &search_keywords,
            )?,
            MemoryOp::ResourceInsert {
                resource_type,
                file_path,
                file_hash,
                title,
                summary,
                content,
                search_keywords,
            } => self.store_resource_memory(&ResourceMemoryWrite {
                resource_type: &resource_type,
                file_path: file_path.as_deref(),
                file_hash: file_hash.as_deref(),
                title: &title,
                summary: &summary,
                content: content.as_deref(),
                search_keywords: &search_keywords,
            })?,
            MemoryOp::KnowledgeInsert {
                entry_type,
                caption,
                secret_value,
                sensitivity,
                search_keywords,
            } => self.store_knowledge_memory(
                &entry_type,
                &caption,
                &secret_value,
                sensitivity,
                &search_keywords,
            )?,
            _ => anyhow::bail!("unsupported memory store operation"),
        };

        Ok(id_out)
    }

    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String> {
        let results = self.search_knowledge_fts(caption_query, 3, &["low", "medium", "high"])?;
        Ok(serde_json::to_string(&results)?)
    }

    // memory_record_event removed from trait
}

fn memory_store_op(memory_type: MemoryType, data: serde_json::Value) -> anyhow::Result<MemoryOp> {
    let obj = data
        .as_object()
        .ok_or_else(|| anyhow!("memory store data must be a JSON object"))?;

    let required = |key: &str| -> anyhow::Result<String> {
        obj.get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("memory store missing required field '{key}'"))
    };

    match memory_type {
        MemoryType::Semantic => Ok(MemoryOp::SemanticInsert {
            name: required("name")?,
            category: required("category")?,
            summary: required("summary")?,
            details: obj
                .get("details")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            search_keywords: required("search_keywords")?,
        }),
        MemoryType::Procedural => {
            let steps = obj
                .get("steps")
                .ok_or_else(|| anyhow!("memory store missing required field 'steps'"))?;
            if !steps.is_array() {
                anyhow::bail!("memory store field 'steps' must be an array");
            }
            Ok(MemoryOp::ProceduralInsert {
                entry_type: required("entry_type")?,
                trigger_pattern: obj
                    .get("trigger_pattern")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_default(),
                summary: required("summary")?,
                steps: serde_json::to_string(steps)?,
                search_keywords: required("search_keywords")?,
            })
        }
        MemoryType::Resource => Ok(MemoryOp::ResourceInsert {
            resource_type: required("resource_type")?,
            file_path: obj
                .get("file_path")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            file_hash: obj
                .get("file_hash")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            title: required("title")?,
            summary: required("summary")?,
            content: obj
                .get("content")
                .and_then(|v| v.as_str())
                .map(str::to_string),
            search_keywords: required("search_keywords")?,
        }),
        MemoryType::Knowledge => Ok(MemoryOp::KnowledgeInsert {
            entry_type: required("entry_type")?,
            caption: required("caption")?,
            secret_value: required("secret_value")?,
            sensitivity: match obj.get("sensitivity") {
                None => Sensitivity::Medium,
                Some(value) => {
                    let raw = value.as_str().ok_or_else(|| {
                        anyhow!("memory store field 'sensitivity' must be a string")
                    })?;
                    Sensitivity::parse(raw)?
                }
            },
            search_keywords: required("search_keywords")?,
        }),
        MemoryType::Episodic | MemoryType::Core => {
            anyhow::bail!(
                "memory store does not support type '{}'; use dedicated APIs",
                memory_type.as_str()
            )
        }
    }
}

#[derive(Default)]
pub struct DaemonDb;

impl DaemonDb {
    pub fn new() -> Self {
        Self
    }

    fn request(&self, request: DaemonRequest) -> anyhow::Result<Option<serde_json::Value>> {
        match crate::daemon_client::send_to_global(&request)? {
            DaemonResponse::Ok { data } => Ok(data),
            DaemonResponse::Error { message } => Err(anyhow!(message)),
        }
    }

    fn data_or_empty(data: Option<serde_json::Value>) -> serde_json::Value {
        data.unwrap_or_else(|| serde_json::json!({}))
    }
}

impl DbAccess for DaemonDb {
    fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<ConversationExchange>> {
        let data = Self::data_or_empty(self.request(DaemonRequest::GetConversations {
            session: session_id.to_string(),
            limit,
        })?);
        let arr = data
            .get("conversations")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| ConversationExchange {
                query: v
                    .get("query")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                response_type: v
                    .get("response_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .into(),
                response: v
                    .get("response")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                explanation: v
                    .get("explanation")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                result_exit_code: v
                    .get("result_exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                result_output_snippet: v
                    .get("result_output_snippet")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                created_at: v
                    .get("created_at")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            })
            .collect())
    }

    fn recent_commands_with_summaries(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandWithSummary>> {
        let data =
            Self::data_or_empty(self.request(DaemonRequest::RecentCommandsWithSummaries {
                session: session_id.to_string(),
                limit,
            })?);
        let arr = data
            .get("commands")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| CommandWithSummary {
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                exit_code: v
                    .get("exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                duration_ms: v.get("duration_ms").and_then(|x| x.as_i64()),
                summary: v
                    .get("summary")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                output: v.get("output").and_then(|x| x.as_str()).map(str::to_string),
            })
            .collect())
    }

    fn other_sessions_with_summaries(
        &self,
        session_id: &str,
        max_ttys: usize,
        summaries_per_tty: usize,
    ) -> anyhow::Result<Vec<OtherSessionSummary>> {
        let data =
            Self::data_or_empty(self.request(DaemonRequest::OtherSessionsWithSummaries {
                session: session_id.to_string(),
                max_ttys,
                summaries_per_tty,
            })?);
        let arr = data
            .get("commands")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| OtherSessionSummary {
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                exit_code: v
                    .get("exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                summary: v
                    .get("summary")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                tty: v
                    .get("tty")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                shell: v
                    .get("shell")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                session_id: v
                    .get("session_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect())
    }

    fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>> {
        let data = Self::data_or_empty(self.request(DaemonRequest::SearchHistory {
            query: query.to_string(),
            limit,
        })?);
        let arr = data
            .get("results")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| HistoryMatch {
                id: v.get("id").and_then(|x| x.as_i64()).unwrap_or_default(),
                session_id: v
                    .get("session_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                exit_code: v
                    .get("exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                output: v.get("output").and_then(|x| x.as_str()).map(str::to_string),
                summary: v
                    .get("summary")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                cmd_highlight: v
                    .get("cmd_highlight")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                output_highlight: v
                    .get("output_highlight")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            })
            .collect())
    }

    fn search_history_advanced(
        &self,
        fts_query: Option<&str>,
        regex_pattern: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        exit_code: Option<i32>,
        failed_only: bool,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<HistoryMatch>> {
        let data = Self::data_or_empty(self.request(DaemonRequest::SearchHistoryAdvanced {
            fts_query: fts_query.map(str::to_string),
            regex_pattern: regex_pattern.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            exit_code,
            failed_only,
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        })?);
        let arr = data
            .get("results")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| HistoryMatch {
                id: v.get("id").and_then(|x| x.as_i64()).unwrap_or_default(),
                session_id: v
                    .get("session_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                exit_code: v
                    .get("exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                output: v.get("output").and_then(|x| x.as_str()).map(str::to_string),
                summary: v
                    .get("summary")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
                cmd_highlight: v
                    .get("cmd_highlight")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                output_highlight: v
                    .get("output_highlight")
                    .and_then(|x| x.as_str())
                    .map(str::to_string),
            })
            .collect())
    }

    fn search_command_entities(
        &self,
        executable: Option<&str>,
        entity: Option<&str>,
        entity_type: Option<&str>,
        since: Option<&str>,
        until: Option<&str>,
        session_filter: Option<&str>,
        current_session: Option<&str>,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandEntityMatch>> {
        let limit = limit.min(200);
        let data = Self::data_or_empty(self.request(DaemonRequest::SearchCommandEntities {
            executable: executable.map(str::to_string),
            entity: entity.map(str::to_string),
            entity_type: entity_type.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        })?);
        let arr = data
            .get("results")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| CommandEntityMatch {
                command_id: v
                    .get("command_id")
                    .and_then(|x| x.as_i64())
                    .unwrap_or_default(),
                session_id: v
                    .get("session_id")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                started_at: v
                    .get("started_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                executable: v
                    .get("executable")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                entity: v
                    .get("entity")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                entity_type: v
                    .get("entity_type")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
            })
            .collect())
    }

    fn insert_conversation(
        &self,
        session_id: &str,
        query: &str,
        response_type: &str,
        response: &str,
        explanation: Option<&str>,
        executed: bool,
        pending: bool,
    ) -> anyhow::Result<i64> {
        let data = Self::data_or_empty(self.request(DaemonRequest::InsertConversation {
            session_id: session_id.to_string(),
            query: query.to_string(),
            response_type: response_type.into(),
            response: response.to_string(),
            explanation: explanation.map(str::to_string),
            executed,
            pending,
        })?);
        Ok(data.get("id").and_then(|v| v.as_i64()).unwrap_or_default())
    }

    fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::ClearConversations {
            session: session_id.to_string(),
        })?;
        Ok(())
    }

    fn commands_needing_llm_summary(&self, limit: usize) -> anyhow::Result<Vec<CommandForSummary>> {
        let data =
            Self::data_or_empty(self.request(DaemonRequest::CommandsNeedingLlmSummary { limit })?);
        let arr = data
            .get("commands")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| CommandForSummary {
                id: v.get("id").and_then(|x| x.as_i64()).unwrap_or_default(),
                command: v
                    .get("command")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                cwd: v.get("cwd").and_then(|x| x.as_str()).map(str::to_string),
                exit_code: v
                    .get("exit_code")
                    .and_then(|x| x.as_i64())
                    .map(|n| n as i32),
                output: v.get("output").and_then(|x| x.as_str()).map(str::to_string),
            })
            .collect())
    }

    fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool> {
        let data = Self::data_or_empty(self.request(DaemonRequest::UpdateSummary {
            id,
            summary: summary.to_string(),
        })?);
        Ok(data
            .get("updated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::MarkSummaryError {
            id,
            error: error.to_string(),
        })?;
        Ok(())
    }

    fn memory_retrieve_prompt(
        &self,
        ctx: &crate::memory::types::MemoryQueryContext,
    ) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryRetrieve {
            context_json: serde_json::to_string(ctx)?,
        })?);
        Ok(data
            .get("prompt")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    fn memory_search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemorySearch {
            query: query.to_string(),
            memory_type,
            limit,
        })?);
        Ok(serde_json::to_string(&data)?)
    }

    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::MemoryCoreAppend {
            label: label.to_string(),
            content: content.to_string(),
        })?;
        Ok(())
    }

    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::MemoryCoreRewrite {
            label: label.to_string(),
            content: content.to_string(),
        })?;
        Ok(())
    }

    fn memory_store(&self, memory_type: MemoryType, data_json: &str) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryStore {
            memory_type,
            data_json: data_json.to_string(),
        })?);
        Ok(data
            .get("id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string())
    }

    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryRetrieveSecret {
            caption_query: caption_query.to_string(),
        })?);
        Ok(serde_json::to_string(&data)?)
    }

    // memory_record_event removed from trait
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::memory::types::MemoryType;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    fn setup_isolated_home() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().expect("temp home");
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    #[test]
    fn db_memory_store_supports_all_store_memory_types() {
        let db = Db::open_in_memory().expect("open in-memory db");

        let sem_id = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Semantic,
            r#"{"name":"tooling","category":"project","summary":"uses cargo","search_keywords":"cargo tooling"}"#,
        )
        .expect("store semantic");
        assert!(sem_id.starts_with("sem_"));

        let proc_id = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Procedural,
            r#"{"entry_type":"workflow","trigger_pattern":"deploy","summary":"deploy app","steps":["build","ship"],"search_keywords":"deploy workflow"}"#,
        )
        .expect("store procedural");
        assert!(proc_id.starts_with("proc_"));

        let res_id = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Resource,
            r#"{"resource_type":"doc","title":"README","summary":"docs","search_keywords":"readme docs"}"#,
        )
        .expect("store resource");
        assert!(res_id.starts_with("res_"));

        let kv_id = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Knowledge,
            r#"{"entry_type":"token","caption":"test token","secret_value":"abc123","sensitivity":"high","search_keywords":"token test"}"#,
        )
        .expect("store knowledge");
        assert!(kv_id.starts_with("kv_"));

        assert_eq!(db.list_all_semantic().expect("semantic list").len(), 1);
        assert_eq!(db.list_all_procedural().expect("procedural list").len(), 1);
        assert_eq!(
            db.search_resource_fts("readme", 10)
                .expect("resource search")
                .len(),
            1
        );
        assert_eq!(
            db.search_knowledge_fts("token", 10, &["low", "medium", "high"])
                .expect("knowledge search")
                .len(),
            1
        );
    }

    #[test]
    fn db_memory_store_resource_rejects_path_without_hash() {
        let db = Db::open_in_memory().expect("open in-memory db");

        let err = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Resource,
            r#"{"resource_type":"doc","file_path":"/tmp/readme.md","title":"README","summary":"docs","search_keywords":"readme docs"}"#,
        )
        .expect_err("resource with file_path but no file_hash should fail");

        assert!(
            err.to_string().contains("requires non-empty file_hash"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn db_memory_store_resource_rejects_path_with_blank_hash() {
        let db = Db::open_in_memory().expect("open in-memory db");

        let err = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Resource,
            r#"{"resource_type":"doc","file_path":"/tmp/readme.md","file_hash":"   ","title":"README","summary":"docs","search_keywords":"readme docs"}"#,
        )
        .expect_err("resource with blank file_hash should fail");

        assert!(
            err.to_string().contains("requires non-empty file_hash"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn db_memory_store_resource_upserts_with_path_and_hash() {
        let db = Db::open_in_memory().expect("open in-memory db");

        let id1 = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Resource,
            r#"{"resource_type":"doc","file_path":"/tmp/readme.md","file_hash":"hash-v1","title":"README","summary":"docs v1","search_keywords":"readme docs"}"#,
        )
        .expect("initial resource insert should succeed");

        let id2 = <Db as DbAccess>::memory_store(
            &db,
            MemoryType::Resource,
            r#"{"resource_type":"doc","file_path":"/tmp/readme.md","file_hash":"hash-v2","title":"README","summary":"docs v2","search_keywords":"readme docs"}"#,
        )
        .expect("upsert should succeed");

        assert_eq!(id1, id2, "same file_path should upsert existing row");
        assert_eq!(
            db.search_resource_fts("docs", 10)
                .expect("resource search")
                .len(),
            1,
            "upsert should not duplicate rows"
        );
    }

    #[test]
    fn memory_store_op_rejects_invalid_knowledge_sensitivity() {
        let err = memory_store_op(
            MemoryType::Knowledge,
            serde_json::json!({
                "entry_type": "token",
                "caption": "test",
                "secret_value": "val",
                "sensitivity": "critical",
                "search_keywords": "token"
            }),
        )
        .expect_err("invalid sensitivity should be rejected");

        assert!(
            err.to_string().contains("invalid sensitivity"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn memory_store_op_rejects_non_string_knowledge_sensitivity() {
        let err = memory_store_op(
            MemoryType::Knowledge,
            serde_json::json!({
                "entry_type": "token",
                "caption": "test",
                "secret_value": "val",
                "sensitivity": 123,
                "search_keywords": "token"
            }),
        )
        .expect_err("non-string sensitivity should be rejected");

        assert!(
            err.to_string().contains("must be a string"),
            "unexpected error: {err}"
        );
    }

    fn spawn_mock_global_daemon(
        home_path: &Path,
        response: DaemonResponse,
    ) -> (
        std::sync::mpsc::Receiver<serde_json::Value>,
        std::thread::JoinHandle<()>,
    ) {
        let nsh_dir = home_path.join(".nsh");
        std::fs::create_dir_all(&nsh_dir).expect("create ~/.nsh");
        let socket_path = crate::daemon::global_daemon_socket_path();
        let _ = std::fs::remove_file(&socket_path);
        let listener = UnixListener::bind(&socket_path).expect("bind mock daemon socket");

        let (tx, rx) = std::sync::mpsc::channel();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept connection");
            let mut line = String::new();
            let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
            reader.read_line(&mut line).expect("read request line");
            let request_json: serde_json::Value =
                serde_json::from_str(line.trim()).expect("parse request json");
            tx.send(request_json).expect("send captured request");
            let mut response_json = serde_json::to_string(&response).expect("serialize response");
            response_json.push('\n');
            stream
                .write_all(response_json.as_bytes())
                .expect("write response");
            stream.flush().expect("flush response");
            // keep the listener alive briefly to avoid ECONNREFUSED races in follow-up calls
            std::thread::sleep(std::time::Duration::from_millis(50));
        });

        (rx, handle)
    }

    #[test]
    #[serial]
    fn get_conversations_maps_response_and_defaults_missing_fields() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "conversations": [
                    {
                        "query": "why did this fail?",
                        "response_type": "chat",
                        "response": "check logs",
                        "explanation": "context",
                        "result_exit_code": 2,
                        "result_output_snippet": "permission denied",
                        "created_at": "2026-02-01T10:00:00Z"
                    },
                    {
                        "query": "minimal"
                    }
                ]
            })),
        );

        let db = DaemonDb::new();
        let rows = db
            .get_conversations("sess-1", 5)
            .expect("get_conversations should succeed");

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].query, "why did this fail?");
        assert_eq!(rows[0].response_type, "chat");
        assert_eq!(rows[0].response, "check logs");
        assert_eq!(rows[0].result_exit_code, Some(2));
        assert_eq!(rows[1].query, "minimal");
        assert_eq!(rows[1].response_type, "");
        assert_eq!(rows[1].response, "");

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "get_conversations");
        assert_eq!(request["session_id"], "sess-1");
        assert_eq!(request["limit"], 5);
        assert_eq!(request["v"], crate::daemon::DAEMON_PROTOCOL_VERSION);
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn search_history_advanced_sends_filters_and_maps_results() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "results": [
                    {
                        "id": 42,
                        "session_id": "sess-9",
                        "command": "ssh root@example.com",
                        "cwd": "/tmp",
                        "exit_code": 255,
                        "started_at": "2026-02-01T10:00:00Z",
                        "output": "Permission denied",
                        "summary": "failed ssh",
                        "cmd_highlight": "ssh <b>root@example.com</b>",
                        "output_highlight": "<b>Permission denied</b>"
                    }
                ]
            })),
        );

        let db = DaemonDb::new();
        let rows = db
            .search_history_advanced(
                Some("ssh"),
                Some("root@"),
                Some("2h"),
                Some("now"),
                Some(255),
                true,
                Some("current"),
                Some("sess-9"),
                17,
            )
            .expect("search_history_advanced should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, 42);
        assert_eq!(rows[0].session_id, "sess-9");
        assert_eq!(rows[0].command, "ssh root@example.com");
        assert_eq!(rows[0].exit_code, Some(255));
        assert_eq!(rows[0].output.as_deref(), Some("Permission denied"));

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "search_history_advanced");
        assert_eq!(request["fts_query"], "ssh");
        assert_eq!(request["regex_pattern"], "root@");
        assert_eq!(request["failed_only"], true);
        assert_eq!(request["session_filter"], "current");
        assert_eq!(request["current_session"], "sess-9");
        assert_eq!(request["limit"], 17);
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn daemon_error_response_is_propagated() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (_request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::error("database temporarily unavailable"),
        );

        let db = DaemonDb::new();
        // simulate an error via a read-only request
        let err = db
            .search_history("foo", 1)
            .expect_err("should propagate error");
        assert!(err.to_string().contains("database temporarily unavailable"));
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn search_command_entities_maps_rows_and_forwards_filters() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "results": [
                    {
                        "command_id": 11,
                        "session_id": "sess-entity",
                        "command": "ssh admin@host",
                        "cwd": "/srv",
                        "started_at": "2026-02-02T00:00:00Z",
                        "executable": "ssh",
                        "entity": "admin@host",
                        "entity_type": "ssh_target"
                    }
                ]
            })),
        );

        let db = DaemonDb::new();
        let rows = db
            .search_command_entities(
                Some("ssh"),
                Some("host"),
                Some("ssh_target"),
                Some("1d"),
                Some("now"),
                Some("current"),
                Some("sess-entity"),
                12,
            )
            .expect("search_command_entities should succeed");

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].command_id, 11);
        assert_eq!(rows[0].session_id, "sess-entity");
        assert_eq!(rows[0].executable, "ssh");
        assert_eq!(rows[0].entity, "admin@host");
        assert_eq!(rows[0].entity_type, "ssh_target");

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "search_command_entities");
        assert_eq!(request["executable"], "ssh");
        assert_eq!(request["entity"], "host");
        assert_eq!(request["entity_type"], "ssh_target");
        assert_eq!(request["session_filter"], "current");
        assert_eq!(request["current_session"], "sess-entity");
        assert_eq!(request["limit"], 12);
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn search_history_advanced_propagates_daemon_errors() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (_request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::error("advanced search unavailable"),
        );

        let db = DaemonDb::new();
        let err = db
            .search_history_advanced(None, None, None, None, None, false, None, None, 5)
            .expect_err("search_history_advanced should propagate daemon errors");
        assert!(err.to_string().contains("advanced search unavailable"));
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn search_command_entities_propagates_daemon_errors() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (_request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::error("entity search unavailable"),
        );

        let db = DaemonDb::new();
        let err = db
            .search_command_entities(None, None, None, None, None, None, None, 5)
            .expect_err("search_command_entities should propagate daemon errors");
        assert!(err.to_string().contains("entity search unavailable"));
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn memory_retrieve_prompt_sends_context_and_maps_prompt() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "prompt": "<core_memory>...</core_memory>"
            })),
        );

        let db = DaemonDb::new();
        let ctx = crate::memory::types::MemoryQueryContext {
            query: "how to build".into(),
            cwd: Some("/tmp".into()),
            session_id: Some("sess-xyz".into()),
            interaction_mode: crate::memory::types::InteractionMode::NaturalLanguage,
            error_context: None,
        };
        let prompt = db
            .memory_retrieve_prompt(&ctx)
            .expect("memory_retrieve_prompt should succeed");
        assert!(prompt.contains("<core_memory>"));

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "memory_retrieve");
        assert_eq!(request["v"], crate::daemon::DAEMON_PROTOCOL_VERSION);
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn memory_search_maps_results() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "results": [
                    {"type": "semantic", "id": "sem_1234", "summary": "Uses cargo", "score": 0.0}
                ]
            })),
        );

        let db = DaemonDb::new();
        let json = db
            .memory_search("cargo", None, 5)
            .expect("memory_search should succeed");
        assert!(json.contains("results"));
        assert!(json.contains("sem_1234"));

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "memory_search");
        assert_eq!(request["query"], "cargo");
        assert_eq!(request["limit"], 5);
        handle.join().expect("join daemon thread");
    }
}
