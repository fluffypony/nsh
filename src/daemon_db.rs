use anyhow::anyhow;

use crate::daemon::{DaemonRequest, DaemonResponse};
use crate::db::{
    CommandEntityMatch, CommandForSummary, CommandWithSummary, ConversationExchange, Db,
    HistoryMatch, OtherSessionSummary,
};

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
    fn memory_search(&self, query: &str, memory_type: Option<&str>, limit: usize) -> anyhow::Result<String>;
    fn memory_core_get(&self) -> anyhow::Result<String>;
    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()>;
    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()>;
    fn memory_store(&self, memory_type: &str, data_json: &str) -> anyhow::Result<String>;
    fn memory_delete(&self, memory_type: &str, id: &str) -> anyhow::Result<()>;
    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String>;
    fn memory_stats(&self) -> anyhow::Result<String>;
    fn memory_record_event(&self, event_json: &str) -> anyhow::Result<()>;
}

impl DbAccess for Db {
    fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<ConversationExchange>> {
        Ok(self.get_conversations(session_id, limit)?)
    }

    fn recent_commands_with_summaries(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandWithSummary>> {
        Ok(self.recent_commands_with_summaries(session_id, limit)?)
    }

    fn other_sessions_with_summaries(
        &self,
        session_id: &str,
        max_ttys: usize,
        summaries_per_tty: usize,
    ) -> anyhow::Result<Vec<OtherSessionSummary>> {
        Ok(self.other_sessions_with_summaries(session_id, max_ttys, summaries_per_tty)?)
    }

    fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>> {
        Ok(self.search_history(query, limit)?)
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
        Ok(self.search_history_advanced(
            fts_query,
            regex_pattern,
            since,
            until,
            exit_code,
            failed_only,
            session_filter,
            current_session,
            limit,
        )?)
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
        Ok(self.search_command_entities(
            executable,
            entity,
            entity_type,
            since,
            until,
            session_filter,
            current_session,
            limit,
        )?)
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
        Ok(self.insert_conversation(
            session_id,
            query,
            response_type,
            response,
            explanation,
            executed,
            pending,
        )?)
    }

    fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()> {
        Ok(self.clear_conversations(session_id)?)
    }

    fn commands_needing_llm_summary(&self, limit: usize) -> anyhow::Result<Vec<CommandForSummary>> {
        Ok(self.commands_needing_llm_summary(limit)?)
    }

    fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool> {
        Ok(self.update_summary(id, summary)?)
    }

    fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()> {
        Ok(self.mark_summary_error(id, error)?)
    }

    fn memory_search(&self, query: &str, memory_type: Option<&str>, limit: usize) -> anyhow::Result<String> {
        let mut results = serde_json::Map::new();
        let should_search = |mt: &str| memory_type.is_none() || memory_type == Some(mt);

        // Parse temporal expressions to constrain episodic search by time range
        let temporal_range = crate::memory::temporal::parse_temporal_expression(
            query,
            chrono::Utc::now(),
        );
        // Use space separator to match SQLite's datetime() format: "YYYY-MM-DD HH:MM:SS"
        let since_str = temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        if should_search("episodic") {
            match self.search_episodic_fts_since(query, limit, None, since_ref) {
                Ok(items) => { results.insert("episodic".into(), serde_json::to_value(&items)?); }
                Err(e) => { tracing::debug!("memory_search episodic failed: {e}"); }
            }
        }
        if should_search("semantic") {
            match self.search_semantic_fts(query, limit) {
                Ok(items) => { results.insert("semantic".into(), serde_json::to_value(&items)?); }
                Err(e) => { tracing::debug!("memory_search semantic failed: {e}"); }
            }
        }
        if should_search("procedural") {
            match self.search_procedural_fts(query, limit) {
                Ok(items) => { results.insert("procedural".into(), serde_json::to_value(&items)?); }
                Err(e) => { tracing::debug!("memory_search procedural failed: {e}"); }
            }
        }
        if should_search("resource") {
            match self.search_resource_fts(query, limit) {
                Ok(items) => { results.insert("resource".into(), serde_json::to_value(&items)?); }
                Err(e) => { tracing::debug!("memory_search resource failed: {e}"); }
            }
        }
        if should_search("knowledge") {
            match self.search_knowledge_fts(query, limit, &["low", "medium"]) {
                Ok(items) => { results.insert("knowledge".into(), serde_json::to_value(&items)?); }
                Err(e) => { tracing::debug!("memory_search knowledge failed: {e}"); }
            }
        }
        Ok(serde_json::to_string(&results)?)
    }

    fn memory_core_get(&self) -> anyhow::Result<String> {
        let blocks = self.get_core_memory()?;
        Ok(serde_json::to_string(&blocks)?)
    }

    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()> {
        Ok(self.append_core_block(label, content)?)
    }

    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()> {
        Ok(self.update_core_block(label, content)?)
    }

    fn memory_store(&self, memory_type: &str, data_json: &str) -> anyhow::Result<String> {
        let data: serde_json::Value = serde_json::from_str(data_json)?;
        let id = crate::memory::types::generate_id(match memory_type {
            "episodic" => "ep",
            "semantic" => "sem",
            "procedural" => "proc",
            "resource" => "res",
            "knowledge" => "kv",
            _ => "mem",
        });
        match memory_type {
            "semantic" => {
                let item = serde_json::from_value::<crate::memory::types::SemanticItem>(data)?;
                self.conn_execute_batch(&format!(
                    "INSERT OR REPLACE INTO semantic_memory (id, name, category, summary, details, search_keywords) \
                     VALUES ('{}', '{}', '{}', '{}', {}, '{}')",
                    item.id.replace('\'', "''"),
                    item.name.replace('\'', "''"),
                    item.category.replace('\'', "''"),
                    item.summary.replace('\'', "''"),
                    item.details.as_ref().map_or("NULL".into(), |d| format!("'{}'", d.replace('\'', "''"))),
                    item.search_keywords.replace('\'', "''"),
                ))?;
            }
            _ => {
                // For other types, store as-is — the daemon handler will use the memory system
            }
        }
        Ok(id)
    }

    fn memory_delete(&self, memory_type: &str, id: &str) -> anyhow::Result<()> {
        let table = match memory_type {
            "episodic" => "episodic_memory",
            "semantic" => "semantic_memory",
            "procedural" => "procedural_memory",
            "resource" => "resource_memory",
            "knowledge" => "knowledge_vault",
            _ => anyhow::bail!("unknown memory type: {memory_type}"),
        };
        Ok(self.delete_memory_by_type_and_id(table, id)?)
    }

    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String> {
        let results = self.search_knowledge_fts(caption_query, 3, &["low", "medium", "high"])?;
        Ok(serde_json::to_string(&results)?)
    }

    fn memory_stats(&self) -> anyhow::Result<String> {
        let stats = Db::memory_stats(self)?;
        Ok(serde_json::to_string(&serde_json::json!({
            "core": stats.core_count,
            "episodic": stats.episodic_count,
            "semantic": stats.semantic_count,
            "procedural": stats.procedural_count,
            "resource": stats.resource_count,
            "knowledge": stats.knowledge_count,
        }))?)
    }

    fn memory_record_event(&self, _event_json: &str) -> anyhow::Result<()> {
        // Direct DB access doesn't buffer events — this is handled by the MemorySystem
        // via the daemon. This is a no-op for direct Db access.
        Ok(())
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
                    .to_string(),
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
        let data = match self.request(DaemonRequest::SearchHistoryAdvanced {
            fts_query: fts_query.map(str::to_string),
            regex_pattern: regex_pattern.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            exit_code,
            failed_only,
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        }) {
            Ok(d) => Self::data_or_empty(d),
            Err(e) => {
                tracing::warn!("search_history_advanced failed: {e}");
                return Ok(Vec::new());
            }
        };
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
        let data = match self.request(DaemonRequest::SearchCommandEntities {
            executable: executable.map(str::to_string),
            entity: entity.map(str::to_string),
            entity_type: entity_type.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        }) {
            Ok(d) => Self::data_or_empty(d),
            Err(e) => {
                tracing::warn!("search_command_entities failed: {e}");
                return Ok(Vec::new());
            }
        };
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
            response_type: response_type.to_string(),
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

    fn memory_search(&self, query: &str, memory_type: Option<&str>, limit: usize) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemorySearch {
            query: query.to_string(),
            memory_type: memory_type.map(String::from),
            limit,
        })?);
        Ok(serde_json::to_string(&data)?)
    }

    fn memory_core_get(&self) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryGetCore)?);
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

    fn memory_store(&self, memory_type: &str, data_json: &str) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryStore {
            memory_type: memory_type.to_string(),
            data_json: data_json.to_string(),
        })?);
        Ok(data.get("id").and_then(|v| v.as_str()).unwrap_or("").to_string())
    }

    fn memory_delete(&self, memory_type: &str, id: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::MemoryDelete {
            memory_type: memory_type.to_string(),
            id: id.to_string(),
        })?;
        Ok(())
    }

    fn memory_retrieve_secret(&self, caption_query: &str) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryRetrieveSecret {
            caption_query: caption_query.to_string(),
        })?);
        Ok(serde_json::to_string(&data)?)
    }

    fn memory_stats(&self) -> anyhow::Result<String> {
        let data = Self::data_or_empty(self.request(DaemonRequest::MemoryStats)?);
        Ok(serde_json::to_string(&data)?)
    }

    fn memory_record_event(&self, event_json: &str) -> anyhow::Result<()> {
        self.request(DaemonRequest::MemoryRecordEvent {
            event_json: event_json.to_string(),
        })?;
        Ok(())
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;

    struct EnvVarGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set<K: Into<String>, V: AsRef<str>>(key: K, value: V) -> Self {
            let key = key.into();
            let original = std::env::var(&key).ok();
            unsafe {
                std::env::set_var(&key, value.as_ref());
            }
            Self { key, original }
        }

        fn remove<K: Into<String>>(key: K) -> Self {
            let key = key.into();
            let original = std::env::var(&key).ok();
            unsafe {
                std::env::remove_var(&key);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(&self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(&self.key);
                }
            }
        }
    }

    fn setup_isolated_home() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().expect("temp home");
        let home_guard = EnvVarGuard::set("HOME", home.path().to_string_lossy());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    fn spawn_mock_global_daemon(
        home_path: &Path,
        response: DaemonResponse,
    ) -> (std::sync::mpsc::Receiver<serde_json::Value>, std::thread::JoinHandle<()>) {
        let nsh_dir = home_path.join(".nsh");
        std::fs::create_dir_all(&nsh_dir).expect("create ~/.nsh");
        let socket_path = nsh_dir.join("nshd.sock");
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
        assert_eq!(request["session"], "sess-1");
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
        let err = db.search_history("foo", 1).expect_err("should propagate error");
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

    
}
