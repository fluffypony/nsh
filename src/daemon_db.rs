use anyhow::anyhow;

use crate::daemon::{DaemonRequest, DaemonResponse};
use crate::db::{
    CommandEntityMatch, CommandForSummary, CommandWithSummary, ConversationExchange, Db,
    HistoryMatch, Memory, OtherSessionSummary,
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
    fn get_memories(&self, limit: usize) -> anyhow::Result<Vec<Memory>>;
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
    fn search_memories(&self, query: &str) -> anyhow::Result<Vec<Memory>>;
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
    fn upsert_memory(&self, key: &str, value: &str) -> anyhow::Result<(i64, bool)>;
    fn delete_memory(&self, id: i64) -> anyhow::Result<bool>;
    fn update_memory(
        &self,
        id: i64,
        key: Option<&str>,
        value: Option<&str>,
    ) -> anyhow::Result<bool>;
    fn commands_needing_llm_summary(&self, limit: usize) -> anyhow::Result<Vec<CommandForSummary>>;
    fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool>;
    fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()>;
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

    fn get_memories(&self, limit: usize) -> anyhow::Result<Vec<Memory>> {
        Ok(self.get_memories(limit)?)
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

    fn search_memories(&self, query: &str) -> anyhow::Result<Vec<Memory>> {
        Ok(self.search_memories(query)?)
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

    fn upsert_memory(&self, key: &str, value: &str) -> anyhow::Result<(i64, bool)> {
        Ok(self.upsert_memory(key, value)?)
    }

    fn delete_memory(&self, id: i64) -> anyhow::Result<bool> {
        Ok(self.delete_memory(id)?)
    }

    fn update_memory(
        &self,
        id: i64,
        key: Option<&str>,
        value: Option<&str>,
    ) -> anyhow::Result<bool> {
        Ok(self.update_memory(id, key, value)?)
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

    fn get_memories(&self, limit: usize) -> anyhow::Result<Vec<Memory>> {
        let data = Self::data_or_empty(self.request(DaemonRequest::GetMemories { limit })?);
        let arr = data
            .get("memories")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| Memory {
                id: v.get("id").and_then(|x| x.as_i64()).unwrap_or_default(),
                key: v
                    .get("key")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                value: v
                    .get("value")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                created_at: v
                    .get("created_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                updated_at: v
                    .get("updated_at")
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

    fn search_memories(&self, query: &str) -> anyhow::Result<Vec<Memory>> {
        let data = Self::data_or_empty(self.request(DaemonRequest::SearchMemories {
            query: query.to_string(),
        })?);
        let arr = data
            .get("memories")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        Ok(arr
            .into_iter()
            .map(|v| Memory {
                id: v.get("id").and_then(|x| x.as_i64()).unwrap_or_default(),
                key: v
                    .get("key")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                value: v
                    .get("value")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                created_at: v
                    .get("created_at")
                    .and_then(|x| x.as_str())
                    .unwrap_or_default()
                    .to_string(),
                updated_at: v
                    .get("updated_at")
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

    fn upsert_memory(&self, key: &str, value: &str) -> anyhow::Result<(i64, bool)> {
        let data = Self::data_or_empty(self.request(DaemonRequest::UpsertMemory {
            key: key.to_string(),
            value: value.to_string(),
        })?);
        Ok((
            data.get("id").and_then(|v| v.as_i64()).unwrap_or_default(),
            data.get("updated")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
        ))
    }

    fn delete_memory(&self, id: i64) -> anyhow::Result<bool> {
        let data = Self::data_or_empty(self.request(DaemonRequest::DeleteMemory { id })?);
        Ok(data
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    fn update_memory(
        &self,
        id: i64,
        key: Option<&str>,
        value: Option<&str>,
    ) -> anyhow::Result<bool> {
        let data = Self::data_or_empty(self.request(DaemonRequest::UpdateMemory {
            id,
            key: key.unwrap_or_default().to_string(),
            value: value.unwrap_or_default().to_string(),
        })?);
        Ok(data
            .get("updated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
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
}
