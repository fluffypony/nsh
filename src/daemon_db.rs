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
        let err = db
            .get_memories(10)
            .expect_err("error response should propagate as anyhow error");
        assert!(
            err.to_string().contains("database temporarily unavailable"),
            "unexpected error: {err}"
        );
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
    fn upsert_and_update_memory_default_missing_fields_safely() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "id": 0
            })),
        );

        let db = DaemonDb::new();
        let (id, updated) = db
            .upsert_memory("key", "value")
            .expect("upsert_memory should succeed");
        assert_eq!(id, 0);
        assert!(!updated);
        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "upsert_memory");
        assert_eq!(request["key"], "key");
        assert_eq!(request["value"], "value");
        handle.join().expect("join daemon thread");

        let (request_rx2, handle2) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({})),
        );
        let was_updated = db
            .update_memory(7, None, None)
            .expect("update_memory should succeed");
        assert!(!was_updated);
        let request2 = request_rx2.recv().expect("captured request 2");
        assert_eq!(request2["type"], "update_memory");
        assert_eq!(request2["id"], 7);
        assert_eq!(request2["key"], "");
        assert_eq!(request2["value"], "");
        handle2.join().expect("join daemon thread 2");
    }
}
