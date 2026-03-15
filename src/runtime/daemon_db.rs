use anyhow::anyhow;
use serde::de::DeserializeOwned;

use crate::daemon::{DaemonRequest, DaemonResponse};
use crate::db::{
    CommandEntityMatch, CommandForSummary, CommandWithSummary, ConversationExchange, Db,
    HistoryMatch, OtherSessionSummary, ResourceMemoryWrite,
};
use crate::memory::types::{MemoryOp, MemoryType, Sensitivity};

macro_rules! direct_dbaccess_method {
    ($(#[$meta:meta])* fn $name:ident (&self $(, $arg:ident : $ty:ty )* $(,)? ) -> $return:ty;) => {
        $(#[$meta])*
        fn $name(&self, $( $arg : $ty ),*) -> $return {
            let db = self.require_direct_db(stringify!($name))?;
            Db::$name(db, $( $arg ),*).map_err(Into::into)
        }
    };
}

pub trait DbAccess {
    fn direct_db(&self) -> Option<&Db> {
        None
    }

    fn require_direct_db(&self, operation: &'static str) -> anyhow::Result<&Db> {
        self.direct_db()
            .ok_or_else(|| anyhow!("{operation} requires direct Db access"))
    }

    direct_dbaccess_method!(
        fn get_conversations(
            &self,
            session_id: &str,
            limit: usize,
        ) -> anyhow::Result<Vec<ConversationExchange>>;
    );
    direct_dbaccess_method!(
        fn recent_commands_with_summaries(
            &self,
            session_id: &str,
            limit: usize,
        ) -> anyhow::Result<Vec<CommandWithSummary>>;
    );
    direct_dbaccess_method!(
        fn other_sessions_with_summaries(
            &self,
            session_id: &str,
            max_ttys: usize,
            summaries_per_tty: usize,
        ) -> anyhow::Result<Vec<OtherSessionSummary>>;
    );
    direct_dbaccess_method!(
        fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>>;
    );
    direct_dbaccess_method!(
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
    );
    direct_dbaccess_method!(
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
    );
    direct_dbaccess_method!(
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
    );
    direct_dbaccess_method!(
        fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()>;
    );

    direct_dbaccess_method!(
        fn commands_needing_llm_summary(
            &self,
            limit: usize,
        ) -> anyhow::Result<Vec<CommandForSummary>>;
    );
    direct_dbaccess_method!(
        fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool>;
    );
    direct_dbaccess_method!(
        fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()>;
    );

    // ── Memory system ──────────────────────────────────
    fn memory_retrieve_prompt(
        &self,
        _ctx: &crate::memory::types::MemoryQueryContext,
    ) -> anyhow::Result<String> {
        let db = self.require_direct_db("memory_retrieve_prompt")?;
        let mut memories = crate::memory::types::RetrievedMemories::default();
        if let Ok(core) = db.core_memory() {
            memories.core = core;
        }
        if let Ok(top_sem) = db.list_top_accessed_semantic(5) {
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
        let db = self.require_direct_db("memory_search")?;
        let mut results = serde_json::Map::new();
        let should_search = |mt: MemoryType| memory_type.is_none() || memory_type == Some(mt);

        let temporal_range =
            crate::memory::temporal::parse_temporal_expression(query, chrono::Utc::now());
        let since_str =
            temporal_range.map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S").to_string());
        let since_ref = since_str.as_deref();

        if should_search(MemoryType::Episodic) {
            match db.search_episodic_fts_since(query, limit, None, since_ref) {
                Ok(items) => {
                    results.insert("episodic".into(), serde_json::to_value(&items)?);
                }
                Err(error) => {
                    tracing::debug!("memory_search episodic failed: {error}");
                }
            }
        }
        if should_search(MemoryType::Semantic) {
            match db.search_semantic_fts(query, limit) {
                Ok(items) => {
                    results.insert("semantic".into(), serde_json::to_value(&items)?);
                }
                Err(error) => {
                    tracing::debug!("memory_search semantic failed: {error}");
                }
            }
        }
        if should_search(MemoryType::Procedural) {
            match db.search_procedural_fts(query, limit) {
                Ok(items) => {
                    results.insert("procedural".into(), serde_json::to_value(&items)?);
                }
                Err(error) => {
                    tracing::debug!("memory_search procedural failed: {error}");
                }
            }
        }
        if should_search(MemoryType::Resource) {
            match db.search_resource_fts(query, limit) {
                Ok(items) => {
                    results.insert("resource".into(), serde_json::to_value(&items)?);
                }
                Err(error) => {
                    tracing::debug!("memory_search resource failed: {error}");
                }
            }
        }
        if should_search(MemoryType::Knowledge) {
            match db.search_knowledge_fts(query, limit, &["low", "medium"]) {
                Ok(items) => {
                    results.insert("knowledge".into(), serde_json::to_value(&items)?);
                }
                Err(error) => {
                    tracing::debug!("memory_search knowledge failed: {error}");
                }
            }
        }
        Ok(serde_json::to_string(&results)?)
    }

    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()> {
        let db = self.require_direct_db("memory_core_append")?;
        db.append_core_block(label, content).map_err(Into::into)
    }

    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()> {
        let db = self.require_direct_db("memory_core_rewrite")?;
        db.update_core_block(label, content).map_err(Into::into)
    }

    fn memory_store(&self, memory_type: MemoryType, data_json: &str) -> anyhow::Result<String> {
        let db = self.require_direct_db("memory_store")?;
        let data: serde_json::Value = serde_json::from_str(data_json)?;
        let op = memory_store_op(memory_type, data)?;
        let id_out = match op {
            MemoryOp::SemanticInsert {
                name,
                category,
                summary,
                details,
                search_keywords,
            } => db.store_semantic_memory(
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
            } => db.store_procedural_memory(
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
            } => db.store_resource_memory(&ResourceMemoryWrite {
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
            } => db.store_knowledge_memory(
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

    fn memory_retrieve_secret(
        &self,
        caption_query: &str,
        explicit_user_request: Option<&str>,
    ) -> anyhow::Result<String> {
        let _ = explicit_user_request;
        let db = self.require_direct_db("memory_retrieve_secret")?;
        let results = db.search_knowledge_fts(caption_query, 3, &["low", "medium", "high"])?;
        Ok(serde_json::to_string(&results)?)
    }
    // Note: event recording is routed via daemon requests from query flow; no direct trait use required.
}

impl DbAccess for Db {
    fn direct_db(&self) -> Option<&Db> {
        Some(self)
    }
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

#[derive(Debug, serde::Deserialize)]
struct ConversationsResponse {
    conversations: Vec<ConversationExchange>,
}

#[derive(Debug, serde::Deserialize)]
struct CommandsWithSummariesResponse {
    commands: Vec<CommandWithSummary>,
}

#[derive(Debug, serde::Deserialize)]
struct OtherSessionsSummariesResponse {
    commands: Vec<OtherSessionSummary>,
}

#[derive(Debug, serde::Deserialize)]
struct HistoryMatchesResponse {
    results: Vec<HistoryMatch>,
}

#[derive(Debug, serde::Deserialize)]
struct CommandEntityMatchesResponse {
    results: Vec<CommandEntityMatch>,
}

#[derive(Debug, serde::Deserialize)]
struct CommandsNeedingSummaryResponse {
    commands: Vec<CommandForSummary>,
}

#[derive(Debug, serde::Deserialize)]
struct UpdateSummaryResponse {
    updated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct PromptResponse {
    prompt: String,
}

#[derive(Debug, serde::Deserialize)]
struct IntIdResponse {
    id: i64,
}

#[derive(Debug, serde::Deserialize)]
struct StringIdResponse {
    id: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SecretSearchMatch {
    id: String,
    entry_type: String,
    caption: String,
    sensitivity: Sensitivity,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SecretSearchResponse {
    results: Vec<SecretSearchMatch>,
}

impl DaemonDb {
    pub fn new() -> Self {
        Self
    }

    fn request_data<T: DeserializeOwned>(&self, request: DaemonRequest) -> anyhow::Result<T> {
        match crate::daemon_client::send_to_global(&request)? {
            DaemonResponse::Ok { data: Some(data) } => serde_json::from_value(data).map_err(|e| {
                anyhow!(
                    "daemon returned invalid {} payload: {e}",
                    std::any::type_name::<T>()
                )
            }),
            DaemonResponse::Ok { data: None } => anyhow::bail!(
                "daemon returned no payload for {}",
                std::any::type_name::<T>()
            ),
            DaemonResponse::Error { message } => Err(anyhow!(message)),
        }
    }

    fn request_unit(&self, request: DaemonRequest) -> anyhow::Result<()> {
        match crate::daemon_client::send_to_global(&request)? {
            DaemonResponse::Ok { data: None } => Ok(()),
            DaemonResponse::Ok { data: Some(_) } => {
                anyhow::bail!("daemon returned unexpected payload for unit response")
            }
            DaemonResponse::Error { message } => Err(anyhow!(message)),
        }
    }

    fn caller_context() -> crate::daemon::CallerContext {
        crate::daemon::current_caller_context()
    }

    fn caller_context_with_request(
        explicit_user_request: Option<&str>,
    ) -> crate::daemon::CallerContext {
        crate::daemon::current_caller_context_with_request(explicit_user_request)
    }
}

impl DbAccess for DaemonDb {
    fn get_conversations(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<ConversationExchange>> {
        let response: ConversationsResponse = self.request_data(DaemonRequest::GetConversations {
            session: session_id.to_string(),
            limit,
            caller: Self::caller_context(),
        })?;
        Ok(response.conversations)
    }

    fn recent_commands_with_summaries(
        &self,
        session_id: &str,
        limit: usize,
    ) -> anyhow::Result<Vec<CommandWithSummary>> {
        let response: CommandsWithSummariesResponse =
            self.request_data(DaemonRequest::RecentCommandsWithSummaries {
                session: session_id.to_string(),
                limit,
                caller: Self::caller_context(),
            })?;
        Ok(response.commands)
    }

    fn other_sessions_with_summaries(
        &self,
        session_id: &str,
        max_ttys: usize,
        summaries_per_tty: usize,
    ) -> anyhow::Result<Vec<OtherSessionSummary>> {
        let response: OtherSessionsSummariesResponse =
            self.request_data(DaemonRequest::OtherSessionsWithSummaries {
                session: session_id.to_string(),
                max_ttys,
                summaries_per_tty,
                caller: Self::caller_context(),
            })?;
        Ok(response.commands)
    }

    fn search_history(&self, query: &str, limit: usize) -> anyhow::Result<Vec<HistoryMatch>> {
        let response: HistoryMatchesResponse = self.request_data(DaemonRequest::SearchHistory {
            query: query.to_string(),
            limit,
        })?;
        Ok(response.results)
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
        let response: HistoryMatchesResponse =
            self.request_data(DaemonRequest::SearchHistoryAdvanced {
            fts_query: fts_query.map(str::to_string),
            regex_pattern: regex_pattern.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            exit_code,
            failed_only,
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        })?;
        Ok(response.results)
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
        let response: CommandEntityMatchesResponse =
            self.request_data(DaemonRequest::SearchCommandEntities {
            executable: executable.map(str::to_string),
            entity: entity.map(str::to_string),
            entity_type: entity_type.map(str::to_string),
            since: since.map(str::to_string),
            until: until.map(str::to_string),
            session_filter: session_filter.map(str::to_string),
            current_session: current_session.map(str::to_string),
            limit,
        })?;
        Ok(response.results)
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
        let response: IntIdResponse = self.request_data(DaemonRequest::InsertConversation {
            session_id: session_id.to_string(),
            query: query.to_string(),
            response_type: response_type.into(),
            response: response.to_string(),
            explanation: explanation.map(str::to_string),
            executed,
            pending,
        })?;
        Ok(response.id)
    }

    fn clear_conversations(&self, session_id: &str) -> anyhow::Result<()> {
        self.request_unit(DaemonRequest::ClearConversations {
            session: session_id.to_string(),
        })
    }

    fn commands_needing_llm_summary(&self, limit: usize) -> anyhow::Result<Vec<CommandForSummary>> {
        let response: CommandsNeedingSummaryResponse =
            self.request_data(DaemonRequest::CommandsNeedingLlmSummary { limit })?;
        Ok(response.commands)
    }

    fn update_summary(&self, id: i64, summary: &str) -> anyhow::Result<bool> {
        let response: UpdateSummaryResponse = self.request_data(DaemonRequest::UpdateSummary {
            id,
            summary: summary.to_string(),
        })?;
        Ok(response.updated)
    }

    fn mark_summary_error(&self, id: i64, error: &str) -> anyhow::Result<()> {
        self.request_unit(DaemonRequest::MarkSummaryError {
            id,
            error: error.to_string(),
        })
    }

    fn memory_retrieve_prompt(
        &self,
        ctx: &crate::memory::types::MemoryQueryContext,
    ) -> anyhow::Result<String> {
        let response: PromptResponse = self.request_data(DaemonRequest::MemoryRetrieve {
            context_json: serde_json::to_string(ctx)?,
        })?;
        Ok(response.prompt)
    }

    fn memory_search(
        &self,
        query: &str,
        memory_type: Option<MemoryType>,
        limit: usize,
    ) -> anyhow::Result<String> {
        let data: serde_json::Value = self.request_data(DaemonRequest::MemorySearch {
            query: query.to_string(),
            memory_type,
            limit,
        })?;
        Ok(serde_json::to_string(&data)?)
    }

    fn memory_core_append(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.request_unit(DaemonRequest::MemoryCoreAppend {
            label: label.to_string(),
            content: content.to_string(),
            caller: Self::caller_context(),
        })
    }

    fn memory_core_rewrite(&self, label: &str, content: &str) -> anyhow::Result<()> {
        self.request_unit(DaemonRequest::MemoryCoreRewrite {
            label: label.to_string(),
            content: content.to_string(),
            caller: Self::caller_context(),
        })
    }

    fn memory_store(&self, memory_type: MemoryType, data_json: &str) -> anyhow::Result<String> {
        let response: StringIdResponse = self.request_data(DaemonRequest::MemoryStore {
            memory_type,
            data_json: data_json.to_string(),
            caller: Self::caller_context(),
        })?;
        Ok(response.id)
    }

    fn memory_retrieve_secret(
        &self,
        caption_query: &str,
        explicit_user_request: Option<&str>,
    ) -> anyhow::Result<String> {
        let response: SecretSearchResponse = self.request_data(DaemonRequest::MemoryRetrieveSecret {
            caption_query: caption_query.to_string(),
            caller: Self::caller_context_with_request(explicit_user_request),
        })?;
        Ok(serde_json::to_string(&response)?)
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
    fn get_conversations_maps_typed_response() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let _session_guard = EnvVarGuard::set("NSH_SESSION_ID", "caller-sess");
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
                        "query": "minimal",
                        "response_type": "command",
                        "response": "cargo test",
                        "result_exit_code": 0
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
        assert_eq!(rows[1].response_type, "command");
        assert_eq!(rows[1].response, "cargo test");
        assert_eq!(rows[1].result_exit_code, Some(0));

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "get_conversations");
        assert_eq!(request["session_id"], "sess-1");
        assert_eq!(request["limit"], 5);
        assert_eq!(request["caller"]["session"], "caller-sess");
        assert_eq!(request["v"], crate::daemon::DAEMON_PROTOCOL_VERSION);
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn get_conversations_invalid_payload_surfaces_deserialize_error() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "conversations": [
                    {
                        "query": "broken",
                        "response_type": 123,
                        "response": "noop"
                    }
                ]
            })),
        );

        let db = DaemonDb::new();
        let err = db
            .get_conversations("sess-1", 5)
            .expect_err("invalid payload should fail");

        assert!(
            err.to_string().contains("invalid"),
            "unexpected error: {err}"
        );

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "get_conversations");
        handle.join().expect("join daemon thread");
    }

    #[test]
    #[serial]
    fn memory_retrieve_secret_forwards_explicit_user_request() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_isolated_home();
        let _session_guard = EnvVarGuard::set("NSH_SESSION_ID", "caller-sess");
        let (request_rx, handle) = spawn_mock_global_daemon(
            home.path(),
            DaemonResponse::ok_with_data(serde_json::json!({
                "results": []
            })),
        );

        let db = DaemonDb::new();
        let result = db
            .memory_retrieve_secret("prod api", Some("show me the production api key"))
            .expect("memory_retrieve_secret should succeed");

        assert!(result.contains("results"));

        let request = request_rx.recv().expect("captured request");
        assert_eq!(request["type"], "memory_retrieve_secret");
        assert_eq!(request["caption_query"], "prod api");
        assert_eq!(request["caller"]["session"], "caller-sess");
        assert_eq!(
            request["caller"]["explicit_user_request"],
            "show me the production api key"
        );
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
