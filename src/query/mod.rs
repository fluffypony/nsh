mod prompt;

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::{config::Config, context, daemon_db::DbAccess, provider::*, streaming, tools};
use std::collections::{HashMap, HashSet};

pub use prompt::build_system_prompt;

type ToolFuture = std::pin::Pin<
    Box<
        dyn std::future::Future<
                Output = (String, String, Result<tools::ToolInvocationOutcome, String>),
            >,
    >,
>;

fn display_tool_error(error: &str, json_output: bool) {
    if json_output {
        let event = serde_json::json!({
            "type": "tool_error",
            "error": error,
            "report_url": "https://github.com/fluffypony/nsh/issues/new"
        });
        eprintln!("{}", serde_json::to_string(&event).unwrap_or_default());
    } else {
        eprintln!(
            "  \x1b[31m↳ tool error: {}\x1b[0m",
            crate::util::truncate(error, 300)
        );
        eprintln!(
            "  \x1b[2m↳ if this persists, report at: https://github.com/fluffypony/nsh/issues/new\x1b[0m"
        );
    }
}

fn push_wrapped_tool_result(
    tool_results: &mut Vec<ContentBlock>,
    tool_use_id: String,
    tool_name: &str,
    content: &str,
    is_error: bool,
    boundary: &str,
) {
    let wrapped = crate::security::wrap_tool_result(tool_name, content, boundary);
    tool_results.push(ContentBlock::ToolResult {
        tool_use_id,
        content: wrapped,
        is_error,
    });
}

/// Apply the standard redact → sanitize pipeline to tool output content.
fn finalize_tool_content(content: &str, config: &Config) -> String {
    let redacted = crate::redact::redact_secrets(content, &config.redaction);
    crate::security::sanitize_tool_output(&redacted)
}

/// Push a tool result from a `Result<ToolInvocationOutcome>`, handling
/// the Ok/Err conversion, redaction, sanitization, wrapping with boundary,
/// and appending to results.
fn push_outcome_tool_result(
    tool_results: &mut Vec<ContentBlock>,
    tool_use_id: String,
    tool_name: &str,
    result: anyhow::Result<tools::ToolInvocationOutcome>,
    boundary: &str,
    config: &Config,
) {
    let (content, is_error) = match result {
        Ok(outcome) => outcome.into_parts(),
        Err(e) => (format!("Error: {e}"), true),
    };
    let finalized = finalize_tool_content(&content, config);
    push_wrapped_tool_result(tool_results, tool_use_id, tool_name, &finalized, is_error, boundary);
}

/// Wraps a tool future with timeout handling.
/// In autorun mode: auto-extends once, then returns timeout error.
/// In interactive mode: prompts user to continue waiting.
async fn execute_with_timeout<F, T>(
    fut: F,
    tool_name: &str,
    timeout_secs: u64,
    extension_secs: u64,
    force_autorun: bool,
) -> Result<T, String>
where
    F: std::future::Future<Output = T>,
{
    tokio::pin!(fut);
    let mut total_elapsed = 0u64;
    let initial_timeout = timeout_secs.max(1);
    let extension_timeout = extension_secs.max(1);
    let mut current_timeout = initial_timeout;
    let mut used_auto_extension = false;

    loop {
        match tokio::time::timeout(std::time::Duration::from_secs(current_timeout), &mut fut).await
        {
            Ok(result) => return Ok(result),
            Err(_) => {
                total_elapsed = total_elapsed.saturating_add(current_timeout);

                if force_autorun {
                    // In autorun, auto-extend once, then fail fast with diagnostics.
                    if !used_auto_extension {
                        used_auto_extension = true;
                        current_timeout = extension_timeout;
                        eprintln!(
                            "\x1b[2m  ↳ {} still running ({}s), auto-extending by {}s...\x1b[0m",
                            tool_name, total_elapsed, extension_timeout
                        );
                        continue;
                    }
                    return Err(format!(
                        "Tool '{}' timed out after {}s in autorun mode (including one extension). Try a different approach.",
                        tool_name, total_elapsed
                    ));
                }

                // Interactive: ask user
                eprintln!(
                    "\n  \x1b[1;33m⏱ Tool '{}' has been running for {}s\x1b[0m",
                    tool_name, total_elapsed
                );
                eprint!("\x1b[1;33m  Continue waiting? [Y/n] \x1b[0m");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let keep_waiting =
                    tokio::task::spawn_blocking(crate::tools::read_tty_confirmation_default_yes)
                        .await
                        .unwrap_or(false);
                if !keep_waiting {
                    return Err(format!(
                        "Tool '{}' cancelled by user after {}s timeout. Try a different approach.",
                        tool_name, total_elapsed
                    ));
                }
                // Continue waiting with extension window to avoid repeated prompts.
                current_timeout = extension_timeout;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct QueryOptions {
    pub think: bool,
    pub private: bool,
    pub force_autorun: bool,
    pub json_output: bool,
}

struct QueryPromptState {
    query: String,
    original_query: String,
    boundary: String,
    xml_context: String,
    system: String,
    messages: Vec<Message>,
}

struct QueryToolRuntime {
    skills: Vec<crate::skills::Skill>,
    mcp_client: Arc<tokio::sync::Mutex<crate::mcp::McpClient>>,
    tool_defs: Vec<tools::ToolDefinition>,
    class_tools: HashMap<String, Vec<tools::ToolDefinition>>,
    loaded_classes: HashSet<String>,
    mcp_tool_names: HashSet<String>,
}

struct QueryLlmRuntime {
    cancelled: Arc<AtomicBool>,
    provider: ActiveProvider,
    chain: Vec<String>,
}

struct QuerySession<'a> {
    config: &'a Config,
    db: &'a dyn DbAccess,
    session_id: &'a str,
    opts: QueryOptions,
    display: streaming::StreamDisplay,
    prompt: QueryPromptState,
    llm: QueryLlmRuntime,
    tools: QueryToolRuntime,
}

impl<'a> QuerySession<'a> {
    fn primary_model(&self) -> String {
        self.llm
            .chain
            .first()
            .cloned()
            .unwrap_or_else(|| self.config.provider.model.clone())
    }

    fn model_capabilities(&self) -> crate::config::ModelCapabilities {
        crate::config::model_capabilities(&self.config.provider.default, &self.primary_model())
    }

    fn build_request(
        &self,
        tool_defs: &[tools::ToolDefinition],
        extra_body: Option<serde_json::Value>,
    ) -> ChatRequest {
        ChatRequest {
            model: self.primary_model(),
            system: self.prompt.system.clone(),
            messages: self.prompt.messages.clone(),
            tools: tool_defs.to_vec(),
            tool_choice: if self.model_capabilities().supports_tool_calling {
                ToolChoice::Required
            } else {
                ToolChoice::Auto
            },
            max_tokens: 4096,
            stream: true,
            extra_body,
        }
    }

    fn render_chat_response(&self, response: &str) -> anyhow::Result<()> {
        tools::chat::render_response(response, self.display.json_output_enabled())
    }
}

struct QueryLoopState {
    tool_health: crate::tool_health::ToolHealthTracker,
    query_start: std::time::Instant,
    max_query_duration: std::time::Duration,
    force_json_next: bool,
    json_retry_count: u32,
    deferred_chat_renders: Vec<String>,
    repeat_guard: RepeatGuard,
    abort_tool_loop: bool,
    no_tool_call_streak: u32,
}

impl QueryLoopState {
    fn new(config: &Config) -> Self {
        Self {
            tool_health: crate::tool_health::ToolHealthTracker::new(),
            query_start: std::time::Instant::now(),
            max_query_duration: std::time::Duration::from_secs(
                config.execution.max_query_duration_seconds,
            ),
            force_json_next: false,
            json_retry_count: 0,
            deferred_chat_renders: Vec::new(),
            repeat_guard: RepeatGuard::default(),
            abort_tool_loop: false,
            no_tool_call_streak: 0,
        }
    }

    fn flush_deferred_chat_renders(&mut self, session: &QuerySession<'_>) -> anyhow::Result<()> {
        for response in self.deferred_chat_renders.drain(..) {
            session.render_chat_response(&response)?;
        }
        Ok(())
    }
}

fn normalize_query_input(query: &str) -> String {
    let query = if query == "__NSH_CONTINUE__" {
        "Continue the previous pending task. The latest output is in the context above."
    } else {
        query
    };

    match query.trim().to_lowercase().as_str() {
        "fix" | "fix it" | "fix this" | "fix last" | "wtf" | "why" | "what happened" | "help" => {
            "The previous command failed. Analyze the error output from the terminal context, \
             diagnose the problem, and suggest a corrected command. The error is already in your \
             terminal context — respond directly with the fix."
                .to_string()
        }
        "again" | "retry" => {
            "Re-run the last command that failed, applying any obvious fixes if the error is clear."
                .to_string()
        }
        "try again" | "that's wrong" | "wrong" | "no" | "nope" | "not that" => {
            "The previous response was wrong or didn't solve the problem. Review what you \
             suggested before (visible in the conversation context) and provide a DIFFERENT \
             solution. Do not repeat the same command or approach."
                .to_string()
        }
        _ => query.to_string(),
    }
}

async fn initialize_query_session<'a>(
    query: &str,
    config: &'a Config,
    db: &'a dyn DbAccess,
    session_id: &'a str,
    opts: QueryOptions,
) -> anyhow::Result<QuerySession<'a>> {
    let cancelled = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&cancelled)).ok();

    let boundary = crate::security::generate_boundary();
    let query = normalize_query_input(query);
    let original_query = query.clone();
    let display = streaming::StreamDisplay::new(&config.display, opts.json_output);

    let provider = ActiveProvider::default_from_config(config)?;
    let chain = if config.models.main.is_empty() {
        vec![config.provider.model.clone()]
    } else {
        config.models.main.clone()
    };

    // ── Skills + MCP ───────────────────────────────────
    let skills = crate::skills::load_skills();

    let mcp_client = Arc::new(tokio::sync::Mutex::new(crate::mcp::McpClient::new()));
    {
        let mut mc = mcp_client.lock().await;
        mc.start_servers(&config.mcp).await;
    }

    let mut tool_defs = tools::all_tool_definitions();
    let skill_tool_defs = crate::skills::skill_tool_definitions(&skills);
    let mcp_tool_defs_all = mcp_client.lock().await.tool_definitions();
    tool_defs.extend(skill_tool_defs.clone());
    tool_defs.extend(mcp_tool_defs_all.clone());

    // Build tool classes for JIT loading
    let mut class_tools: HashMap<String, Vec<tools::ToolDefinition>> = HashMap::new();
    // Skill classes: one tool per skill
    for sk in &skills {
        let class = format!("skill:{}", sk.name);
        let defs = crate::skills::skill_tool_definitions(std::slice::from_ref(sk));
        class_tools.insert(class, defs);
    }
    // MCP classes: group by server name (prefix mcp_<server>_)
    let mcp_info = mcp_client.lock().await.server_info();
    for (server, _count) in mcp_info {
        let prefix = format!("mcp_{}_", server);
        let mut defs = Vec::new();
        for d in &mcp_tool_defs_all {
            if d.name.starts_with(&prefix) {
                defs.push(d.clone());
            }
        }
        class_tools.insert(format!("mcp:{}", server), defs);
    }

    // Track which classes are already loaded (skills and MCP tools are preloaded initially)
    let loaded_classes: HashSet<String> = class_tools.keys().cloned().collect();

    // Add meta-tools for JIT discovery/loading
    tool_defs.push(tools::ToolDefinition {
        name: "list_tools".into(),
        description: "Load tools from a specific class into the active toolset. Classes look like 'skill:<name>' or 'mcp:<server>'.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {"class_name": {"type": "string", "description": "Class name: skill:<name> or mcp:<server>"}},
            "required": ["class_name"]
        }),
    });
    tool_defs.push(tools::ToolDefinition {
        name: "find_tools".into(),
        description: "Search installed tool classes that can help with a goal. Returns suggestions and how to load them via list_tools.".into(),
        parameters: serde_json::json!({
            "type": "object",
            "properties": {"goal": {"type": "string", "description": "What you want to accomplish"}},
            "required": ["goal"]
        }),
    });

    let mcp_tool_names: std::collections::HashSet<String> = mcp_client
        .lock()
        .await
        .tool_definitions()
        .iter()
        .map(|t| t.name.clone())
        .collect();

    // ── Context ────────────────────────────────────────
    let ctx = context::build_context(db, session_id, config)?;
    let xml_context = context::build_xml_context(&ctx, config);

    let mcp_info = mcp_client.lock().await.server_info();
    let config_xml = crate::config::build_config_xml(config, &skills, &mcp_info);

    let mut relevant_history_xml = String::new();
    let should_search_history = original_query.len() >= 4
        && original_query.chars().any(|c| c.is_alphanumeric())
        && !original_query.starts_with("The previous command failed")
        && !original_query.starts_with("Re-run the last command")
        && !original_query.starts_with("Continue the previous pending");
    if should_search_history {
        let search_term = &original_query[..original_query.len().min(200)];
        let history_hits = db.search_history(search_term, 5).unwrap_or_default();
        if !history_hits.is_empty() {
            relevant_history_xml.push_str("<relevant_history_from_db>\n");
            for hit in &history_hits {
                relevant_history_xml.push_str("  <entry>\n");
                relevant_history_xml.push_str(&format!(
                    "    <historical_command>{}</historical_command>\n",
                    context::xml_escape(&hit.command)
                ));
                if let Some(summary) = &hit.summary {
                    relevant_history_xml.push_str(&format!(
                        "    <summary>{}</summary>\n",
                        context::xml_escape(summary)
                    ));
                }
                relevant_history_xml.push_str("  </entry>\n");
            }
            relevant_history_xml.push_str("</relevant_history_from_db>\n");
        }
    }

    // ── Active Memory Retrieval ──────────────────────
    let memory_prompt =
        if config.memory.enabled && !config.memory.incognito && config.memory.inject_prompt {
            let memory_ctx = crate::memory::types::MemoryQueryContext {
                query: query.to_string(),
                cwd: Some(ctx.terminal.cwd.clone()),
                session_id: Some(session_id.to_string()),
                interaction_mode: if query.starts_with("The previous command failed") {
                    crate::memory::types::InteractionMode::ErrorFix
                } else {
                    crate::memory::types::InteractionMode::NaturalLanguage
                },
                error_context: None,
            };
            match db.memory_retrieve_prompt(&memory_ctx) {
                Ok(prompt) => prompt,
                Err(e) => {
                    tracing::debug!("Memory retrieval failed: {e}");
                    String::new()
                }
            }
        } else {
            String::new()
        };

    let system = build_system_prompt(
        &ctx,
        &xml_context,
        &boundary,
        &config_xml,
        &relevant_history_xml,
        &memory_prompt,
    );
    let mut messages = Vec::new();

    // Conversation history from this session
    for exchange in &ctx.history.conversation_history {
        let tool_id = uuid::Uuid::new_v4().to_string();
        messages.push(exchange.to_user_message());
        messages.push(exchange.to_assistant_message(&tool_id));
        let mut tool_msg = exchange.to_tool_result_message(&tool_id);
        for block in &mut tool_msg.content {
            if let ContentBlock::ToolResult { content, .. } = block {
                *content = crate::redact::redact_secrets(content, &config.redaction);
            }
        }
        messages.push(tool_msg);
    }

    messages.push(Message {
        role: Role::User,
        content: vec![ContentBlock::Text {
            text: query.to_string(),
        }],
    });

    Ok(QuerySession {
        config,
        db,
        session_id,
        opts,
        display,
        prompt: QueryPromptState {
            query,
            original_query,
            boundary,
            xml_context,
            system,
            messages,
        },
        llm: QueryLlmRuntime {
            cancelled,
            provider,
            chain,
        },
        tools: QueryToolRuntime {
            skills,
            mcp_client,
            tool_defs,
            class_tools,
            loaded_classes,
            mcp_tool_names,
        },
    })
}

async fn finalize_query_session(session: QuerySession<'_>) {
    session.tools.mcp_client.lock().await.shutdown().await;

    let config_clone = session.config.clone();
    let session_clone = session.session_id.to_string();
    tokio::spawn(async move {
        if let Err(e) = backfill_llm_summaries(&config_clone, &session_clone).await {
            tracing::debug!("LLM summary backfill: {e}");
        }
    });
}

pub async fn handle_query(
    query: &str,
    config: &Config,
    db: &dyn DbAccess,
    session_id: &str,
    opts: QueryOptions,
) -> anyhow::Result<()> {
    let mut session = initialize_query_session(query, config, db, session_id, opts).await?;
    let result = run_agent_tool_loop(&mut session).await;
    finalize_query_session(session).await;
    result
}

enum IterationDecision {
    Continue,
    ReturnOk,
    Response(Message),
}

fn update_time_budget(
    session: &mut QuerySession<'_>,
    loop_state: &QueryLoopState,
    iteration: usize,
) {
    let elapsed = loop_state.query_start.elapsed();
    if loop_state.max_query_duration.as_secs() == 0 {
        return;
    }

    let total = loop_state.max_query_duration.as_secs().max(1);
    let remaining_pct = 100u64.saturating_sub(elapsed.as_secs() * 100 / total);
    if remaining_pct <= 20 && remaining_pct > 0 && iteration > 0 {
        eprintln!(
            "\x1b[2m  ⏱ {}% of time budget remaining\x1b[0m",
            remaining_pct
        );
        session.prompt.messages.push(Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: format!(
                    "[SYSTEM: You have approximately {}s remaining in your time budget. Wrap up your current approach. If incomplete, summarize progress and remaining steps.]",
                    (loop_state.max_query_duration.as_secs() as f64 * remaining_pct as f64
                        / 100.0) as u64,
                ),
            }],
        });
    } else if elapsed >= loop_state.max_query_duration && !session.opts.force_autorun {
        eprintln!(
            "\x1b[33mnsh: time budget of {}s reached\x1b[0m",
            loop_state.max_query_duration.as_secs()
        );
        eprint!("\x1b[33mContinue? [Y/n] \x1b[0m");
        let _ = std::io::Write::flush(&mut std::io::stderr());
        if !crate::tools::read_tty_confirmation_default_yes() {
            session.prompt.messages.push(Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text:
                        "Time budget exceeded. Respond NOW with 'chat' tool summarizing progress and remaining steps."
                            .into(),
                }],
            });
        }
    }
}

fn ensure_query_not_cancelled(session: &QuerySession<'_>) -> anyhow::Result<()> {
    if session.llm.cancelled.load(Ordering::SeqCst) {
        eprint!("\x1b[0m");
        eprintln!("\nnsh: interrupted");
        anyhow::bail!("interrupted");
    }
    Ok(())
}

async fn stream_iteration_response(
    session: &mut QuerySession<'_>,
    tool_defs: &[tools::ToolDefinition],
    loop_state: &mut QueryLoopState,
    iteration: usize,
    max_iterations: usize,
) -> anyhow::Result<IterationDecision> {
    let extra_body = if loop_state.force_json_next {
        loop_state.force_json_next = false;
        Some(serde_json::json!({"response_format": {"type": "json_object"}}))
    } else {
        None
    };

    let request = session
        .llm
        .provider
        .prepare_request(session.build_request(tool_defs, extra_body));

    let _spinner = session.display.spinner_guard();
    let chain_result = chain::call_chain_with_fallback_think(
        session.llm.provider.provider(),
        request,
        &session.llm.chain,
        session.opts.think,
    )
    .await;
    drop(_spinner);

    let (mut rx, _used_model) = match chain_result {
        Ok(result) => result,
        Err(error) => {
            let msg = error.to_string();
            let is_retryable = crate::provider::chain::is_retryable_error(&error);
            if msg.contains("401") || msg.contains("403") || msg.contains("Unauthorized") {
                eprintln!(
                    "\x1b[33mnsh: authentication error — check your API key: nsh config edit\x1b[0m"
                );
                return Ok(IterationDecision::ReturnOk);
            }
            if is_retryable && iteration < max_iterations - 1 {
                let backoff = std::time::Duration::from_secs(2u64.pow(iteration.min(4) as u32));
                if session.opts.force_autorun {
                    eprintln!(
                        "\x1b[33mnsh: provider error, retrying in {}s: {}\x1b[0m",
                        backoff.as_secs(),
                        crate::util::truncate(&msg, 100)
                    );
                    tokio::time::sleep(backoff).await;
                    return Ok(IterationDecision::Continue);
                }

                eprintln!(
                    "\x1b[33mnsh: provider error: {}\x1b[0m",
                    crate::util::truncate(&msg, 100)
                );
                eprint!("\x1b[33mRetry? [Y/n] \x1b[0m");
                let _ = std::io::Write::flush(&mut std::io::stderr());
                if crate::tools::read_tty_confirmation_default_yes() {
                    tokio::time::sleep(backoff).await;
                    return Ok(IterationDecision::Continue);
                }
            }

            let display_msg = crate::util::truncate(&msg, 300);
            eprintln!(
                "\x1b[33mnsh: couldn't reach {}: {}\x1b[0m",
                session.config.provider.default, display_msg
            );
            eprintln!(
                "  If this persists, report at: https://github.com/fluffypony/nsh/issues/new"
            );
            return Ok(IterationDecision::ReturnOk);
        }
    };

    crate::connectivity::trigger_immediate_check();
    let stream_timeout =
        std::time::Duration::from_secs(session.config.provider.timeout_seconds * 5);
    let response = match tokio::time::timeout(
        stream_timeout,
        session
            .display
            .consume_stream(&mut rx, &session.llm.cancelled),
    )
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) if error.to_string().contains("interrupted") => {
            eprintln!("\nnsh: interrupted");
            return Err(error);
        }
        Ok(Err(error)) => {
            eprintln!("\x1b[33mnsh: stream error: {}\x1b[0m", error);
            if iteration < max_iterations - 1 {
                eprintln!("  Retrying...");
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                return Ok(IterationDecision::Continue);
            }
            return Err(error);
        }
        Err(_) => {
            eprintln!(
                "\x1b[33mnsh: LLM response stream timed out after {}s\x1b[0m",
                stream_timeout.as_secs()
            );
            if iteration < max_iterations - 1 {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                return Ok(IterationDecision::Continue);
            }
            anyhow::bail!("LLM response timed out");
        }
    };

    Ok(IterationDecision::Response(response))
}

async fn normalize_iteration_response(
    session: &QuerySession<'_>,
    response: Message,
    tool_defs: &[tools::ToolDefinition],
    loop_state: &mut QueryLoopState,
) -> Message {
    let has_tool_calls = response
        .content
        .iter()
        .any(|block| matches!(block, ContentBlock::ToolUse { .. }));
    if has_tool_calls {
        return response;
    }

    let caps = session.model_capabilities();
    if !loop_state.force_json_next && loop_state.json_retry_count < 3 {
        loop_state.force_json_next = true;
        loop_state.json_retry_count += 1;
    } else {
        loop_state.force_json_next = false;
    }

    let text_content = crate::provider::message_text_content(&response);
    let required = [
        crate::json_extract::RequiredKeyPath::new(&["tool"]),
        crate::json_extract::RequiredKeyPath::new(&["input"]),
    ];

    if let Ok(json) = crate::json_extract::extract_and_validate(&text_content, &required) {
        return message_from_loose_tool_json(json).unwrap_or(response);
    }

    let retry_request = crate::provider::ChatRequest {
        model: session
            .llm
            .provider
            .effective_model_name(&session.primary_model()),
        system: session.prompt.system.clone(),
        messages: session.prompt.messages.clone(),
        tools: tool_defs.to_vec(),
        tool_choice: crate::provider::ToolChoice::None,
        max_tokens: 1024,
        stream: false,
        extra_body: if caps.supports_json_mode {
            Some(serde_json::json!({"response_format": {"type": "json_object"}}))
        } else {
            None
        },
    };
    let retry_request = session.llm.provider.prepare_request(retry_request);

    if let Ok(json) = crate::json_extract::extract_with_retry(
        session.llm.provider.provider(),
        retry_request,
        &required,
        2,
    )
    .await
    {
        return message_from_loose_tool_json(json).unwrap_or(response);
    }

    crate::json_extract::extract_json(&text_content)
        .and_then(message_from_loose_tool_json)
        .unwrap_or(response)
}

fn message_from_loose_tool_json(json: serde_json::Value) -> Option<Message> {
    if let Some(name) = json
        .get("tool")
        .or(json.get("name"))
        .and_then(|value| value.as_str())
    {
        let input = json
            .get("input")
            .or(json.get("arguments"))
            .cloned()
            .unwrap_or_else(|| json.clone());
        return Some(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: uuid::Uuid::new_v4().to_string(),
                name: name.to_string(),
                input,
            }],
        });
    }
    if json.get("command").is_some() {
        return Some(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: uuid::Uuid::new_v4().to_string(),
                name: "command".to_string(),
                input: json,
            }],
        });
    }
    if json.get("response").is_some() {
        return Some(Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: uuid::Uuid::new_v4().to_string(),
                name: "chat".to_string(),
                input: json,
            }],
        });
    }
    None
}

async fn run_agent_tool_loop(session: &mut QuerySession<'_>) -> anyhow::Result<()> {
    let config = session.config;
    let db = session.db;
    let session_id = session.session_id;
    let opts = session.opts;
    let query = session.prompt.query.clone();
    let original_query = session.prompt.original_query.clone();
    let boundary = session.prompt.boundary.clone();
    let query = query.as_str();
    let boundary = boundary.as_str();
    let cancelled = Arc::clone(&session.llm.cancelled);
    let public_tool_ctx = tools::ToolInvocationContext::query(
        original_query.as_str(),
        db,
        session_id,
        opts.private,
        config,
        opts.force_autorun,
    )
    .with_json_output(session.display.json_output_enabled());
    let skills = session.tools.skills.clone();
    let mcp_client = Arc::clone(&session.tools.mcp_client);
    let class_tools = session.tools.class_tools.clone();
    let mcp_tool_names = session.tools.mcp_tool_names.clone();
    let xml_context = session.prompt.xml_context.clone();

    // ── Agentic tool loop ──────────────────────────────
    let max_iterations = config.execution.effective_max_tool_iterations();
    let mut loop_state = QueryLoopState::new(config);
    for iteration in 0..max_iterations {
        loop_state.flush_deferred_chat_renders(session)?;

        update_time_budget(session, &loop_state, iteration);
        if let Err(error) = ensure_query_not_cancelled(session) {
            mcp_client.lock().await.shutdown().await;
            return Err(error);
        }
        let current_tool_defs = session.tools.tool_defs.clone();

        let response = match stream_iteration_response(
            session,
            &current_tool_defs,
            &mut loop_state,
            iteration,
            max_iterations,
        )
        .await?
        {
            IterationDecision::Continue => continue,
            IterationDecision::ReturnOk => {
                mcp_client.lock().await.shutdown().await;
                return Ok(());
            }
            IterationDecision::Response(response) => response,
        };
        let response =
            normalize_iteration_response(session, response, &current_tool_defs, &mut loop_state)
                .await;
        let messages = &mut session.prompt.messages;

        messages.push(response.clone());

        // Detect empty or meaningless responses (no tool calls, only whitespace text)
        let has_meaningful_content = response.content.iter().any(|b| match b {
            ContentBlock::Text { text } => !text.trim().is_empty(),
            ContentBlock::ToolUse { .. } => true,
            _ => false,
        });
        if !has_meaningful_content {
            messages.push(Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text:
                        "Your response was empty. Please respond with a tool call or explanation."
                            .into(),
                }],
            });
            loop_state.no_tool_call_streak = loop_state.no_tool_call_streak.saturating_add(1);
            continue;
        }
        // ── Classify tool calls ────────────────────────
        let mut has_terminal_tool = false;
        let mut tool_results: Vec<ContentBlock> = Vec::new();
        let mut parallel_calls: Vec<(String, String, serde_json::Value)> = Vec::new();
        let mut ask_user_calls: Vec<(String, String, serde_json::Value)> = Vec::new();

        for block in &response.content {
            if let ContentBlock::ToolUse { id, name, input } = block {
                if let Err(msg) = validate_tool_input(name, input) {
                    let wrapped = crate::security::wrap_tool_result(name, &msg, boundary);
                    tool_results.push(ContentBlock::ToolResult {
                        tool_use_id: id.clone(),
                        content: wrapped,
                        is_error: true,
                    });
                    // If the model repeats the same invalid tool call inputs, inject correction and continue; abort after 5
                    if loop_state.repeat_guard.note_invalid(name, input) {
                        eprintln!(
                            "\x1b[33mnsh: model repeated an invalid tool call — injecting correction\x1b[0m"
                        );
                        let correction = format!(
                            "CRITICAL: You have made the same invalid tool call for '{}' multiple times with the same bad input. You MUST either: (1) fix the input to match the required schema, (2) use a completely different tool, or (3) use the 'chat' tool to explain what you're trying to do and why you're stuck. Do NOT repeat the same call again.",
                            name
                        );
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: crate::security::wrap_tool_result(name, &correction, boundary),
                            is_error: true,
                        });
                        // Abort after 5 consecutive repeat failures (correction at 4 didn't help)
                        if loop_state.repeat_guard.repeat_fail_count >= 5 {
                            loop_state.abort_tool_loop = true;
                            break;
                        }
                        continue;
                    }
                    continue;
                }

                // Additional semantic guard: if model insists on store_memory semantic with empty data, abort sooner
                if name == "store_memory" {
                    let mt = input["memory_type"].as_str().unwrap_or("");
                    if mt == "semantic"
                        && let Some(data) = input.get("data")
                    {
                        let validation = (|| -> anyhow::Result<()> {
                            let pt = crate::memory::types::MemoryType::parse(mt)?;
                            crate::tools::memory::validate_store_memory_input(pt, data)
                        })();
                        if let Err(e) = validation {
                            let msg = e.to_string();
                            let wrapped = crate::security::wrap_tool_result(name, &msg, boundary);
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: wrapped,
                                is_error: true,
                            });
                            if loop_state.repeat_guard.note_invalid(name, input) {
                                eprintln!(
                                    "\x1b[33mnsh: repeated invalid semantic store_memory; aborting tool loop\x1b[0m"
                                );
                                loop_state.abort_tool_loop = true;
                                break;
                            }
                            continue;
                        }
                    }
                }

                match name.as_str() {
                    "command" => match tools::command::invoke(input, &public_tool_ctx) {
                        Err(e) => {
                            let err_msg = format!("Command tool error: {e}");
                            display_tool_error(&err_msg, opts.json_output);
                            push_wrapped_tool_result(
                                &mut tool_results,
                                id.clone(),
                                name,
                                &err_msg,
                                true,
                                boundary,
                            );
                        }
                        Ok(tools::ToolInvocationResult::Terminal) => {
                            has_terminal_tool = true;
                        }
                        Ok(result) => {
                            let (content, is_error) =
                                result.into_outcome_or_failure(name).into_parts();
                            let finalized = finalize_tool_content(&content, config);
                            push_wrapped_tool_result(
                                &mut tool_results,
                                id.clone(),
                                name,
                                &finalized,
                                is_error,
                                boundary,
                            );
                        }
                    },
                    "chat" => {
                        let response_text = input["response"].as_str().unwrap_or("").to_string();
                        let chat_ctx = public_tool_ctx.with_render_output(false);
                        match tools::chat::invoke(input, &chat_ctx) {
                            Ok(result) => {
                                let (content, is_error) =
                                    result.into_outcome_or_failure(name).into_parts();
                                if !is_error {
                                    loop_state.deferred_chat_renders.push(response_text);
                                }
                                push_wrapped_tool_result(
                                    &mut tool_results,
                                    id.clone(),
                                    name,
                                    &content,
                                    is_error,
                                    boundary,
                                );
                            }
                            Err(e) => {
                                let err_msg = format!("Error: {e}");
                                push_wrapped_tool_result(
                                    &mut tool_results,
                                    id.clone(),
                                    name,
                                    &err_msg,
                                    true,
                                    boundary,
                                );
                            }
                        }
                    }
                    "write_file" => {
                        let (content, is_error) = match tools::write_file::execute(
                            input,
                            &public_tool_ctx,
                        ) {
                            Ok(()) => ("File written successfully.".to_string(), false),
                            Err(e) => {
                                let err_msg = format!("Failed to write file: {e}");
                                display_tool_error(&err_msg, opts.json_output);
                                (err_msg, true)
                            }
                        };
                        let wrapped = crate::security::wrap_tool_result(name, &content, boundary);
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: wrapped,
                            is_error,
                        });
                    }
                    "patch_file" => {
                        let (content, is_error) = match tools::patch_file::execute(
                            input,
                            &public_tool_ctx,
                        ) {
                            Ok(outcome) => outcome.into_parts(),
                            Err(e) => {
                                let err_msg = format!("Failed to apply patch: {e}");
                                display_tool_error(&err_msg, opts.json_output);
                                (err_msg, true)
                            }
                        };
                        let wrapped = crate::security::wrap_tool_result(name, &content, boundary);
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: wrapped,
                            is_error,
                        });
                    }
                    "manage_config" => {
                        let result = tools::manage_config::execute_outcome(input);
                        push_outcome_tool_result(&mut tool_results, id.clone(), name, result, boundary, config);
                    }
                    "install_skill" => {
                        let result = tools::install_skill::execute_outcome(input);
                        push_outcome_tool_result(&mut tool_results, id.clone(), name, result, boundary, config);
                    }
                    "install_mcp_server" => {
                        let result = tools::install_mcp::execute_outcome(input, config);
                        push_outcome_tool_result(&mut tool_results, id.clone(), name, result, boundary, config);
                    }
                    "done" => {
                        has_terminal_tool = true;
                        let result = input["result"].as_str().unwrap_or("Task completed.");
                        let th = crate::tui::theme::current_theme();
                        eprintln!("\n  {}✓ {}{}", th.success, result, th.reset);
                    }

                    "ask_user" => {
                        ask_user_calls.push((id.clone(), name.clone(), input.clone()));
                    }
                    "list_tools" => {
                        let class_name = input["class_name"].as_str().unwrap_or("");
                        let th = crate::tui::theme::current_theme();
                        if let Some(defs) = class_tools.get(class_name) {
                            // Only add if not already loaded
                            if !session.tools.loaded_classes.contains(class_name) {
                                for d in defs {
                                    // Avoid duplicate insertion of identical tool names
                                    if !session.tools.tool_defs.iter().any(|t| t.name == d.name) {
                                        session.tools.tool_defs.push(d.clone());
                                    }
                                }
                                session.tools.loaded_classes.insert(class_name.to_string());
                            }
                            let summary = defs
                                .iter()
                                .map(|d| format!("- {}", d.name))
                                .collect::<Vec<_>>()
                                .join("\n");
                            eprintln!(
                                "\n  {}✓{} loaded tools from class '{}':\n{}",
                                th.success, th.reset, class_name, summary
                            );
                            let wrapped = crate::security::wrap_tool_result(
                                name,
                                &format!(
                                    "Loaded {} tool(s) from class '{}'",
                                    defs.len(),
                                    class_name
                                ),
                                boundary,
                            );
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: wrapped,
                                is_error: false,
                            });
                        } else {
                            let wrapped = crate::security::wrap_tool_result(
                                name,
                                &format!("Class '{}' not found", class_name),
                                boundary,
                            );
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: wrapped,
                                is_error: true,
                            });
                        }
                    }
                    "find_tools" => {
                        let goal = input["goal"].as_str().unwrap_or("");
                        let mut suggestions: Vec<(String, usize)> = Vec::new();
                        let goal_lc = goal.to_lowercase();
                        for (class, defs) in &class_tools {
                            // Simple heuristic: match by class name or tool names
                            let hay = format!(
                                "{} {}",
                                class,
                                defs.iter()
                                    .map(|d| &d.name)
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            );
                            if hay.to_lowercase().contains(&goal_lc) {
                                suggestions.push((class.clone(), defs.len()));
                            }
                        }
                        if suggestions.is_empty() {
                            suggestions = class_tools
                                .keys()
                                .take(10)
                                .map(|c| (c.clone(), class_tools[c].len()))
                                .collect();
                        }
                        let mut body = if suggestions.is_empty() {
                            "No matching tool classes found. Use list_tools(class_name) after reviewing available classes.".to_string()
                        } else {
                            let list = suggestions
                                .iter()
                                .map(|(c, n)| format!("- {} ({} tools)", c, n))
                                .collect::<Vec<_>>()
                                .join("\n");
                            format!(
                                "Tool classes that may help:\n{}\nUse list_tools(class_name) to load one.",
                                list
                            )
                        };
                        // If limited/no suggestions, perform a quick web discovery to enrich results
                        if suggestions.len() < 2 {
                            let query = format!("{} tool OR MCP server OR skill", goal);
                            let search_input = serde_json::json!({ "query": query });
                            match crate::tools::web_search::invoke(&search_input, &public_tool_ctx)
                                .await
                            {
                                Ok(tools::ToolInvocationResult::Continue(
                                    tools::ToolInvocationOutcome::Success(text),
                                )) if !text.trim().is_empty() => {
                                    body.push_str("\n\nWeb discovery hints:\n");
                                    body.push_str(&text);
                                }
                                _ => {}
                            }
                        }
                        let wrapped = crate::security::wrap_tool_result(name, &body, boundary);
                        tool_results.push(ContentBlock::ToolResult {
                            tool_use_id: id.clone(),
                            content: wrapped,
                            is_error: false,
                        });
                    }
                    "code" => {
                        let task = input["task"].as_str().unwrap_or("");
                        let extra_context = input["context"].as_str().unwrap_or("");

                        let approved = if opts.force_autorun {
                            true
                        } else {
                            eprint!("\x1b[1;33mAllow coding agent to work on this? [y/N]\x1b[0m ");
                            std::io::stderr().flush().ok();
                            crate::tools::read_tty_confirmation()
                        };

                        if !approved {
                            let msg = "User declined coding agent delegation.";
                            let wrapped = crate::security::wrap_tool_result(name, msg, boundary);
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id.clone(),
                                content: wrapped,
                                is_error: true,
                            });
                        } else {
                            let result = crate::coding_agent::run_coding_agent(
                                crate::coding_agent::CodingAgentRequest {
                                    task,
                                    context: extra_context,
                                    config,
                                    db,
                                    project_context_xml: &xml_context,
                                    cancelled: &cancelled,
                                    force_autorun: opts.force_autorun,
                                },
                            )
                            .await;
                            let (content, is_error) = match result {
                                Ok(summary) => {
                                    if !opts.private {
                                        let redacted_query = crate::redact::redact_secrets(
                                            &original_query,
                                            &config.redaction,
                                        );
                                        let redacted_summary = crate::redact::redact_secrets(
                                            &summary,
                                            &config.redaction,
                                        );
                                        db.insert_conversation(
                                            session_id,
                                            &redacted_query,
                                            "code_agent",
                                            &redacted_summary,
                                            None,
                                            true,
                                            false,
                                        )?;
                                    }
                                    has_terminal_tool = true;
                                    (summary, false)
                                }
                                Err(e) => (format!("Coding agent error: {e}"), true),
                            };
                            let finalized = finalize_tool_content(&content, config);
                            push_wrapped_tool_result(
                                &mut tool_results,
                                id.clone(),
                                name,
                                &finalized,
                                is_error,
                                boundary,
                            );
                        }
                    }
                    _ => {
                        // Check for terminal skills
                        let is_terminal_skill = name.starts_with("skill_") && {
                            let skill_name = name.strip_prefix("skill_").unwrap_or(name);
                            skills.iter().any(|s| s.name == skill_name && s.terminal)
                        };

                        if is_terminal_skill {
                            has_terminal_tool = true;
                            let skill_name = name.strip_prefix("skill_").unwrap_or(name);
                            if let Some(skill) = skills.iter().find(|s| s.name == skill_name) {
                                match crate::skills::execute_skill(skill, input) {
                                    Ok(output) => {
                                        if !output.is_empty() {
                                            eprintln!("{output}");
                                        }
                                    }
                                    Err(e) => eprintln!("Skill error: {e}"),
                                }
                            }
                        } else {
                            parallel_calls.push((id.clone(), name.clone(), input.clone()));
                        }
                    }
                }
            }
        }

        if has_terminal_tool {
            break;
        }

        if loop_state.abort_tool_loop {
            // Inject a correction and continue the outer loop per plan 11g
            loop_state.abort_tool_loop = false;
            messages.push(Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "Your previous tool calls repeatedly failed with invalid inputs. Try a COMPLETELY DIFFERENT approach. If you cannot proceed, call 'done' with a reason explaining what went wrong.".into() }],
            });
            continue;
        }

        // ── Execute intermediate tools ─────────────────
        if !parallel_calls.is_empty() {
            let mut futs: Vec<ToolFuture> = Vec::new();
            let mut input_map: HashMap<String, serde_json::Value> = HashMap::new();

            for (id, name, input) in parallel_calls {
                input_map.insert(id.clone(), input.clone());
                crate::tui::tool_status(&describe_tool_action(&name, &input));
                match name.as_str() {
                    "search_history" => {
                        let outcome = match tools::search_history::invoke(&input, &public_tool_ctx)
                        {
                            Ok(result) => result.into_outcome_or_failure(&name),
                            Err(e) => {
                                let err_msg = format!("{e}");
                                display_tool_error(&err_msg, opts.json_output);
                                tools::ToolInvocationOutcome::failure(err_msg)
                            }
                        };
                        let (content, is_error) = outcome.into_parts();
                        let finalized = finalize_tool_content(&content, config);
                        push_wrapped_tool_result(
                            &mut tool_results,
                            id,
                            &name,
                            &finalized,
                            is_error,
                            boundary,
                        );
                    }
                    "web_search" => {
                        let ws_config = config.clone();
                        let ws_input = input.clone();
                        let timeout = input
                            .get("expected_timeout_seconds")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(crate::tools::default_timeout_for_tool("web_search"));
                        let extension_timeout = config.execution.tool_timeout_extension_seconds;
                        let force_autorun = opts.force_autorun;
                        futs.push(Box::pin(async move {
                            let ctx =
                                tools::ToolInvocationContext::standalone(&ws_config, force_autorun);
                            let fut = async {
                                tools::web_search::invoke(&ws_input, &ctx)
                                    .await
                                    .map(|result| result.into_outcome_or_failure("web_search"))
                            };
                            let result = match execute_with_timeout(
                                fut,
                                "web_search",
                                timeout,
                                extension_timeout,
                                force_autorun,
                            )
                            .await
                            {
                                Ok(Ok(outcome)) => Ok(outcome),
                                Ok(Err(e)) => Err(format!("{e}")),
                                Err(msg) => Err(msg),
                            };
                            (id, name, result)
                        }));
                    }
                    "github" => {
                        let input_clone = input.clone();
                        let github_config = config.clone();
                        let timeout = input_clone
                            .get("expected_timeout_seconds")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(crate::tools::default_timeout_for_tool("github"));
                        let extension_timeout = config.execution.tool_timeout_extension_seconds;
                        let force_autorun = opts.force_autorun;
                        futs.push(Box::pin(async move {
                            let fut = async {
                                Ok::<crate::tools::ToolInvocationOutcome, anyhow::Error>(
                                    crate::tools::ToolInvocationOutcome::from_result(
                                        crate::tools::github::execute(&input_clone, &github_config)
                                            .await,
                                    ),
                                )
                            };
                            let result = match execute_with_timeout(
                                fut,
                                "github",
                                timeout,
                                extension_timeout,
                                force_autorun,
                            )
                            .await
                            {
                                Ok(Ok(outcome)) => Ok(outcome),
                                Ok(Err(e)) => Err(format!("{e}")),
                                Err(msg) => Err(msg),
                            };
                            (id, name, result)
                        }));
                    }
                    // ── Memory tools (non-terminal) ──────────
                    "search_memory"
                    | "core_memory_append"
                    | "core_memory_rewrite"
                    | "store_memory"
                    | "retrieve_secret" => {
                        // Gate on memory config
                        if !config.memory.enabled || config.memory.incognito {
                            let wrapped = crate::security::wrap_tool_result(
                                &name,
                                "Memory system is disabled or in incognito mode",
                                boundary,
                            );
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id,
                                content: wrapped,
                                is_error: true,
                            });
                        } else if let Err(e) =
                            crate::security::assess_memory_tool_call(&name, &input, messages)
                        {
                            let wrapped = crate::security::wrap_tool_result(
                                &name,
                                &format!("Security check failed: {e}"),
                                boundary,
                            );
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id,
                                content: wrapped,
                                is_error: true,
                            });
                        } else {
                            let (content, is_error) = match name.as_str() {
                                "search_memory" => {
                                    let mt = input["memory_type"].as_str().unwrap_or("all");
                                    let q = input["query"].as_str().unwrap_or("");
                                    let lim =
                                        (input["limit"].as_u64().unwrap_or(10) as usize).min(50);
                                    match crate::tools::memory::execute_search_memory(
                                        db, mt, q, lim,
                                    ) {
                                        Ok(results) => (results, false),
                                        Err(e) => (format!("Error: {e}"), true),
                                    }
                                }
                                "core_memory_append" => {
                                    let label = input["label"].as_str().unwrap_or("");
                                    let content = input["content"].as_str().unwrap_or("");
                                    match crate::tools::memory::execute_core_memory_append(
                                        db, label, content,
                                    ) {
                                        Ok(msg) => (msg, false),
                                        Err(e) => (format!("Error: {e}"), true),
                                    }
                                }
                                "core_memory_rewrite" => {
                                    let label = input["label"].as_str().unwrap_or("");
                                    let content = input["content"].as_str().unwrap_or("");
                                    match crate::tools::memory::execute_core_memory_rewrite(
                                        db, label, content,
                                    ) {
                                        Ok(msg) => (msg, false),
                                        Err(e) => (format!("Error: {e}"), true),
                                    }
                                }
                                "store_memory" => {
                                    let memory_type = input["memory_type"].as_str().unwrap_or("");
                                    let data =
                                        input.get("data").cloned().unwrap_or(serde_json::json!({}));
                                    match crate::tools::memory::execute_store_memory(
                                        db,
                                        memory_type,
                                        &data,
                                    ) {
                                        Ok(msg) => (msg, false),
                                        Err(e) => (format!("Error: {e}"), true),
                                    }
                                }
                                "retrieve_secret" => {
                                    let caption_query =
                                        input["caption_query"].as_str().unwrap_or("");
                                    match crate::tools::memory::execute_retrieve_secret(
                                        db,
                                        caption_query,
                                        Some(original_query.as_str()),
                                    ) {
                                        Ok(secret) => (secret, false),
                                        Err(e) => (format!("Error: {e}"), true),
                                    }
                                }
                                _ => unreachable!(),
                            };
                            // For retrieve_secret, apply redaction so the secret
                            // doesn't persist in conversation history unredacted
                            let content = if name == "retrieve_secret" {
                                crate::redact::redact_secrets(&content, &config.redaction)
                            } else {
                                content
                            };
                            let sanitized = crate::security::sanitize_tool_output(&content);
                            let wrapped =
                                crate::security::wrap_tool_result(&name, &sanitized, boundary);
                            tool_results.push(ContentBlock::ToolResult {
                                tool_use_id: id,
                                content: wrapped,
                                is_error,
                            });
                        }
                    }
                    _ => {
                        // MCP tools
                        if mcp_tool_names.contains(&name) {
                            let mcp = Arc::clone(&mcp_client);
                            let name_exec = name.clone();
                            let id_ret = id;
                            let name_ret = name;
                            let timeout = input
                                .get("expected_timeout_seconds")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(crate::tools::default_timeout_for_tool("mcp"));
                            let extension_timeout = config.execution.tool_timeout_extension_seconds;
                            let force_autorun = opts.force_autorun;
                            futs.push(Box::pin(async move {
                                let fut_call = async {
                                    let mut mc = mcp.lock().await;
                                    mc.call_tool(&name_exec, input).await
                                };
                                let result = match execute_with_timeout(
                                    fut_call,
                                    &name_ret,
                                    timeout,
                                    extension_timeout,
                                    force_autorun,
                                )
                                .await
                                {
                                    Ok(Ok(r)) => Ok(tools::ToolInvocationOutcome::success(r)),
                                    Ok(Err(e)) => Err(format!("{e}")),
                                    Err(msg) => Err(msg),
                                };
                                (id_ret, name_ret, result)
                            }));
                        } else {
                            let cfg_clone = config.clone();
                            let name_for_exec = name.clone();
                            let id_ret = id;
                            let name_ret = name;
                            let tool_timeout = input
                                .get("expected_timeout_seconds")
                                .and_then(|v| v.as_u64())
                                .unwrap_or(crate::tools::default_timeout_for_tool(&name_for_exec));
                            // Try exact match first
                            let mut matched_skill = skills
                                .iter()
                                .find(|s| format!("skill_{}", s.name) == name_for_exec)
                                .cloned();
                            // If the model used a slightly different skill name (e.g., 'humanizer' vs 'humanize'),
                            // attempt a simple fuzzy match to map to an existing installed skill.
                            if matched_skill.is_none() && name_for_exec.starts_with("skill_") {
                                let req = name_for_exec.trim_start_matches("skill_");
                                let candidates: Vec<&crate::skills::Skill> =
                                    skills.iter().collect();
                                // Heuristic: try common suffix trims and then minimal edit distance <= 2
                                let trims = ["er", "or", "r", "s", "ing", "izer", "ise", "ize"];
                                let mut bases = vec![req.to_string()];
                                for t in &trims {
                                    if let Some(base) = req.strip_suffix(t) {
                                        bases.push(base.to_string());
                                    }
                                }
                                // Prefer substring proximity
                                if let Some(s) = candidates.iter().find(|s| {
                                    bases.iter().any(|b| {
                                        s.name == *b
                                            || s.name.starts_with(b)
                                            || b.starts_with(&s.name)
                                    })
                                }) {
                                    matched_skill = Some((**s).clone());
                                } else {
                                    // Fallback: minimal edit distance
                                    let mut best: Option<(&crate::skills::Skill, usize)> = None;
                                    for s in &candidates {
                                        let d = crate::util::levenshtein_distance(req, &s.name);
                                        if best.map(|(_, bd)| d < bd).unwrap_or(true) {
                                            best = Some((s, d));
                                        }
                                    }
                                    if let Some((s, d)) = best
                                        && d <= 2
                                    {
                                        matched_skill = Some((*s).clone());
                                    }
                                }
                            }
                            if let Some(skill) = matched_skill {
                                let timeout = input
                                    .get("expected_timeout_seconds")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(crate::tools::default_timeout_for_tool("skill"));
                                let extension_timeout =
                                    config.execution.tool_timeout_extension_seconds;
                                let force_autorun = opts.force_autorun;
                                futs.push(Box::pin(async move {
                                    let fut = crate::skills::execute_skill_async(skill, input);
                                    let result = match execute_with_timeout(
                                        fut,
                                        &name_ret,
                                        timeout,
                                        extension_timeout,
                                        force_autorun,
                                    )
                                    .await
                                    {
                                        Ok(Ok(r)) => Ok(tools::ToolInvocationOutcome::success(r)),
                                        Ok(Err(e)) => Err(format!("{e}")),
                                        Err(msg) => Err(msg),
                                    };
                                    (id_ret, name_ret, result)
                                }));
                            } else {
                                let force_autorun = opts.force_autorun;
                                let extension_timeout =
                                    config.execution.tool_timeout_extension_seconds;
                                futs.push(Box::pin(async move {
                                    let task = tokio::task::spawn_blocking(move || {
                                        execute_sync_tool_outcome(
                                            &name_for_exec,
                                            &input,
                                            &cfg_clone,
                                        )
                                    });
                                    let result = match execute_with_timeout(
                                        task,
                                        &name_ret,
                                        tool_timeout,
                                        extension_timeout,
                                        force_autorun,
                                    )
                                    .await
                                    {
                                        Ok(Ok(inner)) => inner.map_err(|e| format!("{e}")),
                                        Ok(Err(e)) => Err(format!("task panicked: {e}")),
                                        Err(msg) => Err(msg),
                                    };
                                    (id_ret, name_ret, result)
                                }));
                            }
                        }
                    }
                }
            }

            let results = futures::future::join_all(futs).await;
            for (id, name, result) in results {
                let (content, is_error) = match result {
                    Ok(outcome) => {
                        let (content, is_error) = outcome.into_parts();
                        if is_error {
                            display_tool_error(&content, opts.json_output);
                            let enriched = if let Some(inp) = input_map.get(&id) {
                                loop_state.tool_health.enrich_error(&name, inp, &content)
                            } else {
                                content
                            };
                            (enriched, true)
                        } else {
                            (content, false)
                        }
                    }
                    Err(e) => {
                        display_tool_error(&e, opts.json_output);
                        let enriched = if let Some(inp) = input_map.get(&id) {
                            loop_state.tool_health.enrich_error(&name, inp, &e)
                        } else {
                            e.clone()
                        };
                        (enriched, true)
                    }
                };
                loop_state.tool_health.record(&name, !is_error);
                let finalized = finalize_tool_content(&content, config);
                let finalized = crate::util::truncate(&finalized, 32000);
                let wrapped = crate::security::wrap_tool_result(&name, &finalized, boundary);
                tool_results.push(ContentBlock::ToolResult {
                    tool_use_id: id,
                    content: wrapped,
                    is_error,
                });
            }
        }

        // Execute ask_user sequentially
        for (id, name, input) in ask_user_calls {
            eprintln!("  \x1b[2m↳ asking for input...\x1b[0m");
            let (content, is_error) = match tools::ask_user::invoke(&input, &public_tool_ctx) {
                Ok(result) => result.into_outcome_or_failure(&name).into_parts(),
                Err(e) => (format!("Error: {e}"), true),
            };
            let finalized = finalize_tool_content(&content, config);
            push_wrapped_tool_result(&mut tool_results, id, &name, &finalized, is_error, boundary);
        }

        if tool_results.is_empty() {
            if loop_state.force_json_next {
                continue;
            }
            loop_state.no_tool_call_streak = loop_state.no_tool_call_streak.saturating_add(1);
            if loop_state.no_tool_call_streak >= 5 {
                loop_state.force_json_next = false;
                eprintln!("\x1b[2mnsh: model unable to produce tool calls after 5 attempts\x1b[0m");
                messages.push(Message { role: Role::User, content: vec![ContentBlock::Text { text: "You have failed to produce tool calls multiple times. Use the 'chat' tool NOW to provide your best answer, or use 'command' to suggest a shell command. This is your last chance.".to_string() }] });
                if loop_state.no_tool_call_streak >= 8 {
                    break;
                }
                continue;
            }
            messages.push(Message { role: Role::User, content: vec![ContentBlock::Text { text: format!(
                "You must respond with a tool call. Iteration {}/{} — you have {} attempts remaining. Use 'chat' for explanations or 'command' for actions. Plain text outside tool calls is discarded.",
                iteration + 1, max_iterations, max_iterations - iteration - 1) }] });
            continue;
        } else {
            loop_state.no_tool_call_streak = 0;
        }

        messages.push(Message {
            role: Role::Tool,
            content: tool_results,
        });
    }

    loop_state.flush_deferred_chat_renders(session)?;

    Ok(())
}

fn execute_sync_tool_outcome(
    name: &str,
    input: &serde_json::Value,
    config: &Config,
) -> anyhow::Result<tools::ToolInvocationOutcome> {
    let sfa_read = config.tools.sensitive_file_access;
    match name {
        "grep_file" => tools::grep_file::execute_outcome_with_access(input, sfa_read),
        "read_file" => tools::read_file::execute_outcome_with_access(input, sfa_read),
        "list_directory" => tools::list_directory::execute_outcome_with_access(input, sfa_read),
        "glob" => tools::glob::execute_outcome_with_access(input, sfa_read),
        "run_command" => {
            let cmd = input["command"].as_str().unwrap_or("");
            tools::run_command::execute_outcome(cmd, config)
        }
        "man_page" => {
            let cmd = input["command"].as_str().unwrap_or("");
            let section = input["section"].as_u64().map(|s| s as u8);
            Ok(tools::ToolInvocationOutcome::from_result(
                tools::man_page::execute(cmd, section),
            ))
        }
        unknown => Ok(tools::ToolInvocationOutcome::failure(format!(
            "Unknown tool: {unknown}"
        ))),
    }
}

fn describe_tool_action(name: &str, input: &serde_json::Value) -> String {
    // Use shared descriptions for common tools (read_file, write_file, grep_file, etc.)
    if let Some(desc) = crate::tools::runtime::describe::describe_common_tool(name, input) {
        return desc;
    }
    match name {
        "search_history" => {
            if let Some(q) = input["query"].as_str()
                && !q.trim().is_empty()
            {
                return format!("searching history for \"{q}\"");
            }
            if let Some(cmd) = input["command"].as_str() {
                if let Some(entity) = input["entity"].as_str() {
                    return format!("searching history for `{cmd}` targets matching \"{entity}\"");
                }
                return format!("searching history for `{cmd}` targets");
            }
            if let Some(entity) = input["entity"].as_str() {
                return format!("searching history for target \"{entity}\"");
            }
            "searching history for \"...\"".to_string()
        }
        "code" => {
            let task = input["task"].as_str().unwrap_or("...");
            let preview: String = task.chars().take(60).collect();
            format!("coding: {preview}")
        }
        "run_command" => {
            let cmd = input["command"].as_str().unwrap_or("...");
            // Present in a consistent, literal style so users see what is being executed.
            // Also hint that output will be shown and interpreted.
            format!("↳ running `{cmd}`")
        }
        "web_search" => {
            let q = input["query"].as_str().unwrap_or("...");
            format!("searching \"{q}\"")
        }
        "github" => {
            let action = input["action"].as_str().unwrap_or("?");
            let repo = input["repo"].as_str().unwrap_or("?");
            let goal = input["goal"].as_str().unwrap_or("");
            if goal.is_empty() {
                format!("github {action} on {repo}")
            } else {
                format!("github {action} on {repo} (goal: {goal})")
            }
        }
        "man_page" => {
            let cmd = input["command"].as_str().unwrap_or("?");
            format!("reading man page: {cmd}")
        }
        "manage_config" => {
            let action = input["action"].as_str().unwrap_or("set");
            let key = input["key"].as_str().unwrap_or("...");
            format!("config {action}: {key}")
        }
        "install_skill" => {
            if let Some(repo) = input["repo"].as_str() {
                format!("installing skill from repo: {repo}")
            } else {
                let name = input["name"].as_str().unwrap_or("...");
                format!("installing skill: {name}")
            }
        }
        "install_mcp_server" => {
            let name = input["name"].as_str().unwrap_or("...");
            format!("installing MCP server: {name}")
        }
        "search_memory" => {
            let q = input["query"].as_str().unwrap_or("...");
            let mt = input["memory_type"].as_str().unwrap_or("all");
            format!("searching {mt} memory for \"{q}\"")
        }
        "core_memory_append" => {
            let label = input["label"].as_str().unwrap_or("...");
            format!("appending to core memory: {label}")
        }
        "core_memory_rewrite" => {
            let label = input["label"].as_str().unwrap_or("...");
            format!("rewriting core memory: {label}")
        }
        "store_memory" => {
            let mt = input["memory_type"].as_str().unwrap_or("...");
            format!("storing to {mt} memory")
        }
        "retrieve_secret" => {
            let q = input["caption_query"].as_str().unwrap_or("...");
            format!("retrieving secret: \"{q}\"")
        }
        other => other.to_string(),
    }
}

fn validate_tool_input(name: &str, input: &serde_json::Value) -> Result<(), String> {
    if name == "install_skill" {
        let has_str = |key: &str| {
            input
                .get(key)
                .and_then(|v| v.as_str())
                .map(|s| !s.trim().is_empty())
                .unwrap_or(false)
        };
        // Repo mode: just needs a repo/url — skip all other validation
        let have_repo = has_str("repo") || has_str("url");
        // Also detect URLs passed in name field
        let name_is_url = input
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| {
                s.contains("github.com")
                    || s.contains("gitlab.com")
                    || s.starts_with("https://")
                    || s.starts_with("http://")
            })
            .unwrap_or(false);
        if have_repo || name_is_url {
            return Ok(());
        }
        // Manual mode: require name + description + (command OR runtime+script OR docs)
        if !has_str("name") || !has_str("description") {
            return Err(
                "Missing required field 'name' or 'description' for tool 'install_skill'. \
                        To install from a Git repo, pass repo=URL instead."
                    .to_string(),
            );
        }
        if !(has_str("command") || (has_str("runtime") && has_str("script")) || has_str("docs")) {
            return Err("Provide either 'command', both 'runtime' and 'script', or 'docs' for 'install_skill'".to_string());
        }
        return Ok(());
    }

    let required_fields: &[&str] = match name {
        "command" => &["command", "explanation"],
        "chat" => &["response"],
        "grep_file" | "read_file" => &["path"],
        "write_file" => &["path", "content", "reason"],
        "patch_file" => &["path", "search", "replace", "reason"],
        "glob" => &["pattern"],
        "code" => &["task"],
        "run_command" => &["command", "reason"],
        "web_search" => &["query"],
        "github" => &["action", "repo"],
        "ask_user" => &["question"],
        "man_page" => &["command"],
        "manage_config" => &["action", "key"],
        "install_mcp_server" => &["name"],
        "search_memory" => &["memory_type", "query"],
        "core_memory_append" => &["label", "content"],
        "core_memory_rewrite" => &["label", "content"],
        "store_memory" => &["memory_type", "data"],
        "retrieve_secret" => &["caption_query"],
        _ => &[],
    };
    for field in required_fields {
        if input.get(field).is_none() {
            return Err(format!(
                "Missing required field '{field}' for tool '{name}'"
            ));
        }
    }
    Ok(())
}

async fn backfill_llm_summaries(config: &Config, _session_id: &str) -> anyhow::Result<()> {
    let db = crate::daemon_db::DaemonDb::new();
    let commands = db.commands_needing_llm_summary(3)?;
    for cmd in &commands {
        match crate::summary::generate_llm_summary(cmd, config).await {
            Ok(summary) => {
                let _ = db.update_summary(cmd.id, &summary);
            }
            Err(e) => {
                let _ = db.mark_summary_error(cmd.id, &e.to_string());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod query_loop_tests {
    use super::{
        run_agent_tool_loop, streaming, QueryLlmRuntime, QueryOptions, QueryPromptState,
        QuerySession, QueryToolRuntime,
    };
    use crate::config::Config;
    use crate::provider::{
        ActiveProvider, ChatRequest, ContentBlock, LlmProvider, Message, Role, StreamEvent,
    };
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::sync::atomic::AtomicBool;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    struct MockProvider {
        streams: Mutex<VecDeque<Vec<StreamEvent>>>,
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        async fn complete(&self, _request: ChatRequest) -> anyhow::Result<Message> {
            anyhow::bail!("complete should not be called in query loop tests")
        }

        async fn stream(
            &self,
            _request: ChatRequest,
        ) -> anyhow::Result<mpsc::Receiver<StreamEvent>> {
            let events = self
                .streams
                .lock()
                .expect("lock mock streams")
                .pop_front()
                .expect("stream script");
            let (tx, rx) = mpsc::channel(16);
            tokio::spawn(async move {
                for event in events {
                    let _ = tx.send(event).await;
                }
            });
            Ok(rx)
        }
    }

    fn build_test_session<'a>(
        config: &'a Config,
        db: &'a crate::db::Db,
        session_id: &'a str,
        streams: Vec<Vec<StreamEvent>>,
    ) -> QuerySession<'a> {
        QuerySession {
            config,
            db,
            session_id,
            opts: QueryOptions {
                json_output: true,
                ..Default::default()
            },
            display: streaming::StreamDisplay::new(&config.display, true),
            prompt: QueryPromptState {
                query: "solve it".into(),
                original_query: "solve it".into(),
                boundary: "test-boundary".into(),
                xml_context: "<context />".into(),
                system: "system".into(),
                messages: vec![Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text {
                        text: "solve it".into(),
                    }],
                }],
            },
            llm: QueryLlmRuntime {
                cancelled: Arc::new(AtomicBool::new(false)),
                provider: ActiveProvider::new(
                    Box::new(MockProvider {
                        streams: Mutex::new(VecDeque::from(streams)),
                    }),
                    None,
                ),
                chain: vec!["test-model".into()],
            },
            tools: QueryToolRuntime {
                skills: Vec::new(),
                mcp_client: Arc::new(tokio::sync::Mutex::new(crate::mcp::McpClient::new())),
                tool_defs: Vec::new(),
                class_tools: HashMap::new(),
                loaded_classes: HashSet::new(),
                mcp_tool_names: HashSet::new(),
            },
        }
    }

    fn done_tool_events(result: &str) -> Vec<StreamEvent> {
        vec![
            StreamEvent::ToolUseStart {
                id: "done-1".into(),
                name: "done".into(),
            },
            StreamEvent::ToolUseDelta(format!(r#"{{"result":"{result}"}}"#)),
            StreamEvent::ToolUseEnd,
            StreamEvent::Done { usage: None },
        ]
    }

    #[tokio::test]
    async fn run_agent_tool_loop_handles_done_tool_response() {
        let config = Config::default();
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session("s1", "tty0", "zsh", 1234)
            .expect("create session");
        let mut session =
            build_test_session(&config, &db, "s1", vec![done_tool_events("finished")]);

        run_agent_tool_loop(&mut session)
            .await
            .expect("query loop should finish");
    }

    #[tokio::test]
    async fn run_agent_tool_loop_records_chat_tool_before_done() {
        let config = Config::default();
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session("s1", "tty0", "zsh", 1234)
            .expect("create session");
        let mut session = build_test_session(
            &config,
            &db,
            "s1",
            vec![
                vec![
                    StreamEvent::ToolUseStart {
                        id: "chat-1".into(),
                        name: "chat".into(),
                    },
                    StreamEvent::ToolUseDelta(r#"{"response":"hello from tool"}"#.into()),
                    StreamEvent::ToolUseEnd,
                    StreamEvent::Done { usage: None },
                ],
                done_tool_events("wrapped up"),
            ],
        );

        run_agent_tool_loop(&mut session)
            .await
            .expect("query loop should finish");

        let conversations = db.get_conversations("s1", 10).expect("load conversations");
        assert_eq!(conversations.len(), 1);
        assert_eq!(conversations[0].response_type, "chat");
        assert_eq!(conversations[0].response, "hello from tool");
    }
}

#[cfg(test)]
mod repeat_guard_tests {
    use super::RepeatGuard;

    #[test]
    fn repeat_guard_triggers_on_third_repeat() {
        let mut guard = RepeatGuard::default();
        let name = "store_memory";
        let payload = serde_json::json!({"memory_type":"semantic","data":{}});
        assert!(!guard.note_invalid(name, &payload));
        assert!(!guard.note_invalid(name, &payload));
        assert!(!guard.note_invalid(name, &payload));
        // Fourth identical invalid should trigger
        assert!(guard.note_invalid(name, &payload));
    }

    #[test]
    fn repeat_guard_resets_on_different_payload() {
        let mut guard = RepeatGuard::default();
        let name = "store_memory";
        let p1 = serde_json::json!({"data":{}});
        let p2 = serde_json::json!({"data":{"x":1}});
        assert!(!guard.note_invalid(name, &p1));
        assert!(!guard.note_invalid(name, &p1));
        // different input hash resets counter
        assert!(!guard.note_invalid(name, &p2));
        // repeating new payload now accumulates again
        assert!(!guard.note_invalid(name, &p2));
        assert!(!guard.note_invalid(name, &p2));
        assert!(guard.note_invalid(name, &p2));
    }
}
#[derive(Default)]
struct RepeatGuard {
    last_tool_signature: Option<(String, String)>,
    repeat_fail_count: u8,
}

impl RepeatGuard {
    fn note_invalid(&mut self, name: &str, input: &serde_json::Value) -> bool {
        // Pending commands are part of multi-step workflows; don't penalize repetition
        if name == "command"
            && input
                .get("pending")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
        {
            self.repeat_fail_count = 0;
            return false;
        }
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(input.to_string().as_bytes());
        let hex = format!("{:x}", hasher.finalize());
        let sig = (name.to_string(), hex);
        if self.last_tool_signature.as_ref() == Some(&sig) {
            self.repeat_fail_count = self.repeat_fail_count.saturating_add(1);
        } else {
            self.repeat_fail_count = 1;
        }
        self.last_tool_signature = Some(sig);
        self.repeat_fail_count >= 4
    }
}
