use crate::cli::HistoryAction;

use super::daemon_runtime::global_daemon_payload;

pub(super) fn handle_history_command(action: HistoryAction) -> anyhow::Result<()> {
    match action {
        HistoryAction::Search { query, limit } => {
            let request = crate::daemon::DaemonRequest::SearchHistory { query, limit };
            match global_daemon_payload::<crate::daemon::HistorySearchPayload>(&request) {
                Ok(response) if response.results.is_empty() => eprintln!("No results found."),
                Ok(response) => {
                    for result in response.results {
                        let code = result
                            .exit_code
                            .map(|exit| format!(" (exit {exit})"))
                            .unwrap_or_default();
                        println!("[{}]{code} {}", result.started_at, result.cmd_highlight);
                        if let Some(highlight) = result.output_highlight {
                            let preview: String = highlight.chars().take(200).collect();
                            println!("  {preview}");
                        }
                    }
                }
                Err(error) => eprintln!("nsh: {error}"),
            }
        }
    }
    Ok(())
}

pub(super) fn handle_cost_command(period: String) -> anyhow::Result<()> {
    let usage_period = match period.as_str() {
        "today" => crate::db::UsagePeriod::Today,
        "week" => crate::db::UsagePeriod::Week,
        "month" => crate::db::UsagePeriod::Month,
        "all" => crate::db::UsagePeriod::All,
        _ => crate::db::UsagePeriod::Month,
    };
    let request = crate::daemon::DaemonRequest::GetUsageStats { period: usage_period };
    let stats = match global_daemon_payload::<crate::daemon::UsageStatsPayload>(&request) {
        Ok(response) if !response.stats.is_empty() => response.stats,
        _ => {
            eprintln!("No usage data recorded yet.");
            return Ok(());
        }
    };
    eprintln!("Model                               Calls  Input Tok  Output Tok  Cost (USD)");
    eprintln!("─────────────────────────────────────────────────────────────────────────────");
    let mut total_cost = 0.0_f64;
    let mut total_calls = 0_i64;
    for entry in &stats {
        eprintln!(
            "{:<35} {:>5}  {:>9}  {:>10}  ${:.4}",
            entry.model, entry.calls, entry.input_tokens, entry.output_tokens, entry.cost_usd
        );
        total_cost += entry.cost_usd;
        total_calls += entry.calls;
    }
    eprintln!("─────────────────────────────────────────────────────────────────────────────");
    eprintln!(
        "{:<35} {:>5}                        ${:.4}",
        "TOTAL", total_calls, total_cost
    );
    Ok(())
}

pub(super) fn handle_export_command(
    format: Option<String>,
    session: Option<String>,
) -> anyhow::Result<()> {
    let session_id = session.unwrap_or_else(|| std::env::var("NSH_SESSION_ID").unwrap_or_default());
    let request = crate::daemon::DaemonRequest::GetConversations {
        session: session_id.clone(),
        limit: 1000,
        caller: crate::daemon::current_caller_context(),
    };
    let conversations =
        global_daemon_payload::<crate::daemon::ConversationsPayload>(&request)?.conversations;
    if conversations.is_empty() {
        eprintln!("No conversations found for session {session_id}");
    } else {
        match format.as_deref().unwrap_or("markdown") {
            "json" => println!("{}", serde_json::to_string_pretty(&conversations)?),
            _ => {
                for conversation in &conversations {
                    let query = conversation.query.as_str();
                    let response_type = conversation.response_type.as_str();
                    let response = conversation.response.as_str();
                    let explanation = conversation.explanation.as_deref().unwrap_or("");
                    println!("**Q:** {query}\n");
                    match response_type {
                        "command" => println!("```bash\n{response}\n```\n{explanation}\n"),
                        _ => println!("{response}\n"),
                    }
                }
            }
        }
    }
    Ok(())
}

pub(super) fn handle_history_import_run_command() {
    let result = crate::daemon_client::ensure_global_daemon_running();
    crate::history_import::clear_import_lock();
    if let Err(error) = result {
        tracing::debug!("background history import failed: {error}");
    }
}
