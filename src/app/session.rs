use crate::cli::SessionAction;

use super::daemon_runtime::{
    global_daemon_payload, optional_global_daemon_payload, send_to_global_or_fallback,
};

pub(super) fn handle_session_command(action: SessionAction) -> anyhow::Result<()> {
    match action {
        SessionAction::Start {
            session,
            tty,
            shell,
            pid,
        } => {
            let start_json =
                serde_json::json!({"session_id": session, "tty": tty, "shell": shell, "pid": pid})
                    .to_string();
            crate::debug_io::daemon_log("daemon.log", "session_start", &start_json);
            let request = crate::daemon::DaemonRequest::CreateSession {
                session,
                tty,
                shell,
                pid: pid as i64,
            };
            if let Err(error) = send_to_global_or_fallback(&request) {
                tracing::debug!("daemon unavailable for session start: {error}");
            }
        }
        SessionAction::End { session } => {
            let end_json = serde_json::json!({"session_id": session}).to_string();
            crate::debug_io::daemon_log("daemon.log", "session_end", &end_json);
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::EndSession {
                session: session.clone(),
            });
            crate::shell_hooks::cleanup_pending_files(&session);
        }
        SessionAction::Label { label, session } => {
            let session_id = session.unwrap_or_else(|| {
                std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
            });
            let request = crate::daemon::DaemonRequest::SetSessionLabel {
                session: session_id,
                label: label.clone(),
                caller: crate::daemon::current_caller_context(),
            };
            match global_daemon_payload::<crate::daemon::SessionLabelUpdatePayload>(&request) {
                Ok(response) if response.updated => eprintln!("nsh: session labeled \"{label}\""),
                _ => eprintln!("nsh: session not found"),
            }
        }
        SessionAction::LastCwd { tty } => {
            let config = crate::config::Config::load().unwrap_or_default();
            if !config.context.restore_last_cwd_per_tty {
                return Ok(());
            }
            if let Some(cwd) = crate::fast_cwd::get_tty_cwd(&tty) {
                println!("{cwd}");
                return Ok(());
            }
            let request = crate::daemon::DaemonRequest::LatestCwdForTty { tty };
            if let Ok(Some(response)) =
                optional_global_daemon_payload::<crate::daemon::LatestCwdPayload>(&request)
                && let Some(cwd) = response.cwd
            {
                println!("{cwd}");
            }
        }
        SessionAction::SuppressedExitCodes => {
            let config = crate::config::Config::load().unwrap_or_default();
            let codes = config.hints.normalized_suppressed_exit_codes();
            if !codes.is_empty() {
                println!(
                    "{}",
                    codes
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ")
                );
            }
        }
        SessionAction::IgnoreExitCode { code } => {
            let updated = crate::config::add_suppressed_exit_code(code)?;
            let codes = updated
                .codes
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            if updated.added {
                eprintln!("nsh: suppressed exit code {code} for failure hints [{codes}]");
            } else {
                eprintln!("nsh: exit code {code} is already suppressed [{codes}]");
            }
        }
    }
    Ok(())
}

pub(super) fn handle_reset_command() -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    match send_to_global_or_fallback(&crate::daemon::DaemonRequest::ClearConversations {
        session: session_id,
        caller: crate::daemon::current_caller_context(),
    }) {
        Ok(crate::daemon::DaemonResponse::Error { message }) => {
            eprintln!("nsh: failed to clear conversations: {message}");
        }
        _ => {
            // Ok response or daemon not available (no-op) — both are fine
            eprintln!("nsh: conversation context cleared");
        }
    }
    Ok(())
}

pub(super) fn handle_heartbeat_command(session: String) {
    let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::Heartbeat { session });
}

pub(super) fn handle_redact_next_command() -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    let flag_path = crate::config::Config::nsh_dir().join(format!("redact_next_{session_id}"));
    std::fs::write(&flag_path, "")?;
    eprintln!("nsh: next command output will not be captured");
    Ok(())
}
