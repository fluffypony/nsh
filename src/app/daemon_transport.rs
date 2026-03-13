use crate::cli::{DaemonReadAction, DaemonSendAction};

pub(super) fn handle_daemon_send_command(action: DaemonSendAction) -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = action;
        eprintln!("Daemon is not supported on this platform.");
        return Ok(());
    }

    let session_id = match &action {
        DaemonSendAction::Record { session, .. } => session.clone(),
        DaemonSendAction::Heartbeat { session } => session.clone(),
        DaemonSendAction::CaptureMark { session } => session.clone(),
        DaemonSendAction::Status
        | DaemonSendAction::CliProxyEnsure
        | DaemonSendAction::CliProxyStatus
        | DaemonSendAction::CliProxyRestart
        | DaemonSendAction::CheckUpdates => {
            std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
        }
    };

    if let DaemonSendAction::Record { tty, cwd, .. } = &action {
        let _ = crate::fast_cwd::update_tty_cwd(tty, cwd);
    }

    if matches!(
        &action,
        DaemonSendAction::Record { .. } | DaemonSendAction::Heartbeat { .. }
    ) {
        super::daemon_runtime::maybe_stage_hook_reload_notice(Some(&session_id));
    }

    let request = match &action {
        DaemonSendAction::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            duration_ms,
            tty,
            pid,
            shell,
        } => crate::daemon::DaemonRequest::Record {
            session: session.clone(),
            command: command.clone(),
            cwd: cwd.clone(),
            exit_code: *exit_code,
            started_at: started_at.clone(),
            tty: tty.clone(),
            pid: *pid,
            shell: shell.clone(),
            duration_ms: *duration_ms,
            output: None,
        },
        DaemonSendAction::Heartbeat { session } => crate::daemon::DaemonRequest::Heartbeat {
            session: session.clone(),
        },
        DaemonSendAction::CaptureMark { session } => crate::daemon::DaemonRequest::CaptureMark {
            session: session.clone(),
        },
        DaemonSendAction::Status => crate::daemon::DaemonRequest::Status,
        DaemonSendAction::CliProxyEnsure => crate::daemon::DaemonRequest::EnsureCLIProxyApi,
        DaemonSendAction::CliProxyStatus => crate::daemon::DaemonRequest::CLIProxyApiStatus,
        DaemonSendAction::CliProxyRestart => crate::daemon::DaemonRequest::CLIProxyApiRestart,
        DaemonSendAction::CheckUpdates => crate::daemon::DaemonRequest::CheckForUpdates,
    };

    match crate::daemon_client::try_send_request(&session_id, &request) {
        Some(response) => {
            if let crate::daemon::DaemonResponse::Error { message } = response {
                eprintln!("nsh: daemon error: {message}");
            }
        }
        None => match action {
            DaemonSendAction::Record {
                session,
                command,
                cwd,
                exit_code,
                started_at,
                duration_ms,
                tty,
                pid,
                shell,
            } => {
                let global_request = crate::daemon::DaemonRequest::Record {
                    session,
                    command,
                    cwd,
                    exit_code,
                    started_at,
                    tty,
                    pid,
                    shell,
                    duration_ms,
                    output: None,
                };
                let _ = super::daemon_runtime::send_to_global_or_fallback(&global_request);
            }
            DaemonSendAction::Heartbeat { session } => {
                let _ = super::daemon_runtime::send_to_global_or_fallback(
                    &crate::daemon::DaemonRequest::Heartbeat { session },
                );
            }
            DaemonSendAction::CaptureMark { .. } => {}
            DaemonSendAction::Status
            | DaemonSendAction::CliProxyEnsure
            | DaemonSendAction::CliProxyStatus
            | DaemonSendAction::CliProxyRestart
            | DaemonSendAction::CheckUpdates => {
                eprintln!("nsh: daemon not running");
            }
        },
    }
    Ok(())
}

pub(super) fn handle_daemon_read_command(action: DaemonReadAction) -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = action;
        eprintln!("Daemon is not supported on this platform.");
        return Ok(());
    }

    let session_id = match &action {
        DaemonReadAction::CaptureRead { session, .. } => session.clone(),
        DaemonReadAction::Scrollback { .. } => {
            std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
        }
    };

    let request = match &action {
        DaemonReadAction::CaptureRead { session, max_lines } => {
            crate::daemon::DaemonRequest::CaptureRead {
                session: session.clone(),
                max_lines: *max_lines,
            }
        }
        DaemonReadAction::Scrollback { max_lines } => crate::daemon::DaemonRequest::Scrollback {
            max_lines: *max_lines,
        },
    };

    match &action {
        DaemonReadAction::CaptureRead { .. } => {
            if let Some(response) = crate::daemon_client::try_send_request(&session_id, &request) {
                match response.into_payload::<crate::daemon::CaptureOutputPayload>() {
                    Ok(payload) => print!("{}", payload.output),
                    Err(error) => eprintln!("nsh: daemon error: {error}"),
                }
            }
        }
        DaemonReadAction::Scrollback { .. } => {
            if let Some(response) = crate::daemon_client::try_send_request(&session_id, &request) {
                match response.into_payload::<crate::daemon::ScrollbackPayload>() {
                    Ok(payload) => print!("{}", payload.scrollback),
                    Err(error) => eprintln!("nsh: daemon error: {error}"),
                }
            }
        }
    }
    Ok(())
}
