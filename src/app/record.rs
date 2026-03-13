pub(super) struct RecordCommandInput {
    pub(super) session: String,
    pub(super) command: String,
    pub(super) cwd: String,
    pub(super) exit_code: i32,
    pub(super) started_at: String,
    pub(super) duration_ms: Option<i64>,
    pub(super) tty: String,
    pub(super) pid: i32,
    pub(super) shell: String,
}

pub(super) fn handle_record_command(input: RecordCommandInput) -> anyhow::Result<()> {
    let RecordCommandInput {
        session,
        command,
        cwd,
        exit_code,
        started_at,
        duration_ms,
        tty,
        pid,
        shell,
    } = input;
    let session_for_checks = session.clone();
    super::daemon_runtime::maybe_stage_hook_reload_notice(Some(&session));
    let request = crate::daemon::DaemonRequest::Record {
        session: session.clone(),
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
    if let crate::daemon::DaemonRequest::Record { tty, cwd, .. } = &request {
        let _ = crate::fast_cwd::update_tty_cwd(tty, cwd);
    }
    match super::daemon_runtime::send_to_global_or_fallback(&request) {
        Ok(crate::daemon::DaemonResponse::Error { message }) => {
            eprintln!("nsh: record error: {message}");
        }
        Err(error) => {
            tracing::debug!("daemon unavailable for record: {error}");
        }
        _ => {}
    }
    super::daemon_runtime::check_daemon_versions(&session_for_checks);
    Ok(())
}
