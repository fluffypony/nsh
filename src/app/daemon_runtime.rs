use serde::de::DeserializeOwned;

pub(super) fn bootstrap_global_daemon() -> anyhow::Result<()> {
    if !crate::daemon_client::is_global_daemon_running() {
        crate::daemon_client::ensure_global_daemon_running()?;
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    if !crate::daemon_client::is_global_daemon_running() {
        anyhow::bail!("nsh is still starting up");
    }
    crate::daemon_client::ensure_daemon_version_matches()?;
    Ok(())
}

pub(super) fn ensure_daemon_ready(json: bool) -> anyhow::Result<bool> {
    if bootstrap_global_daemon().is_ok() {
        return Ok(true);
    }
    if json {
        eprintln!(
            "{}",
            serde_json::json!({"type": "error", "message": "nsh is still starting up"})
        );
    } else {
        eprintln!("\x1b[2mnsh is still starting up, try again in a moment.\x1b[0m");
    }
    Ok(false)
}

pub(super) fn send_to_global_or_fallback(
    request: &crate::daemon::DaemonRequest,
) -> anyhow::Result<crate::daemon::DaemonResponse> {
    #[cfg(unix)]
    {
        crate::daemon_client::send_to_global_with_retry(request.clone())
    }
    #[cfg(not(unix))]
    {
        crate::daemon_client::send_to_global(request)
    }
}

pub(super) fn global_daemon_payload<T: DeserializeOwned>(
    request: &crate::daemon::DaemonRequest,
) -> anyhow::Result<T> {
    bootstrap_global_daemon()?;
    send_to_global_or_fallback(request)?.into_payload()
}

pub(super) fn optional_global_daemon_payload<T: DeserializeOwned>(
    request: &crate::daemon::DaemonRequest,
) -> anyhow::Result<Option<T>> {
    bootstrap_global_daemon()?;
    send_to_global_or_fallback(request)?.into_optional_payload()
}

pub(super) fn signal_daemon_restart() {
    #[cfg(unix)]
    {
        if crate::daemon_client::signal_daemon_restart() {
            return;
        }
    }
    let marker = crate::config::Config::nsh_dir().join("nshd_restart_pending");
    let _ = std::fs::write(&marker, "");
}

pub(super) fn maybe_stage_hook_reload_notice(session: Option<&str>) {
    if let Ok(env_hash) = std::env::var("NSH_HOOK_HASH")
        && !env_hash.is_empty()
        && env_hash != env!("NSH_HOOK_HASH")
    {
        let dir = crate::config::Config::nsh_dir();
        let notice = dir.join("update_notice");
        let tmp = dir.join("update_notice.tmp");
        let _ = std::fs::write(&tmp, "hooks_updated");
        let _ = std::fs::rename(&tmp, &notice);
        if let Some(session) = session {
            let message_path = dir.join(format!("nsh_msg_{session}"));
            let _ = std::fs::write(&message_path, "hooks_updated\n");
        }
    }
}
