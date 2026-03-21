use super::daemon_runtime::{
    global_daemon_payload, maybe_stage_hook_reload_notice, optional_global_daemon_payload,
};

pub(super) fn handle_status_command() -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "(not set)".into());
    let config = crate::config::Config::load().unwrap_or_default();
    let build_version = env!("NSH_BUILD_VERSION");
    let pty_active = std::env::var("NSH_TTY").is_ok();
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "unknown".into());
    let db_path = crate::config::Config::nsh_dir().join("nsh.db");
    let db_size = std::fs::metadata(&db_path)
        .map(|metadata| metadata.len())
        .unwrap_or(0);
    let db_size_str = if db_size > 1_048_576 {
        format!("{:.1} MB", db_size as f64 / 1_048_576.0)
    } else {
        format!("{:.1} KB", db_size as f64 / 1024.0)
    };

    let session_label = if session_id != "(not set)" {
        optional_global_daemon_payload::<crate::daemon::SessionLabelPayload>(
            &crate::daemon::DaemonRequest::GetSessionLabel {
                session: session_id.clone(),
                caller: crate::daemon::current_caller_context(),
            },
        )
        .ok()
        .flatten()
        .and_then(|response| response.label)
    } else {
        None
    };

    let global_daemon_status = if crate::daemon_client::is_global_daemon_running() {
        "running"
    } else {
        "not running"
    };

    eprintln!("nsh status:");
    eprintln!("  Core:       {build_version}");
    if let Ok(data) = crate::daemon_client::send_to_global(&crate::daemon::DaemonRequest::Status)
        .and_then(|response| response.into_payload::<crate::daemon::DaemonStatusPayload>())
    {
        if data.build_version.is_empty() {
            eprintln!("  Daemon:     v{}", data.version);
        } else {
            eprintln!(
                "  Daemon:     v{} (build: {})",
                data.version, data.build_version
            );
        }
    }
    eprintln!("  Session:    {session_id}");
    if let Some(label) = session_label {
        eprintln!("  Label:      {label}");
    }
    eprintln!("  Shell:      {shell}");
    eprintln!("  PTY active: {}", if pty_active { "yes" } else { "no" });
    eprintln!("  Global daemon: {global_daemon_status}");
    if crate::daemon_client::is_global_daemon_running()
        && let Ok(data) = global_daemon_payload::<crate::daemon::CLIProxyApiStatusPayload>(
            &crate::daemon::DaemonRequest::CLIProxyApiStatus,
        )
    {
        let version = data.version.as_deref().unwrap_or("");
        let last_check = data.last_update_check.as_deref().unwrap_or("");
        let last_status = data.last_update_status.as_deref().unwrap_or("");
        let last_check_pretty = if last_check.is_empty() {
            String::new()
        } else if let Ok(timestamp) = chrono::DateTime::parse_from_rfc3339(last_check) {
            let now = chrono::Utc::now();
            let ago = now.signed_duration_since(timestamp.with_timezone(&chrono::Utc));
            if ago.num_seconds() < 60 {
                format!("{}s ago", ago.num_seconds())
            } else if ago.num_minutes() < 60 {
                format!("{}m ago", ago.num_minutes())
            } else if ago.num_hours() < 48 {
                format!("{}h ago", ago.num_hours())
            } else {
                format!("{}d ago", ago.num_days())
            }
        } else {
            last_check.to_string()
        };
        if data.running {
            if let Some(port) = data.port {
                eprintln!("  Sidecar:    running on :{port} ({version})");
            } else {
                eprintln!("  Sidecar:    running ({version})");
            }
        } else {
            eprintln!("  Sidecar:    not running");
        }
        if !last_check.is_empty() || !last_status.is_empty() {
            if last_check_pretty.is_empty() {
                eprintln!("  Updates:    last_check={last_check} status={last_status}");
            } else {
                eprintln!(
                    "  Updates:    last_check={last_check} ({last_check_pretty}) status={last_status}"
                );
            }
        }
    }
    eprintln!("  Provider:   {}", config.provider.default);
    eprintln!("  Model:      {}", config.provider.model);
    eprintln!("  DB path:    {}", db_path.display());
    eprintln!("  DB size:    {db_size_str}");

    // Remote access status
    #[cfg(feature = "remote")]
    {
        if config.remote.enabled {
            #[cfg(unix)]
            if let Ok(crate::daemon::DaemonResponse::Ok {
                data: Some(d),
            }) = crate::daemon_client::send_to_global(
                &crate::daemon::DaemonRequest::RemoteStatus,
            ) {
                let node_id = d["node_id"].as_str().unwrap_or("unknown");
                let short_id = &node_id[..16.min(node_id.len())];
                let peers = d["connected_peers"].as_u64().unwrap_or(0);
                eprintln!("  Remote:     enabled (EndpointId: {short_id}...)");
                eprintln!("  Peers:      {peers} connected");
            } else {
                eprintln!("  Remote:     enabled (daemon not running)");
            }
        } else {
            eprintln!("  Remote:     disabled");
        }
    }
    let hooks_outdated = std::env::var("NSH_HOOK_HASH")
        .map(|hash| hash != env!("NSH_HOOK_HASH"))
        .unwrap_or(false);
    if hooks_outdated {
        let notice = crate::config::Config::nsh_dir().join("update_notice");
        if !notice.exists() {
            let _ = std::fs::write(&notice, "hooks_updated");
        }
    }
    eprintln!(
        "  Hooks:      {}",
        if hooks_outdated {
            "outdated (auto-refresh pending \u{2014} will reload on next prompt)"
        } else {
            "current"
        }
    );
    maybe_stage_hook_reload_notice(std::env::var("NSH_SESSION_ID").ok().as_deref());
    Ok(())
}
