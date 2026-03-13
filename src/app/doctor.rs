use crate::cli::DoctorAction;

pub(super) fn handle_doctor_command(
    action: Option<DoctorAction>,
    no_prune: bool,
    no_vacuum: bool,
    prune_days: Option<u32>,
) -> anyhow::Result<()> {
    if let Some(DoctorAction::Capture) = action {
        let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".to_string());
        let daemon_socket = crate::daemon::daemon_socket_path(&session_id);
        let daemon_running = crate::daemon_client::is_daemon_running(&session_id);
        let wrapped = std::env::var("NSH_PTY_ACTIVE").is_ok();
        let output_capture_active = daemon_running && wrapped;

        if output_capture_active {
            eprintln!("nsh doctor capture: OK — command output capture is active");
        } else {
            eprintln!(
                "nsh doctor capture: NOT ACTIVE — command rows may be recorded without output"
            );
        }
        eprintln!("  session: {session_id}");
        eprintln!(
            "  daemon socket: {} ({})",
            daemon_socket.display(),
            if daemon_socket.exists() {
                "exists"
            } else {
                "missing"
            }
        );
        eprintln!(
            "  daemon reachable: {}",
            if daemon_running { "yes" } else { "no" }
        );
        eprintln!("  wrapped shell: {}", if wrapped { "yes" } else { "no" });
        if !wrapped {
            eprintln!("  hint: start your shell with `nsh wrap` (or keep it in your rc file)");
        }
        if wrapped && !daemon_running {
            eprintln!("  hint: restart the wrapped shell to recreate daemon socket");
        }
        return Ok(());
    }

    let config = crate::config::Config::load().unwrap_or_default();
    let global_running = crate::daemon_client::is_global_daemon_running();
    eprintln!(
        "  Global daemon: {}",
        if global_running {
            "running"
        } else {
            "not running"
        }
    );
    eprint!("  Shell hooks version... ");
    match std::env::var("NSH_HOOK_HASH") {
        Ok(value) if value == env!("NSH_HOOK_HASH") => eprintln!("OK"),
        Ok(value) => eprintln!(
            "OUTDATED (hooks={}, binary={})",
            &value[..8],
            &env!("NSH_HOOK_HASH")[..8]
        ),
        Err(_) => eprintln!("unknown (not in an nsh-wrapped shell)"),
    }
    let retention = prune_days.unwrap_or(config.context.retention_days);
    let request = crate::daemon::DaemonRequest::RunDoctor {
        retention_days: retention,
        no_prune,
        no_vacuum,
    };
    match super::daemon_runtime::send_to_global_or_fallback(&request) {
        Ok(crate::daemon::DaemonResponse::Error { message }) => anyhow::bail!(message),
        Ok(_) => {}
        Err(error) => {
            eprintln!("  Database maintenance skipped (daemon unavailable: {error})");
        }
    }
    cleanup_staged_updates();
    Ok(())
}

fn cleanup_staged_updates() {
    let nsh_dir = crate::config::Config::nsh_dir();
    let updates_dir = nsh_dir.join("updates");
    if !updates_dir.exists() {
        return;
    }
    let pending_path = nsh_dir.join("update_pending");
    let pending_staged: Option<std::path::PathBuf> = std::fs::read_to_string(&pending_path)
        .ok()
        .and_then(|content| serde_json::from_str::<serde_json::Value>(&content).ok())
        .and_then(|value| value["staged_path"].as_str().map(std::path::PathBuf::from))
        .and_then(|path| std::fs::canonicalize(&path).ok());

    if let Ok(entries) = std::fs::read_dir(&updates_dir) {
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let dominated = match &pending_staged {
                    Some(pending) => std::fs::canonicalize(&path).ok().as_ref() != Some(pending),
                    None => true,
                };
                if dominated {
                    let _ = std::fs::remove_file(&path);
                    removed += 1;
                }
            }
        }
        if removed > 0 {
            eprintln!("  Stale staged updates... {removed} removed");
        } else {
            eprintln!("  Stale staged updates... none");
        }
    }
}
