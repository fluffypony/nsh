pub(super) fn handle_cli_proxy_action(action: &str) -> anyhow::Result<()> {
    let request = match action {
        "ensure" => crate::daemon::DaemonRequest::EnsureCLIProxyApi,
        "status" => crate::daemon::DaemonRequest::CLIProxyApiStatus,
        "restart" => crate::daemon::DaemonRequest::CLIProxyApiRestart,
        "check-updates" => crate::daemon::DaemonRequest::CheckForUpdates,
        _ => {
            eprintln!("Usage: nsh cliproxy <ensure|status|restart|check-updates>");
            return Ok(());
        }
    };
    super::daemon_runtime::bootstrap_global_daemon()?;
    let response = super::daemon_runtime::send_to_global_or_fallback(&request)?;
    match response {
        crate::daemon::DaemonResponse::Ok { data: Some(data) } => println!("{data}"),
        crate::daemon::DaemonResponse::Ok { data: None } => println!("ok"),
        crate::daemon::DaemonResponse::Error { message } => eprintln!("nsh: {message}"),
    }
    Ok(())
}

pub(super) fn handle_init_command(shell: String, hash: bool) -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "(none)".into());
    let init_json =
        serde_json::json!({"shell": shell, "hash": hash, "session_id": session_id}).to_string();
    crate::debug_io::daemon_log("daemon.log", "init_start", &init_json);
    if hash {
        println!("{}", env!("NSH_HOOK_HASH"));
        return Ok(());
    }

    let nsh_dir = crate::config::Config::nsh_dir();
    let _ = std::fs::remove_file(nsh_dir.join("update_notice"));
    let mut script = crate::init::generate_init_script(&shell);
    if let Ok(config) = crate::config::Config::load()
        && !config.shell_hooks.iterm2_cwd_reporting
    {
        let inject = match shell.as_str() {
            "zsh" | "bash" => "export NSH_NO_ITERM2_CWD=1\n",
            "fish" => "set -gx NSH_NO_ITERM2_CWD 1\n",
            _ => "",
        };
        if !inject.is_empty() {
            script = format!("{inject}{script}");
        }
    }
    print!("{script}");
    Ok(())
}

pub(super) fn handle_completions_command(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut command = crate::cli::Cli::command();
    generate(shell, &mut command, "nsh", &mut std::io::stdout());
}
