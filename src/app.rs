use clap::Parser;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

use crate::cli::{
    Cli, Commands, ConfigAction, DaemonReadAction, DaemonSendAction, DoctorAction, HistoryAction,
    MemoryAction, ProviderAction, SessionAction,
};
use crate::daemon_db::DbAccess;

fn ensure_daemon_ready(json: bool) -> anyhow::Result<bool> {
    if crate::daemon_client::is_global_daemon_running() {
        let _ = crate::daemon_client::ensure_daemon_version_matches();
        return Ok(true);
    }
    let _ = crate::daemon_client::ensure_global_daemon_running();
    std::thread::sleep(std::time::Duration::from_millis(500));
    if crate::daemon_client::is_global_daemon_running() {
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

fn send_to_global_or_fallback(
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

fn global_daemon_payload<T: DeserializeOwned>(
    request: &crate::daemon::DaemonRequest,
) -> anyhow::Result<T> {
    send_to_global_or_fallback(request)?.into_payload()
}

fn optional_global_daemon_payload<T: DeserializeOwned>(
    request: &crate::daemon::DaemonRequest,
) -> anyhow::Result<Option<T>> {
    send_to_global_or_fallback(request)?.into_optional_payload()
}

/// Send SIGHUP to the running daemon for immediate graceful restart.
/// Falls back to writing a marker file (for non-Unix).
fn signal_daemon_restart() {
    #[cfg(unix)]
    {
        if crate::daemon_client::signal_daemon_restart() {
            return;
        }
    }
    let marker = crate::config::Config::nsh_dir().join("nshd_restart_pending");
    let _ = std::fs::write(&marker, "");
}

fn handle_cli_proxy_action(action: &str) -> anyhow::Result<()> {
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
    let response = send_to_global_or_fallback(&request)?;
    match response {
        crate::daemon::DaemonResponse::Ok { data: Some(data) } => println!("{data}"),
        crate::daemon::DaemonResponse::Ok { data: None } => println!("ok"),
        crate::daemon::DaemonResponse::Error { message } => eprintln!("nsh: {message}"),
    }
    Ok(())
}

pub fn main_inner() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    crate::live_update::snapshot_binary_meta();
    crate::security::secure_nsh_directory();

    {
        let nsh_dir = crate::config::Config::nsh_dir();
        let fingerprint_path = nsh_dir.join("build.fingerprint");
        let current_fingerprint = env!("NSH_BUILD_FINGERPRINT");
        let stored_fingerprint = std::fs::read_to_string(&fingerprint_path).unwrap_or_default();
        if stored_fingerprint.trim() != current_fingerprint {
            let _ = std::fs::create_dir_all(&nsh_dir);
            let _ = std::fs::write(&fingerprint_path, current_fingerprint);
            if crate::daemon_client::is_global_daemon_running() {
                crate::daemon_client::signal_daemon_restart();
            }
            let notice = nsh_dir.join("update_notice");
            let _ = std::fs::write(&notice, "hooks_updated");
        }
    }

    let cli = Cli::parse();

    if let Commands::Nshd = &cli.command {
        #[cfg(unix)]
        {
            return crate::global_daemon::run_global_daemon();
        }
        #[cfg(not(unix))]
        {
            eprintln!("nsh: global daemon is not supported on this platform");
            return Ok(());
        }
    }

    if let Commands::CliProxy { action } = &cli.command {
        return handle_cli_proxy_action(action);
    }

    apply_pending_update(false);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    match cli.command {
        Commands::Nshd => unreachable!(),
        Commands::CliProxy { .. } => unreachable!(),
        Commands::Init { shell, hash } => handle_init_command(shell, hash)?,
        Commands::Query {
            words,
            think,
            private,
            json,
        } => handle_query_command(words, think, private, json).await?,
        Commands::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            duration_ms,
            tty,
            pid,
            shell,
        } => handle_record_command(RecordCommandInput {
            session,
            command,
            cwd,
            exit_code,
            started_at,
            duration_ms,
            tty,
            pid,
            shell,
        })?,
        Commands::Session { action } => handle_session_command(action)?,
        Commands::History { action } => handle_history_command(action)?,
        Commands::Reset => handle_reset_command()?,
        Commands::Config { action } => handle_config_command(action)?,
        Commands::Cost { period } => handle_cost_command(period)?,
        Commands::Provider { action } => handle_provider_command(action).await?,
        Commands::Chat => handle_chat_command().await?,
        Commands::Export { format, session } => handle_export_command(format, session)?,
        Commands::Status => handle_status_command()?,
        Commands::Completions { shell } => handle_completions_command(shell),
        Commands::Doctor {
            action,
            no_prune,
            no_vacuum,
            prune_days,
        } => handle_doctor_command(action, no_prune, no_vacuum, prune_days)?,
        Commands::Heartbeat { session } => handle_heartbeat_command(session),
        Commands::RedactNext => handle_redact_next_command()?,
        Commands::Restart => handle_restart_command()?,
        Commands::Autoconfigure { interactive } => handle_autoconfigure_command(interactive)?,
        Commands::Update => handle_update_command().await?,
        Commands::Memory { action } => handle_memory_command(action)?,
        Commands::DaemonSend { action } => handle_daemon_send_command(action)?,
        Commands::DaemonRead { action } => handle_daemon_read_command(action)?,
        Commands::HistoryImportRun => handle_history_import_run_command(),
    }

    Ok(())
}

fn handle_init_command(shell: String, hash: bool) -> anyhow::Result<()> {
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
        && !config.shell_hooks.iterm2_cwd_reporting {
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

async fn handle_query_command(
    words: Vec<String>,
    think: bool,
    private: bool,
    json: bool,
) -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "(none)".into());
    let tty = std::env::var("NSH_TTY").unwrap_or_else(|_| "(none)".into());
    let query_json =
        serde_json::json!({"session_id": session_id, "tty": tty, "think": think, "private": private, "json": json}).to_string();
    crate::debug_io::daemon_log("daemon.log", "query_start", &query_json);
    if words.is_empty() {
        eprintln!("Usage: ? <your question>");
        std::process::exit(1);
    }

    if !ensure_daemon_ready(json)? {
        return Ok(());
    }

    if crate::history_import::import_in_progress() {
        eprintln!("\x1b[2m⏳ nsh is still indexing history; results may be incomplete.\x1b[0m");
    }

    let mut query_text = words.join(" ");
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        use std::io::Read;

        let max_pipe_bytes: u64 = 33000;
        let mut piped = String::new();
        std::io::stdin()
            .take(max_pipe_bytes)
            .read_to_string(&mut piped)?;
        if !piped.is_empty() {
            let truncated = crate::util::truncate(&piped, 32000);
            query_text = format!("<piped_input>\n{truncated}\n</piped_input>\n\n{query_text}");
        }
    }

    let (query_text, force_autorun) = if query_text.ends_with("!!") {
        (query_text[..query_text.len() - 2].trim().to_string(), true)
    } else {
        (query_text, false)
    };
    let config = crate::config::Config::load()?;
    let force_autorun = force_autorun || config.execution.mode == "autorun";
    let db = crate::daemon_db::DaemonDb::new();
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    if private {
        if json {
            eprintln!(
                "{}",
                serde_json::json!({"type": "private_mode", "enabled": true})
            );
        } else {
            eprintln!("\x1b[2m🔒 private mode\x1b[0m");
        }
    }
    let result = crate::query::handle_query(
        &query_text,
        &config,
        &db,
        &session_id,
        crate::query::QueryOptions {
            think,
            private,
            force_autorun,
            json_output: json,
        },
    )
    .await;
    if let Err(ref error) = result
        && error.to_string().contains("interrupted") {
            eprint!("\x1b[?25h\x1b[0m");
            std::io::Write::flush(&mut std::io::stderr()).ok();
            std::process::exit(130);
        }
    result?;
    Ok(())
}

struct RecordCommandInput {
    session: String,
    command: String,
    cwd: String,
    exit_code: i32,
    started_at: String,
    duration_ms: Option<i64>,
    tty: String,
    pid: i32,
    shell: String,
}

fn handle_record_command(input: RecordCommandInput) -> anyhow::Result<()> {
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
    maybe_stage_hook_reload_notice(Some(&session));
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
    match send_to_global_or_fallback(&request) {
        Ok(crate::daemon::DaemonResponse::Error { message }) => {
            eprintln!("nsh: record error: {message}");
        }
        Err(error) => {
            tracing::debug!("daemon unavailable for record: {error}");
        }
        _ => {}
    }
    check_daemon_versions(&session_for_checks);
    Ok(())
}

fn handle_session_command(action: SessionAction) -> anyhow::Result<()> {
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

fn handle_history_command(action: HistoryAction) -> anyhow::Result<()> {
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

fn handle_reset_command() -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::ClearConversations {
        session: session_id,
    });
    eprintln!("nsh: conversation context cleared");
    Ok(())
}

fn handle_config_command(action: Option<ConfigAction>) -> anyhow::Result<()> {
    match action {
        Some(ConfigAction::Path) | None => {
            println!("{}", crate::config::Config::path().display());
        }
        Some(ConfigAction::Show { raw }) => {
            let path = crate::config::Config::path();
            if path.exists() {
                let content = std::fs::read_to_string(&path)?;
                if raw {
                    print!("{content}");
                } else {
                    match content.parse::<toml::Value>() {
                        Ok(mut value) => {
                            redact_config_keys(&mut value);
                            print!("{}", toml::to_string_pretty(&value)?);
                        }
                        Err(_) => print!("{content}"),
                    }
                }
            } else {
                eprintln!("No config file found at {}", path.display());
                eprintln!("Run with defaults or create one.");
            }
        }
        Some(ConfigAction::Edit) => {
            let editor = std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
            let path = crate::config::Config::path();
            let dir = path.parent().unwrap();
            std::fs::create_dir_all(dir)?;
            std::process::Command::new(&editor).arg(&path).status()?;
        }
    }
    Ok(())
}

fn handle_cost_command(period: String) -> anyhow::Result<()> {
    let request = crate::daemon::DaemonRequest::GetUsageStats { period };
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

async fn handle_provider_command(action: ProviderAction) -> anyhow::Result<()> {
    match action {
        ProviderAction::ListLocal => {
            let base_url = crate::config::Config::load()
                .ok()
                .and_then(|config| {
                    config
                        .provider
                        .ollama
                        .as_ref()
                        .and_then(|ollama| ollama.base_url.clone())
                })
                .unwrap_or_else(|| "http://localhost:11434".into());
            let url = format!("{}/api/tags", base_url.trim_end_matches("/v1"));
            match reqwest::get(&url).await {
                Ok(response) if response.status().is_success() => {
                    let json: serde_json::Value = response.json().await?;
                    if let Some(models) = json["models"].as_array() {
                        if models.is_empty() {
                            eprintln!("No models found. Pull one with: ollama pull <model>");
                        } else {
                            eprintln!("Available Ollama models:");
                            for model in models {
                                let name = model["name"].as_str().unwrap_or("?");
                                let size = model["size"].as_u64().unwrap_or(0);
                                let size_gb = size as f64 / 1_073_741_824.0;
                                eprintln!("  {name} ({size_gb:.1} GB)");
                            }
                        }
                    }
                }
                Ok(response) => {
                    eprintln!("Ollama API error: {}", response.status());
                }
                Err(_) => {
                    eprintln!("Could not connect to Ollama at {url}");
                    eprintln!("Is Ollama running? Start it with: ollama serve");
                }
            }
        }
    }
    Ok(())
}

fn handle_doctor_command(
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
    match send_to_global_or_fallback(&request) {
        Ok(crate::daemon::DaemonResponse::Error { message }) => anyhow::bail!(message),
        Ok(_) => {}
        Err(error) => {
            eprintln!("  Database maintenance skipped (daemon unavailable: {error})");
        }
    }
    cleanup_staged_updates();
    Ok(())
}

fn handle_heartbeat_command(session: String) {
    let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::Heartbeat { session });
}

fn handle_redact_next_command() -> anyhow::Result<()> {
    let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    let flag_path = crate::config::Config::nsh_dir().join(format!("redact_next_{session_id}"));
    std::fs::write(&flag_path, "")?;
    eprintln!("nsh: next command output will not be captured");
    Ok(())
}

fn handle_autoconfigure_command(interactive: bool) -> anyhow::Result<()> {
    crate::autoconfigure::run_autoconfigure(interactive)?;
    Ok(())
}

fn handle_restart_command() -> anyhow::Result<()> {
    eprint!("nsh: signaling daemon restart...");
    signal_daemon_restart();
    std::thread::sleep(std::time::Duration::from_millis(1000));
    crate::daemon_client::ensure_global_daemon_running()?;
    eprintln!(" done");
    Ok(())
}

async fn handle_update_command() -> anyhow::Result<()> {
    eprintln!("nsh: checking for updates...");

    let target = match current_target_triple() {
        Some(target) => target,
        None => {
            let arch = std::env::consts::ARCH;
            let os = std::env::consts::OS;
            eprintln!("nsh: unsupported platform {os}/{arch}. Build from source:");
            eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
            std::process::exit(1);
        }
    };

    let records = match resolve_update_txt().await {
        Ok(records) => records,
        Err(error) => {
            eprintln!("nsh: DNS lookup failed: {error}");
            eprintln!("  Falling back to dig...");
            match resolve_update_txt_fallback() {
                Ok(records) => records,
                Err(fallback_error) => {
                    eprintln!("nsh: DNS fallback also failed: {fallback_error}");
                    std::process::exit(1);
                }
            }
        }
    };

    let (version, expected_sha) = match find_latest_for_target(&records, target) {
        Some(found) => found,
        None => {
            eprintln!("nsh: no release found for {target} in DNS records");
            std::process::exit(1);
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    if crate::util::compare_versions(&version, current_version) != std::cmp::Ordering::Greater {
        eprintln!("nsh: already up to date (v{current_version})");
        return Ok(());
    }

    eprintln!("nsh: v{version} available (current: v{current_version})");

    let url = format!(
        "https://github.com/fluffypony/nsh/releases/download/v{version}/nsh-{target}.tar.gz"
    );
    eprintln!("nsh: downloading {target}...");
    let client = reqwest::Client::new();
    let download_response = client.get(&url).send().await?;
    if !download_response.status().is_success() {
        eprintln!("nsh: no pre-built binary available. Build from source:");
        eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
        std::process::exit(1);
    }

    let bytes = download_response.bytes().await?;

    let staging_dir = crate::config::Config::nsh_dir().join("updates");
    std::fs::create_dir_all(&staging_dir)?;
    let staged_path = staging_dir.join(format!("nsh-{version}-{target}"));

    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.file_name().map(|name| name == "nsh").unwrap_or(false) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&staged_path)?;
            std::io::copy(&mut entry, &mut file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o755))?;
            }
            found = true;
            break;
        }
    }

    if !found {
        let _ = std::fs::remove_file(&staged_path);
        eprintln!("nsh: binary not found in archive");
        std::process::exit(1);
    }

    let actual_sha = sha256_file(&staged_path)?;
    if actual_sha != expected_sha {
        let _ = std::fs::remove_file(&staged_path);
        eprintln!("nsh: SHA256 verification failed!");
        eprintln!("  Expected: {expected_sha}");
        eprintln!("  Got:      {actual_sha}");
        std::process::exit(1);
    }
    eprintln!("nsh: SHA256 verified (DNS ✓)");

    let current_exe = std::env::current_exe()?;
    let pending_path = crate::config::Config::nsh_dir().join("update_pending");
    let pending_info = serde_json::json!({
        "version": version,
        "staged_path": staged_path.to_string_lossy(),
        "target_binary": current_exe.to_string_lossy(),
        "sha256": expected_sha,
        "downloaded_at": chrono::Utc::now().to_rfc3339(),
    });
    atomic_write(
        &pending_path,
        serde_json::to_string_pretty(&pending_info)?.as_bytes(),
    )?;

    apply_pending_update(false);
    signal_daemon_restart();
    eprintln!("nsh: update applied, daemon will restart gracefully");
    Ok(())
}

fn handle_memory_command(action: MemoryAction) -> anyhow::Result<()> {
    if !ensure_daemon_ready(false)? {
        return Ok(());
    }
    match action {
        MemoryAction::Search {
            query,
            r#type,
            limit,
        } => {
            let request = crate::daemon::DaemonRequest::MemorySearch {
                query,
                memory_type: match r#type {
                    Some(memory_type) => {
                        Some(crate::memory::types::MemoryType::parse(&memory_type)?)
                    }
                    None => None,
                },
                limit,
            };
            match send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                crate::daemon::DaemonResponse::Ok { data: None } => {
                    println!("No results");
                }
                crate::daemon::DaemonResponse::Error { message } => {
                    eprintln!("error: {message}");
                }
            }
        }
        MemoryAction::Stats => {
            let request = crate::daemon::DaemonRequest::MemoryStats;
            match send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                response => eprintln!("{response:?}"),
            }
        }
        MemoryAction::Core => {
            let request = crate::daemon::DaemonRequest::MemoryGetCore;
            match send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                response => eprintln!("{response:?}"),
            }
        }
        MemoryAction::Maintain => {
            eprintln!("Running memory decay...");
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryRunDecay);
            eprintln!("Running memory reflection...");
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryRunReflection);
            eprintln!("Memory maintenance complete.");
        }
        MemoryAction::Bootstrap => {
            eprintln!("Running memory bootstrap scan...");
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryBootstrapScan);
            eprintln!("Bootstrap scan complete.");
        }
        MemoryAction::Clear { r#type } => {
            if let Some(ref memory_type) = r#type {
                let parsed_type = match crate::memory::types::MemoryType::parse(memory_type) {
                    Ok(memory_type) => memory_type,
                    Err(_) => {
                        eprintln!(
                            "Unknown memory type '{}'. Valid types: episodic, semantic, procedural, resource, knowledge, core",
                            memory_type,
                        );
                        return Ok(());
                    }
                };
                let _ =
                    send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryClearByType {
                        memory_type: parsed_type,
                        confirmed: true,
                        caller: crate::daemon::current_caller_context(),
                    });
                eprintln!("{memory_type} memories cleared.");
            } else {
                let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryClearAll {
                    confirmed: true,
                    caller: crate::daemon::current_caller_context(),
                });
                eprintln!("All memories cleared.");
            }
        }
        MemoryAction::Decay => {
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryRunDecay);
            eprintln!("Memory decay complete.");
        }
        MemoryAction::Reflect => {
            let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::MemoryRunReflection);
            eprintln!("Memory reflection complete.");
        }
        MemoryAction::Export { format: _ } => {
            let request = crate::daemon::DaemonRequest::MemoryExportAll;
            match send_to_global_or_fallback(&request)? {
                crate::daemon::DaemonResponse::Ok { data: Some(data) } => {
                    println!("{}", serde_json::to_string_pretty(&data)?);
                }
                response => eprintln!("{response:?}"),
            }
        }
        MemoryAction::Telemetry => {
            let request = crate::daemon::DaemonRequest::MemoryStats;
            match global_daemon_payload::<crate::daemon::MemoryTelemetryPayload>(&request) {
                Ok(telemetry) => println!("{}", serde_json::to_string_pretty(&telemetry)?),
                Err(error) => eprintln!("error: {error}"),
            }
        }
    }
    Ok(())
}

fn handle_daemon_send_command(action: DaemonSendAction) -> anyhow::Result<()> {
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
        maybe_stage_hook_reload_notice(Some(&session_id));
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
                let _ = send_to_global_or_fallback(&global_request);
            }
            DaemonSendAction::Heartbeat { session } => {
                let _ = send_to_global_or_fallback(&crate::daemon::DaemonRequest::Heartbeat {
                    session,
                });
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
    check_daemon_versions(&session_id);
    Ok(())
}

fn handle_daemon_read_command(action: DaemonReadAction) -> anyhow::Result<()> {
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

async fn handle_chat_command() -> anyhow::Result<()> {
    use std::io::Write;

    if !ensure_daemon_ready(false)? {
        return Ok(());
    }
    let config = crate::config::Config::load()?;
    crate::streaming::configure_display(&config.display);
    let db = crate::daemon_db::DaemonDb::new();
    let session_id =
        std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    eprintln!("nsh chat (type 'exit' or Ctrl-D to quit, 'reset' to clear context)");
    let mut last_config_mtime = std::fs::metadata(crate::config::Config::path())
        .and_then(|metadata| metadata.modified())
        .ok();
    let mut config = config;
    let mut version_warning_shown = false;
    loop {
        eprint!("\x1b[1;36m?\x1b[0m ");
        std::io::stderr().flush()?;
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !version_warning_shown {
            let notice = crate::config::Config::nsh_dir().join("update_notice");
            if notice.exists() {
                eprintln!("\x1b[2m⟳ nsh updated — exit and re-run for latest hooks\x1b[0m");
                version_warning_shown = true;
            }
        }
        match line {
            "exit" | "quit" => break,
            "reset" => {
                db.clear_conversations(&session_id)?;
                eprintln!("Context cleared.");
                continue;
            }
            _ => {}
        }
        if let Ok(metadata) = std::fs::metadata(crate::config::Config::path())
            && let Ok(mtime) = metadata.modified()
                && last_config_mtime.as_ref() != Some(&mtime)
                    && let Ok(new_config) = crate::config::Config::load() {
                        config = new_config;
                        last_config_mtime = Some(mtime);
                    }
        if let Err(error) = crate::query::handle_query(
            line,
            &config,
            &db,
            &session_id,
            crate::query::QueryOptions::default(),
        )
        .await
        {
            eprintln!("\x1b[33mnsh: {error}\x1b[0m");
        }
    }
    Ok(())
}

fn handle_export_command(format: Option<String>, session: Option<String>) -> anyhow::Result<()> {
    let session_id = session.unwrap_or_else(|| std::env::var("NSH_SESSION_ID").unwrap_or_default());
    let request = crate::daemon::DaemonRequest::GetConversations {
        session: session_id.clone(),
        limit: 1000,
        caller: crate::daemon::current_caller_context(),
    };
    let conversations = global_daemon_payload::<crate::daemon::ConversationsPayload>(&request)?
        .conversations;
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

fn handle_status_command() -> anyhow::Result<()> {
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
            eprintln!("  Daemon:     v{} (build: {})", data.version, data.build_version);
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

fn handle_completions_command(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut command = crate::cli::Cli::command();
    generate(shell, &mut command, "nsh", &mut std::io::stdout());
}

fn handle_history_import_run_command() {
    let result = crate::daemon_client::ensure_global_daemon_running();
    crate::history_import::clear_import_lock();
    if let Err(error) = result {
        tracing::debug!("background history import failed: {error}");
    }
}

fn parse_dns_txt_records(raw: &str) -> Vec<(String, String, String)> {
    fn valid_version(version: &str) -> bool {
        !version.is_empty()
            && version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    }

    fn valid_target(target: &str) -> bool {
        !target.is_empty()
            && target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    raw.lines()
        .filter_map(|line| {
            let cleaned = line.trim().trim_matches('"');
            let parts: Vec<&str> = cleaned.splitn(3, ':').collect();
            if parts.len() == 3 {
                let (version, target, sha) = (parts[0], parts[1], parts[2]);
                if valid_version(version)
                    && valid_target(target)
                    && sha.len() == 64
                    && sha.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Some((version.to_string(), target.to_string(), sha.to_string()));
                }
            }
            None
        })
        .collect()
}

async fn resolve_update_txt() -> anyhow::Result<Vec<(String, String, String)>> {
    use hickory_resolver::Resolver;

    let resolver = Resolver::builder_tokio()?.build();
    let response = resolver.txt_lookup("update.nsh.tools").await?;
    let mut raw = String::new();
    for record in response.iter() {
        let txt = record.to_string();
        raw.push_str(txt.trim().trim_matches('"'));
        raw.push('\n');
    }
    let records = parse_dns_txt_records(&raw);
    if records.is_empty() {
        anyhow::bail!("no valid version:target:sha256 records found in DNS TXT");
    }
    Ok(records)
}

fn resolve_update_txt_fallback() -> anyhow::Result<Vec<(String, String, String)>> {
    let output = std::process::Command::new("dig")
        .args(["+short", "TXT", "update.nsh.tools"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("dig command failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let records = parse_dns_txt_records(&text);
    if records.is_empty() {
        anyhow::bail!("no valid version:target:sha256 records in dig output");
    }
    Ok(records)
}

fn current_target_triple() -> Option<&'static str> {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    match (os, arch) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("freebsd", "x86") => Some("i686-unknown-freebsd"),
        ("freebsd", "x86_64") => Some("x86_64-unknown-freebsd"),
        ("linux", "x86") => Some("i686-unknown-linux-gnu"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("linux", "riscv64") => Some("riscv64gc-unknown-linux-gnu"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Some("aarch64-pc-windows-msvc"),
        _ => None,
    }
}

fn find_latest_for_target(
    records: &[(String, String, String)],
    target: &str,
) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for (version, record_target, sha) in records {
        if record_target == target {
            match &best {
                Some((best_version, _)) => {
                    if crate::util::compare_versions(version, best_version)
                        == std::cmp::Ordering::Greater
                    {
                        best = Some((version.clone(), sha.clone()));
                    }
                }
                None => best = Some((version.clone(), sha.clone())),
            }
        }
    }
    best
}

fn sha256_file(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn apply_pending_update(_reexec: bool) {
    let result = (|| -> anyhow::Result<()> {
        let pending_path = crate::config::Config::nsh_dir().join("update_pending");
        if !pending_path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&pending_path)?;
        let info: serde_json::Value = match serde_json::from_str(&content) {
            Ok(value) => value,
            Err(_) => {
                let _ = std::fs::remove_file(&pending_path);
                anyhow::bail!("corrupt update_pending file, removed");
            }
        };

        let version = info["version"].as_str().unwrap_or("");
        let staged_path_str = info["staged_path"].as_str().unwrap_or("");
        let expected_sha = info["sha256"].as_str().unwrap_or("");

        let staged_path = std::path::PathBuf::from(staged_path_str);
        if !staged_path.exists() {
            let _ = std::fs::remove_file(&pending_path);
            return Ok(());
        }

        if expected_sha.is_empty() {
            let _ = std::fs::remove_file(&pending_path);
            anyhow::bail!("update_pending missing sha256");
        }
        let actual_sha = sha256_file(&staged_path)?;
        if actual_sha != expected_sha {
            let _ = std::fs::remove_file(&pending_path);
            let _ = std::fs::remove_file(&staged_path);
            anyhow::bail!("staged binary SHA mismatch");
        }

        let core_dir = crate::config::Config::nsh_dir().join("bin");
        std::fs::create_dir_all(&core_dir)?;
        let core_path = core_dir.join("nsh-core");
        let tmp_path = core_dir.join("nsh-core.tmp");
        std::fs::copy(&staged_path, &tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp_path, &core_path)?;

        let _ = std::fs::remove_file(&pending_path);
        let _ = std::fs::remove_file(&staged_path);

        eprintln!("nsh: updated to v{version}");

        let notice_path = crate::config::Config::nsh_dir().join("update_notice");
        let _ = std::fs::write(
            &notice_path,
            format!(
                "v{version} installed — queries active immediately, shell hooks refresh on next terminal"
            ),
        );

        signal_daemon_restart();
        Ok(())
    })();
    if let Err(error) = result {
        tracing::debug!("apply_pending_update failed: {error}");
    }
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

fn redact_config_keys(value: &mut toml::Value) {
    match value {
        toml::Value::Table(table) => {
            for (key, child) in table.iter_mut() {
                if key == "api_key" {
                    if let toml::Value::String(string) = child {
                        if string.chars().count() > 8 {
                            let prefix: String = string.chars().take(4).collect();
                            let suffix: String = string
                                .chars()
                                .rev()
                                .take(4)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            *string = format!("{prefix}...{suffix}");
                        } else {
                            *string = "****".into();
                        }
                    }
                } else {
                    redact_config_keys(child);
                }
            }
        }
        toml::Value::Array(array) => {
            for child in array {
                redact_config_keys(child);
            }
        }
        _ => {}
    }
}

fn maybe_stage_hook_reload_notice(session: Option<&str>) {
    if let Ok(env_hash) = std::env::var("NSH_HOOK_HASH")
        && !env_hash.is_empty() && env_hash != env!("NSH_HOOK_HASH") {
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

fn check_daemon_versions(session_id: &str) {
    let _ = session_id;
    static CHECKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if CHECKED
        .compare_exchange(
            false,
            true,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        )
        .is_ok()
    {
        let _ = crate::daemon_client::ensure_daemon_version_matches();
    }
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
