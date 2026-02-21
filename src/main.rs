mod ansi;
mod audit;
mod autoconfigure;
mod cli;
mod coding_agent;
mod config;
mod context;
mod daemon;
mod daemon_client;
mod daemon_db;
mod db;
mod debug_io;
mod display;
mod fast_cwd;
#[cfg(unix)]
mod global_daemon;
mod history_import;
mod init;
mod json_display;
mod json_extract;
#[allow(dead_code)]
mod mcp;
mod memory;
mod provider;
#[cfg(unix)]
mod pty;
#[cfg(windows)]
#[path = "pty_windows.rs"]
mod pty;
mod pump;
mod query;
mod redact;
mod security;
mod shell_hooks;
mod skills;
mod stream_consumer;
mod streaming;
mod summary;
mod tools;
mod util;

use crate::daemon_db::DbAccess;
use clap::Parser;
use cli::{
    Cli, Commands, ConfigAction, DaemonReadAction, DaemonSendAction, DoctorAction, HistoryAction,
    MemoryAction, ProviderAction, SessionAction,
};
use sha2::{Digest, Sha256};

fn ensure_daemon_ready(json: bool) -> anyhow::Result<bool> {
    if daemon_client::is_global_daemon_running() {
        return Ok(true);
    }
    let _ = daemon_client::ensure_global_daemon_running();
    std::thread::sleep(std::time::Duration::from_millis(500));
    if daemon_client::is_global_daemon_running() {
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
    request: &daemon::DaemonRequest,
) -> anyhow::Result<daemon::DaemonResponse> {
    match daemon_client::send_to_global(request) {
        Ok(resp) => Ok(resp),
        Err(_) => {
            let _ = daemon_client::ensure_global_daemon_running();
            daemon_client::send_to_global(request)
        }
    }
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    security::secure_nsh_directory();

    let cli = Cli::parse();

    if let Commands::Nshd = cli.command {
        #[cfg(unix)]
        {
            return global_daemon::run_global_daemon();
        }
        #[cfg(not(unix))]
        {
            eprintln!("nsh: global daemon is not supported on this platform");
            return Ok(());
        }
    }

    if let Commands::Wrap { ref shell } = cli.command {
        #[cfg(not(unix))]
        {
            eprintln!("nsh: PTY wrapping is not available on this platform.");
            eprintln!("  nsh query, history, and tools work without wrapping.");
            eprintln!("  For full functionality, use WSL: wsl --install");
            std::process::exit(0);
        }

        apply_pending_update();

        if config::Config::nsh_dir().join("update_pending").exists() {
            eprintln!("\x1b[2mnsh: update ready, will apply on next shell start\x1b[0m");
        }

        let shell = if shell.is_empty() {
            std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
        } else {
            shell.clone()
        };
        return pty::run_wrapped_shell(&shell);
    }

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?
        .block_on(async_main(cli))
}

async fn async_main(cli: Cli) -> anyhow::Result<()> {
    debug_io::set_enabled(config::Config::load().unwrap_or_default().debug.llm_io);

    match cli.command {
        Commands::Wrap { .. } => unreachable!(),
        Commands::Nshd => unreachable!(),

        Commands::Init { shell } => {
            let script = init::generate_init_script(&shell);
            print!("{script}");
        }

        Commands::Query {
            words,
            think,
            private,
            json,
        } => {
            if words.is_empty() {
                eprintln!("Usage: ? <your question>");
                std::process::exit(1);
            }

            if !ensure_daemon_ready(json)? {
                return Ok(());
            }

            if history_import::import_in_progress() {
                eprintln!(
                    "\x1b[2m⏳ nsh is still indexing history; results may be incomplete.\x1b[0m"
                );
            }
            let mut query_text = words.join(" ");

            // Pipe/stdin support
            use std::io::IsTerminal;
            if !std::io::stdin().is_terminal() {
                use std::io::Read;
                let max_pipe_bytes: u64 = 33000; // slightly over 32k to detect truncation
                let mut piped = String::new();
                std::io::stdin()
                    .take(max_pipe_bytes)
                    .read_to_string(&mut piped)?;
                if !piped.is_empty() {
                    let truncated = crate::util::truncate(&piped, 32000);
                    query_text =
                        format!("<piped_input>\n{truncated}\n</piped_input>\n\n{query_text}");
                }
            }

            // Auto-run suffix: strip trailing !!
            let (query_text, force_autorun) = if query_text.ends_with("!!") {
                (query_text[..query_text.len() - 2].trim().to_string(), true)
            } else {
                (query_text, false)
            };
            let config = config::Config::load()?;
            let force_autorun = force_autorun || config.execution.mode == "autorun";
            let db = daemon_db::DaemonDb::new();
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
            let result = query::handle_query(
                &query_text,
                &config,
                &db,
                &session_id,
                query::QueryOptions {
                    think,
                    private,
                    force_autorun,
                    json_output: json,
                },
            )
            .await;
            if let Err(ref e) = result {
                if e.to_string().contains("interrupted") {
                    eprint!("\x1b[?25h\x1b[0m");
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    std::process::exit(130);
                }
            }
            result?;
        }

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
        } => {
            let request = daemon::DaemonRequest::Record {
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
            if let daemon::DaemonRequest::Record { tty, cwd, .. } = &request {
                let _ = fast_cwd::update_tty_cwd(tty, cwd);
            }
            match send_to_global_or_fallback(&request) {
                Ok(daemon::DaemonResponse::Error { message }) => {
                    eprintln!("nsh: record error: {message}");
                }
                Err(e) => {
                    tracing::debug!("daemon unavailable for record: {e}");
                }
                _ => {}
            }
        }

        Commands::Session { action } => match action {
            SessionAction::Start {
                session,
                tty,
                shell,
                pid,
            } => {
                let request = daemon::DaemonRequest::CreateSession {
                    session,
                    tty,
                    shell,
                    pid: pid as i64,
                };
                if let Err(e) = send_to_global_or_fallback(&request) {
                    tracing::debug!("daemon unavailable for session start: {e}");
                }
            }
            SessionAction::End { session } => {
                let _ = send_to_global_or_fallback(&daemon::DaemonRequest::EndSession {
                    session: session.clone(),
                });
                shell_hooks::cleanup_pending_files(&session);
            }
            SessionAction::Label { label, session } => {
                let session_id = session.unwrap_or_else(|| {
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
                });
                let request = daemon::DaemonRequest::SetSessionLabel {
                    session: session_id,
                    label: label.clone(),
                };
                match send_to_global_or_fallback(&request) {
                    Ok(daemon::DaemonResponse::Ok { data: Some(d) }) => {
                        if d.get("updated").and_then(|v| v.as_bool()).unwrap_or(false) {
                            eprintln!("nsh: session labeled \"{label}\"");
                        } else {
                            eprintln!("nsh: session not found");
                        }
                    }
                    _ => eprintln!("nsh: session not found"),
                }
            }
            SessionAction::LastCwd { tty } => {
                let config = config::Config::load().unwrap_or_default();
                if !config.context.restore_last_cwd_per_tty {
                    return Ok(());
                }
                if let Some(cwd) = fast_cwd::get_tty_cwd(&tty) {
                    println!("{cwd}");
                    return Ok(());
                }
                let request = daemon::DaemonRequest::LatestCwdForTty { tty };
                if let Ok(daemon::DaemonResponse::Ok { data: Some(d) }) =
                    send_to_global_or_fallback(&request)
                {
                    if let Some(cwd) = d.get("cwd").and_then(|v| v.as_str()) {
                        println!("{cwd}");
                    }
                }
            }
            SessionAction::SuppressedExitCodes => {
                let config = config::Config::load().unwrap_or_default();
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
                let updated = config::add_suppressed_exit_code(code)?;
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
        },

        Commands::History { action } => match action {
            HistoryAction::Search { query, limit } => {
                let request = daemon::DaemonRequest::SearchHistory { query, limit };
                match send_to_global_or_fallback(&request) {
                    Ok(daemon::DaemonResponse::Ok { data: Some(d) }) => {
                        let results = d.get("results").and_then(|v| v.as_array());
                        if let Some(results) = results {
                            if results.is_empty() {
                                eprintln!("No results found.");
                            } else {
                                for r in results {
                                    let started =
                                        r.get("started_at").and_then(|v| v.as_str()).unwrap_or("");
                                    let exit_code = r.get("exit_code").and_then(|v| v.as_i64());
                                    let code = exit_code
                                        .map(|c| format!(" (exit {c})"))
                                        .unwrap_or_default();
                                    let cmd_hl = r
                                        .get("cmd_highlight")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("");
                                    println!("[{started}]{code} {cmd_hl}");
                                    if let Some(hl) =
                                        r.get("output_highlight").and_then(|v| v.as_str())
                                    {
                                        let preview: String = hl.chars().take(200).collect();
                                        println!("  {preview}");
                                    }
                                }
                            }
                        } else {
                            eprintln!("No results found.");
                        }
                    }
                    Ok(daemon::DaemonResponse::Error { message }) => eprintln!("nsh: {message}"),
                    _ => eprintln!("No results found."),
                }
            }
        },

        Commands::Reset => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
            let _ = send_to_global_or_fallback(&daemon::DaemonRequest::ClearConversations {
                session: session_id,
            });
            eprintln!("nsh: conversation context cleared");
        }

        Commands::Config { action } => match action {
            Some(ConfigAction::Path) | None => {
                println!("{}", config::Config::path().display());
            }
            Some(ConfigAction::Show { raw }) => {
                let path = config::Config::path();
                if path.exists() {
                    let content = std::fs::read_to_string(&path)?;
                    if raw {
                        print!("{content}");
                    } else {
                        match content.parse::<toml::Value>() {
                            Ok(mut val) => {
                                redact_config_keys(&mut val);
                                print!("{}", toml::to_string_pretty(&val)?);
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
                let path = config::Config::path();
                let dir = path.parent().unwrap();
                std::fs::create_dir_all(dir)?;
                std::process::Command::new(&editor).arg(&path).status()?;
            }
        },

        Commands::Cost { period } => {
            let request = daemon::DaemonRequest::GetUsageStats {
                period: period.clone(),
            };
            let stats_result = match send_to_global_or_fallback(&request) {
                Ok(daemon::DaemonResponse::Ok { data: Some(d) }) => d,
                _ => {
                    eprintln!("No usage data recorded yet.");
                    return Ok(());
                }
            };
            let stats = stats_result
                .get("stats")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if stats.is_empty() {
                eprintln!("No usage data recorded yet.");
            } else {
                eprintln!(
                    "Model                               Calls  Input Tok  Output Tok  Cost (USD)"
                );
                eprintln!(
                    "─────────────────────────────────────────────────────────────────────────────"
                );
                let mut total_cost = 0.0_f64;
                let mut total_calls = 0_i64;
                for entry in &stats {
                    let model = entry.get("model").and_then(|v| v.as_str()).unwrap_or("?");
                    let calls = entry.get("calls").and_then(|v| v.as_i64()).unwrap_or(0);
                    let input_tok = entry
                        .get("input_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let output_tok = entry
                        .get("output_tokens")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0);
                    let cost = entry
                        .get("cost_usd")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0);
                    eprintln!(
                        "{model:<35} {calls:>5}  {input_tok:>9}  {output_tok:>10}  ${cost:.4}"
                    );
                    total_cost += cost;
                    total_calls += calls;
                }
                eprintln!(
                    "─────────────────────────────────────────────────────────────────────────────"
                );
                eprintln!(
                    "{:<35} {:>5}                        ${:.4}",
                    "TOTAL", total_calls, total_cost
                );
            }
        }

        Commands::Provider { action } => match action {
            ProviderAction::ListLocal => {
                let base_url = config::Config::load()
                    .ok()
                    .and_then(|c| c.provider.ollama.as_ref().and_then(|a| a.base_url.clone()))
                    .unwrap_or_else(|| "http://localhost:11434".into());
                let url = format!("{}/api/tags", base_url.trim_end_matches("/v1"));
                match reqwest::get(&url).await {
                    Ok(resp) if resp.status().is_success() => {
                        let json: serde_json::Value = resp.json().await?;
                        if let Some(models) = json["models"].as_array() {
                            if models.is_empty() {
                                eprintln!("No models found. Pull one with: ollama pull <model>");
                            } else {
                                eprintln!("Available Ollama models:");
                                for m in models {
                                    let name = m["name"].as_str().unwrap_or("?");
                                    let size = m["size"].as_u64().unwrap_or(0);
                                    let size_gb = size as f64 / 1_073_741_824.0;
                                    eprintln!("  {name} ({size_gb:.1} GB)");
                                }
                            }
                        }
                    }
                    Ok(resp) => {
                        eprintln!("Ollama API error: {}", resp.status());
                    }
                    Err(_) => {
                        eprintln!("Could not connect to Ollama at {url}");
                        eprintln!("Is Ollama running? Start it with: ollama serve");
                    }
                }
            }
        },

        Commands::Doctor {
            action,
            no_prune,
            no_vacuum,
            prune_days,
        } => {
            if let Some(DoctorAction::Capture) = action {
                let session_id =
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".to_string());
                let daemon_socket = daemon::daemon_socket_path(&session_id);
                let daemon_running = daemon_client::is_daemon_running(&session_id);
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
                    eprintln!(
                        "  hint: start your shell with `nsh wrap` (or keep it in your rc file)"
                    );
                }
                if wrapped && !daemon_running {
                    eprintln!("  hint: restart the wrapped shell to recreate daemon socket");
                }
            } else {
                let config = config::Config::load().unwrap_or_default();
                let global_running = daemon_client::is_global_daemon_running();
                eprintln!(
                    "  Global daemon: {}",
                    if global_running {
                        "running"
                    } else {
                        "not running"
                    }
                );
                let retention = prune_days.unwrap_or(config.context.retention_days);
                let request = daemon::DaemonRequest::RunDoctor {
                    retention_days: retention,
                    no_prune,
                    no_vacuum,
                };
                match send_to_global_or_fallback(&request) {
                    Ok(daemon::DaemonResponse::Error { message }) => {
                        anyhow::bail!(message);
                    }
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("  Database maintenance skipped (daemon unavailable: {e})");
                    }
                }
                cleanup_staged_updates();
            }
        }

        Commands::Heartbeat { session } => {
            let _ = send_to_global_or_fallback(&daemon::DaemonRequest::Heartbeat { session });
        }

        Commands::RedactNext => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
            let flag_path = config::Config::nsh_dir().join(format!("redact_next_{session_id}"));
            std::fs::write(&flag_path, "")?;
            eprintln!("nsh: next command output will not be captured");
        }

        Commands::Autoconfigure => {
            crate::autoconfigure::run_autoconfigure()?;
        }

        Commands::Restart => {
            eprint!("nsh: stopping daemon...");
            if daemon_client::stop_global_daemon() {
                eprintln!(" stopped");
            } else {
                eprintln!(" not running");
            }
            eprint!("nsh: starting daemon...");
            daemon_client::ensure_global_daemon_running()?;
            eprintln!(
                " started (pid {})",
                std::fs::read_to_string(daemon::global_daemon_pid_path())
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            );
        }

        Commands::Update => {
            eprintln!("nsh: checking for updates...");

            let target = match current_target_triple() {
                Some(t) => t,
                None => {
                    let arch = std::env::consts::ARCH;
                    let os = std::env::consts::OS;
                    eprintln!("nsh: unsupported platform {os}/{arch}. Build from source:");
                    eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
                    std::process::exit(1);
                }
            };

            let records = match resolve_update_txt().await {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("nsh: DNS lookup failed: {e}");
                    eprintln!("  Falling back to dig...");
                    match resolve_update_txt_fallback() {
                        Ok(r) => r,
                        Err(e2) => {
                            eprintln!("nsh: DNS fallback also failed: {e2}");
                            std::process::exit(1);
                        }
                    }
                }
            };

            let (version, expected_sha) = match find_latest_for_target(&records, target) {
                Some(v) => v,
                None => {
                    eprintln!("nsh: no release found for {target} in DNS records");
                    std::process::exit(1);
                }
            };

            let current_version = env!("CARGO_PKG_VERSION");
            if util::compare_versions(&version, current_version) != std::cmp::Ordering::Greater {
                eprintln!("nsh: already up to date (v{current_version})");
                return Ok(());
            }

            eprintln!("nsh: v{version} available (current: v{current_version})");

            let url = format!(
                "https://github.com/fluffypony/nsh/releases/download/v{version}/nsh-{target}.tar.gz"
            );
            eprintln!("nsh: downloading {target}...");
            let client = reqwest::Client::new();
            let download_resp = client.get(&url).send().await?;
            if !download_resp.status().is_success() {
                eprintln!("nsh: no pre-built binary available. Build from source:");
                eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
                std::process::exit(1);
            }

            let bytes = download_resp.bytes().await?;

            let staging_dir = config::Config::nsh_dir().join("updates");
            std::fs::create_dir_all(&staging_dir)?;
            let staged_path = staging_dir.join(format!("nsh-{version}-{target}"));

            let decoder = flate2::read::GzDecoder::new(&bytes[..]);
            let mut archive = tar::Archive::new(decoder);
            let mut found = false;
            for entry in archive.entries()? {
                let mut entry = entry?;
                let path = entry.path()?.to_path_buf();
                if path.file_name().map(|n| n == "nsh").unwrap_or(false) {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .open(&staged_path)?;
                    std::io::copy(&mut entry, &mut file)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &staged_path,
                            std::fs::Permissions::from_mode(0o755),
                        )?;
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
            let pending_path = config::Config::nsh_dir().join("update_pending");
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

            eprintln!("nsh: update v{version} downloaded and verified.");
            eprintln!("  It will be applied automatically on your next shell start.");
        }

        Commands::Memory { action } => {
            if !ensure_daemon_ready(false)? {
                return Ok(());
            }
            match action {
                MemoryAction::Search { query, r#type, limit } => {
                    let request = daemon::DaemonRequest::MemorySearch {
                        query,
                        memory_type: r#type,
                        limit,
                    };
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            println!("{}", serde_json::to_string_pretty(&d)?);
                        }
                        daemon::DaemonResponse::Ok { data: None } => {
                            println!("No results");
                        }
                        daemon::DaemonResponse::Error { message } => {
                            eprintln!("error: {message}");
                        }
                    }
                }
                MemoryAction::Stats => {
                    let request = daemon::DaemonRequest::MemoryStats;
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            println!("{}", serde_json::to_string_pretty(&d)?);
                        }
                        resp => eprintln!("{resp:?}"),
                    }
                }
                MemoryAction::Core => {
                    let request = daemon::DaemonRequest::MemoryGetCore;
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            println!("{}", serde_json::to_string_pretty(&d)?);
                        }
                        resp => eprintln!("{resp:?}"),
                    }
                }
                MemoryAction::Maintain => {
                    eprintln!("Running memory decay...");
                    let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryRunDecay);
                    eprintln!("Running memory reflection...");
                    let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryRunReflection);
                    eprintln!("Memory maintenance complete.");
                }
                MemoryAction::Bootstrap => {
                    eprintln!("Running memory bootstrap scan...");
                    let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryBootstrapScan);
                    eprintln!("Bootstrap scan complete.");
                }
                MemoryAction::Clear { r#type } => {
                    if let Some(ref memory_type) = r#type {
                        let valid = ["episodic", "semantic", "procedural", "resource", "knowledge", "core"];
                        if !valid.contains(&memory_type.as_str()) {
                            eprintln!("Unknown memory type '{}'. Valid types: {}", memory_type, valid.join(", "));
                            return Ok(());
                        }
                        let _ = send_to_global_or_fallback(
                            &daemon::DaemonRequest::MemoryClearByType { memory_type: memory_type.clone() }
                        );
                        eprintln!("{memory_type} memories cleared.");
                    } else {
                        let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryClearAll);
                        eprintln!("All memories cleared.");
                    }
                }
                MemoryAction::Decay => {
                    let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryRunDecay);
                    eprintln!("Memory decay complete.");
                }
                MemoryAction::Reflect => {
                    let _ = send_to_global_or_fallback(&daemon::DaemonRequest::MemoryRunReflection);
                    eprintln!("Memory reflection complete.");
                }
                MemoryAction::Export { format: _ } => {
                    let request = daemon::DaemonRequest::MemoryStats;
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            println!("{}", serde_json::to_string_pretty(&d)?);
                        }
                        resp => eprintln!("{resp:?}"),
                    }
                }
            }
        }

        Commands::DaemonSend { action } => {
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
                DaemonSendAction::Status => {
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
                }
            };

            if let DaemonSendAction::Record { tty, cwd, .. } = &action {
                let _ = fast_cwd::update_tty_cwd(tty, cwd);
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
                } => daemon::DaemonRequest::Record {
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
                DaemonSendAction::Heartbeat { session } => daemon::DaemonRequest::Heartbeat {
                    session: session.clone(),
                },
                DaemonSendAction::CaptureMark { session } => daemon::DaemonRequest::CaptureMark {
                    session: session.clone(),
                },
                DaemonSendAction::Status => daemon::DaemonRequest::Status,
            };

            match daemon_client::try_send_request(&session_id, &request) {
                Some(resp) => {
                    if let daemon::DaemonResponse::Error { message } = resp {
                        eprintln!("nsh: daemon error: {message}");
                    }
                }
                None => {
                    // Per-session daemon unavailable — try global daemon for DB ops
                    match action {
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
                            let global_request = daemon::DaemonRequest::Record {
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
                            let _ = send_to_global_or_fallback(&daemon::DaemonRequest::Heartbeat {
                                session,
                            });
                        }
                        DaemonSendAction::CaptureMark { .. } => {}
                        DaemonSendAction::Status => {
                            eprintln!("nsh: daemon not running");
                        }
                    }
                }
            }
        }

        Commands::DaemonRead { action } => {
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
                    daemon::DaemonRequest::CaptureRead {
                        session: session.clone(),
                        max_lines: *max_lines,
                    }
                }
                DaemonReadAction::Scrollback { max_lines } => daemon::DaemonRequest::Scrollback {
                    max_lines: *max_lines,
                },
            };

            match daemon_client::try_send_request(&session_id, &request) {
                Some(daemon::DaemonResponse::Ok { data: Some(d) }) => {
                    let text = d
                        .get("output")
                        .or_else(|| d.get("scrollback"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    print!("{text}");
                }
                Some(daemon::DaemonResponse::Error { message }) => {
                    eprintln!("nsh: daemon error: {message}");
                }
                _ => {}
            }
        }

        Commands::Chat => {
            use std::io::Write;
            if !ensure_daemon_ready(false)? {
                return Ok(());
            }
            let config = config::Config::load()?;
            streaming::configure_display(&config.display);
            let db = daemon_db::DaemonDb::new();
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
            eprintln!("nsh chat (type 'exit' or Ctrl-D to quit, 'reset' to clear context)");
            let mut last_config_mtime = std::fs::metadata(config::Config::path())
                .and_then(|m| m.modified())
                .ok();
            let mut config = config;
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
                match line {
                    "exit" | "quit" => break,
                    "reset" => {
                        db.clear_conversations(&session_id)?;
                        eprintln!("Context cleared.");
                        continue;
                    }
                    _ => {}
                }
                // Hot-reload config if changed
                if let Ok(meta) = std::fs::metadata(config::Config::path()) {
                    if let Ok(mtime) = meta.modified() {
                        if last_config_mtime.as_ref() != Some(&mtime) {
                            if let Ok(new_config) = config::Config::load() {
                                config = new_config;
                                last_config_mtime = Some(mtime);
                            }
                        }
                    }
                }
                if let Err(e) = query::handle_query(
                    line,
                    &config,
                    &db,
                    &session_id,
                    query::QueryOptions::default(),
                )
                .await
                {
                    eprintln!("\x1b[33mnsh: {e}\x1b[0m");
                }
            }
        }

        Commands::Export { format, session } => {
            let session_id =
                session.unwrap_or_else(|| std::env::var("NSH_SESSION_ID").unwrap_or_default());
            let request = daemon::DaemonRequest::GetConversations {
                session: session_id.clone(),
                limit: 1000,
            };
            let convos = match send_to_global_or_fallback(&request)? {
                daemon::DaemonResponse::Ok { data: Some(d) } => d
                    .get("conversations")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default(),
                daemon::DaemonResponse::Error { message } => anyhow::bail!(message),
                _ => Vec::new(),
            };
            if convos.is_empty() {
                eprintln!("No conversations found for session {session_id}");
            } else {
                match format.as_deref().unwrap_or("markdown") {
                    "json" => {
                        println!("{}", serde_json::to_string_pretty(&convos)?);
                    }
                    _ => {
                        for c in &convos {
                            let query = c.get("query").and_then(|v| v.as_str()).unwrap_or("");
                            let response_type = c
                                .get("response_type")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let response = c.get("response").and_then(|v| v.as_str()).unwrap_or("");
                            let explanation =
                                c.get("explanation").and_then(|v| v.as_str()).unwrap_or("");
                            println!("**Q:** {}\n", query);
                            match response_type {
                                "command" => {
                                    println!("```bash\n{}\n```\n{}\n", response, explanation)
                                }
                                _ => println!("{}\n", response),
                            }
                        }
                    }
                }
            }
        }

        Commands::Status => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "(not set)".into());
            let config = config::Config::load().unwrap_or_default();
            let build_version = env!("NSH_BUILD_VERSION");
            let pty_active = std::env::var("NSH_TTY").is_ok();
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "unknown".into());
            let db_path = config::Config::nsh_dir().join("nsh.db");
            let db_size = std::fs::metadata(&db_path).map(|m| m.len()).unwrap_or(0);
            let db_size_str = if db_size > 1_048_576 {
                format!("{:.1} MB", db_size as f64 / 1_048_576.0)
            } else {
                format!("{:.1} KB", db_size as f64 / 1024.0)
            };

            let session_label = if session_id != "(not set)" {
                if let Ok(daemon::DaemonResponse::Ok { data: Some(d) }) =
                    send_to_global_or_fallback(&daemon::DaemonRequest::GetSessionLabel {
                        session: session_id.clone(),
                    })
                {
                    d.get("label").and_then(|v| v.as_str()).map(String::from)
                } else {
                    None
                }
            } else {
                None
            };

            let global_daemon_status = if daemon_client::is_global_daemon_running() {
                "running"
            } else {
                "not running"
            };

            eprintln!("nsh status:");
            eprintln!("  Version:    {build_version}");
            eprintln!("  Session:    {session_id}");
            if let Some(label) = session_label {
                eprintln!("  Label:      {label}");
            }
            eprintln!("  Shell:      {shell}");
            eprintln!("  PTY active: {}", if pty_active { "yes" } else { "no" });
            eprintln!("  Global daemon: {global_daemon_status}");
            eprintln!("  Provider:   {}", config.provider.default);
            eprintln!("  Model:      {}", config.provider.model);
            eprintln!("  DB path:    {}", db_path.display());
            eprintln!("  DB size:    {db_size_str}");
        }
        Commands::Completions { shell } => {
            use clap::CommandFactory;
            use clap_complete::generate;
            let mut cmd = cli::Cli::command();
            generate(shell, &mut cmd, "nsh", &mut std::io::stdout());
        }

        Commands::HistoryImportRun => {
            let result = daemon_client::ensure_global_daemon_running();
            history_import::clear_import_lock();
            if let Err(e) = result {
                tracing::debug!("background history import failed: {e}");
            }
        }
    }

    Ok(())
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
    for (version, t, sha) in records {
        if t == target {
            match &best {
                Some((bv, _)) => {
                    if util::compare_versions(version, bv) == std::cmp::Ordering::Greater {
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
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn apply_pending_update() {
    let result = (|| -> anyhow::Result<()> {
        let pending_path = config::Config::nsh_dir().join("update_pending");
        if !pending_path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&pending_path)?;
        let info: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(_) => {
                let _ = std::fs::remove_file(&pending_path);
                anyhow::bail!("corrupt update_pending file, removed");
            }
        };

        let version = info["version"].as_str().unwrap_or("");
        let staged_str = info["staged_path"].as_str().unwrap_or("");
        let expected_sha = info["sha256"].as_str().unwrap_or("");

        let staged_path = std::path::PathBuf::from(staged_str);
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

        let current_exe = std::env::current_exe()?;
        let new_path = current_exe.with_extension("new");
        std::fs::copy(&staged_path, &new_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&new_path, std::fs::Permissions::from_mode(0o755))?;
        }
        #[cfg(unix)]
        std::fs::rename(&new_path, &current_exe)?;
        #[cfg(windows)]
        {
            let old_path = current_exe.with_extension("old");
            let _ = std::fs::remove_file(&old_path);
            std::fs::rename(&current_exe, &old_path)?;
            std::fs::rename(&new_path, &current_exe)?;
            let _ = std::fs::remove_file(&old_path);
        }

        let _ = std::fs::remove_file(&pending_path);
        let _ = std::fs::remove_file(&staged_path);

        eprintln!("nsh: updated to v{version}");

        let args: Vec<String> = std::env::args().skip(1).collect();
        #[cfg(unix)]
        {
            let exe_path = current_exe.to_string_lossy().to_string();
            let mut new_args = vec![exe_path.as_str()];
            for a in &args {
                new_args.push(a.as_str());
            }
            let _err = pty::exec_execvp(&exe_path, &new_args);
        }
        #[cfg(windows)]
        {
            let _ = std::process::Command::new(&current_exe).args(&args).spawn();
            std::process::exit(0);
        }
        Ok(())
    })();
    if let Err(e) = result {
        tracing::debug!("apply_pending_update failed: {e}");
    }
}

#[cfg(test)]
fn should_check_for_updates(db: &db::Db) -> bool {
    match db.get_meta("last_update_check") {
        Ok(Some(ts)) => {
            if let Ok(last) = chrono::DateTime::parse_from_rfc3339(&ts) {
                let elapsed = chrono::Utc::now().signed_duration_since(last);
                elapsed.num_hours() >= 24
            } else {
                true
            }
        }
        _ => true,
    }
}

#[cfg(test)]
#[allow(dead_code)]
fn background_update_check() -> anyhow::Result<()> {
    let target = current_target_triple().ok_or_else(|| anyhow::anyhow!("unsupported platform"))?;
    let current_version = env!("CARGO_PKG_VERSION");

    let records = resolve_update_txt_fallback()?;
    let (latest_version, expected_sha) = find_latest_for_target(&records, target)
        .ok_or_else(|| anyhow::anyhow!("no DNS record for {target}"))?;

    if util::compare_versions(&latest_version, current_version) != std::cmp::Ordering::Greater {
        let db = db::Db::open()?;
        db.set_meta("last_update_check", &chrono::Utc::now().to_rfc3339())?;
        return Ok(());
    }

    let pending_path = config::Config::nsh_dir().join("update_pending");
    if pending_path.exists() {
        return Ok(());
    }

    let url = format!(
        "https://github.com/fluffypony/nsh/releases/download/v{latest_version}/nsh-{target}.tar.gz"
    );
    let output = std::process::Command::new("curl")
        .args(["-fsSL", &url])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("download failed");
    }

    let staging_dir = config::Config::nsh_dir().join("updates");
    std::fs::create_dir_all(&staging_dir)?;
    let staged_path = staging_dir.join(format!("nsh-{latest_version}-{target}"));
    let tmp_staged = staging_dir.join(format!(
        "nsh-{latest_version}-{target}.{}",
        std::process::id()
    ));

    let decoder = flate2::read::GzDecoder::new(&output.stdout[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.file_name().map(|n| n == "nsh").unwrap_or(false) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_staged)?;
            std::io::copy(&mut entry, &mut file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&tmp_staged, std::fs::Permissions::from_mode(0o755))?;
            }
            found = true;
            break;
        }
    }
    if !found {
        let _ = std::fs::remove_file(&tmp_staged);
        anyhow::bail!("binary not found in archive");
    }

    let actual_sha = sha256_file(&tmp_staged)?;
    if actual_sha != expected_sha {
        let _ = std::fs::remove_file(&tmp_staged);
        anyhow::bail!("SHA256 mismatch: expected {expected_sha}, got {actual_sha}");
    }
    std::fs::rename(&tmp_staged, &staged_path)?;

    let current_exe = std::env::current_exe()?;
    let pending_info = serde_json::json!({
        "version": latest_version,
        "staged_path": staged_path.to_string_lossy(),
        "target_binary": current_exe.to_string_lossy(),
        "sha256": expected_sha,
        "downloaded_at": chrono::Utc::now().to_rfc3339(),
    });
    atomic_write(
        &pending_path,
        serde_json::to_string_pretty(&pending_info)?.as_bytes(),
    )?;

    let db = db::Db::open()?;
    db.set_meta("last_update_check", &chrono::Utc::now().to_rfc3339())?;

    Ok(())
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn cleanup_staged_updates() {
    let nsh_dir = config::Config::nsh_dir();
    let updates_dir = nsh_dir.join("updates");
    if !updates_dir.exists() {
        return;
    }
    let pending_path = nsh_dir.join("update_pending");
    let pending_staged: Option<std::path::PathBuf> = std::fs::read_to_string(&pending_path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v["staged_path"].as_str().map(std::path::PathBuf::from))
        .and_then(|p| std::fs::canonicalize(&p).ok());

    if let Ok(entries) = std::fs::read_dir(&updates_dir) {
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let dominated = match &pending_staged {
                    Some(p) => std::fs::canonicalize(&path).ok().as_ref() != Some(p),
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

fn redact_config_keys(val: &mut toml::Value) {
    match val {
        toml::Value::Table(table) => {
            for (key, v) in table.iter_mut() {
                if key == "api_key" {
                    if let toml::Value::String(s) = v {
                        if s.chars().count() > 8 {
                            let prefix: String = s.chars().take(4).collect();
                            let suffix: String = s
                                .chars()
                                .rev()
                                .take(4)
                                .collect::<String>()
                                .chars()
                                .rev()
                                .collect();
                            *s = format!("{prefix}...{suffix}");
                        } else {
                            *s = "****".into();
                        }
                    }
                } else {
                    redact_config_keys(v);
                }
            }
        }
        toml::Value::Array(arr) => {
            for v in arr {
                redact_config_keys(v);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_sha() -> &'static str {
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    }

    // --- parse_dns_txt_records ---

    #[test]
    fn parse_dns_valid_records() {
        let input = format!("0.1.0:aarch64-apple-darwin:{}", valid_sha());
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "0.1.0");
        assert_eq!(records[0].1, "aarch64-apple-darwin");
        assert_eq!(records[0].2, valid_sha());
    }

    #[test]
    fn parse_dns_invalid_sha_length() {
        let records = parse_dns_txt_records("0.1.0:target:abcdef");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_non_hex_sha() {
        let bad_sha = "zzzzzz0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let input = format!("0.1.0:target:{bad_sha}");
        let records = parse_dns_txt_records(&input);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_too_few_parts() {
        let records = parse_dns_txt_records("0.1.0:target_only");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_empty_input() {
        let records = parse_dns_txt_records("");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_quoted_lines() {
        let input = format!("\"0.1.0:aarch64-apple-darwin:{}\"", valid_sha());
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "0.1.0");
    }

    #[test]
    fn parse_dns_mixed_valid_invalid() {
        let sha = valid_sha();
        let input = format!(
            "0.1.0:target_a:{sha}\nbad_line\n0.2.0:target_b:{sha}\n0.3.0:target_c:tooshort"
        );
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, "0.1.0");
        assert_eq!(records[1].0, "0.2.0");
    }

    // --- current_target_triple ---

    #[test]
    fn current_target_triple_returns_some() {
        assert!(current_target_triple().is_some());
    }

    // --- find_latest_for_target ---

    #[test]
    fn find_latest_no_records() {
        let records: Vec<(String, String, String)> = vec![];
        assert!(find_latest_for_target(&records, "x86_64-unknown-linux-gnu").is_none());
    }

    #[test]
    fn find_latest_single_match() {
        let sha = valid_sha().to_string();
        let records = vec![("0.5.0".to_string(), "linux".to_string(), sha.clone())];
        let result = find_latest_for_target(&records, "linux");
        assert_eq!(result, Some(("0.5.0".to_string(), sha)));
    }

    #[test]
    fn find_latest_picks_highest_version() {
        let sha = valid_sha().to_string();
        let records = vec![
            (
                "0.1.0".to_string(),
                "linux".to_string(),
                "sha_old".to_string(),
            ),
            ("0.3.0".to_string(), "linux".to_string(), sha.clone()),
            (
                "0.2.0".to_string(),
                "linux".to_string(),
                "sha_mid".to_string(),
            ),
        ];
        let result = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(result.0, "0.3.0");
        assert_eq!(result.1, sha);
    }

    #[test]
    fn find_latest_no_matching_target() {
        let sha = valid_sha().to_string();
        let records = vec![("0.1.0".to_string(), "linux".to_string(), sha)];
        assert!(find_latest_for_target(&records, "macos").is_none());
    }

    // --- sha256_file ---

    #[test]
    fn sha256_file_known_content() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.bin");
        let content = b"hello world";
        std::fs::write(&path, content).unwrap();

        let result = sha256_file(&path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(content);
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(result, expected);
    }

    // --- atomic_write ---

    #[test]
    fn atomic_write_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");
        atomic_write(&path, b"test data").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "test data");
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("output.txt");
        std::fs::write(&path, "old").unwrap();
        atomic_write(&path, b"new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    // --- redact_config_keys ---

    #[test]
    fn redact_long_api_key() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "sk-1234567890abcdef""#).unwrap();
        redact_config_keys(&mut val);
        let s = val.get("api_key").unwrap().as_str().unwrap();
        assert_eq!(s, "sk-1...cdef");
    }

    #[test]
    fn redact_short_api_key() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "short""#).unwrap();
        redact_config_keys(&mut val);
        let s = val.get("api_key").unwrap().as_str().unwrap();
        assert_eq!(s, "****");
    }

    #[test]
    fn redact_exactly_8_chars() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "12345678""#).unwrap();
        redact_config_keys(&mut val);
        let s = val.get("api_key").unwrap().as_str().unwrap();
        assert_eq!(s, "****");
    }

    #[test]
    fn redact_nested_tables() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [provider]
            api_key = "sk-abcdefghijklmnop"
            [provider.sub]
            api_key = "tiny"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        let outer = val["provider"]["api_key"].as_str().unwrap();
        assert!(outer.contains("..."));
        let inner = val["provider"]["sub"]["api_key"].as_str().unwrap();
        assert_eq!(inner, "****");
    }

    #[test]
    fn redact_array_of_tables() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [[providers]]
            api_key = "sk-longkeyvalue1234"
            [[providers]]
            name = "other"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        let first = val["providers"][0]["api_key"].as_str().unwrap();
        assert!(first.contains("..."));
    }

    #[test]
    fn redact_no_api_key() {
        let mut val: toml::Value = toml::from_str(r#"name = "hello""#).unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["name"].as_str().unwrap(), "hello");
    }

    // --- should_check_for_updates ---

    #[test]
    fn should_check_no_previous_check() {
        let db = db::Db::open_in_memory().unwrap();
        assert!(should_check_for_updates(&db));
    }

    #[test]
    fn should_check_recent_check() {
        let db = db::Db::open_in_memory().unwrap();
        db.set_meta("last_update_check", &chrono::Utc::now().to_rfc3339())
            .unwrap();
        assert!(!should_check_for_updates(&db));
    }

    #[test]
    fn should_check_old_check() {
        let db = db::Db::open_in_memory().unwrap();
        let old = chrono::Utc::now() - chrono::Duration::hours(25);
        db.set_meta("last_update_check", &old.to_rfc3339()).unwrap();
        assert!(should_check_for_updates(&db));
    }

    #[test]
    fn should_check_invalid_timestamp() {
        let db = db::Db::open_in_memory().unwrap();
        db.set_meta("last_update_check", "not-a-date").unwrap();
        assert!(should_check_for_updates(&db));
    }

    // --- parse_dns_txt_records (additional edge cases) ---

    #[test]
    fn parse_dns_sha_63_chars() {
        let short_sha = &valid_sha()[..63];
        let input = format!("0.1.0:target:{short_sha}");
        let records = parse_dns_txt_records(&input);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_sha_65_chars() {
        let long_sha = format!("{}a", valid_sha());
        let input = format!("0.1.0:target:{long_sha}");
        let records = parse_dns_txt_records(&input);
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_multiple_valid() {
        let sha = valid_sha();
        let input = format!("0.1.0:linux:{sha}\n0.2.0:macos:{sha}\n0.3.0:windows:{sha}");
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].1, "linux");
        assert_eq!(records[1].1, "macos");
        assert_eq!(records[2].1, "windows");
    }

    #[test]
    fn parse_dns_extra_whitespace() {
        let sha = valid_sha();
        let input = format!("  0.1.0:target:{sha}  ");
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "0.1.0");
    }

    #[test]
    fn parse_dns_colons_in_version_uses_splitn() {
        let sha = valid_sha();
        let input = format!("0.1.0:target:with:extra:{sha}");
        let records = parse_dns_txt_records(&input);
        assert!(records.is_empty());
    }

    // --- find_latest_for_target (additional edge cases) ---

    #[test]
    fn find_latest_multiple_versions_same_target() {
        let sha1 = valid_sha().to_string();
        let sha2 = "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let records = vec![
            ("0.1.0".to_string(), "linux".to_string(), sha1.clone()),
            ("0.5.0".to_string(), "linux".to_string(), sha2.clone()),
            (
                "0.3.0".to_string(),
                "linux".to_string(),
                "aaa0000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
            (
                "0.2.0".to_string(),
                "linux".to_string(),
                "bbb0000000000000000000000000000000000000000000000000000000000000".to_string(),
            ),
        ];
        let result = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(result.0, "0.5.0");
        assert_eq!(result.1, sha2);
    }

    #[test]
    fn find_latest_same_version_different_targets() {
        let sha_linux = valid_sha().to_string();
        let sha_macos =
            "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let records = vec![
            ("0.2.0".to_string(), "linux".to_string(), sha_linux.clone()),
            ("0.2.0".to_string(), "macos".to_string(), sha_macos.clone()),
        ];
        let linux = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(linux.1, sha_linux);
        let macos = find_latest_for_target(&records, "macos").unwrap();
        assert_eq!(macos.1, sha_macos);
    }

    #[test]
    fn find_latest_empty_version_string() {
        let sha = valid_sha().to_string();
        let records = vec![("".to_string(), "linux".to_string(), sha.clone())];
        let result = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(result.0, "");
        assert_eq!(result.1, sha);
    }

    // --- sha256_file (additional edge cases) ---

    #[test]
    fn sha256_file_large_content() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        let content = vec![0xABu8; 16 * 1024];
        std::fs::write(&path, &content).unwrap();

        let result = sha256_file(&path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(result, expected);
    }

    #[test]
    fn sha256_file_empty() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, b"").unwrap();

        let result = sha256_file(&path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"");
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(result, expected);
    }

    #[test]
    fn sha256_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.bin");
        assert!(sha256_file(&path).is_err());
    }

    // --- atomic_write (additional edge cases) ---

    #[test]
    fn atomic_write_nonexistent_directory() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_such_dir").join("file.txt");
        assert!(atomic_write(&path, b"data").is_err());
    }

    // --- redact_config_keys (additional edge cases) ---

    #[test]
    fn redact_deeply_nested_api_key() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [a.b.c]
            api_key = "sk-deep-nested-key-value"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        let s = val["a"]["b"]["c"]["api_key"].as_str().unwrap();
        assert!(s.contains("..."));
        assert!(!s.contains("deep"));
    }

    #[test]
    fn redact_array_containing_tables_with_api_key() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [[services]]
            name = "svc1"
            api_key = "sk-array-table-key99"

            [[services]]
            name = "svc2"
            api_key = "sk-another-key-here"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        let k1 = val["services"][0]["api_key"].as_str().unwrap();
        let k2 = val["services"][1]["api_key"].as_str().unwrap();
        assert!(k1.contains("..."));
        assert!(k2.contains("..."));
        assert_eq!(val["services"][0]["name"].as_str().unwrap(), "svc1");
    }

    #[test]
    fn redact_api_key_exactly_8_chars_boundary() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "abcdefgh""#).unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["api_key"].as_str().unwrap(), "****");
    }

    #[test]
    fn redact_api_key_7_chars() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "abcdefg""#).unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["api_key"].as_str().unwrap(), "****");
    }

    #[test]
    fn redact_api_key_9_chars() {
        let mut val: toml::Value = toml::from_str(r#"api_key = "abcdefghi""#).unwrap();
        redact_config_keys(&mut val);
        let s = val["api_key"].as_str().unwrap();
        assert_eq!(s, "abcd...fghi");
    }

    #[test]
    fn redact_multiple_api_keys_different_subtables() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [provider_a]
            api_key = "sk-provider-a-longkey"
            [provider_b]
            api_key = "short"
            [provider_c]
            api_key = "sk-provider-c-longkey"
            other = "untouched"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        let a = val["provider_a"]["api_key"].as_str().unwrap();
        let b = val["provider_b"]["api_key"].as_str().unwrap();
        let c = val["provider_c"]["api_key"].as_str().unwrap();
        assert!(a.contains("..."));
        assert_eq!(b, "****");
        assert!(c.contains("..."));
        assert_eq!(val["provider_c"]["other"].as_str().unwrap(), "untouched");
    }

    #[test]
    fn redact_non_string_api_key() {
        let mut val: toml::Value = toml::from_str(r#"api_key = 12345"#).unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["api_key"].as_integer().unwrap(), 12345);
    }

    // --- cleanup_staged_updates (logic pattern tests) ---

    #[test]
    fn cleanup_staged_updates_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let updates_dir = dir.path().join("updates");
        std::fs::create_dir_all(&updates_dir).unwrap();
        let entries: Vec<_> = std::fs::read_dir(&updates_dir).unwrap().flatten().collect();
        assert!(entries.is_empty());
    }

    #[test]
    fn cleanup_staged_updates_no_dir() {
        let dir = tempfile::tempdir().unwrap();
        let updates_dir = dir.path().join("updates");
        assert!(!updates_dir.exists());
    }

    // --- current_target_triple ---

    #[test]
    fn current_target_triple_is_known_value() {
        let triple = current_target_triple();
        if let Some(t) = triple {
            let known = [
                "aarch64-apple-darwin",
                "x86_64-apple-darwin",
                "i686-unknown-freebsd",
                "x86_64-unknown-freebsd",
                "i686-unknown-linux-gnu",
                "x86_64-unknown-linux-gnu",
                "aarch64-unknown-linux-gnu",
                "riscv64gc-unknown-linux-gnu",
            ];
            assert!(known.contains(&t), "unexpected triple: {t}");
        }
    }

    // --- redact_config_keys (empty table, non-string api_key_cmd, deep no api_key) ---

    #[test]
    fn redact_empty_table() {
        let mut val: toml::Value = toml::Value::Table(toml::map::Map::new());
        redact_config_keys(&mut val);
        assert_eq!(val.as_table().unwrap().len(), 0);
    }

    #[test]
    fn redact_non_string_api_key_bool() {
        let mut val: toml::Value = toml::from_str("api_key = true").unwrap();
        redact_config_keys(&mut val);
        assert!(val["api_key"].as_bool().unwrap());
    }

    #[test]
    fn redact_api_key_cmd_not_redacted() {
        let mut val: toml::Value = toml::from_str(
            r#"
            api_key_cmd = "pass show openai"
            api_key = "sk-longapikey12345678"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["api_key_cmd"].as_str().unwrap(), "pass show openai");
        assert!(val["api_key"].as_str().unwrap().contains("..."));
    }

    #[test]
    fn redact_deeply_nested_no_api_key() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [a.b.c.d]
            name = "deep"
            value = 42
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["a"]["b"]["c"]["d"]["name"].as_str().unwrap(), "deep");
        assert_eq!(val["a"]["b"]["c"]["d"]["value"].as_integer().unwrap(), 42);
    }

    // --- apply_pending_update (missing update_pending file) ---

    #[test]
    fn apply_pending_update_no_pending_file_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let pending = dir.path().join("update_pending");
        assert!(!pending.exists());
    }

    // --- should_check_for_updates (boundary at exactly 24 hours) ---

    #[test]
    fn should_check_exactly_24_hours() {
        let db = db::Db::open_in_memory().unwrap();
        let exactly_24h = chrono::Utc::now() - chrono::Duration::hours(24);
        db.set_meta("last_update_check", &exactly_24h.to_rfc3339())
            .unwrap();
        assert!(should_check_for_updates(&db));
    }

    #[test]
    fn should_check_23_hours_59_min() {
        let db = db::Db::open_in_memory().unwrap();
        let almost = chrono::Utc::now() - chrono::Duration::minutes(23 * 60 + 59);
        db.set_meta("last_update_check", &almost.to_rfc3339())
            .unwrap();
        assert!(!should_check_for_updates(&db));
    }

    // --- find_latest_for_target (equal versions, first wins) ---

    #[test]
    fn find_latest_equal_versions_keeps_first() {
        let sha_a = valid_sha().to_string();
        let sha_b = "1111111111111111111111111111111111111111111111111111111111111111".to_string();
        let records = vec![
            ("1.0.0".to_string(), "linux".to_string(), sha_a.clone()),
            ("1.0.0".to_string(), "linux".to_string(), sha_b.clone()),
        ];
        let result = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(result.0, "1.0.0");
        assert_eq!(result.1, sha_a);
    }

    // --- parse_dns_txt_records (malformed entries) ---

    #[test]
    fn parse_dns_only_one_colon() {
        let records = parse_dns_txt_records("version:target");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_no_colons() {
        let records = parse_dns_txt_records("justplaintext");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_dns_sha_non_hex() {
        let bad_sha = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        let input = format!("0.1.0:target:{bad_sha}");
        let records = parse_dns_txt_records(&input);
        assert!(records.is_empty());
    }

    // --- sha256_file (binary content) ---

    #[test]
    fn sha256_file_binary_content() {
        use sha2::{Digest, Sha256};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("binary.bin");
        let content: Vec<u8> = (0..=255).collect();
        std::fs::write(&path, &content).unwrap();

        let result = sha256_file(&path).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let expected = format!("{:x}", hasher.finalize());
        assert_eq!(result, expected);
    }

    // --- atomic_write (overwrite preserves content) ---

    #[test]
    fn atomic_write_overwrite_multiple_times() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.txt");
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"second").unwrap();
        atomic_write(&path, b"third").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third");
    }

    // --- util::compare_versions (exercised from main.rs test module) ---

    #[test]
    fn compare_versions_non_numeric_components() {
        assert_eq!(
            util::compare_versions("abc.def", "1.2"),
            std::cmp::Ordering::Less
        );
    }

    #[test]
    fn compare_versions_empty_string() {
        assert_eq!(util::compare_versions("", ""), std::cmp::Ordering::Equal);
        assert_eq!(
            util::compare_versions("", "0.0.1"),
            std::cmp::Ordering::Less
        );
    }

    // --- current_target_triple (macOS-specific) ---

    #[cfg(target_os = "macos")]
    #[test]
    fn current_target_triple_returns_some_on_macos() {
        let triple = current_target_triple().unwrap();
        assert!(triple.ends_with("-apple-darwin"));
    }

    #[test]
    fn redact_api_key_cmd_string_in_subtable() {
        let mut val: toml::Value = toml::from_str(
            r#"
            [provider]
            api_key_cmd = "security find-generic-password -s openai"
            api_key = "sk-subtable-longkey123"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        assert_eq!(
            val["provider"]["api_key_cmd"].as_str().unwrap(),
            "security find-generic-password -s openai"
        );
        assert!(val["provider"]["api_key"].as_str().unwrap().contains("..."));
    }

    #[test]
    fn redact_api_key_empty_string() {
        let mut val: toml::Value = toml::from_str(r#"api_key = """#).unwrap();
        redact_config_keys(&mut val);
        assert_eq!(val["api_key"].as_str().unwrap(), "****");
    }

    #[test]
    fn redact_only_api_key_leaves_other_keys_intact() {
        let mut val: toml::Value = toml::from_str(
            r#"
            api_key = "sk-secret-longapikey"
            model = "gpt-4"
            base_url = "https://api.example.com"
            api_key_cmd = "echo secret"
            "#,
        )
        .unwrap();
        redact_config_keys(&mut val);
        assert!(val["api_key"].as_str().unwrap().contains("..."));
        assert_eq!(val["model"].as_str().unwrap(), "gpt-4");
        assert_eq!(val["base_url"].as_str().unwrap(), "https://api.example.com");
        assert_eq!(val["api_key_cmd"].as_str().unwrap(), "echo secret");
    }

    #[test]
    fn find_latest_for_target_no_match() {
        let records = vec![(
            "1.0.0".to_string(),
            "linux".to_string(),
            valid_sha().to_string(),
        )];
        let result = find_latest_for_target(&records, "macos");
        assert!(result.is_none());
    }

    #[test]
    fn find_latest_for_target_picks_highest_version() {
        let sha = valid_sha().to_string();
        let records = vec![
            ("0.1.0".to_string(), "linux".to_string(), sha.clone()),
            ("0.3.0".to_string(), "linux".to_string(), sha.clone()),
            ("0.2.0".to_string(), "linux".to_string(), sha.clone()),
        ];
        let result = find_latest_for_target(&records, "linux").unwrap();
        assert_eq!(result.0, "0.3.0");
    }

    #[test]
    fn parse_dns_multiple_lines() {
        let sha1 = valid_sha();
        let sha2 = "1111111111111111111111111111111111111111111111111111111111111111";
        let input =
            format!("0.1.0:aarch64-apple-darwin:{sha1}\n0.2.0:x86_64-unknown-linux-gnu:{sha2}\n");
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].0, "0.1.0");
        assert_eq!(records[1].0, "0.2.0");
    }

    #[test]
    fn parse_dns_quoted_line() {
        let sha = valid_sha();
        let input = format!("\"0.1.0:target:{sha}\"");
        let records = parse_dns_txt_records(&input);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].0, "0.1.0");
    }
}
