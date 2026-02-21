// Library root for nsh: exposes modules and shared main entry for binaries.

pub mod ansi;
pub mod audit;
pub mod autoconfigure;
pub mod cli;
pub mod coding_agent;
pub mod config;
pub mod context;
pub mod daemon;
pub mod daemon_client;
pub mod daemon_db;
pub mod db;
pub mod debug_io;
pub mod display;
pub mod fast_cwd;
#[cfg(unix)]
pub mod global_daemon;
pub mod history_import;
pub mod init;
pub mod json_display;
pub mod json_extract;
#[allow(dead_code)]
pub mod mcp;
pub mod memory;
pub mod live_update;
pub mod provider;
#[cfg(unix)]
pub mod pty;
#[cfg(windows)]
#[path = "pty_windows.rs"]
pub mod pty;
pub mod pump;
pub mod query;
pub mod redact;
pub mod security;
pub mod shell_hooks;
pub mod skills;
pub mod stream_consumer;
pub mod streaming;
pub mod summary;
pub mod tools;
pub mod util;

pub mod shim;

use clap::Parser;
use cli::{
    Cli, Commands, ConfigAction, DaemonReadAction, DaemonSendAction, DoctorAction, HistoryAction,
    MemoryAction, ProviderAction, SessionAction,
};
use sha2::{Digest, Sha256};
use crate::daemon_db::DbAccess;

fn ensure_daemon_ready(json: bool) -> anyhow::Result<bool> {
    if daemon_client::is_global_daemon_running() {
        let _ = daemon_client::ensure_daemon_version_matches();
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
    // Use robust retry path to bridge brief restarts
    #[cfg(unix)]
    {
        return daemon_client::send_to_global_with_retry(request.clone());
    }
    #[cfg(not(unix))]
    {
        return daemon_client::send_to_global(request);
    }
}

/// Send SIGHUP to the running daemon for immediate graceful restart.
/// Falls back to writing a marker file (for non-Unix).
fn signal_daemon_restart() {
    #[cfg(unix)]
    {
        if daemon_client::signal_daemon_restart() {
            return;
        }
    }
    let marker = config::Config::nsh_dir().join("nshd_restart_pending");
    let _ = std::fs::write(&marker, "");
}

pub fn main_inner() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Capture binary state early
    live_update::snapshot_binary_meta();

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

    // Do not handle Wrap here — shim handles it directly

    // Apply pending update for commands (no re-exec; shim delegates new core next run)
    apply_pending_update(false);

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

        Commands::Init { shell, hash } => {
            if hash {
                println!("{}", env!("NSH_HOOK_HASH"));
                return Ok(());
            }
            // Clear stale update markers since this is a fresh shell session
            let nsh_dir = config::Config::nsh_dir();
            let _ = std::fs::remove_file(nsh_dir.join("update_notice"));
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
                let max_pipe_bytes: u64 = 33000;
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
            let session_for_checks = session.clone();
            let request = daemon::DaemonRequest::Record {
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
            check_daemon_versions(&session_for_checks);
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
                eprint!("  Shell hooks version... ");
                match std::env::var("NSH_HOOK_HASH") {
                    Ok(v) if v == env!("NSH_HOOK_HASH") => eprintln!("OK"),
                    Ok(v) => eprintln!(
                        "OUTDATED (hooks={}, binary={})",
                        &v[..8],
                        &env!("NSH_HOOK_HASH")[..8]
                    ),
                    Err(_) => eprintln!("unknown (not in an nsh-wrapped shell)"),
                }
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
            eprint!("nsh: signaling daemon restart...");
            signal_daemon_restart();
            std::thread::sleep(std::time::Duration::from_millis(1000));
            daemon_client::ensure_global_daemon_running()?;
            eprintln!(" done");
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

            // Immediately apply update by installing as ~/.nsh/bin/nsh-core
            apply_pending_update(false);
            signal_daemon_restart();
            eprintln!("nsh: update applied, daemon will restart gracefully");
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
                    let request = daemon::DaemonRequest::MemoryExportAll;
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            println!("{}", serde_json::to_string_pretty(&d)?);
                        }
                        resp => eprintln!("{resp:?}"),
                    }
                }
                MemoryAction::Telemetry => {
                    let request = daemon::DaemonRequest::MemoryStats;
                    match send_to_global_or_fallback(&request)? {
                        daemon::DaemonResponse::Ok { data: Some(d) } => {
                            let telem = serde_json::json!({
                                "decay_runs": d.get("decay_runs").cloned().unwrap_or(serde_json::json!(0)),
                                "last_decay_at": d.get("last_decay_at").cloned().unwrap_or(serde_json::json!("")),
                                "reflection_runs": d.get("reflection_runs").cloned().unwrap_or(serde_json::json!(0)),
                                "last_reflection_at": d.get("last_reflection_at").cloned().unwrap_or(serde_json::json!("")),
                            });
                            println!("{}", serde_json::to_string_pretty(&telem)?);
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
            check_daemon_versions(&session_id);
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
                    let notice = config::Config::nsh_dir().join("update_notice");
                    if notice.exists() {
                        eprintln!(
                            "\x1b[2m⟳ nsh updated — exit and re-run for latest hooks\x1b[0m"
                        );
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
                            println!("**Q:** {query}\n");
                            match response_type {
                                "command" => {
                                    println!("```bash\n{response}\n```\n{explanation}\n")
                                }
                                _ => println!("{response}\n"),
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
            let hooks_outdated = std::env::var("NSH_HOOK_HASH")
                .map(|h| h != env!("NSH_HOOK_HASH"))
                .unwrap_or(false);
            eprintln!(
                "  Hooks:      {}",
                if hooks_outdated {
                    "outdated (run `exec $SHELL` or open new terminal)"
                } else {
                    "current"
                }
            );
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

fn apply_pending_update(_reexec: bool) {
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

        // Install as ~/.nsh/bin/nsh-core (atomic swap)
        let core_dir = config::Config::nsh_dir().join("bin");
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

        // Write an update notice for shell hooks
        let notice_path = config::Config::nsh_dir().join("update_notice");
        let _ = std::fs::write(
            &notice_path,
            format!("v{version} installed — queries active immediately, shell hooks refresh on next terminal"),
        );

        // Signal daemon to restart to pick up new core
        signal_daemon_restart();

        Ok(())
    })();
    if let Err(e) = result {
        tracing::debug!("apply_pending_update failed: {e}");
    }
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

fn check_daemon_versions(session_id: &str) {
    let current_version = env!("CARGO_PKG_VERSION");

    // Check global daemon version; if outdated, request restart
    if let Ok(crate::daemon::DaemonResponse::Ok { data: Some(d) }) =
        daemon_client::send_to_global(&crate::daemon::DaemonRequest::Status)
    {
        if let Some(v) = d.get("version").and_then(|v| v.as_str()) {
            if v != current_version {
                tracing::info!("Global daemon version {} is outdated; signaling restart", v);
                let _ = daemon_client::signal_daemon_restart();
                let _ = daemon_client::ensure_global_daemon_running();
            }
        }
    }

    // Per-session daemon notices are intentionally skipped with shim/core split
    let _ = session_id;
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
