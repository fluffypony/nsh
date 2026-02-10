mod ansi;
mod audit;
mod cli;
mod config;
mod context;
mod daemon;
mod daemon_client;
mod db;
mod display;
mod history_import;
mod init;
mod json_display;
mod json_extract;
#[allow(dead_code)]
mod mcp;
mod provider;
mod pty;
mod pump;
mod query;
mod redact;
mod security;
mod shell_hooks;
mod skills;
#[allow(dead_code)]
mod stream_consumer;
mod streaming;
mod summary;
mod tools;
mod util;

use clap::Parser;
use cli::{
    Cli, Commands, ConfigAction, DaemonReadAction, DaemonSendAction, HistoryAction, ProviderAction,
    SessionAction,
};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    security::secure_nsh_directory();

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { shell } => {
            let script = init::generate_init_script(&shell);
            print!("{script}");
        }

        Commands::Wrap { shell } => {
            apply_pending_update();

            if let Ok(db) = db::Db::open() {
                let _ = db.cleanup_orphaned_sessions();
                if should_check_for_updates(&db) {
                    std::thread::spawn(|| {
                        let _ = background_update_check();
                    });
                }
            }

            if config::Config::nsh_dir().join("update_pending").exists() {
                eprintln!("\x1b[2mnsh: update ready, will apply on next shell start\x1b[0m");
            }

            let shell = if shell.is_empty() {
                std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
            } else {
                shell
            };
            pty::run_wrapped_shell(&shell)?;
        }

        Commands::Query {
            words,
            think,
            private,
            json: _,
        } => {
            if words.is_empty() {
                eprintln!("Usage: ? <your question>");
                std::process::exit(1);
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
            let (_query_text, _force_autorun) = if query_text.ends_with("!!") {
                (query_text[..query_text.len() - 2].trim().to_string(), true)
            } else {
                (query_text, false)
            };
            let query_text = _query_text;
            let config = config::Config::load()?;
            let db = db::Db::open()?;
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
            if private {
                eprintln!("\x1b[2m🔒 private mode\x1b[0m");
            }
            query::handle_query(&query_text, &config, &db, &session_id, think, private).await?;
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
            let db = db::Db::open()?;
            db.insert_command(
                &session,
                &command,
                &cwd,
                Some(exit_code),
                &started_at,
                duration_ms,
                None,
                &tty,
                &shell,
                pid,
            )?;

            if let Ok(Some((conv_id, suggested_cmd))) = db.find_pending_conversation(&session) {
                if command.trim() == suggested_cmd.trim() {
                    let _ = db.update_conversation_result(conv_id, exit_code, None);
                }
            }
        }

        Commands::Session { action } => match action {
            SessionAction::Start {
                session,
                tty,
                shell,
                pid,
            } => {
                let db = db::Db::open()?;
                db.create_session(&session, &tty, &shell, pid as i64)?;
            }
            SessionAction::End { session } => {
                let db = db::Db::open()?;
                db.end_session(&session)?;
                shell_hooks::cleanup_pending_files(&session);
            }
            SessionAction::Label { label, session } => {
                let session_id = session.unwrap_or_else(|| {
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
                });
                let db = db::Db::open()?;
                if db.set_session_label(&session_id, &label)? {
                    eprintln!("nsh: session labeled \"{label}\"");
                } else {
                    eprintln!("nsh: session not found");
                }
            }
        },

        Commands::History { action } => match action {
            HistoryAction::Search { query, limit } => {
                let db = db::Db::open()?;
                let results = db.search_history(&query, limit)?;
                for r in &results {
                    let code = r
                        .exit_code
                        .map(|c| format!(" (exit {c})"))
                        .unwrap_or_default();
                    println!("[{}]{} {}", r.started_at, code, r.cmd_highlight);
                    if let Some(hl) = &r.output_highlight {
                        let preview: String = hl.chars().take(200).collect();
                        println!("  {preview}");
                    }
                }
                if results.is_empty() {
                    eprintln!("No results found.");
                }
            }
        },

        Commands::Reset => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
            let db = db::Db::open()?;
            db.clear_conversations(&session_id)?;
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
            let db = db::Db::open()?;
            let since = match period.as_str() {
                "today" => Some("datetime('now', '-1 day')"),
                "week" => Some("datetime('now', '-7 days')"),
                "month" => Some("datetime('now', '-30 days')"),
                "all" => None,
                _ => Some("datetime('now', '-30 days')"),
            };
            let stats = db.get_usage_stats(since)?;
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
                for (model, calls, input_tok, output_tok, cost) in &stats {
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
            no_prune,
            no_vacuum,
            prune_days,
        } => {
            let config = config::Config::load().unwrap_or_default();
            let db = db::Db::open()?;
            let retention = prune_days.unwrap_or(config.context.retention_days);
            db.run_doctor(retention, no_prune, no_vacuum, &config)?;
            cleanup_staged_updates();
        }

        Commands::Heartbeat { session } => {
            let db = db::Db::open()?;
            db.update_heartbeat(&session)?;
        }

        Commands::RedactNext => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
            let flag_path = config::Config::nsh_dir().join(format!("redact_next_{session_id}"));
            std::fs::write(&flag_path, "")?;
            eprintln!("nsh: next command output will not be captured");
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
            atomic_write(&pending_path, serde_json::to_string_pretty(&pending_info)?.as_bytes())?;

            eprintln!("nsh: update v{version} downloaded and verified.");
            eprintln!("  It will be applied automatically on your next shell start.");
        }

        Commands::DaemonSend { action } => {
            let session_id = match &action {
                DaemonSendAction::Record { session, .. } => session.clone(),
                DaemonSendAction::Heartbeat { session } => session.clone(),
                DaemonSendAction::CaptureMark { session } => session.clone(),
                DaemonSendAction::Status => {
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into())
                }
            };

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
                        let db = db::Db::open()?;
                        db.insert_command(
                            &session,
                            &command,
                            &cwd,
                            Some(exit_code),
                            &started_at,
                            duration_ms,
                            None,
                            &tty,
                            &shell,
                            pid,
                        )?;
                    }
                    DaemonSendAction::Heartbeat { session } => {
                        let db = db::Db::open()?;
                        db.update_heartbeat(&session)?;
                    }
                    DaemonSendAction::CaptureMark { .. } => {}
                    DaemonSendAction::Status => {
                        eprintln!("nsh: daemon not running");
                    }
                },
            }
        }

        Commands::DaemonRead { action } => {
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
            let config = config::Config::load()?;
            streaming::configure_display(&config.display);
            let db = db::Db::open()?;
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
                if let Err(e) =
                    query::handle_query(line, &config, &db, &session_id, false, false).await
                {
                    eprintln!("\x1b[33mnsh: {e}\x1b[0m");
                }
            }
        }

        Commands::Export { format, session } => {
            let session_id =
                session.unwrap_or_else(|| std::env::var("NSH_SESSION_ID").unwrap_or_default());
            let db = db::Db::open()?;
            let convos = db.get_conversations(&session_id, 1000)?;
            if convos.is_empty() {
                eprintln!("No conversations found for session {session_id}");
            } else {
                match format.as_deref().unwrap_or("markdown") {
                    "json" => {
                        let json_convos: Vec<serde_json::Value> = convos
                            .iter()
                            .map(|c| {
                                serde_json::json!({
                                    "query": c.query,
                                    "response_type": c.response_type,
                                    "response": c.response,
                                    "explanation": c.explanation,
                                })
                            })
                            .collect();
                        println!("{}", serde_json::to_string_pretty(&json_convos)?);
                    }
                    _ => {
                        for c in &convos {
                            println!("**Q:** {}\n", c.query);
                            match c.response_type.as_str() {
                                "command" => println!(
                                    "```bash\n{}\n```\n{}\n",
                                    c.response,
                                    c.explanation.as_deref().unwrap_or("")
                                ),
                                _ => println!("{}\n", c.response),
                            }
                        }
                    }
                }
            }
        }

        Commands::Status => {
            let session_id = std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "(not set)".into());
            let config = config::Config::load().unwrap_or_default();
            let db = db::Db::open()?;
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
                db.get_session_label(&session_id).unwrap_or(None)
            } else {
                None
            };

            eprintln!("nsh status:");
            eprintln!("  Session:    {session_id}");
            if let Some(label) = session_label {
                eprintln!("  Label:      {label}");
            }
            eprintln!("  Shell:      {shell}");
            eprintln!("  PTY active: {}", if pty_active { "yes" } else { "no" });
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
    }

    Ok(())
}

fn parse_dns_txt_records(raw: &str) -> Vec<(String, String, String)> {
    raw.lines()
        .filter_map(|line| {
            let cleaned = line.trim().trim_matches('"');
            let parts: Vec<&str> = cleaned.splitn(3, ':').collect();
            if parts.len() == 3 {
                let (version, target, sha) = (parts[0], parts[1], parts[2]);
                if sha.len() == 64 && sha.chars().all(|c| c.is_ascii_hexdigit()) {
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
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
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
        std::fs::rename(&new_path, &current_exe)?;

        let _ = std::fs::remove_file(&pending_path);
        let _ = std::fs::remove_file(&staged_path);

        eprintln!("nsh: updated to v{version}");

        let exe_path = current_exe.to_string_lossy().to_string();
        let args: Vec<String> = std::env::args().collect();
        if !args.is_empty() {
            let mut new_args = vec![exe_path.as_str()];
            for a in args.iter().skip(1) {
                new_args.push(a.as_str());
            }
            let _err = pty::exec_execvp(&exe_path, &new_args);
        }
        Ok(())
    })();
    if let Err(e) = result {
        tracing::debug!("apply_pending_update failed: {e}");
    }
}

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

fn background_update_check() -> anyhow::Result<()> {
    let target = current_target_triple().ok_or_else(|| anyhow::anyhow!("unsupported platform"))?;
    let current_version = env!("CARGO_PKG_VERSION");

    let records = resolve_update_txt_fallback()?;
    let (latest_version, expected_sha) =
        find_latest_for_target(&records, target).ok_or_else(|| {
            anyhow::anyhow!("no DNS record for {target}")
        })?;

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
    let tmp_staged = staging_dir.join(format!("nsh-{latest_version}-{target}.{}", std::process::id()));

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
    atomic_write(&pending_path, serde_json::to_string_pretty(&pending_info)?.as_bytes())?;

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
                        if s.len() > 8 {
                            *s = format!("{}...{}", &s[..4], &s[s.len() - 4..]);
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
