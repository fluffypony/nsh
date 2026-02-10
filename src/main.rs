mod ansi;
mod audit;
mod cli;
mod config;
mod context;
mod daemon;
mod daemon_client;
mod db;
mod display;
mod init;
mod json_display;
mod json_extract;
mod mcp;
mod provider;
mod pty;
mod pump;
mod query;
mod redact;
mod security;
mod shell_hooks;
mod skills;
mod summary;
mod stream_consumer;
mod streaming;
mod tools;
mod util;

use clap::Parser;
use cli::{Cli, Commands, ConfigAction, DaemonReadAction, DaemonSendAction, HistoryAction, ProviderAction, SessionAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env(),
        )
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
            if let Ok(db) = db::Db::open() {
                let _ = db.cleanup_orphaned_sessions();
            }
            let shell = if shell.is_empty() {
                std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
            } else {
                shell
            };
            pty::run_wrapped_shell(&shell)?;
        }

        Commands::Query { words, think, private, json: _ } => {
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
                std::io::stdin().take(max_pipe_bytes).read_to_string(&mut piped)?;
                if !piped.is_empty() {
                    let truncated = crate::util::truncate(&piped, 32000);
                    query_text = format!("<piped_input>\n{truncated}\n</piped_input>\n\n{query_text}");
                }
            }

            // Auto-run suffix: strip trailing !!
            let (_query_text, _force_autorun) = if query_text.ends_with("!!") {
                (query_text[..query_text.len()-2].trim().to_string(), true)
            } else {
                (query_text, false)
            };
            let query_text = _query_text;
            let config = config::Config::load()?;
            let db = db::Db::open()?;
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| "default".into());
            if private {
                eprintln!("\x1b[2m🔒 private mode\x1b[0m");
            }
            query::handle_query(&query_text, &config, &db, &session_id, think, private)
                .await?;
        }

        Commands::Record {
            session,
            command,
            cwd,
            exit_code,
            started_at,
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
                None,
                None,
                &tty,
                &shell,
                pid,
            )?;
        }

        Commands::Session { action } => match action {
            SessionAction::Start { session, tty, shell, pid } => {
                let db = db::Db::open()?;
                db.create_session(&session, &tty, &shell, pid as i64)?;
            }
            SessionAction::End { session } => {
                let db = db::Db::open()?;
                db.end_session(&session)?;
                shell_hooks::cleanup_pending_files(&session);
            }
            SessionAction::Label { label, session } => {
                let session_id = session.unwrap_or_else(||
                    std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into()));
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
                    println!(
                        "[{}]{} {}",
                        r.started_at, code, r.cmd_highlight
                    );
                    if let Some(hl) = &r.output_highlight {
                        let preview: String =
                            hl.chars().take(200).collect();
                        println!("  {preview}");
                    }
                }
                if results.is_empty() {
                    eprintln!("No results found.");
                }
            }
        },

        Commands::Reset => {
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| "default".into());
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
                let editor =
                    std::env::var("EDITOR").unwrap_or_else(|_| "vi".into());
                let path = config::Config::path();
                let dir = path.parent().unwrap();
                std::fs::create_dir_all(dir)?;
                std::process::Command::new(&editor)
                    .arg(&path)
                    .status()?;
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
                eprintln!("Model                               Calls  Input Tok  Output Tok  Cost (USD)");
                eprintln!("─────────────────────────────────────────────────────────────────────────────");
                let mut total_cost = 0.0_f64;
                let mut total_calls = 0_i64;
                for (model, calls, input_tok, output_tok, cost) in &stats {
                    eprintln!(
                        "{:<35} {:>5}  {:>9}  {:>10}  ${:.4}",
                        model, calls, input_tok, output_tok, cost
                    );
                    total_cost += cost;
                    total_calls += calls;
                }
                eprintln!("─────────────────────────────────────────────────────────────────────────────");
                eprintln!("{:<35} {:>5}                        ${:.4}", "TOTAL", total_calls, total_cost);
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

        Commands::Doctor => {
            let config = config::Config::load().unwrap_or_default();
            let db = db::Db::open()?;
            db.run_doctor(config.context.retention_days)?;
        }

        Commands::Heartbeat { session } => {
            let db = db::Db::open()?;
            db.update_heartbeat(&session)?;
        }

        Commands::RedactNext => {
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| "default".into());
            let flag_path = config::Config::nsh_dir()
                .join(format!("redact_next_{session_id}"));
            std::fs::write(&flag_path, "")?;
            eprintln!("nsh: next command output will not be captured");
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
                    session, command, cwd, exit_code, started_at,
                    tty, pid, shell,
                } => daemon::DaemonRequest::Record {
                    session: session.clone(),
                    command: command.clone(),
                    cwd: cwd.clone(),
                    exit_code: *exit_code,
                    started_at: started_at.clone(),
                    tty: tty.clone(),
                    pid: *pid,
                    shell: shell.clone(),
                    duration_ms: None,
                    output: None,
                },
                DaemonSendAction::Heartbeat { session } => {
                    daemon::DaemonRequest::Heartbeat { session: session.clone() }
                }
                DaemonSendAction::CaptureMark { session } => {
                    daemon::DaemonRequest::CaptureMark { session: session.clone() }
                }
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
                            session, command, cwd, exit_code, started_at,
                            tty, pid, shell,
                        } => {
                            let db = db::Db::open()?;
                            db.insert_command(
                                &session, &command, &cwd, Some(exit_code),
                                &started_at, None, None, &tty, &shell, pid,
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
                    }
                }
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
                DaemonReadAction::Scrollback { max_lines } => {
                    daemon::DaemonRequest::Scrollback { max_lines: *max_lines }
                }
            };

            match daemon_client::try_send_request(&session_id, &request) {
                Some(daemon::DaemonResponse::Ok { data: Some(d) }) => {
                    let text = d.get("output")
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
                if let Err(e) = query::handle_query(line, &config, &db, &session_id, false, false).await {
                    eprintln!("\x1b[33mnsh: {e}\x1b[0m");
                }
            }
        }

        Commands::Export { format, session } => {
            let session_id = session.unwrap_or_else(||
                std::env::var("NSH_SESSION_ID").unwrap_or_default());
            let db = db::Db::open()?;
            let convos = db.get_conversations(&session_id, 1000)?;
            if convos.is_empty() {
                eprintln!("No conversations found for session {session_id}");
            } else {
                match format.as_deref().unwrap_or("markdown") {
                    "json" => {
                        let json_convos: Vec<serde_json::Value> = convos.iter().map(|c| {
                            serde_json::json!({
                                "query": c.query,
                                "response_type": c.response_type,
                                "response": c.response,
                                "explanation": c.explanation,
                            })
                        }).collect();
                        println!("{}", serde_json::to_string_pretty(&json_convos)?);
                    }
                    _ => {
                        for c in &convos {
                            println!("**Q:** {}\n", c.query);
                            match c.response_type.as_str() {
                                "command" => println!("```bash\n{}\n```\n{}\n",
                                    c.response,
                                    c.explanation.as_deref().unwrap_or("")),
                                _ => println!("{}\n", c.response),
                            }
                        }
                    }
                }
            }
        }

        Commands::Status => {
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| "(not set)".into());
            let config = config::Config::load().unwrap_or_default();
            let db = db::Db::open()?;
            let pty_active = std::env::var("NSH_TTY").is_ok();
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "unknown".into());
            let db_path = config::Config::nsh_dir().join("nsh.db");
            let db_size = std::fs::metadata(&db_path)
                .map(|m| m.len())
                .unwrap_or(0);
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

fn redact_config_keys(val: &mut toml::Value) {
    match val {
        toml::Value::Table(table) => {
            for (key, v) in table.iter_mut() {
                if key == "api_key" {
                    if let toml::Value::String(s) = v {
                        if s.len() > 8 {
                            *s = format!("{}...{}", &s[..4], &s[s.len()-4..]);
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
