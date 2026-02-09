mod ansi;
mod cli;
mod config;
mod context;
mod db;
mod init;
mod provider;
mod pty;
mod pump;
mod query;
mod redact;
mod shell_hooks;
mod streaming;
mod tools;
mod util;

use clap::Parser;
use cli::{Cli, Commands, ConfigAction, HistoryAction, SessionAction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env(),
        )
        .with_writer(std::io::stderr)
        .init();

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

        Commands::Query { words } => {
            if words.is_empty() {
                eprintln!("Usage: ? <your question>");
                std::process::exit(1);
            }
            let query_text = words.join(" ");
            let config = config::Config::load()?;
            let db = db::Db::open()?;
            let session_id = std::env::var("NSH_SESSION_ID")
                .unwrap_or_else(|_| "default".into());
            query::handle_query(&query_text, &config, &db, &session_id)
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
            Some(ConfigAction::Show) => {
                let path = config::Config::path();
                if path.exists() {
                    print!("{}", std::fs::read_to_string(&path)?);
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

        Commands::Doctor => {
            let db = db::Db::open()?;
            db.run_doctor()?;
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
    }

    Ok(())
}
