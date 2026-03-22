use clap::Parser;

use crate::cli::{Cli, Commands};

mod bootstrap;
mod chat;
mod config_command;
mod daemon_runtime;
mod daemon_transport;
mod doctor;
mod history;
mod init;
mod memory;
mod provider;
mod query;
mod record;
#[cfg(feature = "remote")]
mod remote;
mod runtime;
mod session;
mod shell_hooks;
mod status;

use self::bootstrap::{handle_cli_proxy_action, handle_completions_command, handle_init_command};
use self::chat::handle_chat_command;
use self::config_command::handle_config_command;
use self::daemon_transport::{handle_daemon_read_command, handle_daemon_send_command};
use self::doctor::handle_doctor_command;
use self::history::{
    handle_cost_command, handle_export_command, handle_history_command,
    handle_history_import_run_command,
};
use self::memory::handle_memory_command;
use self::provider::handle_provider_command;
use self::query::handle_query_command;
use self::record::{RecordCommandInput, handle_record_command};
use self::runtime::{
    apply_pending_update, handle_autoconfigure_command, handle_restart_command,
    handle_update_command,
};
use self::session::{
    handle_heartbeat_command, handle_redact_next_command, handle_reset_command,
    handle_session_command,
};
use self::status::handle_status_command;

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
        Commands::McpServe => crate::mcp_server::run_mcp_server()?,
        Commands::ParsePendingJson { field } => {
            // Read JSON from stdin and print the requested field.
            // Replaces the python3 dependency in shell hooks.
            let mut input = String::new();
            std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
            if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&input) {
                match parsed.get(&field) {
                    Some(serde_json::Value::String(s)) => print!("{s}"),
                    Some(serde_json::Value::Bool(b)) => print!("{b}"),
                    Some(v) => print!("{v}"),
                    None => {} // field not found, print nothing
                }
            }
        }
        #[cfg(feature = "remote")]
        Commands::Remote { action } => remote::handle_remote_command(action)?,
    }

    Ok(())
}
