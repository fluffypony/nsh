pub(super) async fn handle_query_command(
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

    if !super::daemon_runtime::ensure_daemon_ready(json)? {
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
        && error.to_string().contains("interrupted")
    {
        eprint!("\x1b[?25h\x1b[0m");
        std::io::Write::flush(&mut std::io::stderr()).ok();
        std::process::exit(130);
    }
    result?;
    Ok(())
}
