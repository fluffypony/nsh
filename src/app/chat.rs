use crate::daemon_db::DbAccess;

pub(super) async fn handle_chat_command() -> anyhow::Result<()> {
    use std::io::Write;

    if !super::daemon_runtime::ensure_daemon_ready(false)? {
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
            && let Ok(new_config) = crate::config::Config::load()
        {
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
