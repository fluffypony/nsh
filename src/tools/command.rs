use crate::db::Db;

/// Handle the `command` tool: display explanation, write command to
/// pending file for shell hook to prefill.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
) -> anyhow::Result<()> {
    let command = input["command"].as_str().unwrap_or("");
    let explanation = input["explanation"].as_str().unwrap_or("");
    let pending = input["pending"].as_bool().unwrap_or(false);

    // Display explanation
    let color = "\x1b[3;36m"; // cyan italic
    let reset = "\x1b[0m";
    eprintln!("{color}{explanation}{reset}");

    // Write command to pending file for shell hook to pick up
    let nsh_dir = crate::config::Config::nsh_dir();
    let cmd_file =
        nsh_dir.join(format!("pending_cmd_{session_id}"));
    std::fs::write(&cmd_file, command)?;

    if pending {
        let pending_file =
            nsh_dir.join(format!("pending_flag_{session_id}"));
        std::fs::write(&pending_file, "1")?;
    }

    // Record in conversation history
    db.insert_conversation(
        session_id,
        original_query,
        "command",
        command,
        Some(explanation),
        false,
        pending,
    )?;

    Ok(())
}
