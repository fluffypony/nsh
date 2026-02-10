use crate::db::Db;
use crate::security::RiskLevel;

/// Handle the `command` tool: display explanation, write command to
/// pending file for shell hook to prefill.
pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
) -> anyhow::Result<()> {
    let command = input["command"].as_str().unwrap_or("");
    let explanation = input["explanation"].as_str().unwrap_or("");
    let pending = input["pending"].as_bool().unwrap_or(false);

    let (risk, reason) = crate::security::assess_command(command);

    match &risk {
        RiskLevel::Dangerous => {
            let reason_str = reason.unwrap_or("potentially destructive command");
            eprintln!("\x1b[1;31m⚠ DANGEROUS: {reason_str}\x1b[0m");
            eprintln!("\x1b[1;31mCommand: {command}\x1b[0m");
            eprint!("\x1b[1;31mType 'yes' to proceed: \x1b[0m");
            let mut input_line = String::new();
            std::io::stdin().read_line(&mut input_line)?;
            if input_line.trim() != "yes" {
                eprintln!("Aborted.");
                return Ok(());
            }
        }
        RiskLevel::Elevated => {
            let reason_str = reason.unwrap_or("elevated privileges");
            eprintln!("\x1b[33m⚡ {reason_str}\x1b[0m");
        }
        RiskLevel::Safe => {}
    }

    // Display explanation
    let color = "\x1b[3;36m"; // cyan italic
    let reset = "\x1b[0m";
    eprintln!("{color}{explanation}{reset}");

    // Write command to pending file for shell hook to pick up
    let nsh_dir = crate::config::Config::nsh_dir();
    let cmd_file = nsh_dir.join(format!("pending_cmd_{session_id}"));

    // Atomic write: temp file + rename, with 0o600 permissions
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = cmd_file.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(command.as_bytes())?;
        std::fs::rename(&tmp, &cmd_file)?;
    }

    if pending {
        let pending_file = nsh_dir.join(format!("pending_flag_{session_id}"));
        let tmp = pending_file.with_extension("tmp");
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(b"1")?;
        }
        std::fs::rename(&tmp, &pending_file)?;
    }

    if !private {
        let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
        let redacted_response = crate::redact::redact_secrets(command, &config.redaction);
        let redacted_explanation = Some(crate::redact::redact_secrets(explanation, &config.redaction));
        db.insert_conversation(
            session_id,
            &redacted_query,
            "command",
            &redacted_response,
            redacted_explanation.as_deref(),
            false,
            pending,
        )?;
        crate::audit::audit_log(session_id, original_query, "command", command, &risk.to_string());
    }

    Ok(())
}
