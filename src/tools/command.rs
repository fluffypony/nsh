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
    force_autorun: bool,
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
            let input_line = {
                use std::io::{BufRead, IsTerminal};
                if std::io::stdin().is_terminal() {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line
                } else {
                    match std::fs::File::open("/dev/tty") {
                        Ok(tty) => {
                            let mut reader = std::io::BufReader::new(tty);
                            let mut line = String::new();
                            reader.read_line(&mut line)?;
                            line
                        }
                        Err(_) => {
                            eprintln!(
                                "Cannot confirm — stdin is piped. Aborting dangerous command."
                            );
                            return Ok(());
                        }
                    }
                }
            };
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

    // Display rich command preview
    display_command_preview(command, explanation, &risk);

    if force_autorun && matches!(risk, RiskLevel::Safe) {
        eprintln!("\x1b[2m(auto-running)\x1b[0m");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(command)
            .status();
        let exit_code = status.as_ref().map(|s| s.code().unwrap_or(-1)).unwrap_or(-1);
        if !private {
            let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
            let redacted_response = crate::redact::redact_secrets(command, &config.redaction);
            let redacted_explanation = Some(crate::redact::redact_secrets(
                explanation,
                &config.redaction,
            ));
            db.insert_conversation(
                session_id,
                &redacted_query,
                "command",
                &redacted_response,
                redacted_explanation.as_deref(),
                true,
                false,
            )?;
            crate::audit::audit_log(
                session_id,
                original_query,
                "command",
                command,
                &risk.to_string(),
            );
        }
        if !status.map(|s| s.success()).unwrap_or(false) {
            eprintln!("\x1b[33mcommand exited with code {exit_code}\x1b[0m");
        }
        return Ok(());
    }

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

    if !pending {
        // Clear any stale pending_flag from a previous sequence
        let stale_flag = nsh_dir.join(format!("pending_flag_{session_id}"));
        let _ = std::fs::remove_file(&stale_flag);
    }

    if !private {
        let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
        let redacted_response = crate::redact::redact_secrets(command, &config.redaction);
        let redacted_explanation = Some(crate::redact::redact_secrets(
            explanation,
            &config.redaction,
        ));
        db.insert_conversation(
            session_id,
            &redacted_query,
            "command",
            &redacted_response,
            redacted_explanation.as_deref(),
            false,
            pending,
        )?;
        crate::audit::audit_log(
            session_id,
            original_query,
            "command",
            command,
            &risk.to_string(),
        );
    }

    Ok(())
}

fn display_command_preview(command: &str, explanation: &str, risk: &crate::security::RiskLevel) {
    let color = match risk {
        RiskLevel::Dangerous => "\x1b[1;31m",
        RiskLevel::Elevated => "\x1b[1;33m",
        RiskLevel::Safe => "\x1b[1;36m",
    };
    let reset = "\x1b[0m";
    let dim = "\x1b[2m";

    let content_width = command.len().max(explanation.len()).clamp(20, 60);
    let box_width = content_width + 4;

    let top_label = " nsh ";
    let top_line = format!(
        "╭─{top_label}{:─<width$}╮",
        "",
        width = box_width - top_label.len() - 1
    );
    let bottom_line = format!("╰{:─<width$}╯", "", width = box_width + 1);

    eprintln!("{color}{top_line}{reset}");
    if !explanation.is_empty() {
        for line in explanation.lines() {
            eprintln!("{color}│{reset} {dim}{line}{reset}");
        }
        eprintln!("{color}│{reset}");
    }
    eprintln!("{color}│{reset} $ {command}");
    eprintln!("{color}{bottom_line}{reset}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::RiskLevel;

    #[test]
    fn test_display_command_preview_safe() {
        display_command_preview("ls -la", "List files in current directory", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_elevated() {
        display_command_preview("sudo rm file", "Remove file with sudo", &RiskLevel::Elevated);
    }

    #[test]
    fn test_display_command_preview_dangerous() {
        display_command_preview("rm -rf /", "Delete everything!", &RiskLevel::Dangerous);
    }

    #[test]
    fn test_display_command_preview_empty() {
        display_command_preview("", "", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_long_command() {
        let long = "a".repeat(100);
        display_command_preview(&long, "Long command", &RiskLevel::Safe);
    }
}
