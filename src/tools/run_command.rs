use crate::config::Config;
use crate::redact;
use std::process::Command;

pub fn execute(cmd: &str, config: &Config) -> anyhow::Result<String> {
    if !config.tools.is_command_allowed(cmd) {
        // Assess risk and prompt the user for approval when not allowlisted
        let (risk, reason) = crate::security::assess_command(cmd);
        match risk {
            crate::security::RiskLevel::Dangerous => {
                eprintln!(
                    "\n  {}⚠ DANGEROUS background command requested:{} {}",
                    crate::tui::style::BOLD_RED,
                    crate::tui::style::RESET,
                    reason.unwrap_or("")
                );
                eprintln!("  $ {cmd}");
                eprint!(
                    "  {}Type 'yes' to proceed: {}",
                    crate::tui::style::BOLD_RED,
                    crate::tui::style::RESET
                );
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap_or(0);
                if line.trim() != "yes" {
                    return Ok("DENIED: dangerous command not approved".to_string());
                }
            }
            crate::security::RiskLevel::Elevated => {
                eprintln!(
                    "\n  {}⚡ Agent wants to run a background command:{}",
                    crate::tui::style::BOLD_YELLOW,
                    crate::tui::style::RESET
                );
                eprintln!("  $ {cmd}");
                eprint!(
                    "  {}Allow? [y/N]{} ",
                    crate::tui::style::BOLD_YELLOW,
                    crate::tui::style::RESET
                );
                let _ = std::io::Write::flush(&mut std::io::stderr());
                if !crate::tools::read_tty_confirmation() {
                    return Ok("DENIED: command not approved".to_string());
                }
            }
            crate::security::RiskLevel::Safe => {
                eprintln!(
                    "\n  {}Agent wants to run:{} $ {}",
                    crate::tui::style::DIM,
                    crate::tui::style::RESET,
                    cmd
                );
                eprint!(
                    "  {}Allow? [Y/n]{} ",
                    crate::tui::style::BOLD_YELLOW,
                    crate::tui::style::RESET
                );
                let _ = std::io::Write::flush(&mut std::io::stderr());
                if !crate::tools::read_tty_confirmation() {
                    return Ok("DENIED: command not approved".to_string());
                }
            }
        }
    }

    let sensitive_paths = [
        "/.ssh",
        "/.gnupg",
        "/.aws",
        "/.nsh",
        "/id_rsa",
        "/id_ed25519",
    ];
    let lower_cmd = cmd.to_lowercase();
    if sensitive_paths.iter().any(|p| lower_cmd.contains(p)) {
        return Ok("DENIED: command references a sensitive path".to_string());
    }

    #[cfg(windows)]
    let output = Command::new("cmd").args(["/C", cmd]).output()?;

    #[cfg(not(windows))]
    let output = {
        let argv =
            shell_words::split(cmd).map_err(|e| anyhow::anyhow!("failed to parse command: {e}"))?;
        let (exe, args) = argv
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty command"))?;
        Command::new(exe).args(args).output()?
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let max_chars = 8000;
    let mut result = String::new();

    if !stdout.is_empty() {
        result.push_str(&crate::util::truncate(&stdout, max_chars));
    }
    if !stderr.is_empty() {
        result.push_str("\n--- stderr ---\n");
        result.push_str(&crate::util::truncate(&stderr, max_chars / 4));
    }
    result.push_str(&format!(
        "\n[exit code: {}]",
        output.status.code().unwrap_or(-1)
    ));

    let redacted = redact::redact_secrets(&result, &config.redaction);
    // Echo visible output for run_command so the user can see what happened,
    // then also return it so the model can interpret it. Keep stdout visible,
    // include stderr section and exit code just like before.
    if !redacted.trim().is_empty() {
        eprintln!("{redacted}");
    }
    Ok(redacted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_allowlist(allowlist: Vec<String>) -> Config {
        let mut config = Config::default();
        config.tools.run_command_allowlist = allowlist;
        config
    }

    #[test]
    fn test_run_command_denied() {
        let config = test_config_with_allowlist(vec!["echo".into()]);
        let result = execute("rm -rf /", &config).unwrap();
        assert!(result.contains("DENIED"));
    }

    #[test]
    fn test_run_command_allowed() {
        let config = test_config_with_allowlist(vec!["echo".into()]);
        let result = execute("echo hello", &config).unwrap();
        assert!(result.contains("hello"));
        assert!(result.contains("[exit code: 0]"));
    }

    #[test]
    fn test_run_command_sensitive_path_denied() {
        let config = test_config_with_allowlist(vec!["cat".into()]);
        let result = execute("cat ~/.ssh/id_rsa", &config).unwrap();
        assert!(result.contains("DENIED"));
        assert!(result.contains("sensitive path"));
    }

    #[test]
    fn test_run_command_with_stderr() {
        let config = test_config_with_allowlist(vec!["ls".into()]);
        let result = execute("ls /nonexistent_path_xyz_12345", &config).unwrap();
        assert!(result.contains("--- stderr ---"));
    }
}
