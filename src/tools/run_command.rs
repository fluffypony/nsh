use crate::config::Config;
use crate::redact;
use std::process::{Command, Stdio};

pub fn execute(cmd: &str, config: &Config) -> anyhow::Result<String> {
    if !config.tools.is_command_allowed(cmd) {
        // Assess risk and prompt the user for approval when not allowlisted
        let (risk, reason) = crate::security::assess_command(cmd);
        match risk {
            crate::security::RiskLevel::Dangerous => {
                let th = crate::tui::theme::current_theme();
                eprintln!("\n  {}⚠ DANGEROUS background command requested:{} {}", th.error, th.reset, reason.unwrap_or(""));
                eprintln!("  $ {cmd}");
                eprint!("  {}Type 'yes' to proceed: {}", th.error, th.reset);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                let mut line = String::new();
                std::io::stdin().read_line(&mut line).unwrap_or(0);
                if line.trim() != "yes" {
                    return Ok("DENIED: dangerous command not approved".to_string());
                }
            }
            crate::security::RiskLevel::Elevated => {
                let th = crate::tui::theme::current_theme();
                eprintln!("\n  {}⚡ Agent wants to run a background command:{}", th.warning, th.reset);
                eprintln!("  $ {cmd}");
                eprint!("  {}Allow? [y/N]{} ", th.warning, th.reset);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                if !crate::tools::read_tty_confirmation() {
                    return Ok("DENIED: command not approved".to_string());
                }
            }
            crate::security::RiskLevel::Safe => {
                let th = crate::tui::theme::current_theme();
                eprintln!("\n  {}Agent wants to run:{} $ {}", th.dim, th.reset, cmd);
                eprint!("  {}Allow? [Y/n]{} ", th.warning, th.reset);
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

    // Guard: reject known-interactive commands that should use the `command` tool
    let interactive_prefixes = [
        "sudo ", "doas ", "su ", "brew install", "brew upgrade", "brew reinstall",
        "apt install", "apt-get install", "dnf install", "yum install", "pacman -S",
        "pip install", "pip3 install", "cargo install", "npm install", "pnpm install",
        "yarn add",
    ];
    if interactive_prefixes.iter().any(|p| lower_cmd.starts_with(p) || lower_cmd.contains(&format!(" {}", p.trim()))) {
        return Ok(format!(
            "DENIED: '{}' may require interactive input or shell state. Use the `command` tool with pending=true instead.",
            cmd.split_whitespace().take(3).collect::<Vec<_>>().join(" ")
        ));
    }

    #[cfg(windows)]
    let (stdout_str, stderr_str, exit_code) = {
        let output = Command::new("cmd").args(["/C", cmd]).output()?;
        (
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
            output.status.code().unwrap_or(-1),
        )
    };

    #[cfg(not(windows))]
    let (stdout_str, stderr_str, exit_code) = {
        if cmd.trim().is_empty() {
            return Ok("DENIED: empty command".to_string());
        }
        let argv =
            shell_words::split(cmd).map_err(|e| anyhow::anyhow!("failed to parse command: {e}"))?;
        let (exe, args) = argv
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty command"))?;

        let mut child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        let mut stdout_reader = child.stdout.take().unwrap();
        let mut stderr_reader = child.stderr.take().unwrap();

        let (tx_out, rx_out) = std::sync::mpsc::channel();
        let (tx_err, rx_err) = std::sync::mpsc::channel();
        let redaction_cfg_out = config.redaction.clone();
        let redaction_cfg_err = config.redaction.clone();

        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 1024];
            let mut full = Vec::new();
            while let Ok(n) = stdout_reader.read(&mut buf) {
                if n == 0 { break; }
                let chunk = String::from_utf8_lossy(&buf[..n]);
                let redacted = redact::redact_secrets(&chunk, &redaction_cfg_out);
                eprint!("{redacted}");
                full.extend_from_slice(&buf[..n]);
            }
            let _ = tx_out.send(full);
        });

        std::thread::spawn(move || {
            use std::io::Read;
            let mut buf = [0u8; 1024];
            let mut full = Vec::new();
            while let Ok(n) = stderr_reader.read(&mut buf) {
                if n == 0 { break; }
                let chunk = String::from_utf8_lossy(&buf[..n]);
                let redacted = redact::redact_secrets(&chunk, &redaction_cfg_err);
                eprint!("{redacted}");
                full.extend_from_slice(&buf[..n]);
            }
            let _ = tx_err.send(full);
        });

        let timeout_secs = config.execution.tool_timeout_seconds.max(30);
        let mut start = std::time::Instant::now();
        let status = loop {
            match child.try_wait()? {
                Some(status) => break status,
                None => {
                    if start.elapsed().as_secs() >= timeout_secs {
                        eprint!("\x1b[1;33mCommand running > {}s. Continue waiting? [Y/n]\x1b[0m ",
                            timeout_secs);
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        if !crate::tools::read_tty_confirmation_default_yes() {
                            let _ = child.kill();
                            let _ = child.wait();
                            return Ok(format!(
                                "Command timed out after {}s. User cancelled.",
                                timeout_secs
                            ));
                        } else {
                            start = std::time::Instant::now();
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        };

        let stdout_bytes = rx_out.recv().unwrap_or_default();
        let stderr_bytes = rx_err.recv().unwrap_or_default();

        (
            String::from_utf8_lossy(&stdout_bytes).into_owned(),
            String::from_utf8_lossy(&stderr_bytes).into_owned(),
            status.code().unwrap_or(-1),
        )
    };

    let max_chars = 8000;
    let mut result = String::new();
    if !stdout_str.is_empty() {
        result.push_str(&crate::util::truncate(&stdout_str, max_chars));
    }
    if !stderr_str.is_empty() {
        result.push_str("\n--- stderr ---\n");
        result.push_str(&crate::util::truncate(&stderr_str, max_chars / 4));
    }
    result.push_str(&format!("\n[exit code: {}]", exit_code));

    Ok(redact::redact_secrets(&result, &config.redaction))
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
