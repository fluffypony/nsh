use crate::config::Config;
use crate::redact;
use std::process::{Command, Stdio};

fn is_shell_operator_token(token: &str) -> bool {
    matches!(
        token,
        "&&" | "||" | "|" | ";" | "&" | ">" | "<" | ">>" | "<<"
    )
}

fn expand_tilde_token(token: &str) -> String {
    if token == "~" {
        return dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| token.to_string());
    }

    if let Some(rest) = token.strip_prefix("~/") {
        return dirs::home_dir()
            .map(|p| p.join(rest).to_string_lossy().to_string())
            .unwrap_or_else(|| token.to_string());
    }

    token.to_string()
}

pub fn execute(cmd: &str, config: &Config) -> anyhow::Result<String> {
    #[cfg(not(windows))]
    let mut parsed_argv = {
        let trimmed = cmd.trim();
        if trimmed.is_empty() {
            return Ok("DENIED: empty command".to_string());
        }

        let parsed = shell_words::split(trimmed)
            .map_err(|e| anyhow::anyhow!("failed to parse command: {e}"))?;
        if parsed.iter().any(|token| is_shell_operator_token(token)) {
            return Ok(
                "DENIED: run_command does not support shell operators (&&, ||, |, ;, redirects). Use the `command` tool with pending=true instead."
                    .to_string(),
            );
        }
        parsed
    };

    if !config.tools.is_command_allowed(cmd) {
        // Assess risk and prompt the user for approval when not allowlisted
        let (risk, reason) = crate::security::assess_command(cmd);
        match risk {
            crate::security::RiskLevel::Dangerous => {
                let th = crate::tui::theme::current_theme();
                eprintln!(
                    "\n  {}⚠ DANGEROUS background command requested:{} {}",
                    th.error,
                    th.reset,
                    reason.unwrap_or("")
                );
                eprintln!("  $ {cmd}");
                eprint!("  {}Type 'yes' to proceed: {}", th.error, th.reset);
                let _ = std::io::Write::flush(&mut std::io::stderr());
                if !crate::tools::read_tty_yes_confirmation() {
                    return Ok("DENIED: dangerous command not approved".to_string());
                }
            }
            crate::security::RiskLevel::Elevated => {
                let th = crate::tui::theme::current_theme();
                eprintln!(
                    "\n  {}⚡ Agent wants to run a background command:{}",
                    th.warning, th.reset
                );
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
                if !crate::tools::read_tty_confirmation_default_yes() {
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
        "sudo ",
        "doas ",
        "su ",
        "brew install",
        "brew upgrade",
        "brew reinstall",
        "apt install",
        "apt-get install",
        "dnf install",
        "yum install",
        "pacman -S",
        "pip install",
        "pip3 install",
        "cargo install",
        "npm install",
        "pnpm install",
        "yarn add",
    ];
    if interactive_prefixes
        .iter()
        .any(|p| lower_cmd.starts_with(p) || lower_cmd.contains(&format!(" {}", p.trim())))
    {
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
        for token in &mut parsed_argv {
            *token = expand_tilde_token(token);
        }

        let (exe, args) = parsed_argv
            .split_first()
            .ok_or_else(|| anyhow::anyhow!("empty command"))?;

        let child = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut pumped =
            crate::tools::process_pump::attach_output_pumps(child, &config.redaction, true);

        let timeout_secs = config.execution.tool_timeout_seconds.max(30);
        let mut start = std::time::Instant::now();
        let status = loop {
            match pumped.child.try_wait()? {
                Some(status) => break status,
                None => {
                    if start.elapsed().as_secs() >= timeout_secs {
                        eprint!(
                            "\x1b[1;33mCommand running > {}s. Continue waiting? [Y/n]\x1b[0m ",
                            timeout_secs
                        );
                        let _ = std::io::Write::flush(&mut std::io::stderr());
                        if !crate::tools::read_tty_confirmation_default_yes() {
                            let _ = pumped.child.kill();
                            let _ = pumped.child.wait();
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

        let (stdout_str, stderr_str) = pumped.finish();

        (stdout_str, stderr_str, status.code().unwrap_or(-1))
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

    #[test]
    fn test_run_command_shell_operators_denied() {
        let config = test_config_with_allowlist(vec!["*".into()]);
        let result = execute("mkdir -p ~/tmp/nsh-test && echo ok", &config).unwrap();
        assert!(result.contains("DENIED"));
        assert!(result.contains("does not support shell operators"));
    }
}
