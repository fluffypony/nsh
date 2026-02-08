use crate::config::Config;
use std::process::Command;

pub fn execute(
    cmd: &str,
    config: &Config,
) -> anyhow::Result<String> {
    if !config.tools.is_command_allowed(cmd) {
        return Ok(format!(
            "DENIED: '{}' is not in the run_command allowlist. \
             Use the 'command' tool instead to let the user \
             approve it.\nAllowed: {:?}",
            cmd, config.tools.run_command_allowlist
        ));
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    let max_chars = 8000;
    let mut result = String::new();

    if !stdout.is_empty() {
        result.push_str(&crate::util::truncate(
            &stdout, max_chars,
        ));
    }
    if !stderr.is_empty() {
        result.push_str("\n--- stderr ---\n");
        result.push_str(&crate::util::truncate(
            &stderr,
            max_chars / 4,
        ));
    }
    result.push_str(&format!(
        "\n[exit code: {}]",
        output.status.code().unwrap_or(-1)
    ));

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config_with_allowlist(
        allowlist: Vec<String>,
    ) -> Config {
        let mut config = Config::default();
        config.tools.run_command_allowlist = allowlist;
        config
    }

    #[test]
    fn test_run_command_denied() {
        let config =
            test_config_with_allowlist(vec!["echo".into()]);
        let result = execute("rm -rf /", &config).unwrap();
        assert!(result.contains("DENIED"));
    }

    #[test]
    fn test_run_command_allowed() {
        let config =
            test_config_with_allowlist(vec!["echo".into()]);
        let result = execute("echo hello", &config).unwrap();
        assert!(result.contains("hello"));
        assert!(result.contains("[exit code: 0]"));
    }
}
