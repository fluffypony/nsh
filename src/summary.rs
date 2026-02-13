use crate::db::CommandForSummary;

pub fn trivial_summary(cmd: &str, exit_code: i32, output: &str) -> Option<String> {
    let first_word = cmd.split_whitespace().next().unwrap_or("");
    match first_word {
        "cd" => Some("Changed directory".into()),
        "clear" | "cls" => Some("Cleared terminal".into()),
        "exit" | "logout" => Some("Exited shell".into()),
        "pwd" => Some("Printed working directory".into()),
        "true" | "false" => Some(format!("Built-in returned {exit_code}")),
        _ if output.trim().is_empty() && exit_code == 0 => {
            Some(format!("Ran `{cmd}` successfully (no output)"))
        }
        _ if output.trim().len() < 20 => None,
        _ => None,
    }
}

pub fn build_summary_prompt(cmd: &CommandForSummary) -> String {
    let output = cmd.output.as_deref().unwrap_or("");
    let truncated = if output.lines().count() > 50 {
        let lines: Vec<&str> = output.lines().collect();
        let first = lines[..25].join("\n");
        let last = lines[lines.len() - 25..].join("\n");
        format!("{first}\n[...]\n{last}")
    } else {
        output.to_string()
    };

    format!(
        "Summarize this shell command and its output in 1-2 sentences. Focus on: what \
         the command did, whether it succeeded or failed, and any key information in the \
         output (error messages, versions, counts, paths).\n\n\
         Command: {}\n\
         Exit code: {}\n\
         CWD: {}\n\n\
         Output (truncated):\n{}",
        cmd.command,
        cmd.exit_code.unwrap_or(-1),
        cmd.cwd.as_deref().unwrap_or("?"),
        truncated,
    )
}

pub async fn generate_llm_summary(
    cmd: &crate::db::CommandForSummary,
    config: &crate::config::Config,
) -> anyhow::Result<String> {
    let prompt = build_summary_prompt(cmd);
    let provider = crate::provider::create_provider(&config.provider.default, config)?;
    let model = config
        .models
        .fast
        .first()
        .cloned()
        .unwrap_or_else(|| config.provider.model.clone());
    let request = crate::provider::ChatRequest {
        model,
        system: "You are a concise command summarizer. Summarize in 1-2 sentences.".into(),
        messages: vec![crate::provider::Message {
            role: crate::provider::Role::User,
            content: vec![crate::provider::ContentBlock::Text { text: prompt }],
        }],
        tools: vec![],
        tool_choice: crate::provider::ToolChoice::None,
        max_tokens: 256,
        stream: false,
        extra_body: None,
    };
    let response = provider.complete(request).await?;
    let text = response
        .content
        .iter()
        .filter_map(|b| {
            if let crate::provider::ContentBlock::Text { text } = b {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("");
    if text.trim().is_empty() {
        anyhow::bail!("empty summary response");
    }
    Ok(text.trim().to_string())
}

pub fn extract_package_association(cmd: &str, exit_code: i32) -> Option<(String, String)> {
    if exit_code != 0 {
        return None;
    }
    let tokens = shell_words::split(cmd).ok()?;
    if tokens.len() < 3 {
        return None;
    }
    let manager = tokens[0]
        .rsplit('/')
        .next()
        .unwrap_or(&tokens[0])
        .to_lowercase();
    let (pkg_name, _action) = match manager.as_str() {
        "npm" | "npx" | "yarn" | "pnpm" => {
            let action = tokens.get(1)?.as_str();
            match action {
                "install" | "update" | "add" | "upgrade" => {
                    let pkg = tokens.iter().skip(2).find(|t| !t.starts_with('-'))?;
                    (pkg.clone(), action)
                }
                _ => return None,
            }
        }
        "pip" | "pip3" | "pipx" | "uv" => {
            if matches!(tokens.get(1)?.as_str(), "install" | "upgrade") {
                let pkg = tokens.iter().skip(2).find(|t| {
                    !t.starts_with('-') && *t != "." && !t.starts_with("./") && !t.contains('/')
                })?;
                (pkg.clone(), tokens[1].as_str())
            } else {
                return None;
            }
        }
        "brew" => {
            let action = tokens.get(1)?.as_str();
            if matches!(action, "install" | "upgrade" | "reinstall") {
                let pkg = tokens.iter().skip(2).find(|t| !t.starts_with('-'))?;
                (pkg.clone(), action)
            } else {
                return None;
            }
        }
        "cargo" => {
            if tokens.get(1)?.as_str() == "install" {
                let pkg = tokens.iter().skip(2).find(|t| !t.starts_with('-'))?;
                (pkg.clone(), "install")
            } else {
                return None;
            }
        }
        "apt" | "apt-get" | "dnf" | "yum" => {
            if matches!(tokens.get(1)?.as_str(), "install") {
                let pkg = tokens.iter().skip(2).find(|t| !t.starts_with('-'))?;
                (pkg.clone(), "install")
            } else {
                return None;
            }
        }
        _ => return None,
    };

    let short_name = pkg_name.rsplit('/').next().unwrap_or(&pkg_name).to_string();
    let key = format!("package: {short_name}");
    let value = format!("{manager} package ({pkg_name}), managed with: {cmd}");
    Some((key, value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trivial_summary_cd() {
        assert_eq!(
            trivial_summary("cd /tmp", 0, ""),
            Some("Changed directory".into())
        );
    }

    #[test]
    fn test_trivial_summary_clear() {
        assert_eq!(
            trivial_summary("clear", 0, ""),
            Some("Cleared terminal".into())
        );
    }

    #[test]
    fn test_trivial_summary_no_output_success() {
        assert_eq!(
            trivial_summary("mkdir foo", 0, ""),
            Some("Ran `mkdir foo` successfully (no output)".into())
        );
    }

    #[test]
    fn test_trivial_summary_none_for_substantial_output() {
        let output = "Compiling nsh v0.1.0\nFinished in 5.2 seconds with 0 warnings";
        assert!(trivial_summary("cargo build", 0, output).is_none());
    }

    #[test]
    fn test_trivial_summary_short_output_returns_none() {
        assert!(trivial_summary("echo hi", 0, "hi").is_none());
    }

    #[test]
    fn test_build_summary_prompt() {
        let cmd = CommandForSummary {
            id: 1,
            command: "cargo test".into(),
            cwd: Some("/project".into()),
            exit_code: Some(0),
            output: Some("running 10 tests\ntest result: ok".into()),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("cargo test"));
        assert!(prompt.contains("Exit code: 0"));
        assert!(prompt.contains("running 10 tests"));
    }

    #[test]
    fn test_build_summary_prompt_truncates_long_output() {
        let lines: Vec<String> = (1..=60).map(|i| format!("line {i}")).collect();
        let output = lines.join("\n");
        let cmd = CommandForSummary {
            id: 2,
            command: "long-cmd".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some(output),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("[...]"));
        assert!(prompt.contains("line 1"));
        assert!(prompt.contains("line 25"));
        assert!(prompt.contains("line 60"));
        assert!(!prompt.contains("line 26\n"));
    }

    #[test]
    fn test_build_summary_prompt_preserves_short_output() {
        let lines: Vec<String> = (1..=50).map(|i| format!("line {i}")).collect();
        let output = lines.join("\n");
        let cmd = CommandForSummary {
            id: 3,
            command: "short-cmd".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some(output),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(!prompt.contains("[...]"));
        assert!(prompt.contains("line 1"));
        assert!(prompt.contains("line 50"));
    }

    #[test]
    fn test_build_summary_prompt_missing_fields() {
        let cmd = CommandForSummary {
            id: 4,
            command: "test".into(),
            cwd: None,
            exit_code: None,
            output: None,
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("CWD: ?"));
        assert!(prompt.contains("Exit code: -1"));
    }

    #[test]
    fn test_trivial_summary_exit_logout() {
        assert_eq!(trivial_summary("exit", 0, ""), Some("Exited shell".into()));
        assert_eq!(
            trivial_summary("logout", 0, ""),
            Some("Exited shell".into())
        );
    }

    #[test]
    fn test_trivial_summary_pwd() {
        assert_eq!(
            trivial_summary("pwd", 0, "/home/user"),
            Some("Printed working directory".into())
        );
    }

    #[test]
    fn test_trivial_summary_true_false() {
        assert_eq!(
            trivial_summary("true", 0, ""),
            Some("Built-in returned 0".into())
        );
        assert_eq!(
            trivial_summary("false", 1, ""),
            Some("Built-in returned 1".into())
        );
    }

    #[test]
    fn test_trivial_summary_cls() {
        assert_eq!(
            trivial_summary("cls", 0, ""),
            Some("Cleared terminal".into())
        );
    }

    #[test]
    fn test_trivial_summary_with_nonzero_exit_no_output() {
        assert_eq!(
            trivial_summary("false", 1, ""),
            Some("Built-in returned 1".into())
        );
        assert!(trivial_summary("unknown_cmd", 1, "").is_none());
    }

    #[test]
    fn test_build_summary_prompt_with_no_output() {
        let cmd = CommandForSummary {
            id: 10,
            command: "silent-cmd".into(),
            cwd: Some("/home".into()),
            exit_code: Some(0),
            output: None,
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("silent-cmd"));
        assert!(prompt.contains("Exit code: 0"));
        assert!(!prompt.contains("[...]"));
    }

    #[test]
    fn test_build_summary_prompt_exactly_50_lines() {
        let lines: Vec<String> = (1..=50).map(|i| format!("line {i}")).collect();
        let output = lines.join("\n");
        let cmd = CommandForSummary {
            id: 11,
            command: "fifty-lines".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some(output),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(!prompt.contains("[...]"));
        assert!(prompt.contains("line 1"));
        assert!(prompt.contains("line 50"));
    }

    #[test]
    fn test_trivial_summary_cd_with_arguments() {
        assert_eq!(
            trivial_summary("cd /home/user/projects", 0, ""),
            Some("Changed directory".into())
        );
        assert_eq!(
            trivial_summary("cd ..", 1, ""),
            Some("Changed directory".into())
        );
    }

    #[test]
    fn test_trivial_summary_output_with_failure() {
        let output = "error: package `foo` not found in registry";
        assert!(trivial_summary("cargo install foo", 1, output).is_none());
    }

    #[test]
    fn test_trivial_summary_whitespace_only_output_nonzero_exit() {
        assert!(trivial_summary("some_cmd", 1, "   \n\t\n  ").is_none());
    }

    #[test]
    fn test_trivial_summary_empty_command() {
        assert_eq!(
            trivial_summary("", 0, ""),
            Some("Ran `` successfully (no output)".into())
        );
    }

    #[test]
    fn test_build_summary_prompt_exactly_51_lines() {
        let lines: Vec<String> = (1..=51).map(|i| format!("line {i}")).collect();
        let output = lines.join("\n");
        let cmd = CommandForSummary {
            id: 20,
            command: "fifty-one".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some(output),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("[...]"));
        assert!(prompt.contains("line 1"));
        assert!(prompt.contains("line 25"));
        assert!(prompt.contains("line 51"));
        assert!(!prompt.contains("line 26\n"));
    }

    #[test]
    fn test_trivial_summary_whitespace_output_success() {
        assert_eq!(
            trivial_summary("touch file", 0, "   \n\t  "),
            Some("Ran `touch file` successfully (no output)".into())
        );
    }

    #[test]
    fn test_trivial_summary_short_output_under_20_chars() {
        assert!(trivial_summary("echo a", 0, "a").is_none());
        assert!(trivial_summary("date", 0, "2025-02-11").is_none());
        assert!(trivial_summary("wc -l", 0, "42 lines").is_none());
    }

    #[test]
    fn test_trivial_summary_short_output_exactly_20_chars() {
        let output = "x".repeat(20);
        assert!(trivial_summary("cmd", 0, &output).is_none());
    }

    #[test]
    fn test_trivial_summary_unknown_cmd_nonzero_exit_with_short_output() {
        assert!(trivial_summary("bad_cmd", 127, "not found").is_none());
    }

    #[test]
    fn test_build_summary_prompt_empty_output_string() {
        let cmd = CommandForSummary {
            id: 100,
            command: "ls".into(),
            cwd: Some("/home".into()),
            exit_code: Some(0),
            output: Some("".into()),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("ls"));
        assert!(prompt.contains("Exit code: 0"));
        assert!(!prompt.contains("[...]"));
    }

    #[test]
    fn test_build_summary_prompt_single_line_output() {
        let cmd = CommandForSummary {
            id: 101,
            command: "echo hello".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some("hello".into()),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains("hello"));
        assert!(!prompt.contains("[...]"));
    }

    #[test]
    fn test_build_summary_prompt_special_characters() {
        let cmd = CommandForSummary {
            id: 21,
            command: r#"echo "hello 'world'" | grep -E '\d+'"#.into(),
            cwd: Some("/tmp/path with spaces".into()),
            exit_code: Some(0),
            output: Some("résultat: <tag>&amp;</tag>\n\ttab\there".into()),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(prompt.contains(r#"echo "hello 'world'" | grep -E '\d+'"#));
        assert!(prompt.contains("résultat"));
        assert!(prompt.contains("<tag>&amp;</tag>"));
    }

    #[test]
    fn test_build_summary_prompt_very_long_single_line() {
        let long_line = "x".repeat(10_000);
        let cmd = CommandForSummary {
            id: 22,
            command: "generate-data".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            output: Some(long_line.clone()),
        };
        let prompt = build_summary_prompt(&cmd);
        assert!(!prompt.contains("[...]"));
        assert!(prompt.contains(&long_line));
    }

    #[test]
    fn test_extract_package_association_npm_install() {
        let result = extract_package_association("npm install -g @sourcegraph/amp", 0);
        assert!(result.is_some());
        let (key, value) = result.unwrap();
        assert!(key.contains("amp"));
        assert!(value.contains("npm"));
    }

    #[test]
    fn test_extract_package_association_failed_command() {
        assert!(extract_package_association("npm install foo", 1).is_none());
    }

    #[test]
    fn test_extract_package_association_brew_install() {
        let result = extract_package_association("brew install ripgrep", 0);
        assert!(result.is_some());
        let (key, _) = result.unwrap();
        assert!(key.contains("ripgrep"));
    }

    #[test]
    fn test_extract_package_association_unknown_manager() {
        assert!(extract_package_association("zypper install foo", 0).is_none());
    }

    #[test]
    fn test_extract_package_association_too_few_tokens() {
        assert!(extract_package_association("npm install", 0).is_none());
    }
}
