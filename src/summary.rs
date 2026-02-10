use crate::db::CommandForSummary;

pub fn trivial_summary(cmd: &str, exit_code: i32, output: &str) -> Option<String> {
    let first_word = cmd.split_whitespace().next().unwrap_or("");
    match first_word {
        "cd" => Some("Changed directory".into()),
        "clear" | "cls" => Some("Cleared terminal".into()),
        "exit" | "logout" => Some("Exited shell".into()),
        "pwd" => Some("Printed working directory".into()),
        "true" | "false" => Some(format!("Built-in returned {exit_code}")),
        _ if output.trim().is_empty() && exit_code == 0 =>
            Some(format!("Ran `{cmd}` successfully (no output)")),
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

pub async fn generate_llm_summary(cmd: &crate::db::CommandForSummary, config: &crate::config::Config) -> anyhow::Result<String> {
    let prompt = build_summary_prompt(cmd);
    let provider = crate::provider::create_provider(&config.provider.default, config)?;
    let model = config.models.fast.first()
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
    let text = response.content.iter()
        .filter_map(|b| if let crate::provider::ContentBlock::Text { text } = b { Some(text.as_str()) } else { None })
        .collect::<Vec<_>>()
        .join("");
    if text.trim().is_empty() {
        anyhow::bail!("empty summary response");
    }
    Ok(text.trim().to_string())
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
}
