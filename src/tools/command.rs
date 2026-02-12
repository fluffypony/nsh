use crate::db::Db;
use crate::security::RiskLevel;
use std::path::Path;

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
    let raw_command = input["command"].as_str().unwrap_or("");
    let explanation = input["explanation"].as_str().unwrap_or("");
    let pending = input["pending"].as_bool().unwrap_or(false);
    let command = normalize_command_for_prefill(raw_command, original_query, db, session_id);

    if let Some(reason) = reject_reason_for_generated_command(&command, original_query) {
        eprintln!("nsh: skipped invalid generated command ({reason})");
        return Ok(());
    }

    let (risk, reason) = crate::security::assess_command(&command);

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

    // Display rich command preview (or JSON event in --json mode)
    if crate::streaming::json_output_enabled() {
        let event = serde_json::json!({
            "type": "command",
            "command": command,
            "explanation": explanation,
            "risk": risk.to_string(),
            "pending": pending,
        });
        eprintln!("{}", serde_json::to_string(&event)?);
    } else {
        match &risk {
            RiskLevel::Safe => {
                if !explanation.is_empty() {
                    eprintln!("\x1b[2m  {explanation}\x1b[0m");
                }
            }
            _ => {
                display_command_preview(&command, explanation, &risk);
                eprintln!("\x1b[2m  ↵ Enter to run · Edit first · Ctrl-C to cancel\x1b[0m");
            }
        }
    }

    let can_autorun = match risk {
        RiskLevel::Safe => true,
        RiskLevel::Elevated => config.execution.allow_unsafe_autorun,
        RiskLevel::Dangerous => false,
    };
    if force_autorun && can_autorun {
        eprintln!("\x1b[2m(auto-running)\x1b[0m");
        let status = std::process::Command::new("sh")
            .arg("-c")
            .arg(command.as_str())
            .status();
        let exit_code = status
            .as_ref()
            .map(|s| s.code().unwrap_or(-1))
            .unwrap_or(-1);
        if !private {
            let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
            let redacted_response = crate::redact::redact_secrets(&command, &config.redaction);
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
                &command,
                &risk.to_string(),
            );
        }
        if !status.map(|s| s.success()).unwrap_or(false) {
            eprintln!("\x1b[33mcommand exited with code {exit_code}\x1b[0m");
        }
        return Ok(());
    }

    if config.execution.mode != "confirm" {
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
    }

    if !private {
        let redacted_query = crate::redact::redact_secrets(original_query, &config.redaction);
        let redacted_response = crate::redact::redact_secrets(&command, &config.redaction);
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
            &command,
            &risk.to_string(),
        );
    }

    eprint!("\x1b[0m");
    std::io::Write::flush(&mut std::io::stderr()).ok();

    Ok(())
}

pub(crate) fn reject_reason_for_generated_command(
    command: &str,
    original_query: &str,
) -> Option<&'static str> {
    let trimmed_command = command.trim();
    if trimmed_command.is_empty() {
        return Some("empty command");
    }

    let trimmed_query = original_query.trim();
    if trimmed_query.is_empty() {
        return None;
    }

    if trimmed_command.eq_ignore_ascii_case(trimmed_query)
        && looks_like_natural_language_question(trimmed_query)
    {
        return Some("model echoed the user's question instead of a shell command");
    }

    let lower = trimmed_command.to_ascii_lowercase();
    let nl_indicators = [
        "please ", "can you ", "could you ", "i want ", "i need ",
        "help me ", "show me how", "how do i ", "what is ",
    ];
    if nl_indicators.iter().any(|p| lower.starts_with(p) || lower.contains(p)) {
        return Some("generated command looks like natural language, not a shell command");
    }

    let cmd_lower = trimmed_command.to_ascii_lowercase();
    let query_lower = trimmed_query.to_ascii_lowercase();
    if cmd_lower == query_lower && !cmd_lower.contains('/') && !cmd_lower.starts_with("cd ") {
        let first_word = cmd_lower.split_whitespace().next().unwrap_or("");
        if !first_word.is_empty() {
            let found_in_path = std::env::var("PATH")
                .unwrap_or_default()
                .split(':')
                .any(|dir| std::path::Path::new(dir).join(first_word).exists());
            if !found_in_path {
                return Some("command appears to be the user's natural language request, not a shell command");
            }
        }
    }

    None
}

fn looks_like_natural_language_question(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    if lower.ends_with('?') {
        return true;
    }

    const QUESTION_PREFIXES: &[&str] = &[
        "what ", "when ", "where ", "why ", "who ", "whom ", "which ", "how ", "can ", "could ",
        "would ", "should ", "do ", "does ", "did ", "is ", "are ", "am ", "was ", "were ",
        "will ",
    ];

    QUESTION_PREFIXES
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

fn normalize_command_for_prefill(
    command: &str,
    original_query: &str,
    db: &Db,
    session_id: &str,
) -> String {
    let trimmed = command.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let source = if trimmed.eq_ignore_ascii_case(original_query.trim()) {
        original_query.trim()
    } else {
        trimmed
    };

    if let Some(cd_command) = normalize_cd_command(source, db, session_id) {
        return cd_command;
    }

    trimmed.to_string()
}

fn normalize_cd_command(command: &str, db: &Db, session_id: &str) -> Option<String> {
    let trimmed = command.trim();
    let rest = trimmed.strip_prefix("cd ")?;
    let rest = rest.trim();
    if rest.is_empty() {
        return Some("cd".to_string());
    }
    if rest == "-" || looks_explicit_cd_target(rest) {
        return Some(format!("cd {rest}"));
    }

    let unquoted = strip_matching_quotes(rest);
    let cleaned = cleanup_cd_target_phrase(unquoted);
    let resolved = resolve_cd_target(cleaned.as_str(), db, session_id);
    Some(format!("cd {}", shell_quote_if_needed(&resolved)))
}

fn looks_explicit_cd_target(target: &str) -> bool {
    target.starts_with('~')
        || target.starts_with('.')
        || target.starts_with('/')
        || target.starts_with('$')
        || target.contains('/')
        || target.contains('*')
        || target.contains('?')
        || target.contains('[')
        || target.contains(']')
}

fn strip_matching_quotes(input: &str) -> &str {
    if input.len() >= 2 {
        let bytes = input.as_bytes();
        if (bytes[0] == b'\'' && bytes[input.len() - 1] == b'\'')
            || (bytes[0] == b'"' && bytes[input.len() - 1] == b'"')
        {
            return &input[1..input.len() - 1];
        }
    }
    input
}

fn cleanup_cd_target_phrase(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || looks_explicit_cd_target(trimmed) {
        return trimmed.to_string();
    }

    const FILLER_WORDS: &[&str] = &[
        "to",
        "into",
        "in",
        "the",
        "a",
        "an",
        "folder",
        "directory",
        "dir",
    ];

    let tokens: Vec<String> = trimmed
        .split_whitespace()
        .filter_map(|tok| {
            let cleaned = tok.trim_matches(|c: char| c == ',' || c == '.');
            let lower = cleaned.to_ascii_lowercase();
            if FILLER_WORDS.contains(&lower.as_str()) {
                return None;
            }
            if cleaned.is_empty() {
                return None;
            }
            Some(cleaned.to_string())
        })
        .collect();

    if tokens.is_empty() {
        trimmed.to_string()
    } else {
        tokens.join(" ")
    }
}

fn resolve_cd_target(target: &str, db: &Db, session_id: &str) -> String {
    if target.is_empty() || looks_explicit_cd_target(target) {
        return target.to_string();
    }

    let candidates = cwd_directory_candidates(target);
    if candidates.is_empty() {
        return target.to_string();
    }
    if candidates.len() == 1 {
        return candidates[0].clone();
    }
    if let Some(from_history) = choose_candidate_from_cd_history(&candidates, db, session_id) {
        return from_history;
    }
    candidates[0].clone()
}

fn cwd_directory_candidates(target: &str) -> Vec<String> {
    let target_lower = target.to_ascii_lowercase();
    let mut exact = Vec::new();
    let mut prefix = Vec::new();
    let mut contains = Vec::new();

    let entries = match std::fs::read_dir(".") {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    for entry in entries.flatten() {
        let file_type = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }

        let name = entry.file_name().to_string_lossy().to_string();
        let lower = name.to_ascii_lowercase();
        if lower == target_lower {
            exact.push(name);
        } else if lower.starts_with(&target_lower) {
            prefix.push(name);
        } else if lower.contains(&target_lower) {
            contains.push(name);
        }
    }

    for group in [&mut exact, &mut prefix, &mut contains] {
        group.sort();
    }

    if !exact.is_empty() {
        exact
    } else if !prefix.is_empty() {
        prefix
    } else {
        contains
    }
}

fn choose_candidate_from_cd_history(
    candidates: &[String],
    db: &Db,
    session_id: &str,
) -> Option<String> {
    let try_filters = [Some("current"), None];
    for session_filter in try_filters {
        let history = db
            .search_history_advanced(
                None,
                Some(r"^cd\s+"),
                None,
                None,
                None,
                false,
                session_filter,
                Some(session_id),
                200,
            )
            .ok()?;

        for row in history {
            let Some(history_target) = extract_cd_target_from_command(&row.command) else {
                continue;
            };
            if let Some(candidate) = match_history_target_to_candidates(&history_target, candidates)
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn extract_cd_target_from_command(command: &str) -> Option<String> {
    if let Ok(parts) = shell_words::split(command) {
        if parts.first().map(|p| p.as_str()) == Some("cd") && parts.len() >= 2 {
            return Some(parts[1].clone());
        }
    }
    None
}

fn match_history_target_to_candidates(
    history_target: &str,
    candidates: &[String],
) -> Option<String> {
    let normalized = history_target.trim();
    if normalized.is_empty() {
        return None;
    }
    let normalized_lower = normalized.to_ascii_lowercase();
    let basename_lower = Path::new(normalized)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_ascii_lowercase());

    candidates.iter().find_map(|candidate| {
        let candidate_lower = candidate.to_ascii_lowercase();
        let path_suffix = format!("/{candidate_lower}");
        if normalized_lower == candidate_lower
            || normalized_lower.ends_with(&path_suffix)
            || basename_lower.as_deref() == Some(candidate_lower.as_str())
        {
            Some(candidate.clone())
        } else {
            None
        }
    })
}

fn shell_quote_if_needed(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-._~/".contains(c))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn display_command_preview(command: &str, explanation: &str, risk: &crate::security::RiskLevel) {
    let color = match risk {
        RiskLevel::Dangerous => "\x1b[1;31m",
        RiskLevel::Elevated => "\x1b[1;33m",
        RiskLevel::Safe => "\x1b[2m",
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
    eprintln!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::RiskLevel;
    use std::path::PathBuf;

    struct CwdGuard {
        old: PathBuf,
    }

    impl CwdGuard {
        fn push_to(path: &std::path::Path) -> Self {
            let old = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { old }
        }
    }

    impl Drop for CwdGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.old);
        }
    }

    #[test]
    fn test_display_command_preview_safe() {
        display_command_preview(
            "ls -la",
            "List files in current directory",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_elevated() {
        display_command_preview(
            "sudo rm file",
            "Remove file with sudo",
            &RiskLevel::Elevated,
        );
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

    #[test]
    fn test_display_command_preview_multiline_explanation() {
        display_command_preview(
            "ls -la",
            "First line of explanation\nSecond line of explanation\nThird line",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_empty_command() {
        display_command_preview("", "Some explanation", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_very_long_explanation() {
        let long_explanation = "x".repeat(200);
        display_command_preview("echo hi", &long_explanation, &RiskLevel::Elevated);
    }

    #[test]
    fn test_display_command_preview_unicode_command() {
        display_command_preview(
            "echo '日本語テスト'",
            "Prints unicode text",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_ansi_escape_in_command() {
        display_command_preview(
            "echo '\x1b[31mred\x1b[0m'",
            "Command containing ANSI escapes",
            &RiskLevel::Safe,
        );
    }

    #[test]
    fn test_display_command_preview_special_chars() {
        display_command_preview(
            "echo '╭─╮│╰─╯'",
            "Command with box-drawing chars",
            &RiskLevel::Elevated,
        );
    }

    #[test]
    fn test_display_command_preview_single_char_explanation() {
        display_command_preview("ls", "X", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_min_boundary() {
        let cmd = "a".repeat(19);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_clamp_lower() {
        let cmd = "a".repeat(20);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_at_max_boundary() {
        let cmd = "a".repeat(60);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_content_width_above_max() {
        let cmd = "a".repeat(61);
        display_command_preview(&cmd, "short", &RiskLevel::Safe);
    }

    #[test]
    fn test_content_width_clamping_values() {
        let clamp = |len: usize| len.max(0).clamp(20, 60);
        assert_eq!(clamp(0), 20);
        assert_eq!(clamp(19), 20);
        assert_eq!(clamp(20), 20);
        assert_eq!(clamp(40), 40);
        assert_eq!(clamp(60), 60);
        assert_eq!(clamp(61), 60);
        assert_eq!(clamp(200), 60);
    }

    #[test]
    fn test_display_command_preview_long_explanation_short_command() {
        let explanation = "b".repeat(80);
        display_command_preview("ls", &explanation, &RiskLevel::Safe);
    }

    #[test]
    fn test_display_command_preview_short_explanation_long_command() {
        let cmd = "c".repeat(80);
        display_command_preview(&cmd, "ok", &RiskLevel::Dangerous);
    }

    #[test]
    fn test_display_command_preview_both_empty_elevated() {
        display_command_preview("", "", &RiskLevel::Elevated);
    }

    fn test_db_with_session(session_id: &str) -> crate::db::Db {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session(session_id, "tty0", "zsh", 12345).unwrap();
        db
    }

    #[test]
    fn test_execute_autorun_safe_command() {
        let session = "test_autorun_safe";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "no-op command",
            "pending": false,
        });
        execute(&input, "test query", &db, session, false, &config, true).unwrap();
    }

    #[test]
    fn test_execute_autorun_safe_private_skips_db() {
        let session = "test_autorun_priv";
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "private command",
            "pending": false,
        });
        execute(&input, "secret query", &db, session, true, &config, true).unwrap();
    }

    #[test]
    fn test_execute_pending_writes_flag() {
        let session = "test_pending_flag";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "echo hello",
            "explanation": "greeting",
            "pending": true,
        });
        execute(&input, "test query", &db, session, false, &config, false).unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        let cmd_file = nsh_dir.join(format!("pending_cmd_{session}"));
        let flag_file = nsh_dir.join(format!("pending_flag_{session}"));
        assert!(cmd_file.exists());
        assert_eq!(std::fs::read_to_string(&cmd_file).unwrap(), "echo hello");
        assert!(flag_file.exists());
        assert_eq!(std::fs::read_to_string(&flag_file).unwrap(), "1");
        let _ = std::fs::remove_file(&cmd_file);
        let _ = std::fs::remove_file(&flag_file);
    }

    #[test]
    fn test_execute_not_pending_clears_stale_flag() {
        let session = "test_clear_stale";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let nsh_dir = crate::config::Config::nsh_dir();
        let flag_file = nsh_dir.join(format!("pending_flag_{session}"));
        std::fs::create_dir_all(&nsh_dir).unwrap();
        std::fs::write(&flag_file, "1").unwrap();
        assert!(flag_file.exists());
        let input = serde_json::json!({
            "command": "echo done",
            "explanation": "final command",
            "pending": false,
        });
        execute(&input, "test query", &db, session, false, &config, false).unwrap();
        assert!(!flag_file.exists());
        let cmd_file = nsh_dir.join(format!("pending_cmd_{session}"));
        let _ = std::fs::remove_file(&cmd_file);
    }

    #[test]
    fn test_execute_missing_fields_defaults() {
        let session = "test_defaults";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({});
        execute(&input, "", &db, session, false, &config, false).unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        let cmd_file = nsh_dir.join(format!("pending_cmd_{session}"));
        assert!(!cmd_file.exists());
    }

    #[test]
    fn test_execute_autorun_records_to_db() {
        let session = "test_autorun_db";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "true",
            "explanation": "recorded command",
            "pending": false,
        });
        execute(&input, "query for db", &db, session, false, &config, true).unwrap();
        let convos = db.get_conversations(session, 10).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].response, "true");
    }

    #[test]
    fn test_cleanup_cd_target_phrase_removes_filler_words() {
        assert_eq!(cleanup_cd_target_phrase("into the blink folder"), "blink");
        assert_eq!(
            cleanup_cd_target_phrase("to my-project directory"),
            "my-project"
        );
        assert_eq!(cleanup_cd_target_phrase("~/code"), "~/code");
    }

    #[test]
    fn test_normalize_cd_command_resolves_single_directory_match() {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let tmp = tempfile::tempdir().unwrap();
        let _cwd_guard = CwdGuard::push_to(tmp.path());
        std::fs::create_dir(tmp.path().join("blink-browse")).unwrap();

        let normalized = normalize_cd_command("cd into the blink folder", &db, "s1").unwrap();
        assert_eq!(normalized, "cd blink-browse");
    }

    #[test]
    fn test_normalize_cd_command_prefers_recent_history_on_ambiguous_match() {
        let session = "test_cd_history";
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        db.create_session(session, "tty0", "zsh", 1234).unwrap();
        db.insert_command(
            session,
            "cd blink-simulated",
            "/tmp",
            Some(0),
            "2026-01-01T00:00:00Z",
            Some(1),
            None,
            "",
            "zsh",
            1234,
        )
        .unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let _cwd_guard = CwdGuard::push_to(tmp.path());
        std::fs::create_dir(tmp.path().join("blink-browse")).unwrap();
        std::fs::create_dir(tmp.path().join("blink-simulated")).unwrap();

        let normalized = normalize_cd_command("cd into the blink folder", &db, session).unwrap();
        assert_eq!(normalized, "cd blink-simulated");
    }

    #[test]
    fn test_normalize_command_for_prefill_keeps_non_cd_command() {
        let db = crate::db::Db::open_in_memory().expect("in-memory db");
        let normalized =
            normalize_command_for_prefill("git status", "show me git status", &db, "default");
        assert_eq!(normalized, "git status");
    }

    #[test]
    fn test_reject_reason_for_generated_command_question_echo() {
        let reason = reject_reason_for_generated_command(
            "when did I last ssh into 135.181.128.145",
            "when did I last ssh into 135.181.128.145",
        );
        assert_eq!(
            reason,
            Some("model echoed the user's question instead of a shell command")
        );
    }

    #[test]
    fn test_reject_reason_for_generated_command_valid_command() {
        let reason = reject_reason_for_generated_command(
            "ssh root@135.181.128.145",
            "ssh root@135.181.128.145",
        );
        assert_eq!(reason, None);
    }

    #[test]
    fn test_execute_skips_prefill_for_question_echo() {
        let session = "test_question_echo";
        let db = test_db_with_session(session);
        let config = crate::config::Config::default();
        let input = serde_json::json!({
            "command": "when did I last ssh into 135.181.128.145",
            "explanation": "This should not be accepted as a command",
            "pending": false,
        });
        execute(
            &input,
            "when did I last ssh into 135.181.128.145",
            &db,
            session,
            false,
            &config,
            false,
        )
        .unwrap();
        let nsh_dir = crate::config::Config::nsh_dir();
        let cmd_file = nsh_dir.join(format!("pending_cmd_{session}"));
        assert!(!cmd_file.exists());
    }
}
