use crate::config::Config;
use crate::db::Db;
use regex::Regex;
use std::collections::HashSet;

pub fn execute(
    db: &Db,
    input: &serde_json::Value,
    config: &Config,
    session_id: &str,
) -> anyhow::Result<String> {
    let query = input.get("query").and_then(|v| v.as_str());
    let regex = input.get("regex").and_then(|v| v.as_str());
    let since = input.get("since").and_then(|v| v.as_str());
    let until = input.get("until").and_then(|v| v.as_str());
    let exit_code = input
        .get("exit_code")
        .and_then(|v| v.as_i64())
        .map(|v| v as i32);
    let failed_only = input
        .get("failed_only")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let session = input.get("session").and_then(|v| v.as_str());
    let limit = input.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;

    // Resolve relative time strings like "1h", "2d", "1w"
    let resolved_since = since.map(resolve_relative_time);
    let resolved_until = until.map(resolve_relative_time);

    // Resolve session filter
    let session_filter = session.and_then(|s| match s {
        "current" => Some(session_id.to_string()),
        "all" | "" => None,
        other => Some(other.to_string()),
    });

    if query.is_none()
        && regex.is_none()
        && since.is_none()
        && until.is_none()
        && exit_code.is_none()
        && !failed_only
        && session.is_none()
    {
        return Ok("No search criteria provided. Use 'query', 'regex', 'since', 'exit_code', or 'failed_only'.".into());
    }

    let ssh_intent = is_ssh_intent(query, regex);
    let raw_limit = if ssh_intent {
        limit.saturating_mul(20).max(200)
    } else {
        limit
    };
    let search_regex = if ssh_intent {
        Some(SSH_COMMAND_REGEX)
    } else {
        regex
    };
    let search_query = if ssh_intent { None } else { query };

    let matches = db.search_history_advanced(
        search_query,
        search_regex,
        resolved_since.as_deref(),
        resolved_until.as_deref(),
        exit_code,
        failed_only,
        session_filter.as_deref(),
        Some(session_id),
        raw_limit,
    )?;

    if matches.is_empty() {
        return Ok("No matching commands found.".into());
    }

    if ssh_intent {
        let summary = summarize_ssh_targets(&matches, query, limit);
        if summary.is_empty() {
            return Ok("No SSH commands found in history.".into());
        }
        return Ok(crate::redact::redact_secrets(&summary, &config.redaction));
    }

    let mut result = String::new();
    for m in &matches {
        let code = m
            .exit_code
            .map(|c| format!(" (exit {c})"))
            .unwrap_or_default();
        result.push_str(&format!(
            "[{}]{} $ {}\n",
            m.started_at, code, m.cmd_highlight,
        ));
        if let Some(cwd) = &m.cwd {
            result.push_str(&format!("  cwd: {cwd}\n"));
        }
        if let Some(hl) = &m.output_highlight {
            let preview = crate::util::truncate(hl, 300);
            result.push_str(&format!("  output: {preview}\n"));
        }
        result.push('\n');
    }

    let memory_query = query.or(regex).unwrap_or("");
    let memory_matches = if memory_query.is_empty() {
        Vec::new()
    } else {
        db.search_memories(memory_query).unwrap_or_default()
    };

    if !memory_matches.is_empty() {
        result.push_str("\n── Memories ──\n");
        for m in &memory_matches {
            result.push_str(&format!("  [memory #{}] {} = {}\n", m.id, m.key, m.value,));
        }
    }

    Ok(crate::redact::redact_secrets(&result, &config.redaction))
}

const SSH_COMMAND_REGEX: &str = r"(?i)(^|\s)(ssh)(\s|$)";

fn is_ssh_intent(query: Option<&str>, regex: Option<&str>) -> bool {
    query
        .or(regex)
        .map(|s| s.to_ascii_lowercase().contains("ssh"))
        .unwrap_or(false)
}

fn summarize_ssh_targets(
    matches: &[crate::db::HistoryMatch],
    query: Option<&str>,
    limit: usize,
) -> String {
    let host_filters = query.map(extract_host_filters).unwrap_or_default();
    let host_filter_set: HashSet<String> = host_filters.into_iter().collect();

    let mut result = String::new();
    if host_filter_set.is_empty() {
        result.push_str("Recent SSH targets (most recent first):\n");
    } else {
        result.push_str("Recent SSH targets matching your query (most recent first):\n");
    }

    let mut seen_targets = HashSet::new();
    let mut rows = 0usize;

    for m in matches {
        let Some(target) = extract_ssh_target(&m.command) else {
            continue;
        };

        if !host_filter_set.is_empty() {
            let target_lc = target.to_ascii_lowercase();
            let cmd_lc = m.command.to_ascii_lowercase();
            let matched = host_filter_set
                .iter()
                .all(|f| target_lc.contains(f) || cmd_lc.contains(f));
            if !matched {
                continue;
            }
        }

        let key = target.to_ascii_lowercase();
        if !seen_targets.insert(key) {
            continue;
        }

        result.push_str(&format!("- [{}] {}\n", m.started_at, target));
        rows += 1;
        if rows >= limit {
            break;
        }
    }

    if rows == 0 { String::new() } else { result }
}

fn extract_host_filters(query: &str) -> Vec<String> {
    let user_host_re = Regex::new(r"\b[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\b").unwrap();
    let ipv4_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    let host_re = Regex::new(r"\b[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}\b").unwrap();

    let mut out = Vec::new();
    for re in [&user_host_re, &ipv4_re, &host_re] {
        for m in re.find_iter(query) {
            out.push(m.as_str().to_ascii_lowercase());
        }
    }
    out.sort();
    out.dedup();
    out
}

fn extract_ssh_target(command: &str) -> Option<String> {
    let tokens = shell_words::split(command).ok()?;
    let mut i = 0usize;

    while i < tokens.len() {
        let tok = tokens[i].as_str();

        if tok == "sudo" || tok == "env" || is_env_assignment(tok) {
            i += 1;
            continue;
        }

        if tok == "ssh" || tok.ends_with("/ssh") {
            return parse_ssh_target_after(&tokens, i + 1);
        }

        i += 1;
    }

    None
}

fn parse_ssh_target_after(tokens: &[String], mut i: usize) -> Option<String> {
    while i < tokens.len() {
        let tok = tokens[i].as_str();
        if tok == "--" {
            i += 1;
            continue;
        }
        if tok.starts_with('-') {
            if ssh_option_takes_value(tok) && i + 1 < tokens.len() {
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        let cleaned = tok.trim_end_matches([',', ';', ':']).to_string();
        if cleaned.is_empty() {
            return None;
        }
        return Some(cleaned);
    }
    None
}

fn is_env_assignment(token: &str) -> bool {
    !token.starts_with('-') && token.contains('=') && !token.starts_with("ssh")
}

fn ssh_option_takes_value(tok: &str) -> bool {
    if tok.starts_with("--") {
        return !tok.contains('=');
    }
    if tok.len() > 2 {
        let short = &tok[..2];
        if matches!(
            short,
            "-b" | "-c"
                | "-D"
                | "-E"
                | "-e"
                | "-F"
                | "-I"
                | "-i"
                | "-J"
                | "-L"
                | "-l"
                | "-m"
                | "-O"
                | "-o"
                | "-p"
                | "-Q"
                | "-R"
                | "-S"
                | "-W"
                | "-w"
        ) {
            // Attached forms like -p22 or -luser do not consume next arg.
            return false;
        }
    }
    matches!(
        tok,
        "-b" | "-c"
            | "-D"
            | "-E"
            | "-e"
            | "-F"
            | "-I"
            | "-i"
            | "-J"
            | "-L"
            | "-l"
            | "-m"
            | "-O"
            | "-o"
            | "-p"
            | "-Q"
            | "-R"
            | "-S"
            | "-W"
            | "-w"
    )
}

fn resolve_relative_time(input: &str) -> String {
    let input = input.trim();
    if input.contains('T') || input.contains('-') {
        return input.to_string();
    }

    let (num, unit) = if input.ends_with('h') {
        (
            input.trim_end_matches('h').parse::<i64>().unwrap_or(1),
            "hours",
        )
    } else if input.ends_with('d') {
        (
            input.trim_end_matches('d').parse::<i64>().unwrap_or(1),
            "days",
        )
    } else if input.ends_with('w') {
        (
            input.trim_end_matches('w').parse::<i64>().unwrap_or(1),
            "weeks",
        )
    } else if input.ends_with('m') {
        (
            input.trim_end_matches('m').parse::<i64>().unwrap_or(1),
            "minutes",
        )
    } else {
        return input.to_string();
    };

    let duration = match unit {
        "minutes" => chrono::Duration::minutes(num),
        "hours" => chrono::Duration::hours(num),
        "days" => chrono::Duration::days(num),
        "weeks" => chrono::Duration::weeks(num),
        _ => return input.to_string(),
    };

    (chrono::Utc::now() - duration).to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{DateTime, Utc};

    #[test]
    fn test_resolve_relative_time_iso_passthrough() {
        let input = "2025-01-01T00:00:00Z";
        assert_eq!(resolve_relative_time(input), input);
    }

    #[test]
    fn test_resolve_relative_time_date_passthrough() {
        let input = "2025-01-01";
        assert_eq!(resolve_relative_time(input), input);
    }

    #[test]
    fn test_resolve_relative_time_hours() {
        let result = resolve_relative_time("2h");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::hours(2);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    #[test]
    fn test_resolve_relative_time_days() {
        let result = resolve_relative_time("3d");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::days(3);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    #[test]
    fn test_resolve_relative_time_weeks() {
        let result = resolve_relative_time("1w");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::weeks(1);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    #[test]
    fn test_resolve_relative_time_minutes() {
        let result = resolve_relative_time("30m");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::minutes(30);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    #[test]
    fn test_resolve_relative_time_unknown_suffix() {
        assert_eq!(resolve_relative_time("5x"), "5x");
    }

    #[test]
    fn test_resolve_relative_time_whitespace_trimming() {
        let result = resolve_relative_time(" 2h ");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::hours(2);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    fn test_db() -> crate::db::Db {
        crate::db::Db::open_in_memory().expect("in-memory db")
    }

    fn insert_test_commands(db: &crate::db::Db) {
        db.insert_command(
            "test_sess",
            "cargo build",
            "/project",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            Some("Compiling..."),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "git push origin main",
            "/project",
            Some(0),
            "2025-06-01T00:01:00Z",
            None,
            Some("Everything up-to-date"),
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "cargo test --release",
            "/project",
            Some(1),
            "2025-06-01T00:02:00Z",
            None,
            Some("test result: FAILED"),
            "",
            "",
            0,
        )
        .unwrap();
    }

    #[test]
    fn test_execute_no_criteria() {
        let db = test_db();
        let config = Config::default();
        let input = serde_json::json!({});
        let result = execute(&db, &input, &config, "sess1").unwrap();
        assert!(result.contains("No search criteria provided"));
    }

    #[test]
    fn test_execute_with_query() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_regex() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"regex": "git.*main"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("git push"));
    }

    #[test]
    fn test_execute_no_results() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "nonexistent_xyz_12345"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("No matching commands found"));
    }

    #[test]
    fn test_execute_with_session_current() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "session": "current"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_session_all() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "session": "all"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_session_specific() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "session": "test_sess"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_failed_only() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"failed_only": true});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo test"));
    }

    #[test]
    fn test_execute_with_exit_code() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"exit_code": 1});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo test"));
    }

    #[test]
    fn test_resolve_relative_time_invalid_number() {
        let result = resolve_relative_time("abch");
        let parsed = result.parse::<DateTime<Utc>>().unwrap();
        let expected = Utc::now() - chrono::Duration::hours(1);
        assert!((parsed - expected).num_seconds().abs() < 5);
    }

    #[test]
    fn test_execute_with_limit() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "limit": 1});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_includes_matching_memories() {
        let db = test_db();
        insert_test_commands(&db);
        db.upsert_memory("cargo_tip", "use cargo check for fast feedback")
            .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("── Memories ──"));
        assert!(result.contains("[memory #"));
        assert!(result.contains("cargo_tip"));
        assert!(result.contains("use cargo check for fast feedback"));
    }

    #[test]
    fn test_execute_no_memories_when_no_match() {
        let db = test_db();
        insert_test_commands(&db);
        db.upsert_memory("unrelated_key", "unrelated_value")
            .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(!result.contains("── Memories ──"));
    }

    #[test]
    fn test_execute_memories_via_regex_fallback() {
        let db = test_db();
        insert_test_commands(&db);
        db.upsert_memory("git_workflow", "always rebase before push")
            .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"regex": "git"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("── Memories ──"));
        assert!(result.contains("git_workflow"));
    }

    #[test]
    fn test_execute_no_memories_section_when_query_empty_via_failed_only() {
        let db = test_db();
        insert_test_commands(&db);
        db.upsert_memory("some_key", "some_value").unwrap();
        let config = Config::default();
        let input = serde_json::json!({"failed_only": true});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(!result.contains("── Memories ──"));
    }

    #[test]
    fn test_result_formatting_with_cwd_and_output() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo build"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cwd: /project"));
        assert!(result.contains("output: "));
    }

    #[test]
    fn test_result_formatting_exit_code() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"exit_code": 1});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("(exit 1)"));
    }

    #[test]
    fn test_result_formatting_exit_code_zero() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"exit_code": 0});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("(exit 0)"));
        assert!(!result.contains("(exit 1)"));
    }

    #[test]
    fn test_execute_session_empty_string_treated_as_all() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "session": ""});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_since_and_until() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({
            "query": "cargo",
            "since": "2025-01-01T00:00:00Z",
            "until": "2025-12-31T23:59:59Z"
        });
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo"));
    }

    #[test]
    fn test_execute_with_relative_since() {
        let db = test_db();
        insert_test_commands(&db);
        let config = Config::default();
        let input = serde_json::json!({"query": "cargo", "since": "30d"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("cargo") || result.contains("No matching"),);
    }

    #[test]
    fn test_extract_ssh_target_basic() {
        assert_eq!(
            extract_ssh_target("ssh fluffypony@example.com"),
            Some("fluffypony@example.com".to_string())
        );
    }

    #[test]
    fn test_extract_ssh_target_with_options() {
        assert_eq!(
            extract_ssh_target("ssh -p 2222 -i ~/.ssh/id_ed25519 admin@10.0.0.10"),
            Some("admin@10.0.0.10".to_string())
        );
        assert_eq!(
            extract_ssh_target("ssh -p2222 root@192.0.2.7"),
            Some("root@192.0.2.7".to_string())
        );
    }

    #[test]
    fn test_extract_ssh_target_skips_non_ssh() {
        assert_eq!(extract_ssh_target("systemctl restart sshd"), None);
        assert_eq!(extract_ssh_target("echo ssh"), None);
    }

    #[test]
    fn test_execute_ssh_query_returns_deduped_recent_targets() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "ssh fluffypony_cwiaf@ssh.phx.nearlyfreespeech.net",
            "/project",
            Some(0),
            "2026-02-11T17:47:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "ssh fluffypony_cwiaf@ssh.phx.nearlyfreespeech.net",
            "/project",
            Some(0),
            "2026-02-11T17:48:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "ssh admin@135.181.128.145",
            "/project",
            Some(0),
            "2026-02-11T17:49:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "ssh"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("Recent SSH targets"));
        assert_eq!(
            result
                .matches("fluffypony_cwiaf@ssh.phx.nearlyfreespeech.net")
                .count(),
            1,
            "duplicate SSH targets should be collapsed to one line"
        );
        assert!(result.contains("admin@135.181.128.145"));
    }

    #[test]
    fn test_execute_ssh_query_with_host_filter() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "ssh fluffypony_cwiaf@ssh.phx.nearlyfreespeech.net",
            "/project",
            Some(0),
            "2026-02-11T17:47:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "ssh admin@135.181.128.145",
            "/project",
            Some(0),
            "2026-02-11T17:49:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "when did I last ssh into 135.181.128.145"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("135.181.128.145"));
        assert!(!result.contains("ssh.phx.nearlyfreespeech.net"));
    }

    #[test]
    fn test_execute_sshd_typo_still_searches_ssh_history() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "ssh admin@203.0.113.11",
            "/project",
            Some(0),
            "2026-02-11T17:49:15Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "what servers have I sshd into recently"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("203.0.113.11"));
    }
}
