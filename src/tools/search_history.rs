use crate::config::Config;
use crate::daemon_db::DbAccess;
use regex::Regex;
use std::collections::HashSet;

const MAX_SEARCH_RESULTS: usize = 50;

#[derive(Debug, Clone)]
struct EntitySearchIntent {
    executable: Option<String>,
    entity: Option<String>,
    entity_type: Option<String>,
    latest_only: bool,
}

pub fn execute(
    db: &dyn DbAccess,
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
    let requested_limit = input.get("limit").and_then(|v| v.as_u64()).unwrap_or(20) as usize;
    let limit = requested_limit.clamp(1, MAX_SEARCH_RESULTS);
    let command_filter = input.get("command").and_then(|v| v.as_str());
    let entity_filter = input.get("entity").and_then(|v| v.as_str());
    let entity_type_filter = input.get("entity_type").and_then(|v| v.as_str());
    let latest_only = input.get("latest_only").and_then(|v| v.as_bool());

    // Resolve relative time strings like "1h", "2d", "1w"
    let resolved_since = since.map(resolve_relative_time);
    let resolved_until = until.map(resolve_relative_time);

    // Resolve session filter
    let session_filter = session.and_then(|s| match s {
        "current" => Some("current".to_string()),
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
        && command_filter.is_none()
        && entity_filter.is_none()
        && entity_type_filter.is_none()
        && latest_only.is_none()
    {
        return Ok("No search criteria provided. Use 'query', 'regex', 'command', 'entity', 'since', 'exit_code', or 'failed_only'.".into());
    }

    if let Some(intent) = infer_entity_search_intent(
        query,
        regex,
        command_filter,
        entity_filter,
        entity_type_filter,
        latest_only,
    ) {
        let raw_limit = if intent.latest_only || intent.entity.is_some() {
            limit.saturating_mul(20).max(200)
        } else {
            limit.saturating_mul(10).max(100)
        }
        .min(MAX_SEARCH_RESULTS);
        let entity_matches = match db.search_command_entities(
            intent.executable.as_deref(),
            intent.entity.as_deref(),
            intent.entity_type.as_deref(),
            resolved_since.as_deref(),
            resolved_until.as_deref(),
            session_filter.as_deref(),
            Some(session_id),
            raw_limit,
        ) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("entity search failed: {e}");
                Vec::new()
            }
        };

        if !entity_matches.is_empty() {
            let summary = summarize_entity_matches(&entity_matches, &intent, limit);
            if !summary.is_empty() {
                return Ok(crate::redact::redact_secrets(&summary, &config.redaction));
            }
        }
    }

    let matches = db.search_history_advanced(
        query,
        regex,
        resolved_since.as_deref(),
        resolved_until.as_deref(),
        exit_code,
        failed_only,
        session_filter.as_deref(),
        Some(session_id),
        limit,
    )?;

    let query_mentions_ssh = query.unwrap_or("").to_ascii_lowercase().contains("ssh");
    let command_mentions_ssh = command_filter
        .map(|cmd| {
            let normalized = cmd.trim().to_ascii_lowercase();
            normalized == "ssh" || normalized.ends_with("/ssh")
        })
        .unwrap_or(false);

    let matches = if matches.is_empty()
        && session == Some("current")
        && (query_mentions_ssh || command_mentions_ssh)
    {
        let fallback_query = if query.unwrap_or("").trim().is_empty() {
            command_filter
        } else {
            query
        };
        db.search_history_advanced(
            fallback_query,
            regex,
            resolved_since.as_deref(),
            resolved_until.as_deref(),
            exit_code,
            failed_only,
            None,
            Some(session_id),
            limit,
        )?
    } else {
        matches
    };

    let matches = dedupe_history_matches(matches, limit);

    if matches.is_empty() {
        return Ok("No matching commands found.".into());
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
            let max_preview = if limit > 20 { 100 } else { 300 };
            let preview = crate::util::truncate(hl, max_preview);
            result.push_str(&format!("  output: {preview}\n"));
        }
        result.push('\n');
    }

    let memory_query = query
        .or(regex)
        .or(command_filter)
        .or(entity_filter)
        .unwrap_or("");
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

    const MAX_TOOL_RESULT_BYTES: usize = 48_000;
    if result.len() > MAX_TOOL_RESULT_BYTES {
        let mut end = MAX_TOOL_RESULT_BYTES;
        while end > 0 && !result.is_char_boundary(end) {
            end -= 1;
        }
        result.truncate(end);
        if let Some(pos) = result.rfind('\n') {
            result.truncate(pos);
        }
        result.push_str("\n... (results truncated due to size)");
    }

    Ok(crate::redact::redact_secrets(&result, &config.redaction))
}

fn dedupe_history_matches(
    matches: Vec<crate::db::HistoryMatch>,
    limit: usize,
) -> Vec<crate::db::HistoryMatch> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(limit.min(matches.len()));
    for m in matches {
        let dedupe_key = format!("{}\u{1f}{}", m.command, m.cwd.clone().unwrap_or_default());
        if seen.insert(dedupe_key) {
            out.push(m);
            if out.len() >= limit {
                break;
            }
        }
    }
    out
}

fn summarize_entity_matches(
    matches: &[crate::db::CommandEntityMatch],
    intent: &EntitySearchIntent,
    limit: usize,
) -> String {
    if matches.is_empty() {
        return String::new();
    }

    if intent.latest_only {
        let m = &matches[0];
        return format!(
            "Most recent matching target:\n- [{}] {} (via {})\n  command: {}\n",
            m.started_at, m.entity, m.executable, crate::util::truncate(&m.command, 200)
        );
    }

    let mut result = String::new();
    if let Some(executable) = &intent.executable {
        result.push_str(&format!(
            "Recent machine targets for `{executable}` (most recent first):\n"
        ));
    } else {
        result.push_str("Recent machine targets (most recent first):\n");
    }

    let mut seen_targets: HashSet<String> = HashSet::new();
    let mut rows = 0usize;

    for m in matches {
        let key = m.entity.to_ascii_lowercase();
        if !seen_targets.insert(key) {
            continue;
        }

        result.push_str(&format!(
            "- [{}] {} (via {})\n",
            m.started_at, m.entity, m.executable
        ));
        rows += 1;
        if rows >= limit {
            break;
        }
    }

    if rows == 0 { String::new() } else { result }
}

fn infer_entity_search_intent(
    query: Option<&str>,
    regex: Option<&str>,
    command: Option<&str>,
    entity: Option<&str>,
    entity_type: Option<&str>,
    latest_only: Option<bool>,
) -> Option<EntitySearchIntent> {
    let query_str = query.unwrap_or("");
    let has_explicit_filters =
        command.is_some() || entity.is_some() || entity_type.is_some() || latest_only.is_some();
    if !has_explicit_filters && regex.is_some() {
        return None;
    }

    let inferred_command = if command.is_none() {
        infer_command_from_query(query_str)
    } else {
        None
    };
    let inferred_entity = if entity.is_none() {
        extract_query_entity(query_str)
    } else {
        None
    };
    let inferred_entity_type = if entity_type.is_none() && is_machine_intent_query(query_str) {
        Some("machine".to_string())
    } else {
        None
    };
    let latest = latest_only.unwrap_or_else(|| query_indicates_latest(query_str));

    let executable = command
        .and_then(normalize_query_command)
        .or(inferred_command);
    let entity_norm = entity.and_then(normalize_query_entity).or(inferred_entity);
    let entity_type_norm = entity_type
        .and_then(normalize_entity_type)
        .or(inferred_entity_type);

    let query_word_count = tokenize_query_words(query_str).len();
    let should_use = has_explicit_filters
        || (executable.is_some()
            && (entity_norm.is_some()
                || entity_type_norm.is_some()
                || is_machine_intent_query(query_str)
                || query_word_count <= 3));

    if !should_use {
        return None;
    }

    Some(EntitySearchIntent {
        executable,
        entity: entity_norm,
        entity_type: entity_type_norm,
        latest_only: latest,
    })
}

fn infer_command_from_query(query: &str) -> Option<String> {
    if query.trim().is_empty() {
        return None;
    }
    let lower = query.to_ascii_lowercase();
    let used_with_re =
        Regex::new(r"\bthat\s+([a-z0-9_./-]+)\s+has\s+been\s+used\s+with\b").unwrap();
    if let Some(caps) = used_with_re.captures(&lower) {
        if let Some(m) = caps.get(1) {
            if let Some(cmd) = normalize_query_command_word(m.as_str()) {
                return Some(cmd);
            }
        }
    }

    let words = tokenize_query_words(&lower);
    for (idx, word) in words.iter().enumerate() {
        if matches!(word.as_str(), "into" | "from" | "to" | "with") {
            if let Some(cmd) = find_previous_command_candidate(&words, idx) {
                return Some(cmd);
            }
        }
    }

    if let Some(i_idx) = words.iter().position(|w| w == "i") {
        if let Some(cmd) = find_next_command_candidate(&words, i_idx + 1) {
            return Some(cmd);
        }
    }

    for word in &words {
        if let Some(cmd) = normalize_query_command_word(word) {
            if !is_query_stopword(&cmd) {
                return Some(cmd);
            }
        }
    }
    None
}

fn find_previous_command_candidate(words: &[String], idx: usize) -> Option<String> {
    for word in words[..idx].iter().rev() {
        if let Some(cmd) = normalize_query_command_word(word) {
            if !is_query_stopword(&cmd) {
                return Some(cmd);
            }
        }
    }
    None
}

fn find_next_command_candidate(words: &[String], start: usize) -> Option<String> {
    for word in words.iter().skip(start) {
        if let Some(cmd) = normalize_query_command_word(word) {
            if !is_query_stopword(&cmd) {
                return Some(cmd);
            }
        }
    }
    None
}

fn normalize_query_command(input: &str) -> Option<String> {
    normalize_query_command_word(input)
}

fn normalize_query_command_word(word: &str) -> Option<String> {
    let mut normalized = word
        .trim()
        .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '-' && c != '.')
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(last) = normalized.rsplit('/').next() {
        normalized = last.to_string();
    }
    if normalized.ends_with("'d") {
        normalized.truncate(normalized.len() - 2);
    }
    if normalized.ends_with("ed") && normalized.len() > 4 {
        normalized.truncate(normalized.len() - 2);
    } else if normalized.ends_with('d') && normalized.len() > 3 {
        let base = &normalized[..normalized.len() - 1];
        if matches!(base, "ssh" | "telnet" | "rsync" | "scp" | "sftp") {
            normalized = base.to_string();
        }
    }
    if normalized == "sshd" {
        normalized = "ssh".to_string();
    }
    if normalized.is_empty()
        || normalized.chars().all(|c| c.is_ascii_digit())
        || is_query_stopword(&normalized)
    {
        return None;
    }
    Some(normalized)
}

fn extract_query_entity(query: &str) -> Option<String> {
    if query.trim().is_empty() {
        return None;
    }

    let user_host_re = Regex::new(r"\b[a-zA-Z0-9._-]+@([a-zA-Z0-9._:-]+)\b").unwrap();
    if let Some(caps) = user_host_re.captures(query) {
        if let Some(m) = caps.get(1) {
            if let Some(v) = normalize_query_entity(m.as_str()) {
                return Some(v);
            }
        }
    }

    let ipv4_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap();
    if let Some(m) = ipv4_re.find(query) {
        if let Some(v) = normalize_query_entity(m.as_str()) {
            return Some(v);
        }
    }

    let host_re = Regex::new(r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\.[a-zA-Z]{2,}\b").unwrap();
    if let Some(m) = host_re.find(query) {
        if let Some(v) = normalize_query_entity(m.as_str()) {
            return Some(v);
        }
    }
    None
}

fn normalize_query_entity(entity: &str) -> Option<String> {
    let token = entity
        .trim()
        .trim_matches(|c: char| matches!(c, '"' | '\'' | ',' | ';' | ')' | '(' | '[' | ']'))
        .trim_matches('.');
    if token.is_empty() {
        return None;
    }
    let mut host = token.rsplit('@').next().unwrap_or(token);
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        host = &host[1..host.len() - 1];
    }
    if let Some((h, port)) = host.rsplit_once(':') {
        if !h.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            host = h;
        }
    }
    let host = host.trim_matches('.');
    if host.is_empty() {
        return None;
    }
    if host.parse::<std::net::Ipv4Addr>().is_ok() || host.parse::<std::net::Ipv6Addr>().is_ok() {
        return Some(host.to_ascii_lowercase());
    }
    if host.eq_ignore_ascii_case("localhost") {
        return Some("localhost".to_string());
    }
    if is_hostname_like(host) {
        return Some(host.to_ascii_lowercase());
    }
    None
}

fn normalize_entity_type(entity_type: &str) -> Option<String> {
    let normalized = entity_type.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "machine" | "host" | "ip" => Some(normalized),
        _ => None,
    }
}

fn tokenize_query_words(query: &str) -> Vec<String> {
    query
        .split_whitespace()
        .map(|w| {
            w.trim_matches(|c: char| {
                !c.is_ascii_alphanumeric() && c != '\'' && c != '_' && c != '-' && c != '.'
            })
            .to_ascii_lowercase()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

fn is_machine_intent_query(query: &str) -> bool {
    let q = query.to_ascii_lowercase();
    [
        "server",
        "servers",
        "machine",
        "machines",
        "host",
        "hosts",
        "hostname",
        "hostnames",
        "ip",
        "ips",
        "address",
        "addresses",
    ]
    .iter()
    .any(|k| q.contains(k))
}

fn query_indicates_latest(query: &str) -> bool {
    let q = query.to_ascii_lowercase();
    q.contains("last") || q.contains("most recent") || q.contains("latest")
}

fn is_query_stopword(word: &str) -> bool {
    matches!(
        word,
        "a" | "all"
            | "am"
            | "an"
            | "and"
            | "are"
            | "been"
            | "did"
            | "do"
            | "from"
            | "had"
            | "has"
            | "have"
            | "hostname"
            | "hostnames"
            | "host"
            | "hosts"
            | "i"
            | "in"
            | "into"
            | "ip"
            | "ips"
            | "is"
            | "last"
            | "latest"
            | "machine"
            | "machines"
            | "most"
            | "my"
            | "of"
            | "on"
            | "recent"
            | "recently"
            | "server"
            | "servers"
            | "that"
            | "the"
            | "to"
            | "used"
            | "what"
            | "when"
            | "which"
            | "with"
            | "were"
    )
}

fn is_hostname_like(value: &str) -> bool {
    if value.len() > 253 {
        return false;
    }
    if !value.contains('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
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
    fn test_execute_dedupes_identical_commands() {
        let db = test_db();
        for i in 0..3 {
            db.insert_command(
                "test_sess",
                "rsyncd root@135.181.128.145:\"/root/blink-browse/logs\" .",
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:00:0{i}Z"),
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        }
        let config = Config::default();
        let input = serde_json::json!({"query": "logs", "limit": 20});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert_eq!(result.lines().filter(|l| l.starts_with('[')).count(), 1);
    }

    #[test]
    fn test_execute_keeps_same_command_across_different_cwds() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "rsyncd root@135.181.128.145:\"/root/blink-browse/logs\" .",
            "/tmp/a",
            Some(0),
            "2025-06-01T00:00:00Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "test_sess",
            "rsyncd root@135.181.128.145:\"/root/blink-browse/logs\" .",
            "/tmp/b",
            Some(0),
            "2025-06-01T00:00:01Z",
            None,
            None,
            "",
            "",
            0,
        )
        .unwrap();
        let config = Config::default();
        let input = serde_json::json!({"query": "logs", "limit": 20});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert_eq!(result.lines().filter(|l| l.starts_with('[')).count(), 2);
        assert!(result.contains("cwd: /tmp/a"));
        assert!(result.contains("cwd: /tmp/b"));
    }

    #[test]
    fn test_execute_clamps_limit_to_100() {
        let db = test_db();
        for i in 0..150 {
            db.insert_command(
                "test_sess",
                &format!("echo unique_{i}"),
                "/tmp",
                Some(0),
                &format!("2025-06-01T00:{:02}:00Z", i % 60),
                None,
                None,
                "",
                "",
                0,
            )
            .unwrap();
        }
        let config = Config::default();
        let input = serde_json::json!({"query": "echo", "limit": 500});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.lines().filter(|l| l.starts_with('[')).count() <= 100);
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
    fn test_execute_query_for_ping_servers_recently() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "ping -c 1 198.51.100.10",
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
            "ping -c 1 api.example.net",
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

        let config = Config::default();
        let input = serde_json::json!({"query": "what are the servers I pinged recently"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("198.51.100.10"));
        assert!(result.contains("api.example.net"));
    }

    #[test]
    fn test_execute_query_for_last_telnet_ip() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "telnet 203.0.113.7 443",
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
        let input = serde_json::json!({"query": "when did I last telnet into 203.0.113.7"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("2026-02-11T17:49:15Z"));
        assert!(result.contains("203.0.113.7"));
    }

    #[test]
    fn test_execute_query_for_custom_command_entities() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "waffle prod1.example.com --check",
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
            "waffle backup.example.net --sync",
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

        let config = Config::default();
        let input = serde_json::json!({"query": "what are all the machines that waffle has been used with"});
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("prod1.example.com"));
        assert!(result.contains("backup.example.net"));
    }

    #[test]
    fn test_infer_command_from_query_inflections() {
        assert_eq!(
            infer_command_from_query("what servers have I sshd into recently"),
            Some("ssh".to_string())
        );
        assert_eq!(
            infer_command_from_query("what servers have I ssh'd into recently"),
            Some("ssh".to_string())
        );
        assert_eq!(
            infer_command_from_query("what are the IP addresses I telnet'd into"),
            Some("telnet".to_string())
        );
        assert_eq!(
            infer_command_from_query("what are the hostnames I recently rsync'd from"),
            Some("rsync".to_string())
        );
    }

    #[test]
    fn test_infer_entity_intent_for_used_with_phrase() {
        let intent = infer_entity_search_intent(
            Some("what are all the machines that waffle has been used with"),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("entity intent");
        assert_eq!(intent.executable.as_deref(), Some("waffle"));
        assert_eq!(intent.entity_type.as_deref(), Some("machine"));
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
        assert!(result.contains("Recent machine targets for `ssh`"));
        assert_eq!(
            result.matches("ssh.phx.nearlyfreespeech.net").count(),
            1,
            "duplicate SSH targets should be collapsed to one line"
        );
        assert!(result.contains("135.181.128.145"));
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

    #[test]
    fn test_execute_current_session_ssh_fallback_with_empty_query_and_command_filter() {
        let db = test_db();
        db.insert_command(
            "test_sess",
            "echo hello",
            "/project",
            Some(0),
            "2026-02-11T17:58:15Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        db.insert_command(
            "other_sess",
            "ssh admin@203.0.113.22",
            "/project",
            Some(0),
            "2026-02-11T17:59:15Z",
            None,
            None,
            "/dev/pts/1",
            "",
            0,
        )
        .unwrap();
        let config = Config::default();
        let input = serde_json::json!({
            "command": "ssh",
            "session": "current",
            "latest_only": true
        });
        let result = execute(&db, &input, &config, "test_sess").unwrap();
        assert!(result.contains("203.0.113.22"));
    }
}
