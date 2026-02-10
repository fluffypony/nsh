use crate::config::Config;
use crate::db::Db;

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
            result.push_str(&format!(
                "  [memory #{}] {} = {}\n",
                m.id, m.key, m.value,
            ));
        }
    }

    Ok(crate::redact::redact_secrets(&result, &config.redaction))
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
            "test_sess", "cargo build", "/project", Some(0),
            "2025-06-01T00:00:00Z", None, Some("Compiling..."), "", "", 0,
        ).unwrap();
        db.insert_command(
            "test_sess", "git push origin main", "/project", Some(0),
            "2025-06-01T00:01:00Z", None, Some("Everything up-to-date"), "", "", 0,
        ).unwrap();
        db.insert_command(
            "test_sess", "cargo test --release", "/project", Some(1),
            "2025-06-01T00:02:00Z", None, Some("test result: FAILED"), "", "", 0,
        ).unwrap();
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
}
