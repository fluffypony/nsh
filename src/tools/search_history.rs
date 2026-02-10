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
