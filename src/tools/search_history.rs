use crate::db::Db;

pub fn execute(
    db: &Db,
    query: &str,
    limit: usize,
) -> anyhow::Result<String> {
    let matches = db.search_history(query, limit)?;

    if matches.is_empty() {
        return Ok(format!(
            "No history matches for '{query}'"
        ));
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

    Ok(result)
}
