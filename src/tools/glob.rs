use glob::Pattern;

pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    let pattern_str = input["pattern"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("pattern is required"))?;
    let root_raw = input["path"].as_str().unwrap_or(".");
    let max_results = input["max_results"]
        .as_u64()
        .map(|n| n.clamp(1, 5000) as usize)
        .unwrap_or(200);

    let root = crate::tools::validate_read_path_with_access(root_raw, "block")
        .map_err(|e| anyhow::anyhow!(e))?;
    if !root.exists() {
        anyhow::bail!("path does not exist: {root_raw}");
    }
    if !root.is_dir() {
        anyhow::bail!("path is not a directory: {root_raw}");
    }

    let pattern = Pattern::new(pattern_str)
        .map_err(|e| anyhow::anyhow!("invalid glob pattern '{pattern_str}': {e}"))?;

    let walker = ignore::WalkBuilder::new(&root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .max_depth(Some(15))
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    let mut matches: Vec<(String, u64)> = Vec::new();
    let mut total_matches = 0usize;

    for entry in walker.flatten() {
        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }
        let rel = match entry.path().strip_prefix(&root) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if pattern.matches(&rel_str) {
            total_matches += 1;
            if matches.len() < max_results {
                let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                matches.push((rel_str, size));
            }
        }
    }

    matches.sort_by(|a, b| a.0.cmp(&b.0));
    let mut out = String::new();
    for (path, size) in &matches {
        out.push_str(&format!("{path} ({})\n", human_size(*size)));
    }
    if total_matches > matches.len() {
        out.push_str(&format!("... and {} more", total_matches - matches.len()));
    }
    if out.trim().is_empty() {
        return Ok("No matches found".into());
    }
    Ok(out.trim_end().to_string())
}

fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.0}{unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.0}PB")
}
