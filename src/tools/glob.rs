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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn execute_matches_files_and_respects_max_results() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("a.rs"), "fn main() {}\n").expect("write a.rs");
        std::fs::create_dir_all(root.path().join("nested")).expect("mkdir nested");
        std::fs::write(root.path().join("nested").join("b.rs"), "pub fn f() {}\n")
            .expect("write b.rs");
        std::fs::write(root.path().join("nested").join("c.txt"), "ignored\n")
            .expect("write c.txt");

        let output = execute(&json!({
            "pattern": "**/*.rs",
            "path": root.path(),
            "max_results": 1,
        }))
        .expect("glob execute");

        assert!(output.contains("a.rs") || output.contains("nested/b.rs"));
        assert!(
            output.contains("... and 1 more"),
            "expected truncation indicator, got: {output}"
        );
    }

    #[test]
    fn execute_returns_no_matches_when_gitignored() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(root.path().join(".git")).expect("create .git dir");
        std::fs::write(root.path().join(".gitignore"), "ignored.txt\n").expect("write .gitignore");
        std::fs::write(root.path().join("ignored.txt"), "secret\n").expect("write ignored");

        let output = execute(&json!({
            "pattern": "*.txt",
            "path": root.path(),
        }))
        .expect("glob execute");

        assert_eq!(output, "No matches found");
    }

    #[test]
    fn execute_errors_for_invalid_pattern_and_bad_paths() {
        let root = tempfile::tempdir().expect("tempdir");
        let file_path = root.path().join("single-file");
        std::fs::write(&file_path, "x").expect("write file");

        let invalid_pattern_err = execute(&json!({
            "pattern": "[",
            "path": root.path(),
        }))
        .expect_err("expected invalid pattern error");
        assert!(
            invalid_pattern_err
                .to_string()
                .contains("invalid glob pattern"),
            "unexpected error: {invalid_pattern_err}"
        );

        let not_dir_err = execute(&json!({
            "pattern": "*",
            "path": file_path,
        }))
        .expect_err("expected non-directory error");
        assert!(not_dir_err.to_string().contains("not a directory"));

        let missing_err = execute(&json!({
            "pattern": "*",
            "path": root.path().join("missing-dir"),
        }))
        .expect_err("expected missing path error");
        assert!(missing_err.to_string().contains("does not exist"));
    }

    #[test]
    fn human_size_formats_boundaries() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(1023), "1023B");
        assert_eq!(human_size(1024), "1KB");
        assert_eq!(human_size(1024 * 1024), "1MB");
    }
}
