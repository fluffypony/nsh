use regex::Regex;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};

#[cfg(unix)]
fn open_for_read(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
fn open_for_read(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    std::fs::File::open(path)
}

#[cfg(test)]
pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    execute_with_access(input, "block")
}

pub fn execute_with_access(
    input: &serde_json::Value,
    sensitive_file_access: &str,
) -> anyhow::Result<String> {
    let raw_path = input["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("path is required"))?;

    let path = match crate::tools::validate_read_path_with_access(raw_path, sensitive_file_access) {
        Ok(p) => p,
        Err(msg) => return Ok(msg),
    };

    let pattern = input["pattern"].as_str();
    let context_lines = input["context_lines"].as_u64().unwrap_or(3) as usize;
    let max_lines = input["max_lines"].as_u64().unwrap_or(100) as usize;

    let path_display = path.display().to_string();
    let file = match open_for_read(&path) {
        Ok(f) => f,
        Err(e) => return Ok(format!("Error reading '{path_display}': {e}")),
    };
    let mut reader = BufReader::new(file);

    match pattern {
        Some(pat) => {
            let re = match Regex::new(pat) {
                Ok(r) => r,
                Err(e) => return Ok(format!("Invalid regex '{pat}': {e}")),
            };

            let mut result = String::new();
            let mut output_lines = 0;
            let mut line_no = 0usize;
            let mut line = String::new();
            let mut before = VecDeque::<(usize, String)>::new();
            let mut after_remaining = 0usize;
            let mut last_emitted_line: Option<usize> = None;

            loop {
                line.clear();
                let bytes = match reader.read_line(&mut line) {
                    Ok(n) => n,
                    Err(e) => return Ok(format!("Error reading '{path_display}': {e}")),
                };
                if bytes == 0 {
                    break;
                }
                line_no += 1;

                let line_str = line.trim_end_matches(['\n', '\r']).to_string();
                let is_match = re.is_match(&line_str);

                if is_match {
                    for (ctx_no, ctx_line) in &before {
                        if last_emitted_line.is_some_and(|n| *ctx_no <= n) {
                            continue;
                        }
                        if output_lines >= max_lines {
                            result.push_str("\n[... truncated]\n");
                            return Ok(result);
                        }
                        result.push_str(&format!("    {ctx_no:>4}: {ctx_line}\n"));
                        output_lines += 1;
                        last_emitted_line = Some(*ctx_no);
                    }

                    if last_emitted_line != Some(line_no) {
                        if output_lines >= max_lines {
                            result.push_str("\n[... truncated]\n");
                            return Ok(result);
                        }
                        result.push_str(&format!(">>> {line_no:>4}: {line_str}\n"));
                        output_lines += 1;
                        last_emitted_line = Some(line_no);
                    }

                    result.push_str("---\n");
                    after_remaining = context_lines;
                } else if after_remaining > 0 {
                    if last_emitted_line != Some(line_no) {
                        if output_lines >= max_lines {
                            result.push_str("\n[... truncated]\n");
                            return Ok(result);
                        }
                        result.push_str(&format!("    {line_no:>4}: {line_str}\n"));
                        output_lines += 1;
                        last_emitted_line = Some(line_no);
                    }
                    after_remaining -= 1;
                }

                if context_lines > 0 {
                    before.push_back((line_no, line_str));
                    while before.len() > context_lines {
                        before.pop_front();
                    }
                }
            }

            if result.is_empty() {
                Ok(format!("No matches for '{pat}' in {path_display}"))
            } else {
                Ok(result)
            }
        }
        None => {
            // No pattern — read the file (up to max_lines)
            let mut result = String::new();
            let mut line = String::new();
            let mut line_no = 0usize;
            let mut total_lines = 0usize;
            loop {
                line.clear();
                let bytes = match reader.read_line(&mut line) {
                    Ok(n) => n,
                    Err(e) => return Ok(format!("Error reading '{path_display}': {e}")),
                };
                if bytes == 0 {
                    break;
                }

                total_lines += 1;
                if line_no < max_lines {
                    line_no += 1;
                    result.push_str(&format!(
                        "{:>4}: {}\n",
                        line_no,
                        line.trim_end_matches(['\n', '\r'])
                    ));
                }
            }

            if total_lines > max_lines {
                result.push_str(&format!("\n[... {} more lines]\n", total_lines - max_lines));
            }

            Ok(result)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn test_grep_file_with_pattern() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "hello world").unwrap();
        writeln!(f, "foo bar").unwrap();
        writeln!(f, "hello again").unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path, "pattern": "hello"});
        let result = execute(&input).unwrap();
        assert!(result.contains("hello world"));
        assert!(result.contains("hello again"));
    }

    #[test]
    fn test_grep_file_no_matches() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "hello world").unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path, "pattern": "nonexistent"});
        let result = execute(&input).unwrap();
        assert!(result.contains("No matches"));
    }

    #[test]
    fn test_grep_file_nonexistent_path() {
        let input = json!({
            "path": "/tmp/nsh_test_nonexistent_file_xyz",
            "pattern": "test"
        });
        let result = execute(&input).unwrap();
        assert!(result.contains("Error reading"));
    }

    #[test]
    fn test_grep_file_missing_path() {
        let input = json!({"pattern": "test"});
        let result = execute(&input);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("path is required"));
    }

    #[test]
    fn test_grep_file_invalid_regex() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "hello").unwrap();
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path, "pattern": "[invalid"});
        let result = execute(&input).unwrap();
        assert!(result.contains("Invalid regex"));
    }

    #[test]
    fn test_grep_file_no_pattern_reads_file() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "line one").unwrap();
        writeln!(f, "line two").unwrap();
        writeln!(f, "line three").unwrap();
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("line one"));
        assert!(result.contains("line two"));
        assert!(result.contains("line three"));
    }

    #[test]
    fn test_grep_file_max_lines_truncation() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..10 {
            writeln!(f, "line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path, "max_lines": 3});
        let result = execute(&input).unwrap();
        assert!(result.contains("more lines"));
    }

    #[test]
    fn test_grep_file_context_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..10 {
            writeln!(f, "line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path, "pattern": "line 5", "context_lines": 1});
        let result = execute(&input).unwrap();
        assert!(result.contains("line 4"));
        assert!(result.contains("line 5"));
        assert!(result.contains("line 6"));
    }

    #[test]
    fn test_grep_file_match_truncated_by_max_lines() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..20 {
            writeln!(f, "match {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path, "pattern": "match", "context_lines": 0, "max_lines": 5});
        let result = execute(&input).unwrap();
        assert!(result.contains("truncated"));
    }
}
