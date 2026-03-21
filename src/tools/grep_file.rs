use crate::config::SensitiveFileAccess;
use crate::tools::ToolInvocationOutcome;
use regex::Regex;
use std::collections::VecDeque;
use std::io::{BufRead, BufReader};

#[cfg(test)]
pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    crate::tools::execute_file_tool_content(input, SensitiveFileAccess::Block, handle)
}

#[cfg(test)]
pub fn execute_with_access(
    input: &serde_json::Value,
    sensitive_file_access: SensitiveFileAccess,
) -> anyhow::Result<String> {
    crate::tools::execute_file_tool_content(input, sensitive_file_access, handle)
}

pub fn execute_outcome_with_access(
    input: &serde_json::Value,
    sensitive_file_access: SensitiveFileAccess,
) -> anyhow::Result<ToolInvocationOutcome> {
    handle(input, sensitive_file_access)
}

fn handle(
    input: &serde_json::Value,
    sensitive_file_access: SensitiveFileAccess,
) -> anyhow::Result<ToolInvocationOutcome> {
    let path = match crate::tools::required_read_path(input, "path", sensitive_file_access)? {
        Ok(path) => path,
        Err(outcome) => return Ok(outcome),
    };

    let pattern = input["pattern"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("pattern is required"))?;
    let context_lines = input["context_lines"].as_u64().unwrap_or(3) as usize;
    let max_lines = input["max_lines"].as_u64().unwrap_or(100) as usize;

    let path_display = path.display().to_string();
    let file = match crate::tools::open_regular_read_file(&path, |path| {
        format!(
            "Cannot grep '{}': not a regular file. Use run_command with 'grep' instead.",
            path.display()
        )
    }) {
        Ok(file) => file,
        Err(outcome) => return Ok(outcome),
    };
    let mut reader = BufReader::new(file);

    grep_matches(
        &mut reader,
        pattern,
        &path_display,
        context_lines,
        max_lines,
        &path,
    )
}

fn grep_matches(
    reader: &mut BufReader<std::fs::File>,
    pattern: &str,
    path_display: &str,
    context_lines: usize,
    max_lines: usize,
    path: &std::path::Path,
) -> anyhow::Result<ToolInvocationOutcome> {
    let re = match Regex::new(pattern) {
        Ok(regex) => regex,
        Err(error) => {
            return Ok(ToolInvocationOutcome::failure(format!(
                "Invalid regex '{pattern}': {error}"
            )));
        }
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
            Ok(bytes) => bytes,
            Err(error) => return Ok(crate::tools::read_failure(path, error)),
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
                    return Ok(ToolInvocationOutcome::success(result));
                }
                result.push_str(&format!("    {ctx_no:>4}: {ctx_line}\n"));
                output_lines += 1;
                last_emitted_line = Some(*ctx_no);
            }

            if last_emitted_line != Some(line_no) {
                if output_lines >= max_lines {
                    result.push_str("\n[... truncated]\n");
                    return Ok(ToolInvocationOutcome::success(result));
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
                    return Ok(ToolInvocationOutcome::success(result));
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
        Ok(ToolInvocationOutcome::success(format!(
            "No matches for '{pattern}' in {path_display}"
        )))
    } else {
        Ok(ToolInvocationOutcome::success(result))
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
    fn test_grep_file_without_pattern_errors() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "line one").unwrap();
        writeln!(f, "line two").unwrap();
        writeln!(f, "line three").unwrap();
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("pattern is required")
        );
    }

    #[test]
    fn test_grep_file_max_lines_truncation() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..10 {
            writeln!(f, "line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path, "pattern": "line", "max_lines": 3});
        let result = execute(&input).unwrap();
        assert!(result.contains("truncated"));
        assert!(result.contains("line 1"));
        assert!(!result.contains("line 9"));
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
