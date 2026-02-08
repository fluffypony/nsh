use regex::Regex;
use std::fs;

pub fn execute(
    input: &serde_json::Value,
) -> anyhow::Result<String> {
    let path = input["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("path is required"))?;
    let pattern = input["pattern"].as_str();
    let context_lines =
        input["context_lines"].as_u64().unwrap_or(3) as usize;
    let max_lines =
        input["max_lines"].as_u64().unwrap_or(100) as usize;

    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => return Ok(format!("Error reading '{path}': {e}")),
    };

    let lines: Vec<&str> = content.lines().collect();

    match pattern {
        Some(pat) => {
            let re = match Regex::new(pat) {
                Ok(r) => r,
                Err(e) => {
                    return Ok(format!(
                        "Invalid regex '{pat}': {e}"
                    ))
                }
            };

            let mut result = String::new();
            let mut output_lines = 0;

            for (i, line) in lines.iter().enumerate() {
                if re.is_match(line) {
                    let start = i.saturating_sub(context_lines);
                    let end =
                        (i + context_lines + 1).min(lines.len());
                    for j in start..end {
                        if output_lines >= max_lines {
                            result.push_str(
                                "\n[... truncated]\n",
                            );
                            return Ok(result);
                        }
                        let marker =
                            if j == i { ">>>" } else { "   " };
                        result.push_str(&format!(
                            "{marker} {:>4}: {}\n",
                            j + 1,
                            lines[j]
                        ));
                        output_lines += 1;
                    }
                    result.push_str("---\n");
                }
            }

            if result.is_empty() {
                Ok(format!(
                    "No matches for '{pat}' in {path}"
                ))
            } else {
                Ok(result)
            }
        }
        None => {
            // No pattern — read the file (up to max_lines)
            let end = max_lines.min(lines.len());
            let mut result = String::new();
            for (i, line) in lines[..end].iter().enumerate() {
                result.push_str(&format!(
                    "{:>4}: {}\n",
                    i + 1,
                    line
                ));
            }
            if lines.len() > max_lines {
                result.push_str(&format!(
                    "\n[... {} more lines]\n",
                    lines.len() - max_lines
                ));
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

        let input =
            json!({"path": path, "pattern": "nonexistent"});
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
}
