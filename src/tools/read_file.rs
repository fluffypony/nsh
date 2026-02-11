use std::fs;

#[cfg(test)]
pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    execute_with_access(input, "block")
}

pub fn execute_with_access(input: &serde_json::Value, sensitive_file_access: &str) -> anyhow::Result<String> {
    let raw_path = input["path"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("path is required"))?;

    let path = match crate::tools::validate_read_path_with_access(raw_path, sensitive_file_access) {
        Ok(p) => p,
        Err(msg) => return Ok(msg),
    };

    let start_line = (input["start_line"].as_u64().unwrap_or(1) as usize).max(1);
    let end_line = input["end_line"].as_u64().unwrap_or(200) as usize;

    let bytes = match fs::read(&path) {
        Ok(b) => b,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };

    if bytes.iter().take(8192).any(|&b| b == 0) {
        return Ok("Binary file, cannot display".into());
    }

    let content = match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Ok("Binary file, cannot display".into()),
    };

    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    if start_line > total_lines {
        return Ok(format!(
            "\n[{}: {total_lines} total lines]\n",
            path.display()
        ));
    }

    let capped_end = end_line.min(start_line + 499).min(total_lines);

    let mut result = String::new();
    for (i, line) in lines[start_line - 1..capped_end].iter().enumerate() {
        result.push_str(&format!("{:>4}: {line}\n", start_line + i));
    }

    if capped_end < total_lines {
        result.push_str(&format!(
            "\n[{}: {total_lines} total lines]\n",
            path.display()
        ));
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn test_read_file_basic() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "line one").unwrap();
        writeln!(f, "line two").unwrap();
        writeln!(f, "line three").unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("   1: line one"));
        assert!(result.contains("   2: line two"));
        assert!(result.contains("   3: line three"));
    }

    #[test]
    fn test_read_file_range() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 1..=10 {
            writeln!(f, "line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path, "start_line": 3, "end_line": 5});
        let result = execute(&input).unwrap();
        assert!(result.contains("   3: line 3"));
        assert!(result.contains("   5: line 5"));
        assert!(!result.contains("   1: line 1"));
        assert!(!result.contains("   6: line 6"));
    }

    #[test]
    fn test_read_file_nonexistent() {
        let input = json!({"path": "/tmp/nsh_test_nonexistent_xyz"});
        let result = execute(&input).unwrap();
        assert!(result.contains("Error reading"));
    }

    #[test]
    fn test_read_file_start_beyond_total() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "only line").unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path, "start_line": 999});
        let result = execute(&input).unwrap();
        assert!(result.contains("1 total lines"));
    }

    #[test]
    fn test_read_file_binary() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0x00, 0x01, 0x02, 0xFF]).unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Binary file"));
    }

    #[test]
    fn test_read_file_path_with_dotdot() {
        let input = json!({"path": "/tmp/../etc/passwd"});
        let result = execute(&input).unwrap();
        assert!(result.contains("Access denied") || result.contains(".."));
    }

    #[test]
    fn test_read_file_invalid_utf8_no_nulls() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(&[0x80, 0x81, 0x82, 0xFE, 0xFF]).unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Binary file"));
    }
}
