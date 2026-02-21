use std::io::{BufRead, BufReader, Read};

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

    let start_line = (input["start_line"].as_u64().unwrap_or(1) as usize).max(1);
    let end_line = input["end_line"].as_u64().unwrap_or(200) as usize;

    let mut probe_file = match open_for_read(&path) {
        Ok(f) => f,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };

    let requested_end = end_line.min(start_line + 499);
    let mut line_buf = Vec::new();
    let mut total_lines = 0usize;
    let mut result = String::new();

    // Quick binary check from the first bytes while keeping streaming behavior.
    let mut prefix = [0_u8; 8192];
    let bytes_read = match probe_file.read(&mut prefix) {
        Ok(n) => n,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };
    if prefix[..bytes_read].contains(&0) {
        return Ok("Binary file, cannot display".into());
    }

    let file = match open_for_read(&path) {
        Ok(f) => f,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };
    let mut stream_reader = BufReader::new(file);

    loop {
        line_buf.clear();
        let n = match stream_reader.read_until(b'\n', &mut line_buf) {
            Ok(n) => n,
            Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
        };
        if n == 0 {
            break;
        }

        if line_buf.contains(&0) {
            return Ok("Binary file, cannot display".into());
        }

        total_lines += 1;
        if total_lines < start_line || total_lines > requested_end {
            continue;
        }

        let mut line = match String::from_utf8(line_buf.clone()) {
            Ok(s) => s,
            Err(_) => return Ok("Binary file, cannot display".into()),
        };
        while line.ends_with('\n') || line.ends_with('\r') {
            line.pop();
        }
        result.push_str(&format!("{total_lines:>4}: {line}\n"));
    }

    if start_line > total_lines {
        return Ok(format!(
            "\n[{}: {total_lines} total lines]\n",
            path.display()
        ));
    }

    if requested_end < total_lines {
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
