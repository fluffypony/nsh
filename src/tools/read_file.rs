use std::io::{BufRead, BufReader, Read};
use std::sync::OnceLock;

static BPE: OnceLock<tiktoken_rs::CoreBPE> = OnceLock::new();

fn get_bpe() -> &'static tiktoken_rs::CoreBPE {
    BPE.get_or_init(|| tiktoken_rs::cl100k_base().expect("failed to init cl100k_base BPE"))
}

fn count_tokens(text: &str) -> usize {
    get_bpe().encode_with_special_tokens(text).len()
}

/// Threshold below which we auto-return the full file on the first call
/// (no need for a two-step metadata→full round-trip).
const AUTO_FULL_LINE_THRESHOLD: usize = 200;

/// Maximum file size we'll read fully into memory (50 MB).
/// Beyond this, we use byte-based token estimation and refuse full reads.
const MAX_READ_BYTES: u64 = 50 * 1024 * 1024;

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

    let full_requested = input["full"].as_bool().unwrap_or(false);
    let has_start = !input["start_line"].is_null();
    let has_end = !input["end_line"].is_null();
    let range_requested = has_start || has_end;

    // --- Check file size before reading into memory ---
    let file_size = match std::fs::metadata(&path) {
        Ok(m) => m.len(),
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };

    if file_size > MAX_READ_BYTES {
        let estimated_lines = estimate_line_count(&path);
        let estimated_tokens = file_size as usize / 4; // rough cl100k_base estimate
        return Ok(format!(
            "File: {path}\n\
             Size: {size_mb:.1} MB\n\
             Estimated lines: ~{estimated_lines}\n\
             Estimated tokens: ~{estimated_tokens} (byte-based estimate, file too large for exact count)\n\
             \n\
             This file exceeds the {max_mb} MB safety limit for full reads. \
             Use start_line/end_line to read specific sections.",
            path = path.display(),
            size_mb = file_size as f64 / (1024.0 * 1024.0),
            max_mb = MAX_READ_BYTES / (1024 * 1024),
        ));
    }

    // --- Binary check on first bytes ---
    let mut probe_file = match open_for_read(&path) {
        Ok(f) => f,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };
    let mut prefix = [0_u8; 8192];
    let bytes_read = match probe_file.read(&mut prefix) {
        Ok(n) => n,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };
    if prefix[..bytes_read].contains(&0) {
        return Ok("Binary file, cannot display".into());
    }
    drop(probe_file);

    // --- Read the entire file into memory ---
    let file = match open_for_read(&path) {
        Ok(f) => f,
        Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
    };
    let mut reader = BufReader::new(file);
    let mut lines: Vec<String> = Vec::new();
    let mut line_buf = Vec::new();
    loop {
        line_buf.clear();
        let n = match reader.read_until(b'\n', &mut line_buf) {
            Ok(n) => n,
            Err(e) => return Ok(format!("Error reading '{}': {e}", path.display())),
        };
        if n == 0 {
            break;
        }
        if line_buf.contains(&0) {
            return Ok("Binary file, cannot display".into());
        }
        let line = match String::from_utf8(line_buf.clone()) {
            Ok(s) => s,
            Err(_) => return Ok("Binary file, cannot display".into()),
        };
        let trimmed = line.trim_end_matches(['\n', '\r']).to_string();
        lines.push(trimmed);
    }

    let total_lines = lines.len();
    let full_text: String = lines.join("\n");
    let token_count = count_tokens(&full_text);

    // --- Full mode takes priority: explicitly requested via full=true ---
    if full_requested {
        return Ok(format_full_file(&path, &lines, total_lines, token_count));
    }

    // --- Range mode: start_line / end_line explicitly specified ---
    if range_requested {
        let start_line = (input["start_line"].as_u64().unwrap_or(1) as usize).max(1);
        let end_line = input["end_line"].as_u64().unwrap_or(total_lines as u64) as usize;
        let end_line = end_line.min(total_lines);

        if start_line > total_lines {
            return Ok(format!(
                "\n[{}: {total_lines} total lines, ~{token_count} tokens (cl100k_base)]\n",
                path.display()
            ));
        }

        let mut result = String::new();
        for (i, line) in lines.iter().enumerate() {
            let line_no = i + 1;
            if line_no < start_line {
                continue;
            }
            if line_no > end_line {
                break;
            }
            result.push_str(&format!("{line_no:>4}: {line}\n"));
        }

        result.push_str(&format!(
            "\n[{}: {total_lines} total lines, ~{token_count} tokens (cl100k_base)]\n",
            path.display()
        ));
        return Ok(result);
    }

    // --- Default mode: auto-return small files, metadata for large ones ---
    if total_lines <= AUTO_FULL_LINE_THRESHOLD {
        return Ok(format_full_file(&path, &lines, total_lines, token_count));
    }

    // Large file: return metadata and let the model decide
    Ok(format!(
        "File: {path}\n\
         Lines: {total_lines}\n\
         Estimated tokens: ~{token_count} (cl100k_base)\n\
         \n\
         This file is larger than {AUTO_FULL_LINE_THRESHOLD} lines. \
         Unless it exceeds ~900k tokens, it's generally safe to request the \
         full content — the upstream provider will error if it doesn't fit \
         the context window.\n\
         \n\
         Call read_file with full=true to read the entire file, \
         or specify start_line/end_line for a specific range.",
        path = path.display(),
    ))
}

/// Fast line count via streaming without loading entire file into memory.
fn estimate_line_count(path: &std::path::Path) -> usize {
    let file = match open_for_read(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let reader = BufReader::new(file);
    reader.lines().count()
}

fn format_full_file(
    path: &std::path::Path,
    lines: &[String],
    total_lines: usize,
    token_count: usize,
) -> String {
    let mut result = String::new();
    for (i, line) in lines.iter().enumerate() {
        result.push_str(&format!("{:>4}: {line}\n", i + 1));
    }
    result.push_str(&format!(
        "\n[{}: {total_lines} total lines, ~{token_count} tokens (cl100k_base)]\n",
        path.display()
    ));
    result
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
        assert!(result.contains("tokens (cl100k_base)"));
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

    #[test]
    fn test_read_file_large_file_returns_metadata() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 1..=300 {
            writeln!(f, "line number {i} with some content to pad it out a bit").unwrap();
        }
        let path = f.path().to_str().unwrap();

        // Default call (no full=true) should return metadata, not content
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Lines: 300"));
        assert!(result.contains("Estimated tokens:"));
        assert!(result.contains("full=true"));
        assert!(!result.contains("   1: line number 1"));
    }

    #[test]
    fn test_read_file_large_file_full_returns_content() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 1..=300 {
            writeln!(f, "line number {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path, "full": true});
        let result = execute(&input).unwrap();
        assert!(result.contains("   1: line number 1"));
        assert!(result.contains(" 300: line number 300"));
        assert!(result.contains("tokens (cl100k_base)"));
    }

    #[test]
    fn test_read_file_large_file_range_works() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 1..=500 {
            writeln!(f, "line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();

        // Range should return content even for large files
        let input = json!({"path": path, "start_line": 490, "end_line": 500});
        let result = execute(&input).unwrap();
        assert!(result.contains(" 490: line 490"));
        assert!(result.contains(" 500: line 500"));
        assert!(!result.contains("   1: line 1"));
    }

    #[test]
    fn test_read_file_small_file_auto_returns_full() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 1..=50 {
            writeln!(f, "content line {i}").unwrap();
        }
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        // Small file should auto-return full content
        assert!(result.contains("   1: content line 1"));
        assert!(result.contains("  50: content line 50"));
    }

    #[test]
    fn test_read_file_token_count_present() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "hello world").unwrap();
        let path = f.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("cl100k_base"));
    }
}
