use crate::config::SensitiveFileAccess;
use crate::tools::ToolInvocationOutcome;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
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

struct ReadRequest {
    path: PathBuf,
    full_requested: bool,
    range: Option<LineRange>,
}

struct LineRange {
    start_line: usize,
    end_line: Option<usize>,
}

#[cfg(test)]
pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    crate::tools::execute_file_tool_content(input, SensitiveFileAccess::Block, handle)
}

#[cfg(test)]
#[allow(dead_code)]
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
    let request = match parse_request(input, sensitive_file_access)? {
        Ok(request) => request,
        Err(outcome) => return Ok(outcome),
    };

    let file_size = match read_file_size(&request.path) {
        Ok(file_size) => file_size,
        Err(outcome) => return Ok(outcome),
    };

    if file_size > MAX_READ_BYTES {
        return Ok(oversized_file_outcome(&request.path, file_size));
    }

    if let Some(outcome) = maybe_read_pseudo_file(&request.path, file_size) {
        return Ok(outcome);
    }

    if let Some(outcome) = probe_binary_file(&request.path) {
        return Ok(outcome);
    }

    let lines = match read_text_lines(&request.path) {
        Ok(lines) => lines,
        Err(outcome) => return Ok(outcome),
    };

    Ok(render_read_response(&request, &lines))
}

fn parse_request(
    input: &serde_json::Value,
    sensitive_file_access: SensitiveFileAccess,
) -> anyhow::Result<Result<ReadRequest, ToolInvocationOutcome>> {
    let path = match crate::tools::required_read_path(input, "path", sensitive_file_access)? {
        Ok(path) => path,
        Err(outcome) => return Ok(Err(outcome)),
    };

    Ok(Ok(ReadRequest {
        path,
        full_requested: input["full"].as_bool().unwrap_or(false),
        range: parse_line_range(input),
    }))
}

fn parse_line_range(input: &serde_json::Value) -> Option<LineRange> {
    let has_start = !input["start_line"].is_null();
    let has_end = !input["end_line"].is_null();
    if !has_start && !has_end {
        return None;
    }

    Some(LineRange {
        start_line: (input["start_line"].as_u64().unwrap_or(1) as usize).max(1),
        end_line: input["end_line"].as_u64().map(|value| value as usize),
    })
}

fn read_file_size(path: &Path) -> Result<u64, ToolInvocationOutcome> {
    std::fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|error| crate::tools::read_failure(path, error))
}

fn oversized_file_outcome(path: &Path, file_size: u64) -> ToolInvocationOutcome {
    let estimated_lines = estimate_line_count(path);
    let estimated_tokens = file_size as usize / 4;
    ToolInvocationOutcome::success(format!(
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
    ))
}

fn maybe_read_pseudo_file(path: &Path, file_size: u64) -> Option<ToolInvocationOutcome> {
    let path_str = path.to_string_lossy();
    if !(path_str.starts_with("/proc/") || path_str.starts_with("/sys/")) || file_size != 0 {
        return None;
    }

    let mut file = match crate::tools::open_for_read(path) {
        Ok(file) => file,
        Err(error) => return Some(crate::tools::read_failure(path, error)),
    };
    let mut buf = vec![0u8; 65536];
    let bytes_read = match file.read(&mut buf) {
        Ok(bytes_read) => bytes_read,
        Err(error) => return Some(crate::tools::read_failure(path, error)),
    };
    let content = String::from_utf8_lossy(&buf[..bytes_read]);

    Some(ToolInvocationOutcome::success(format!(
        "{}\n\n[pseudo-filesystem file, read {} bytes]",
        content.trim(),
        bytes_read
    )))
}

fn probe_binary_file(path: &Path) -> Option<ToolInvocationOutcome> {
    let mut file = match crate::tools::open_regular_read_file(path, special_file_message) {
        Ok(file) => file,
        Err(outcome) => return Some(outcome),
    };
    let mut prefix = [0_u8; 8192];
    let bytes_read = match file.read(&mut prefix) {
        Ok(bytes_read) => bytes_read,
        Err(error) => return Some(crate::tools::read_failure(path, error)),
    };

    if prefix[..bytes_read].contains(&0) {
        return Some(ToolInvocationOutcome::failure(
            "Binary file, cannot display",
        ));
    }

    None
}

fn read_text_lines(path: &Path) -> Result<Vec<String>, ToolInvocationOutcome> {
    let file = crate::tools::open_regular_read_file(path, special_file_message)?;
    let mut reader = BufReader::new(file);
    let mut lines = Vec::new();
    let mut line_buf = Vec::new();

    loop {
        line_buf.clear();
        let bytes_read = match reader.read_until(b'\n', &mut line_buf) {
            Ok(bytes_read) => bytes_read,
            Err(error) => return Err(crate::tools::read_failure(path, error)),
        };
        if bytes_read == 0 {
            break;
        }
        if line_buf.contains(&0) {
            return Err(ToolInvocationOutcome::failure(
                "Binary file, cannot display",
            ));
        }

        let line = match String::from_utf8(line_buf.clone()) {
            Ok(line) => line,
            Err(_) => {
                return Err(ToolInvocationOutcome::failure(
                    "Binary file, cannot display",
                ));
            }
        };
        lines.push(line.trim_end_matches(['\n', '\r']).to_string());
    }

    Ok(lines)
}

fn render_read_response(request: &ReadRequest, lines: &[String]) -> ToolInvocationOutcome {
    let total_lines = lines.len();
    let full_text = lines.join("\n");
    let token_count = count_tokens(&full_text);

    if request.full_requested {
        return ToolInvocationOutcome::success(format_full_file(
            &request.path,
            lines,
            total_lines,
            token_count,
        ));
    }

    if let Some(range) = &request.range {
        return ToolInvocationOutcome::success(format_line_range(
            &request.path,
            lines,
            range,
            total_lines,
            token_count,
        ));
    }

    if total_lines <= AUTO_FULL_LINE_THRESHOLD {
        return ToolInvocationOutcome::success(format_full_file(
            &request.path,
            lines,
            total_lines,
            token_count,
        ));
    }

    ToolInvocationOutcome::success(format!(
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
        path = request.path.display(),
    ))
}

fn format_line_range(
    path: &Path,
    lines: &[String],
    range: &LineRange,
    total_lines: usize,
    token_count: usize,
) -> String {
    if range.start_line > total_lines {
        return format!(
            "\n[{}: {total_lines} total lines, ~{token_count} tokens (cl100k_base)]\n",
            path.display()
        );
    }

    let end_line = range.end_line.unwrap_or(total_lines).min(total_lines);
    let mut result = String::new();
    for (index, line) in lines.iter().enumerate() {
        let line_no = index + 1;
        if line_no < range.start_line {
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
    result
}

fn special_file_message(path: &Path) -> String {
    format!(
        "Cannot read '{}': not a regular file (special device/pipe/socket). \
         Use run_command with 'cat' or 'head' instead.",
        path.display()
    )
}

/// Fast line count via streaming without loading entire file into memory.
fn estimate_line_count(path: &std::path::Path) -> usize {
    let file = match crate::tools::open_for_read(path) {
        Ok(f) => f,
        Err(_) => return 0,
    };
    let mut reader = BufReader::new(file);
    let mut count = 0usize;
    let mut buf = [0u8; 8192];
    let mut total_read: u64 = 0;
    let max_bytes: u64 = 50 * 1024 * 1024;
    loop {
        match std::io::Read::read(&mut reader, &mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_read += n as u64;
                count += buf[..n].iter().filter(|&&b| b == b'\n').count();
                if total_read > max_bytes {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    count
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
