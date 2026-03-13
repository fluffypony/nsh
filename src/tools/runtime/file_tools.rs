use crate::tools::ToolInvocationOutcome;
use serde_json::Value;
use std::fs::File;
use std::path::{Path, PathBuf};

pub(crate) fn execute_file_tool_content<F>(
    input: &Value,
    sensitive_file_access: &str,
    handler: F,
) -> anyhow::Result<String>
where
    F: FnOnce(&Value, &str) -> anyhow::Result<ToolInvocationOutcome>,
{
    crate::tools::outcome_to_content(handler(input, sensitive_file_access))
}

pub(crate) fn execute_file_tool_result<F>(
    input: &Value,
    sensitive_file_access: &str,
    handler: F,
) -> anyhow::Result<String>
where
    F: FnOnce(&Value, &str) -> anyhow::Result<ToolInvocationOutcome>,
{
    crate::tools::outcome_to_result(handler(input, sensitive_file_access))
}

pub(crate) fn required_read_path(
    input: &Value,
    field: &str,
    sensitive_file_access: &str,
) -> anyhow::Result<Result<PathBuf, ToolInvocationOutcome>> {
    let raw_path = input[field]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("{field} is required"))?;
    Ok(validated_read_path(raw_path, sensitive_file_access))
}

pub(crate) fn default_read_path(
    input: &Value,
    field: &str,
    default: &str,
    sensitive_file_access: &str,
) -> Result<PathBuf, ToolInvocationOutcome> {
    let raw_path = input[field].as_str().unwrap_or(default);
    validated_read_path(raw_path, sensitive_file_access)
}

pub(crate) fn ensure_directory(
    path: PathBuf,
    missing_message: String,
    not_directory_message: String,
) -> Result<PathBuf, ToolInvocationOutcome> {
    if !path.exists() {
        return Err(ToolInvocationOutcome::failure(missing_message));
    }
    if !path.is_dir() {
        return Err(ToolInvocationOutcome::failure(not_directory_message));
    }
    Ok(path)
}

pub(crate) fn open_regular_read_file<F>(
    path: &Path,
    special_target_message: F,
) -> Result<File, ToolInvocationOutcome>
where
    F: Fn(&Path) -> String,
{
    if let Some(outcome) = special_read_target_outcome(path, special_target_message) {
        return Err(outcome);
    }

    open_for_read(path).map_err(|err| read_failure(path, err))
}

pub(crate) fn read_failure(path: &Path, error: impl std::fmt::Display) -> ToolInvocationOutcome {
    ToolInvocationOutcome::failure(format!("Error reading '{}': {error}", path.display()))
}

fn validated_read_path(
    raw_path: &str,
    sensitive_file_access: &str,
) -> Result<PathBuf, ToolInvocationOutcome> {
    crate::tools::validate_read_path_tool_outcome(raw_path, sensitive_file_access)
}

#[cfg(unix)]
pub(crate) fn open_for_read(path: &Path) -> std::io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub(crate) fn open_for_read(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

fn special_read_target_outcome<F>(
    path: &Path,
    special_target_message: F,
) -> Option<ToolInvocationOutcome>
where
    F: Fn(&Path) -> String,
{
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;

        if let Ok(meta) = std::fs::symlink_metadata(path) {
            let file_type = meta.file_type();
            if file_type.is_block_device()
                || file_type.is_char_device()
                || file_type.is_fifo()
                || file_type.is_socket()
            {
                return Some(ToolInvocationOutcome::failure(special_target_message(path)));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{ensure_directory, read_failure};
    use std::path::Path;

    #[test]
    fn ensure_directory_reports_missing_and_not_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let missing = root.path().join("missing");
        let file = root.path().join("file.txt");
        std::fs::write(&file, "hello").expect("write file");

        let missing_err = ensure_directory(missing, "missing".to_string(), "not dir".to_string())
            .expect_err("missing path should fail");
        let not_dir_err = ensure_directory(file, "missing".to_string(), "not dir".to_string())
            .expect_err("file path should fail");

        assert_eq!(missing_err.into_content(), "missing");
        assert_eq!(not_dir_err.into_content(), "not dir");
    }

    #[test]
    fn read_failure_formats_consistently() {
        let outcome = read_failure(Path::new("/tmp/demo"), "boom");

        assert_eq!(outcome.into_content(), "Error reading '/tmp/demo': boom");
    }
}
