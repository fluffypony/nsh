use std::fs;
use std::path::{Path, PathBuf};

#[cfg(test)]
pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    execute_with_access(input, "block")
}

pub fn execute_with_access(
    input: &serde_json::Value,
    sensitive_file_access: &str,
) -> anyhow::Result<String> {
    let path_str = input["path"].as_str().unwrap_or(".");
    let show_hidden = input["show_hidden"].as_bool().unwrap_or(false);
    let recursive = input["recursive"].as_bool().unwrap_or(false);
    let max_entries = input["max_entries"]
        .as_u64()
        .map(|v| v.clamp(1, 1000) as usize)
        .unwrap_or(100);

    let path = match crate::tools::validate_read_path_with_access(path_str, sensitive_file_access) {
        Ok(p) => p,
        Err(msg) => return Ok(msg),
    };

    if !path.exists() {
        return Ok(format!("Path does not exist: {path_str}"));
    }
    if !path.is_dir() {
        return Ok(format!("Not a directory: {path_str}"));
    }

    let entries = match collect_entries(path.as_path(), show_hidden, recursive, max_entries) {
        Ok(entries) => entries,
        Err(e) => return Ok(format!("Error reading directory: {e}")),
    };

    if entries.is_empty() {
        Ok(format!("Empty directory: {path_str}"))
    } else {
        Ok(entries.join("\n"))
    }
}

fn collect_entries(
    root: &Path,
    show_hidden: bool,
    recursive: bool,
    max_entries: usize,
) -> std::io::Result<Vec<String>> {
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root.to_path_buf());

    while let Some(dir) = queue.pop_front() {
        let read_dir = fs::read_dir(&dir)?;
        for entry in read_dir {
            if out.len() >= max_entries {
                break;
            }

            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if !show_hidden && name.starts_with('.') {
                continue;
            }

            let rel_display = relative_display(root, &path, recursive);
            let meta = std::fs::symlink_metadata(&path);
            let (size, modified, kind, enqueue_child) = match &meta {
                Ok(m) => {
                    let size = m.len();
                    let modified = m
                        .modified()
                        .ok()
                        .map(|t| {
                            let dt: chrono::DateTime<chrono::Utc> = t.into();
                            dt.format("%Y-%m-%d %H:%M").to_string()
                        })
                        .unwrap_or_else(|| "?".into());
                    let (kind, enqueue_child) = if m.is_dir() {
                        ("dir", recursive)
                    } else if m.is_symlink() {
                        ("link", false)
                    } else {
                        ("file", false)
                    };
                    (size, modified, kind, enqueue_child)
                }
                Err(_) => (0, "?".into(), "?", false),
            };

            if enqueue_child {
                queue.push_back(path.clone());
            }

            let size_str = human_size(size);
            out.push(format!("{kind:<5} {size_str:>8}  {modified}  {rel_display}"));
        }

        if out.len() >= max_entries {
            break;
        }
    }

    out.sort();
    Ok(out)
}

fn relative_display(root: &Path, entry_path: &Path, recursive: bool) -> String {
    if !recursive {
        return entry_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| entry_path.to_string_lossy().to_string());
    }

    entry_path
        .strip_prefix(root)
        .map(PathBuf::from)
        .unwrap_or_else(|_| entry_path.to_path_buf())
        .to_string_lossy()
        .to_string()
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
    fn test_list_directory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file1.txt"), "hello").unwrap();
        std::fs::write(dir.path().join("file2.rs"), "world").unwrap();
        let path = dir.path().to_str().unwrap();

        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("file1.txt"));
        assert!(result.contains("file2.rs"));
        assert!(result.contains("file"));
    }

    #[test]
    fn test_list_directory_hidden_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".hidden"), "").unwrap();
        std::fs::write(dir.path().join("visible"), "").unwrap();
        let path = dir.path().to_str().unwrap();

        let without = execute(&json!({"path": path})).unwrap();
        assert!(!without.contains(".hidden"));
        assert!(without.contains("visible"));

        let with = execute(&json!({"path": path, "show_hidden": true})).unwrap();
        assert!(with.contains(".hidden"));
        assert!(with.contains("visible"));
    }

    #[test]
    fn test_list_directory_nonexistent() {
        let input = json!({"path": "/tmp/nsh_nonexistent_dir_xyz"});
        let result = execute(&input).unwrap();
        assert!(result.contains("Path does not exist"));
    }

    #[test]
    fn test_list_directory_not_a_directory() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let path = f.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Not a directory"));
    }

    #[test]
    fn test_list_directory_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Empty directory"));
    }

    #[test]
    fn test_list_directory_default_path() {
        let input = json!({});
        let result = execute(&input).unwrap();
        assert!(!result.is_empty());
    }

    #[test]
    fn test_list_directory_with_subdirectory() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("subdir")).unwrap();
        std::fs::write(dir.path().join("file.txt"), "content").unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("subdir"));
        assert!(result.contains("file.txt"));
        assert!(result.contains("dir"));
    }

    #[test]
    fn test_list_directory_recursive_with_max_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/c.txt"), "content").unwrap();
        std::fs::write(dir.path().join("top.txt"), "content").unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({
            "path": path,
            "recursive": true,
            "max_entries": 2
        });
        let result = execute(&input).unwrap();
        let lines = result.lines().count();
        assert_eq!(lines, 2);
    }

    #[test]
    fn test_list_directory_recursive_includes_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/b/c.txt"), "content").unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({
            "path": path,
            "recursive": true,
            "show_hidden": true,
            "max_entries": 20
        });
        let result = execute(&input).unwrap();
        assert!(result.contains("a/b/c.txt"));
    }

    #[test]
    fn test_list_directory_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "data").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("link.txt")).unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({"path": path, "show_hidden": false});
        let result = execute(&input).unwrap();
        assert!(result.contains("link"));
    }

    #[test]
    fn test_human_size() {
        assert_eq!(human_size(0), "0B");
        assert_eq!(human_size(500), "500B");
        assert_eq!(human_size(1024), "1KB");
        assert_eq!(human_size(1048576), "1MB");
        assert_eq!(human_size(1073741824), "1GB");
        assert_eq!(human_size(1099511627776), "1TB");
        assert_eq!(human_size(1125899906842624), "1PB");
    }

    #[test]
    fn test_list_directory_unreadable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("noperm");
        std::fs::create_dir(&inner).unwrap();
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o000)).unwrap();
        let path = inner.to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("Error reading directory"));
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_list_directory_metadata_error_on_vanished_entry() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "hello").unwrap();
        let path = dir.path().to_str().unwrap();
        let input = json!({"path": path});
        let result = execute(&input).unwrap();
        assert!(result.contains("a.txt"));
    }

    #[test]
    fn test_human_size_large_pb() {
        let val = 2 * 1125899906842624;
        let result = human_size(val);
        assert!(result.contains("PB"));
    }
}
