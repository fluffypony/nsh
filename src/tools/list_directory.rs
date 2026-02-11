use std::fs;

pub fn execute(input: &serde_json::Value) -> anyhow::Result<String> {
    let path_str = input["path"].as_str().unwrap_or(".");
    let show_hidden = input["show_hidden"].as_bool().unwrap_or(false);

    let path = match crate::tools::validate_read_path(path_str) {
        Ok(p) => p,
        Err(msg) => return Ok(msg),
    };

    if !path.exists() {
        return Ok(format!("Path does not exist: {path_str}"));
    }
    if !path.is_dir() {
        return Ok(format!("Not a directory: {path_str}"));
    }

    let mut entries: Vec<String> = Vec::new();

    let read_dir = match fs::read_dir(path) {
        Ok(rd) => rd,
        Err(e) => return Ok(format!("Error reading directory: {e}")),
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        let name = entry.file_name().to_string_lossy().to_string();

        if !show_hidden && name.starts_with('.') {
            continue;
        }

        let meta = std::fs::symlink_metadata(entry.path());
        let (size, modified, kind) = match &meta {
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
                let kind = if m.is_dir() {
                    "dir"
                } else if m.is_symlink() {
                    "link"
                } else {
                    "file"
                };
                (size, modified, kind)
            }
            Err(_) => (0, "?".into(), "?"),
        };

        let size_str = human_size(size);
        entries.push(format!("{kind:<5} {size_str:>8}  {modified}  {name}"));
    }

    entries.sort();

    if entries.is_empty() {
        Ok(format!("Empty directory: {path_str}"))
    } else {
        Ok(entries.join("\n"))
    }
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
}
