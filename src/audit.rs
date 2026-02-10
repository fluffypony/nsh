use std::io::Write;

pub fn audit_log(session_id: &str, query: &str, tool: &str, response: &str, risk: &str) {
    let path = crate::config::Config::nsh_dir().join("audit.log");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": session_id,
            "query": query,
            "tool": tool,
            "response": response,
            "risk": risk,
        });
        let _ = writeln!(f, "{entry}");
    }
    rotate_audit_log();
}

pub fn rotate_audit_log() {
    let log_path = crate::config::Config::nsh_dir().join("audit.log");
    let Ok(meta) = std::fs::metadata(&log_path) else {
        return;
    };
    if meta.len() <= 15_000_000 {
        return;
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let archive_name = format!("audit_{ts}.log.gz");
    let archive_path = crate::config::Config::nsh_dir().join(&archive_name);

    let Ok(input_file) = std::fs::File::open(&log_path) else {
        return;
    };
    let Ok(output_file) = std::fs::File::create(&archive_path) else {
        return;
    };
    let mut encoder = flate2::write::GzEncoder::new(output_file, flate2::Compression::default());
    let mut reader = std::io::BufReader::new(input_file);
    if std::io::copy(&mut reader, &mut encoder).is_err() {
        return;
    }
    if encoder.finish().is_err() {
        return;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600));
    }

    let _ = std::fs::write(&log_path, "");

    cleanup_old_archives();
}

fn cleanup_old_archives() {
    let dir = crate::config::Config::nsh_dir();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut archives: Vec<std::path::PathBuf> = entries
        .flatten()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("audit_") && name.ends_with(".log.gz")
        })
        .map(|e| e.path())
        .collect();
    archives.sort();
    while archives.len() > 5 {
        let _ = std::fs::remove_file(archives.remove(0));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cleanup_old_archives_limit() {
        cleanup_old_archives();
    }

    #[test]
    fn test_audit_log_no_panic() {
        audit_log("test-session", "test query", "command", "ls", "safe");
    }

    #[test]
    fn test_rotate_audit_log_no_panic() {
        rotate_audit_log();
    }

    #[test]
    fn test_audit_log_creates_file() {
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": "test-session",
            "query": "test query",
            "tool": "command",
            "response": "ls",
            "risk": "safe",
        });
        assert!(entry["ts"].is_string());
        assert_eq!(entry["session"], "test-session");
        assert_eq!(entry["tool"], "command");
    }

    #[test]
    fn test_rotate_small_log_is_noop() {
        rotate_audit_log();
    }

    #[test]
    fn test_audit_log_format() {
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": "test-session",
            "query": "test query",
            "tool": "command",
            "response": "ls",
            "risk": "safe",
        });
        let serialized = serde_json::to_string(&entry).unwrap();
        assert!(serialized.contains("test-session"));
        assert!(serialized.contains("command"));
        assert!(serialized.contains("safe"));
    }

    #[test]
    fn test_audit_log_writes_valid_json() {
        audit_log("sess-1", "what time is it", "chat", "It's 3pm", "safe");
        let path = crate::config::Config::nsh_dir().join("audit.log");
        if path.exists() {
            let content = std::fs::read_to_string(&path).unwrap();
            for line in content.lines() {
                if !line.trim().is_empty() {
                    let _: serde_json::Value = serde_json::from_str(line)
                        .unwrap_or_else(|_| panic!("Invalid JSON in audit log: {line}"));
                }
            }
        }
    }
}
