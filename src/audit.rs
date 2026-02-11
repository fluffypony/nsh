use std::io::Write;
use std::path::Path;

pub fn audit_log(session_id: &str, query: &str, tool: &str, response: &str, risk: &str) {
    let dir = crate::config::Config::nsh_dir();
    audit_log_to_dir(&dir, session_id, query, tool, response, risk);
    rotate_audit_log();
}

fn audit_log_to_dir(
    dir: &Path,
    session_id: &str,
    query: &str,
    tool: &str,
    response: &str,
    risk: &str,
) {
    let path = dir.join("audit.log");
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
}

pub fn rotate_audit_log() {
    let dir = crate::config::Config::nsh_dir();
    rotate_audit_log_in_dir(&dir);
}

fn rotate_audit_log_in_dir(dir: &Path) {
    let log_path = dir.join("audit.log");
    let Ok(meta) = std::fs::metadata(&log_path) else {
        return;
    };
    if meta.len() <= 15_000_000 {
        return;
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let archive_name = format!("audit_{ts}.log.gz");
    let archive_path = dir.join(&archive_name);

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

    cleanup_old_archives_in_dir(dir);
}

#[cfg(test)]
fn cleanup_old_archives() {
    let dir = crate::config::Config::nsh_dir();
    cleanup_old_archives_in_dir(&dir);
}

fn cleanup_old_archives_in_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
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
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": "sess-1",
            "query": "what time is it",
            "tool": "chat",
            "response": "It's 3pm",
            "risk": "safe",
        });
        let serialized = serde_json::to_string(&entry).unwrap();
        let _: serde_json::Value = serde_json::from_str(&serialized)
            .unwrap_or_else(|_| panic!("Invalid JSON: {serialized}"));
        assert!(serialized.contains("sess-1"));
        assert!(serialized.contains("what time is it"));
    }

    #[test]
    fn test_audit_json_has_all_fields() {
        let entry = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "session": "s1",
            "query": "q",
            "tool": "t",
            "response": "r",
            "risk": "safe",
        });
        assert!(entry.get("ts").is_some());
        assert!(entry.get("session").is_some());
        assert!(entry.get("query").is_some());
        assert!(entry.get("tool").is_some());
        assert!(entry.get("response").is_some());
        assert!(entry.get("risk").is_some());
        assert_eq!(entry.as_object().unwrap().len(), 6);
    }

    #[test]
    fn test_audit_log_special_characters() {
        audit_log(
            "sess-special",
            "query with \"quotes\" & <brackets> and\nnewlines",
            "command",
            "echo 'hello world' && rm -rf /",
            "dangerous",
        );
    }

    #[test]
    fn test_audit_log_very_long_strings() {
        let long_query = "x".repeat(100_000);
        let long_response = "y".repeat(100_000);
        audit_log("sess-long", &long_query, "chat", &long_response, "safe");
    }

    #[test]
    fn test_audit_log_empty_strings() {
        audit_log("", "", "", "", "");
    }

    #[test]
    fn test_audit_log_unicode() {
        audit_log("sess-uni", "こんにちは 🌍 émojis", "chat", "Ñoño résumé", "safe");
    }

    #[test]
    fn test_audit_json_timestamp_is_rfc3339() {
        let ts = chrono::Utc::now().to_rfc3339();
        assert!(chrono::DateTime::parse_from_rfc3339(&ts).is_ok());
    }

    #[test]
    fn test_rotate_nonexistent_log_is_noop() {
        let path = crate::config::Config::nsh_dir().join("audit.log");
        let existed = path.exists();
        rotate_audit_log();
        if !existed {
            assert!(!path.exists() || std::fs::metadata(&path).unwrap().len() == 0);
        }
    }

    #[test]
    fn test_audit_json_serializes_special_chars_correctly() {
        let entry = serde_json::json!({
            "ts": "2025-01-01T00:00:00Z",
            "session": "s",
            "query": "line1\nline2\ttab",
            "tool": "cmd",
            "response": "say \"hello\"",
            "risk": "safe",
        });
        let s = serde_json::to_string(&entry).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["query"], "line1\nline2\ttab");
        assert_eq!(parsed["response"], "say \"hello\"");
    }

    #[test]
    fn test_audit_json_null_like_values() {
        let entry = serde_json::json!({
            "ts": "2025-01-01T00:00:00Z",
            "session": "null",
            "query": "undefined",
            "tool": "NaN",
            "response": "false",
            "risk": "true",
        });
        assert!(entry["session"].is_string());
        assert_eq!(entry["session"], "null");
    }

    #[test]
    fn test_cleanup_old_archives_does_not_panic_with_no_dir() {
        cleanup_old_archives();
    }

    #[test]
    fn test_audit_log_to_dir_creates_file_with_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(tmp.path(), "s1", "hello", "chat", "hi", "safe");

        let log_path = tmp.path().join("audit.log");
        assert!(log_path.exists());

        let contents = std::fs::read_to_string(&log_path).unwrap();
        for line in contents.lines() {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("invalid JSON: {e}\nline: {line}"));
            assert_eq!(v["session"], "s1");
            assert_eq!(v["query"], "hello");
            assert_eq!(v["tool"], "chat");
            assert_eq!(v["response"], "hi");
            assert_eq!(v["risk"], "safe");
            assert!(v["ts"].is_string());
        }
    }

    #[test]
    fn test_audit_log_to_dir_appends_multiple_entries() {
        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(tmp.path(), "s1", "q1", "t1", "r1", "safe");
        audit_log_to_dir(tmp.path(), "s2", "q2", "t2", "r2", "high");

        let contents = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        let v1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        let v2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(v1["session"], "s1");
        assert_eq!(v2["session"], "s2");
    }

    #[test]
    fn test_rotate_audit_log_compresses_large_file() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");

        let chunk = "x".repeat(1_000_000);
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            for _ in 0..16 {
                writeln!(f, "{chunk}").unwrap();
            }
        }
        assert!(std::fs::metadata(&log_path).unwrap().len() > 15_000_000);

        rotate_audit_log_in_dir(tmp.path());

        assert_eq!(
            std::fs::metadata(&log_path).unwrap().len(),
            0,
            "original log should be truncated"
        );

        let archives: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .collect();
        assert_eq!(archives.len(), 1, "exactly one archive should exist");

        let gz_path = archives[0].path();
        let gz_file = std::fs::File::open(&gz_path).unwrap();
        let mut decoder = flate2::read::GzDecoder::new(gz_file);
        let mut decompressed = String::new();
        std::io::Read::read_to_string(&mut decoder, &mut decompressed).unwrap();
        assert!(
            decompressed.len() > 15_000_000,
            "decompressed archive should contain the original data"
        );
    }

    #[test]
    fn test_rotate_small_file_is_noop_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        std::fs::write(&log_path, "small content").unwrap();

        rotate_audit_log_in_dir(tmp.path());

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(contents, "small content", "small file should not be rotated");

        let archives: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".log.gz")
            })
            .collect();
        assert!(archives.is_empty(), "no archives should be created for small files");
    }

    #[test]
    fn test_rotate_nonexistent_file_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        rotate_audit_log_in_dir(tmp.path());
    }

    #[test]
    fn test_cleanup_old_archives_keeps_at_most_five() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..8 {
            let name = format!("audit_2025010{i}T000000.log.gz");
            std::fs::write(tmp.path().join(&name), "fake").unwrap();
        }

        let before: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .collect();
        assert_eq!(before.len(), 8);

        cleanup_old_archives_in_dir(tmp.path());

        let after: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(after.len(), 5, "only 5 archives should remain");

        for removed in ["audit_20250100T000000.log.gz", "audit_20250101T000000.log.gz", "audit_20250102T000000.log.gz"] {
            assert!(
                !after.contains(&removed.to_string()),
                "oldest archive {removed} should have been removed"
            );
        }
    }

    #[test]
    fn test_cleanup_old_archives_noop_when_five_or_fewer() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..5 {
            let name = format!("audit_2025010{i}T000000.log.gz");
            std::fs::write(tmp.path().join(&name), "fake").unwrap();
        }

        cleanup_old_archives_in_dir(tmp.path());

        let count = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .count();
        assert_eq!(count, 5, "all 5 archives should remain");
    }

    #[test]
    fn test_cleanup_ignores_non_archive_files() {
        let tmp = tempfile::tempdir().unwrap();
        for i in 0..8 {
            let name = format!("audit_2025010{i}T000000.log.gz");
            std::fs::write(tmp.path().join(&name), "fake").unwrap();
        }
        std::fs::write(tmp.path().join("other_file.txt"), "keep me").unwrap();
        std::fs::write(tmp.path().join("audit.log"), "keep me too").unwrap();

        cleanup_old_archives_in_dir(tmp.path());

        assert!(tmp.path().join("other_file.txt").exists());
        assert!(tmp.path().join("audit.log").exists());
    }

    #[test]
    fn test_rotate_triggers_cleanup() {
        let tmp = tempfile::tempdir().unwrap();

        for i in 0..6 {
            let name = format!("audit_2025010{i}T000000.log.gz");
            std::fs::write(tmp.path().join(&name), "old archive").unwrap();
        }

        let log_path = tmp.path().join("audit.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            let chunk = "z".repeat(1_000_000);
            for _ in 0..16 {
                writeln!(f, "{chunk}").unwrap();
            }
        }

        rotate_audit_log_in_dir(tmp.path());

        let archive_count = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .count();
        assert!(archive_count <= 5, "cleanup should cap archives at 5, got {archive_count}");
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_log_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(tmp.path(), "s1", "q", "t", "r", "safe");

        let log_path = tmp.path().join("audit.log");
        let perms = std::fs::metadata(&log_path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "audit.log should be owner-only");
    }

    #[test]
    fn test_rotate_audit_log_in_dir_cannot_open_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        std::fs::write(&log_path, "x".repeat(16_000_000)).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o000)).unwrap();
        }

        rotate_audit_log_in_dir(tmp.path());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    #[test]
    fn test_cleanup_old_archives_in_dir_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        cleanup_old_archives_in_dir(tmp.path());
        let count = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    #[test]
    fn test_rotate_audit_log_in_dir_cannot_create_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        std::fs::write(&log_path, "y".repeat(16_000_000)).unwrap();

        let archive_dir = tmp.path();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let original_perms = std::fs::metadata(archive_dir).unwrap().permissions();
            std::fs::set_permissions(archive_dir, std::fs::Permissions::from_mode(0o444)).unwrap();
            rotate_audit_log_in_dir(tmp.path());
            std::fs::set_permissions(archive_dir, original_perms).unwrap();
        }
    }

    #[test]
    fn test_audit_log_to_dir_multiple_fields_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(
            tmp.path(),
            "session-with-dashes",
            "query with spaces and \"quotes\"",
            "chat",
            "response\nwith\nnewlines",
            "medium",
        );

        let contents = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(v["session"], "session-with-dashes");
        assert_eq!(v["risk"], "medium");
        assert!(v["response"].as_str().unwrap().contains("newlines"));
    }

    #[test]
    fn test_audit_log_to_dir_invalid_dir() {
        audit_log_to_dir(
            Path::new("/nonexistent/dir/that/does/not/exist"),
            "s1",
            "q",
            "t",
            "r",
            "safe",
        );
    }

    #[test]
    fn test_cleanup_old_archives_standalone() {
        cleanup_old_archives();
    }

    #[test]
    fn test_rotate_clears_log_after_compress() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            let chunk = "a]".repeat(500_000);
            for _ in 0..16 {
                writeln!(f, "{chunk}").unwrap();
            }
        }
        assert!(std::fs::metadata(&log_path).unwrap().len() > 15_000_000);

        rotate_audit_log_in_dir(tmp.path());

        let truncated = std::fs::read_to_string(&log_path).unwrap();
        assert!(truncated.is_empty(), "log should be emptied after rotation");
    }

    #[cfg(unix)]
    #[test]
    fn test_rotate_archive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        {
            let mut f = std::fs::File::create(&log_path).unwrap();
            let chunk = "z".repeat(1_000_000);
            for _ in 0..16 {
                writeln!(f, "{chunk}").unwrap();
            }
        }

        rotate_audit_log_in_dir(tmp.path());

        let archives: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .collect();
        assert_eq!(archives.len(), 1);

        let perms = std::fs::metadata(archives[0].path()).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600, "archive should be owner-only");
    }
}
