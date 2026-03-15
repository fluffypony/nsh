use anyhow::Context;
use std::io::Write;
use std::path::Path;

pub fn audit_log(
    session_id: &str,
    query: &str,
    tool: &str,
    response: &str,
    risk: &str,
) -> anyhow::Result<()> {
    if cfg!(test) {
        return Ok(());
    }

    if std::env::var("NSH_TEST_MODE").is_ok() {
        return Ok(());
    }

    if std::env::var("RUST_TEST_THREADS").is_ok() {
        return Ok(());
    }

    let dir = crate::config::Config::nsh_dir();
    audit_log_to_dir(&dir, session_id, query, tool, response, risk)?;
    rotate_audit_log_in_dir(&dir)
}

fn audit_log_to_dir(
    dir: &Path,
    session_id: &str,
    query: &str,
    tool: &str,
    response: &str,
    risk: &str,
) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("failed to create audit log directory {}", dir.display()))?;
    let path = dir.join("audit.log");
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("failed to open audit log {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to set audit log permissions for {}", path.display()))?;
    }
    let entry = serde_json::json!({
        "ts": chrono::Utc::now().to_rfc3339(),
        "session": session_id,
        "query": query,
        "tool": tool,
        "response": response,
        "risk": risk,
    });
    writeln!(f, "{entry}")
        .with_context(|| format!("failed to append audit entry to {}", path.display()))?;
    Ok(())
}

pub fn rotate_audit_log() -> anyhow::Result<()> {
    let dir = crate::config::Config::nsh_dir();
    rotate_audit_log_in_dir(&dir)
}

fn rotate_audit_log_in_dir(dir: &Path) -> anyhow::Result<()> {
    let log_path = dir.join("audit.log");
    let input_file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&log_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to open audit log {}", log_path.display()));
        }
    };

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;

        // SAFETY: input_file is an open File whose fd is valid for the
        // duration of this call. LOCK_EX | LOCK_NB is a valid flock operation.
        let ret = unsafe { libc::flock(input_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if ret != 0 {
            return Ok(());
        }
    }

    let meta = input_file
        .metadata()
        .with_context(|| format!("failed to stat audit log {}", log_path.display()))?;
    if meta.len() <= 15_000_000 {
        return Ok(());
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S");
    let archive_name = format!("audit_{ts}.log.gz");
    let archive_path = dir.join(&archive_name);

    #[cfg(unix)]
    let output_file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&archive_path)
    };
    #[cfg(not(unix))]
    let output_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&archive_path);

    let output_file = match output_file {
        Ok(file) => file,
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to create audit archive {}", archive_path.display())
            });
        }
    };
    let mut encoder = flate2::write::GzEncoder::new(output_file, flate2::Compression::default());
    let mut reader = std::io::BufReader::new(&input_file);
    std::io::copy(&mut reader, &mut encoder).with_context(|| {
        format!(
            "failed to compress audit log {} into {}",
            log_path.display(),
            archive_path.display()
        )
    })?;
    encoder
        .finish()
        .with_context(|| format!("failed to finish audit archive {}", archive_path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&archive_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to set audit archive permissions for {}",
                    archive_path.display()
                )
            })?;
    }

    input_file
        .set_len(0)
        .with_context(|| format!("failed to truncate audit log {}", log_path.display()))?;

    cleanup_old_archives_in_dir(dir)?;
    Ok(())
}

#[cfg(test)]
fn cleanup_old_archives() -> anyhow::Result<()> {
    let dir = crate::config::Config::nsh_dir();
    cleanup_old_archives_in_dir(&dir)
}

fn cleanup_old_archives_in_dir(dir: &Path) -> anyhow::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to list audit archives in {}", dir.display()));
        }
    };
    let mut archives: Vec<std::path::PathBuf> = entries
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to scan audit archives in {}", dir.display()))?
        .into_iter()
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            name.starts_with("audit_") && name.ends_with(".log.gz")
        })
        .map(|e| e.path())
        .collect();
    archives.sort();
    while archives.len() > 5 {
        let stale = archives.remove(0);
        std::fs::remove_file(&stale)
            .with_context(|| format!("failed to remove audit archive {}", stale.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;

    fn with_temp_home() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        (home, home_guard, xdg_data_guard, xdg_config_guard)
    }

    #[test]
    #[serial_test::serial]
    fn test_cleanup_old_archives_limit() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        cleanup_old_archives().expect("cleanup old archives");
    }

    #[test]
    #[serial_test::serial]
    fn test_audit_log_no_panic() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        audit_log("test-session", "test query", "command", "ls", "safe")
            .expect("audit log");
    }

    #[test]
    #[serial_test::serial]
    fn test_rotate_audit_log_no_panic() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        rotate_audit_log().expect("rotate audit log");
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
    #[serial_test::serial]
    fn test_rotate_small_log_is_noop() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        rotate_audit_log().expect("rotate small audit log");
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
    #[serial_test::serial]
    fn test_audit_log_special_characters() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        audit_log(
            "sess-special",
            "query with \"quotes\" & <brackets> and\nnewlines",
            "command",
            "echo 'hello world' && rm -rf /",
            "dangerous",
        )
        .expect("audit log with special characters");
    }

    #[test]
    #[serial_test::serial]
    fn test_audit_log_very_long_strings() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        let long_query = "x".repeat(100_000);
        let long_response = "y".repeat(100_000);
        audit_log("sess-long", &long_query, "chat", &long_response, "safe")
            .expect("audit log with long strings");
    }

    #[test]
    #[serial_test::serial]
    fn test_audit_log_empty_strings() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        audit_log("", "", "", "", "").expect("audit log with empty strings");
    }

    #[test]
    #[serial_test::serial]
    fn test_audit_log_unicode() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        audit_log(
            "sess-uni",
            "こんにちは 🌍 émojis",
            "chat",
            "Ñoño résumé",
            "safe",
        )
        .expect("audit log with unicode");
    }

    #[test]
    fn test_audit_json_timestamp_is_rfc3339() {
        let ts = chrono::Utc::now().to_rfc3339();
        assert!(chrono::DateTime::parse_from_rfc3339(&ts).is_ok());
    }

    #[test]
    #[serial_test::serial]
    fn test_rotate_nonexistent_log_is_noop() {
        let (_home, _home_guard, _xdg_data_guard, _xdg_config_guard) = with_temp_home();
        let path = crate::config::Config::nsh_dir().join("audit.log");
        let existed = path.exists();
        rotate_audit_log().expect("rotate nonexistent audit log");
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
        cleanup_old_archives().expect("cleanup without audit dir");
    }

    #[test]
    fn test_audit_log_to_dir_creates_file_with_valid_json() {
        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(tmp.path(), "s1", "hello", "chat", "hi", "safe")
            .expect("write audit log");

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
        audit_log_to_dir(tmp.path(), "s1", "q1", "t1", "r1", "safe")
            .expect("write first audit log");
        audit_log_to_dir(tmp.path(), "s2", "q2", "t2", "r2", "high")
            .expect("write second audit log");

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

        rotate_audit_log_in_dir(tmp.path()).expect("rotate large audit log");

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

        rotate_audit_log_in_dir(tmp.path()).expect("leave small audit log in place");

        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert_eq!(
            contents, "small content",
            "small file should not be rotated"
        );

        let archives: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.ends_with(".log.gz")
            })
            .collect();
        assert!(
            archives.is_empty(),
            "no archives should be created for small files"
        );
    }

    #[test]
    fn test_rotate_nonexistent_file_in_dir() {
        let tmp = tempfile::tempdir().unwrap();
        rotate_audit_log_in_dir(tmp.path()).expect("rotate nonexistent file");
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

        cleanup_old_archives_in_dir(tmp.path()).expect("cleanup archived logs");

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

        for removed in [
            "audit_20250100T000000.log.gz",
            "audit_20250101T000000.log.gz",
            "audit_20250102T000000.log.gz",
        ] {
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

        cleanup_old_archives_in_dir(tmp.path()).expect("keep five archives");

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

        cleanup_old_archives_in_dir(tmp.path()).expect("ignore non archive files");

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

        rotate_audit_log_in_dir(tmp.path()).expect("rotate audit log and cleanup old archives");

        let archive_count = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("audit_") && n.ends_with(".log.gz")
            })
            .count();
        assert!(
            archive_count <= 5,
            "cleanup should cap archives at 5, got {archive_count}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_audit_log_file_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        audit_log_to_dir(tmp.path(), "s1", "q", "t", "r", "safe")
            .expect("write audit log with secure permissions");

        let log_path = tmp.path().join("audit.log");
        let perms = std::fs::metadata(&log_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "audit.log should be owner-only"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_rotate_audit_log_in_dir_cannot_open_log() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        std::fs::write(&log_path, "x".repeat(16_000_000)).unwrap();

        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let error =
            rotate_audit_log_in_dir(tmp.path()).expect_err("permission error should surface");
        assert!(error.to_string().contains("failed to open audit log"));

        std::fs::set_permissions(&log_path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn test_cleanup_old_archives_in_dir_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        cleanup_old_archives_in_dir(tmp.path()).expect("cleanup empty archive dir");
        let count = std::fs::read_dir(tmp.path()).unwrap().count();
        assert_eq!(count, 0);
    }

    #[cfg(unix)]
    #[test]
    fn test_rotate_audit_log_in_dir_cannot_create_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let log_path = tmp.path().join("audit.log");
        std::fs::write(&log_path, "y".repeat(16_000_000)).unwrap();

        let archive_dir = tmp.path();
        use std::os::unix::fs::PermissionsExt;
        let original_perms = std::fs::metadata(archive_dir).unwrap().permissions();
        std::fs::set_permissions(archive_dir, std::fs::Permissions::from_mode(0o444)).unwrap();
        let error =
            rotate_audit_log_in_dir(tmp.path()).expect_err("archive creation failure should surface");
        std::fs::set_permissions(archive_dir, original_perms).unwrap();
        assert!(
            format!("{error:#}").contains("audit"),
            "unexpected error: {error:#}"
        );
        let archive_count = std::fs::read_dir(tmp.path())
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".log.gz"))
            .count();
        assert_eq!(archive_count, 0, "rotation should not leave partial archives");
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
        )
        .expect("write audit log with all fields");

        let contents = std::fs::read_to_string(tmp.path().join("audit.log")).unwrap();
        let v: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(v["session"], "session-with-dashes");
        assert_eq!(v["risk"], "medium");
        assert!(v["response"].as_str().unwrap().contains("newlines"));
    }

    #[test]
    fn test_audit_log_to_dir_invalid_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let bad_dir = tmp.path().join("not-a-directory");
        std::fs::write(&bad_dir, "occupied").unwrap();

        let error = audit_log_to_dir(&bad_dir, "s1", "q", "t", "r", "safe")
            .expect_err("audit log write should fail for non-directory path");
        assert!(error.to_string().contains("failed to create audit log directory"));
    }

    #[test]
    fn test_cleanup_old_archives_standalone() {
        cleanup_old_archives().expect("standalone cleanup");
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

        rotate_audit_log_in_dir(tmp.path()).expect("rotate audit log and truncate source");

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

        rotate_audit_log_in_dir(tmp.path()).expect("rotate audit log and set archive permissions");

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
