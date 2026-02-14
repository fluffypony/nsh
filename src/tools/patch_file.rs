use crate::db::Db;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

fn trash_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        dirs::home_dir().unwrap().join(".Trash")
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "windows")]
        {
            return dirs::data_local_dir().unwrap().join("nsh").join("trash");
        }
        dirs::data_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap().join(".local/share"))
            .join("Trash/files")
    }
}

fn is_root() -> bool {
    #[cfg(windows)]
    {
        return false;
    }
    unsafe { libc::geteuid() == 0 }
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        dirs::home_dir().unwrap().join(rest)
    } else if p == "~" {
        dirs::home_dir().unwrap()
    } else {
        PathBuf::from(p)
    }
}

#[cfg(test)]
fn validate_path(path: &Path) -> anyhow::Result<()> {
    validate_path_with_access(path, "block")
}

fn validate_path_with_access(path: &Path, sensitive_file_access: &str) -> anyhow::Result<()> {
    let s = path.to_string_lossy();

    if s.as_bytes().contains(&0) {
        anyhow::bail!("path contains NUL byte");
    }

    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        anyhow::bail!("path traversal (..) not allowed");
    }

    let home = dirs::home_dir().unwrap();
    // Note: TOCTOU race between validation and open is acknowledged but
    // impractical to fix without openat-style path resolution, and is
    // also impractical to abuse or attack.
    let canonical_target = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let sensitive_dirs = [
        home.join(".ssh"),
        home.join(".gnupg"),
        home.join(".gpg"),
        home.join(".aws"),
        home.join(".config/gcloud"),
        home.join(".azure"),
        home.join(".kube"),
        home.join(".docker"),
        home.join(".nsh"),
        home.join("AppData").join("Roaming").join("gnupg"),
        std::path::PathBuf::from(r"C:\Windows"),
        std::path::PathBuf::from(r"C:\Windows\System32"),
    ];
    if sensitive_file_access != "allow" {
        for dir in &sensitive_dirs {
            if canonical_target.starts_with(dir) {
                if sensitive_file_access == "ask" {
                    eprintln!(
                        "\x1b[1;33m⚠ '{}' is in a sensitive directory\x1b[0m",
                        path.display()
                    );
                    eprint!("\x1b[1;33mAllow write? [y/N]\x1b[0m ");
                    let _ = std::io::Write::flush(&mut std::io::stderr());
                    if crate::tools::read_tty_confirmation() {
                        break;
                    }
                }
                anyhow::bail!("writes to {} are blocked", dir.display());
            }
        }
    }
    if canonical_target.starts_with("/etc") && !is_root() {
        anyhow::bail!("writes to /etc/ require root");
    }

    if path.exists() {
        let meta = std::fs::symlink_metadata(path)?;
        if !meta.file_type().is_file() {
            anyhow::bail!("target exists but is not a regular file");
        }
    }

    if let Some(parent) = canonical_target.parent() {
        if parent.exists() {
            let real_parent = parent.canonicalize()?;
            if sensitive_file_access != "allow"
                && sensitive_dirs.iter().any(|d| real_parent.starts_with(d))
            {
                anyhow::bail!("symlink resolves to a blocked directory");
            }
            if real_parent.starts_with("/etc") && !is_root() {
                anyhow::bail!("symlink resolves to /etc/ (requires root)");
            }
        }
    }

    Ok(())
}

fn backup_to_trash(path: &Path) -> anyhow::Result<PathBuf> {
    let trash = trash_dir();
    std::fs::create_dir_all(&trash)?;

    let filename = path.file_name().unwrap_or_default().to_string_lossy();
    let stamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
    let backup_name = format!("{filename}.{stamp}.nsh_backup");
    let dest = trash.join(&backup_name);

    std::fs::copy(path, &dest)?;
    Ok(dest)
}

#[cfg(unix)]
fn write_nofollow(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(content.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_nofollow(path: &Path, content: &str) -> anyhow::Result<()> {
    std::fs::write(path, content)?;
    Ok(())
}

pub fn execute(
    input: &serde_json::Value,
    original_query: &str,
    db: &Db,
    session_id: &str,
    private: bool,
    config: &crate::config::Config,
) -> anyhow::Result<Option<String>> {
    let raw_path = input["path"].as_str().unwrap_or("");
    let search = input["search"].as_str().unwrap_or("");
    let replace = input["replace"].as_str().unwrap_or("");

    let redact_re = regex::Regex::new(r"\[REDACTED:[a-zA-Z0-9_-]+\]").unwrap();
    if redact_re.is_match(search) {
        return Ok(Some(
            "search text contains redaction markers ([REDACTED:...]). \
             Use a different edit anchor that doesn't span redacted content."
                .into(),
        ));
    }
    if redact_re.is_match(replace) {
        return Ok(Some(
            "replacement text contains redaction markers ([REDACTED:...]). \
             Cannot write redacted content. Use the actual values."
                .into(),
        ));
    }

    let reason = input["reason"].as_str().unwrap_or("");

    if raw_path.is_empty() {
        return Ok(Some("path is required".into()));
    }
    if search.is_empty() {
        return Ok(Some("search is required".into()));
    }

    let path = expand_tilde(raw_path);

    if let Err(e) = validate_path_with_access(&path, &config.tools.sensitive_file_access) {
        return Ok(Some(format!("{e}")));
    }

    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            return Ok(Some(format!("cannot read '{}': {e}", path.display())));
        }
    };

    if !content.contains(search) {
        return Ok(Some(format!(
            "search text not found in '{}'",
            path.display()
        )));
    }

    let occurrences = content.matches(search).count();
    let modified = content.replacen(search, replace, 1);

    let cyan_italic = "\x1b[3;36m";
    let red = "\x1b[31m";
    let green = "\x1b[32m";
    let bold_yellow = "\x1b[1;33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    if !reason.is_empty() {
        eprintln!("{cyan_italic}{reason}{reset}");
    }

    eprintln!("{dim}--- {}{reset}", path.display());
    eprintln!("{dim}+++ {}{reset}", path.display());

    for line in search.lines() {
        eprintln!("{red}-{line}{reset}");
    }
    for line in replace.lines() {
        eprintln!("{green}+{line}{reset}");
    }

    if occurrences > 1 {
        eprintln!(
            "{bold_yellow}warning:{reset} search text appears \
             {occurrences} times; only the first occurrence \
             will be replaced"
        );
    }

    eprintln!();
    eprint!("{bold_yellow}Apply this patch? [y/N]{reset} ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();

    if answer != "y" && answer != "yes" {
        eprintln!("{dim}patch declined{reset}");
        if !private {
            db.insert_conversation(
                session_id,
                original_query,
                "patch_file",
                &format!("declined: {}", path.display()),
                Some(reason),
                false,
                false,
            )?;
        }
        return Ok(None);
    }

    let backup = backup_to_trash(&path)?;
    eprintln!("  Backup: {}", backup.display());

    if path.exists() {
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("target is a symlink (refusing to follow)");
        }
    }
    write_nofollow(&path, &modified)?;
    eprintln!("{green}✓ patched {}{reset}", path.display());

    if !private {
        db.insert_conversation(
            session_id,
            original_query,
            "patch_file",
            &format!("patched: {}", path.display()),
            Some(reason),
            true,
            false,
        )?;
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_expand_tilde_with_subpath() {
        let result = expand_tilde("~/foo");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home.join("foo"));
    }

    #[test]
    fn test_expand_tilde_bare() {
        let result = expand_tilde("~");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home);
    }

    #[test]
    fn test_expand_tilde_absolute_path() {
        let result = expand_tilde("/abs/path");
        assert_eq!(result, PathBuf::from("/abs/path"));
    }

    #[test]
    fn test_validate_path_normal() {
        let tmp = std::env::temp_dir().join("nsh_test_patch_validate_ok.txt");
        assert!(validate_path(&tmp).is_ok());
    }

    #[test]
    fn test_validate_path_traversal() {
        let bad = PathBuf::from("/tmp/foo/../bar");
        let err = validate_path(&bad).unwrap_err();
        assert!(
            err.to_string().contains("path traversal"),
            "expected path traversal error, got: {err}"
        );
    }

    #[test]
    fn test_validate_path_blocked_ssh() {
        let home = dirs::home_dir().unwrap();
        let ssh = home.join(".ssh/test_key");
        let err = validate_path(&ssh).unwrap_err();
        assert!(
            err.to_string().contains("blocked"),
            "expected blocked error, got: {err}"
        );
    }

    #[test]
    fn test_validate_path_blocked_nsh() {
        let home = dirs::home_dir().unwrap();
        let nsh = home.join(".nsh/something");
        let err = validate_path(&nsh).unwrap_err();
        assert!(
            err.to_string().contains("blocked"),
            "expected blocked error, got: {err}"
        );
    }

    #[test]
    fn test_is_root_returns_false() {
        assert!(!is_root());
    }

    #[test]
    fn test_trash_dir_contains_trash() {
        let td = trash_dir();
        let s = td.to_string_lossy();
        assert!(
            s.contains("Trash") || s.contains("trash"),
            "expected Trash in path, got: {s}"
        );
    }

    #[test]
    fn test_backup_to_trash() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "patch backup test").unwrap();

        let backup_path = backup_to_trash(tmp.path()).unwrap();
        assert!(backup_path.exists(), "backup file should exist");
        assert!(
            backup_path.to_string_lossy().contains("nsh_backup"),
            "backup filename should contain nsh_backup"
        );

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn test_redaction_marker_in_search() {
        let re = regex::Regex::new(r"\[REDACTED:[a-zA-Z0-9_-]+\]").unwrap();
        assert!(re.is_match("[REDACTED:api-key]"));
        assert!(re.is_match("[REDACTED:github_pat]"));
        assert!(!re.is_match("normal text"));
        assert!(!re.is_match("[NOTREDACTED:foo]"));
    }

    #[test]
    fn test_validate_path_blocked_aws() {
        let home = dirs::home_dir().unwrap();
        let aws = home.join(".aws/credentials");
        let err = validate_path(&aws).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_etc_blocked_non_root() {
        let etc = PathBuf::from("/etc/passwd");
        let err = validate_path(&etc).unwrap_err();
        assert!(err.to_string().contains("/etc"));
    }

    #[test]
    fn test_validate_path_relative_ok() {
        let rel = PathBuf::from("test_file.txt");
        assert!(validate_path(&rel).is_ok());
    }

    #[test]
    fn test_expand_tilde_relative() {
        let result = expand_tilde("relative/path");
        assert_eq!(result, PathBuf::from("relative/path"));
    }

    #[test]
    fn test_write_nofollow_creates_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        write_nofollow(&path, "hello world").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "hello world");
    }

    #[test]
    fn test_validate_path_blocked_gnupg() {
        let home = dirs::home_dir().unwrap();
        let gnupg = home.join(".gnupg/pubring.kbx");
        let err = validate_path(&gnupg).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_blocked_gpg() {
        let home = dirs::home_dir().unwrap();
        let gpg = home.join(".gpg/keyring");
        let err = validate_path(&gpg).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_blocked_gcloud() {
        let home = dirs::home_dir().unwrap();
        let gcloud = home.join(".config/gcloud/credentials");
        let err = validate_path(&gcloud).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_blocked_azure() {
        let home = dirs::home_dir().unwrap();
        let azure = home.join(".azure/config");
        let err = validate_path(&azure).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_allow_bypasses_sensitive_dirs() {
        let home = dirs::home_dir().unwrap();
        let ssh = home.join(".ssh/test_key");
        assert!(validate_path_with_access(&ssh, "allow").is_ok());

        let aws = home.join(".aws/credentials");
        assert!(validate_path_with_access(&aws, "allow").is_ok());

        let nsh = home.join(".nsh/something");
        assert!(validate_path_with_access(&nsh, "allow").is_ok());
    }

    #[test]
    fn test_validate_path_directory_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = validate_path_with_access(dir.path(), "block").unwrap_err();
        assert!(
            err.to_string().contains("not a regular file"),
            "expected not a regular file error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_validate_path_symlink_to_sensitive_dir() {
        let home = dirs::home_dir().unwrap();
        let dir = tempfile::TempDir::new().unwrap();
        let sensitive = home.join(".ssh");
        if sensitive.exists() {
            let link = dir.path().join("link_dir");
            std::os::unix::fs::symlink(&sensitive, &link).unwrap();
            let target = link.join("test_file");
            let err = validate_path_with_access(&target, "block").unwrap_err();
            assert!(
                err.to_string().contains("blocked"),
                "expected blocked error through symlink, got: {err}"
            );
        }
    }

    #[test]
    fn test_validate_path_nul_byte() {
        let bad = PathBuf::from("foo\0bar");
        let err = validate_path_with_access(&bad, "block").unwrap_err();
        assert!(
            err.to_string().contains("NUL"),
            "expected NUL byte error, got: {err}"
        );
    }

    #[test]
    fn test_backup_to_trash_name_with_spaces() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("file with spaces.txt");
        std::fs::write(&path, "content").unwrap();

        let backup_path = backup_to_trash(&path).unwrap();
        assert!(backup_path.exists());
        let name = backup_path.file_name().unwrap().to_string_lossy();
        assert!(name.contains("file with spaces"));
        assert!(name.contains("nsh_backup"));

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn test_backup_to_trash_long_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let long_name = "a".repeat(200) + ".txt";
        let path = dir.path().join(&long_name);
        std::fs::write(&path, "content").unwrap();

        let backup_path = backup_to_trash(&path).unwrap();
        assert!(backup_path.exists());
        assert!(backup_path.to_string_lossy().contains("nsh_backup"));

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn test_write_nofollow_unicode_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("unicode.txt");
        let content = "こんにちは世界 🌍 é à ü ñ «»";
        write_nofollow(&path, content).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    }

    #[test]
    fn test_write_nofollow_empty_string() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.txt");
        write_nofollow(&path, "").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn test_expand_tilde_deeply_nested() {
        let result = expand_tilde("~/a/b/c/d");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home.join("a/b/c/d"));
    }

    #[test]
    fn test_validate_path_etc_non_existent_requires_root() {
        let etc = PathBuf::from("/etc/nsh_nonexistent_test_file");
        let err = validate_path_with_access(&etc, "block").unwrap_err();
        assert!(
            err.to_string().contains("require root"),
            "expected require root error, got: {err}"
        );
    }

    #[test]
    fn test_validate_path_blocked_kube() {
        let home = dirs::home_dir().unwrap();
        let kube = home.join(".kube/config");
        let err = validate_path(&kube).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    #[test]
    fn test_validate_path_blocked_docker() {
        let home = dirs::home_dir().unwrap();
        let docker = home.join(".docker/config.json");
        let err = validate_path(&docker).unwrap_err();
        assert!(err.to_string().contains("blocked"));
    }

    fn test_db() -> Db {
        Db::open_in_memory().unwrap()
    }

    fn test_config() -> crate::config::Config {
        crate::config::Config::default()
    }

    #[test]
    fn test_execute_redaction_marker_in_search() {
        let input = serde_json::json!({
            "path": "/tmp/test.txt",
            "search": "before [REDACTED:api-key] after",
            "replace": "new text",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(
            result
                .unwrap()
                .contains("search text contains redaction markers")
        );
    }

    #[test]
    fn test_execute_redaction_marker_in_replace() {
        let input = serde_json::json!({
            "path": "/tmp/test.txt",
            "search": "normal search",
            "replace": "value [REDACTED:github_pat] here",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(
            result
                .unwrap()
                .contains("replacement text contains redaction markers")
        );
    }

    #[test]
    fn test_execute_empty_path() {
        let input = serde_json::json!({
            "path": "",
            "search": "something",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert_eq!(result, Some("path is required".into()));
    }

    #[test]
    fn test_execute_missing_path_field() {
        let input = serde_json::json!({
            "search": "something",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert_eq!(result, Some("path is required".into()));
    }

    #[test]
    fn test_execute_empty_search() {
        let input = serde_json::json!({
            "path": "/tmp/test.txt",
            "search": "",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert_eq!(result, Some("search is required".into()));
    }

    #[test]
    fn test_execute_path_validation_failure() {
        let input = serde_json::json!({
            "path": "/tmp/foo/../bar",
            "search": "something",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("path traversal"));
    }

    #[test]
    fn test_execute_file_not_found() {
        let input = serde_json::json!({
            "path": "/tmp/nsh_nonexistent_file_for_test_12345.txt",
            "search": "something",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("cannot read"));
    }

    #[test]
    fn test_execute_search_text_not_found() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "hello world").unwrap();

        let input = serde_json::json!({
            "path": path.to_str().unwrap(),
            "search": "nonexistent text",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("search text not found"));
    }

    #[test]
    fn test_execute_redaction_marker_variations() {
        let db = test_db();
        let config = test_config();

        let input = serde_json::json!({
            "path": "/tmp/test.txt",
            "search": "[REDACTED:some_token-123]",
            "replace": "x",
        });
        let result = execute(&input, "q", &db, "s", false, &config).unwrap();
        assert!(
            result
                .unwrap()
                .contains("search text contains redaction markers")
        );

        let input = serde_json::json!({
            "path": "/tmp/test.txt",
            "search": "ok",
            "replace": "[REDACTED:A]",
        });
        let result = execute(&input, "q", &db, "s", false, &config).unwrap();
        assert!(
            result
                .unwrap()
                .contains("replacement text contains redaction markers")
        );
    }

    #[test]
    fn test_execute_sensitive_path_blocked() {
        let home = dirs::home_dir().unwrap();
        let input = serde_json::json!({
            "path": home.join(".ssh/id_rsa").to_str().unwrap(),
            "search": "something",
            "replace": "other",
        });
        let db = test_db();
        let config = test_config();
        let result = execute(&input, "query", &db, "sess", false, &config).unwrap();
        assert!(result.is_some());
        assert!(result.unwrap().contains("blocked"));
    }
}
