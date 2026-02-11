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
        dirs::data_dir()
            .unwrap_or_else(|| dirs::home_dir().unwrap().join(".local/share"))
            .join("Trash/files")
    }
}

fn is_root() -> bool {
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

fn print_diff(old: &str, new: &str) {
    let red = "\x1b[31m";
    let green = "\x1b[32m";
    let reset = "\x1b[0m";

    let old_lines: Vec<&str> = old.lines().collect();
    let new_lines: Vec<&str> = new.lines().collect();
    let max = old_lines.len().max(new_lines.len()).min(100);

    for i in 0..max {
        let ol = old_lines.get(i).copied();
        let nl = new_lines.get(i).copied();

        match (ol, nl) {
            (Some(o), Some(n)) if o == n => {
                eprintln!("  {o}");
            }
            (Some(o), Some(n)) => {
                eprintln!("{red}- {o}{reset}");
                eprintln!("{green}+ {n}{reset}");
            }
            (Some(o), None) => {
                eprintln!("{red}- {o}{reset}");
            }
            (None, Some(n)) => {
                eprintln!("{green}+ {n}{reset}");
            }
            (None, None) => {}
        }
    }

    let total = old_lines.len().max(new_lines.len());
    if total > 100 {
        eprintln!("  ... ({} more lines)", total - 100);
    }
}

fn print_preview(content: &str) {
    let green = "\x1b[32m";
    let reset = "\x1b[0m";

    for (i, line) in content.lines().enumerate() {
        if i >= 50 {
            let total = content.lines().count();
            eprintln!("  ... ({} more lines)", total - 50);
            break;
        }
        eprintln!("{green}+ {line}{reset}");
    }
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
) -> anyhow::Result<()> {
    let raw_path = input["path"].as_str().unwrap_or("");
    let content = input["content"].as_str().unwrap_or("");

    if regex::Regex::new(r"\[REDACTED:[a-zA-Z0-9_-]+\]")
        .unwrap()
        .is_match(content)
    {
        anyhow::bail!(
            "write_file: content contains redaction markers ([REDACTED:...]). \
             Cannot write redacted content to disk. Identify the actual values needed."
        );
    }

    let reason = input["reason"].as_str().unwrap_or("");

    if raw_path.is_empty() {
        anyhow::bail!("write_file: path is required");
    }

    let path = expand_tilde(raw_path);
    validate_path_with_access(&path, &config.tools.sensitive_file_access)?;

    let cyan_italic = "\x1b[3;36m";
    let bold = "\x1b[1m";
    let reset = "\x1b[0m";

    if !reason.is_empty() {
        eprintln!("{cyan_italic}{reason}{reset}");
    }

    eprintln!("{bold}File:{reset} {}", path.display());
    eprintln!();

    let existing = if path.exists() {
        Some(std::fs::read_to_string(&path)?)
    } else {
        None
    };

    if let Some(ref old) = existing {
        eprintln!("{bold}Diff:{reset}");
        print_diff(old, content);
    } else {
        eprintln!("{bold}New file:{reset}");
        print_preview(content);
    }

    eprintln!();
    eprint!("Write this file? [y/N] ");
    io::stderr().flush()?;

    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    let answer = answer.trim().to_lowercase();

    if answer != "y" && answer != "yes" {
        eprintln!("Aborted.");
        return Ok(());
    }

    if existing.is_some() {
        let backup = backup_to_trash(&path)?;
        eprintln!("  Backup: {}", backup.display());
    }

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    if path.exists() {
        let meta = std::fs::symlink_metadata(&path)?;
        if meta.file_type().is_symlink() {
            anyhow::bail!("target is a symlink (refusing to follow)");
        }
    }
    write_nofollow(&path, content)?;
    eprintln!("  Written: {}", path.display());

    if !private {
        db.insert_conversation(
            session_id,
            original_query,
            "write_file",
            &path.to_string_lossy(),
            Some(reason),
            true,
            false,
        )?;
    }

    Ok(())
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
        let tmp = std::env::temp_dir().join("nsh_test_validate_ok.txt");
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
    fn test_print_diff_no_panic() {
        print_diff("", "");
        print_diff("hello\nworld", "hello\nrust");
        print_diff("a", "");
        print_diff("", "b");
        let long = "line\n".repeat(200);
        print_diff(&long, &long);
    }

    #[test]
    fn test_print_preview_no_panic() {
        print_preview("");
        print_preview("single line");
        let long = "line\n".repeat(100);
        print_preview(&long);
    }

    #[test]
    fn test_backup_to_trash() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "backup test content").unwrap();

        let backup_path = backup_to_trash(tmp.path()).unwrap();
        assert!(backup_path.exists(), "backup file should exist");
        assert!(
            backup_path.to_string_lossy().contains("nsh_backup"),
            "backup filename should contain nsh_backup"
        );

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn test_validate_path_blocked_aws() {
        let home = dirs::home_dir().unwrap();
        let aws = home.join(".aws/credentials");
        let err = validate_path(&aws).unwrap_err();
        assert!(err.to_string().contains("blocked"));
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
    fn test_write_nofollow_overwrites_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, "old").unwrap();
        write_nofollow(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn test_print_diff_identical() {
        print_diff("same\nlines", "same\nlines");
    }

    #[test]
    fn test_print_diff_different_lengths() {
        print_diff("a\nb\nc", "a\nb");
        print_diff("a\nb", "a\nb\nc");
    }

    #[test]
    fn test_print_diff_identical_multiline() {
        let content = "line1\nline2\nline3\nline4\nline5";
        print_diff(content, content);
    }

    #[test]
    fn test_print_diff_empty_old_nonempty_new() {
        print_diff("", "new line1\nnew line2\nnew line3");
    }

    #[test]
    fn test_print_diff_nonempty_old_empty_new() {
        print_diff("old line1\nold line2\nold line3", "");
    }

    #[test]
    fn test_print_diff_exactly_100_lines() {
        let content = (1..=100).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        print_diff(&content, &content);
    }

    #[test]
    fn test_print_diff_truncation_over_100_lines() {
        let old = (1..=101).map(|i| format!("old {i}")).collect::<Vec<_>>().join("\n");
        let new = (1..=101).map(|i| format!("new {i}")).collect::<Vec<_>>().join("\n");
        print_diff(&old, &new);
    }

    #[test]
    fn test_print_preview_exactly_50_lines() {
        let content = (1..=50).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        print_preview(&content);
    }

    #[test]
    fn test_print_preview_51_lines_truncates() {
        let content = (1..=51).map(|i| format!("line {i}")).collect::<Vec<_>>().join("\n");
        print_preview(&content);
    }

    #[test]
    fn test_validate_path_allow_sensitive() {
        let home = dirs::home_dir().unwrap();
        let ssh = home.join(".ssh/test_key");
        assert!(validate_path_with_access(&ssh, "allow").is_ok());
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
    fn test_validate_path_directory_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let err = validate_path_with_access(dir.path(), "block").unwrap_err();
        assert!(
            err.to_string().contains("not a regular file"),
            "expected not a regular file error, got: {err}"
        );
    }

    #[test]
    fn test_backup_to_trash_filename_format() {
        let mut tmp = NamedTempFile::new().unwrap();
        writeln!(tmp, "content").unwrap();

        let backup_path = backup_to_trash(tmp.path()).unwrap();
        let name = backup_path.file_name().unwrap().to_string_lossy();
        assert!(name.contains("nsh_backup"), "should contain nsh_backup: {name}");
        assert!(
            regex::Regex::new(r"\d{8}_\d{6}").unwrap().is_match(&name),
            "should contain timestamp YYYYMMDD_HHMMSS: {name}"
        );

        let _ = std::fs::remove_file(&backup_path);
    }

    #[test]
    fn test_write_nofollow_empty_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("empty.txt");
        write_nofollow(&path, "").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "");
    }

    #[test]
    fn test_write_nofollow_unicode_content() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("unicode.txt");
        let content = "こんにちは世界 🌍 é à ü ñ";
        write_nofollow(&path, content).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), content);
    }

    #[test]
    fn test_expand_tilde_nested_path() {
        let result = expand_tilde("~/a/b/c");
        let home = dirs::home_dir().unwrap();
        assert_eq!(result, home.join("a/b/c"));
    }
}
