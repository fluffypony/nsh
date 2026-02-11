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

fn validate_path(path: &Path) -> anyhow::Result<()> {
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
    let canonical_target = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };

    let ssh_dir = home.join(".ssh");
    let nsh_dir = home.join(".nsh");

    if canonical_target.starts_with(&ssh_dir) {
        anyhow::bail!("writes to ~/.ssh/ are blocked");
    }
    if canonical_target.starts_with(&nsh_dir) {
        anyhow::bail!("writes to ~/.nsh/ are blocked");
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
            if real_parent.starts_with(&ssh_dir) || real_parent.starts_with(&nsh_dir) {
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

    if let Err(e) = validate_path(&path) {
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
}
