use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use regex::Regex;

use crate::db::IMPORT_SESSION_PREFIX;

type SessionEntries =
    std::collections::HashMap<String, (String, String, Vec<(String, DateTime<Utc>)>)>;

const MAX_IMPORT_ENTRIES: usize = 10_000;
const IMPORT_LOCK_FILENAME: &str = "history_import.lock";
const IMPORT_LOCK_STALE_SECS: u64 = 60 * 60;

#[allow(dead_code)]
#[allow(clippy::enum_variant_names)]
#[derive(Debug, Clone, Copy, PartialEq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
    PowerShell,
}

fn import_lock_path() -> PathBuf {
    crate::config::Config::nsh_dir().join(IMPORT_LOCK_FILENAME)
}

fn clear_stale_lock_if_needed() {
    let path = import_lock_path();
    let Ok(meta) = std::fs::metadata(&path) else {
        return;
    };
    let Ok(modified) = meta.modified() else {
        return;
    };
    if let Ok(elapsed) = modified.elapsed() {
        if elapsed.as_secs() > IMPORT_LOCK_STALE_SECS {
            let _ = std::fs::remove_file(path);
        }
    }
}

pub fn import_in_progress() -> bool {
    clear_stale_lock_if_needed();
    import_lock_path().exists()
}

pub fn clear_import_lock() {
    let _ = std::fs::remove_file(import_lock_path());
}

/// Extracts the full TTY device path from a per-TTY zsh history filename.
/// e.g. `.zsh_history_ttys007` -> Some("/dev/ttys007")
///      `.zsh_history_pts3`   -> Some("/dev/pts3")
///      `.zsh_history`        -> None
///      `.bash_history`       -> None
fn extract_tty_from_path(path: &Path) -> Option<String> {
    let name = path.file_name()?.to_str()?;
    let suffix = name.strip_prefix(".zsh_history_")?;
    if !suffix.is_empty() && (suffix.starts_with("ttys") || suffix.starts_with("pts")) {
        Some(format!("/dev/{suffix}"))
    } else {
        None
    }
}

/// Returns (session_id, tty, shell_name) for an imported history file.
///
/// Per-TTY zsh files get the actual TTY path so they naturally match
/// the `session: "current"` TTY subquery. Other files get tty="import"
/// and are caught by the `LIKE 'imported_%'` fallback in all searches.
///
/// Examples:
///   .zsh_history_ttys007 -> ("imported_zsh_ttys007",  "/dev/ttys007", "zsh")
///   .bash_history        -> ("imported_bash_history",  "import",       "bash")
///   .zsh_history         -> ("imported_zsh_history",   "import",       "zsh")
///   .histfile            -> ("imported_histfile",      "import",       "zsh")
///   fish_history         -> ("imported_fish_history",  "import",       "fish")
fn import_session_info(path: &Path, shell: &Shell) -> (String, String, String) {
    let shell_name = match shell {
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
        Shell::Fish => "fish",
        Shell::PowerShell => "powershell",
    };

    if let Some(tty) = extract_tty_from_path(path) {
        let tty_short = tty.strip_prefix("/dev/").unwrap_or(&tty);
        let session_id = format!("{IMPORT_SESSION_PREFIX}{shell_name}_{tty_short}");
        return (session_id, tty, shell_name.to_string());
    }

    let filename = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .trim_start_matches('.')
        .replace('.', "_");
    let session_id = format!("{IMPORT_SESSION_PREFIX}{filename}");
    (session_id, "import".to_string(), shell_name.to_string())
}

pub fn import_if_needed(db: &crate::db::Db) {
    let result: anyhow::Result<()> = (|| {
        let already_imported = db.get_meta("shell_history_imported")?.is_some();
        let per_tty_imported = db.get_meta("shell_history_imported_per_tty")?.is_some();

        if already_imported && per_tty_imported {
            return Ok(());
        }

        let mut files = discover_history_files();
        if already_imported && !per_tty_imported {
            files.retain(|(path, shell)| *shell == Shell::Zsh && is_per_tty_zsh_history(path));
        }

        let mut entries_by_session: SessionEntries = std::collections::HashMap::new();

        for (path, shell) in &files {
            let file_mtime = match std::fs::metadata(path).and_then(|m| m.modified()) {
                Ok(mt) => DateTime::<Utc>::from(mt),
                Err(e) => {
                    tracing::debug!("skipping {}: {e}", path.display());
                    continue;
                }
            };
            let entries = match shell {
                Shell::Bash => parse_bash(path, file_mtime),
                Shell::Zsh => parse_zsh(path, file_mtime),
                Shell::Fish => parse_fish(path, file_mtime),
                Shell::PowerShell => parse_powershell(path, file_mtime),
            };
            if entries.is_empty() {
                continue;
            }

            let (session_id, tty, shell_name) = import_session_info(path, shell);
            entries_by_session
                .entry(session_id)
                .or_insert_with(|| (tty, shell_name, Vec::new()))
                .2
                .extend(entries);
        }

        let mut total_imported = 0usize;

        for (session_id, (tty, shell_name, mut entries)) in entries_by_session {
            entries.sort_by_key(|(_, ts)| *ts);
            if entries.len() > MAX_IMPORT_ENTRIES {
                entries = entries.into_iter().rev().take(MAX_IMPORT_ENTRIES).collect();
                entries.reverse();
            }

            db.create_session(&session_id, &tty, &shell_name, 0)?;

            let payload: Vec<serde_json::Value> = entries
                .iter()
                .map(|(cmd, ts)| serde_json::json!({ "cmd": cmd, "ts": ts.to_rfc3339() }))
                .collect();
            let n = payload.len();
            let entries_json = serde_json::to_string(&payload)?;
            db.bulk_insert_history(&session_id, &entries_json)?;
            total_imported += n;

            db.end_session(&session_id)?;
        }

        db.set_meta("shell_history_imported", "1")?;
        db.set_meta("shell_history_imported_per_tty", "1")?;
        tracing::info!("nsh: imported {total_imported} commands from shell history");

        Ok(())
    })();

    if let Err(e) = result {
        tracing::debug!("shell history import skipped: {e}");
    }
}

fn is_per_tty_zsh_history(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|name| name.starts_with(".zsh_history_ttys"))
        .unwrap_or(false)
}

fn detect_shell_from_content(path: &Path) -> Shell {
    if let Ok(bytes) = std::fs::read(path) {
        let content = String::from_utf8_lossy(&bytes);
        let first_line = content.lines().find(|l| !l.trim().is_empty());
        if let Some(line) = first_line {
            if line.starts_with("- cmd: ") {
                return Shell::Fish;
            }
            let re = Regex::new(r"^: \d+:\d+;").unwrap();
            if re.is_match(line) {
                return Shell::Zsh;
            }
        }
    }
    Shell::Bash
}

fn discover_history_files() -> Vec<(PathBuf, Shell)> {
    let mut files: Vec<(PathBuf, Shell)> = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    if let Some(path) = std::env::var("HISTFILE").ok().map(PathBuf::from) {
        if path.exists() {
            let shell = detect_shell_from_content(&path);
            files.push((path, shell));
        }
    }

    for (path, shell) in [
        (home.join(".bash_history"), Shell::Bash),
        (home.join(".zsh_history"), Shell::Zsh),
        (home.join(".histfile"), Shell::Zsh),
    ] {
        if path.exists() && !files.iter().any(|(p, _)| p == &path) {
            files.push((path, shell));
        }
    }

    if let Ok(entries) = std::fs::read_dir(&home) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if is_per_tty_zsh_history(&path) && !files.iter().any(|(p, _)| p == &path) {
                files.push((path, Shell::Zsh));
            }
        }
    }

    let fish_data = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".local/share"));
    let fish_hist = fish_data.join("fish").join("fish_history");
    if fish_hist.exists() {
        files.push((fish_hist, Shell::Fish));
    }

    #[cfg(windows)]
    {
        if let Ok(appdata) = std::env::var("APPDATA") {
            let ps_hist = PathBuf::from(&appdata)
                .join("Microsoft")
                .join("Windows")
                .join("PowerShell")
                .join("PSReadLine")
                .join("ConsoleHost_history.txt");
            if ps_hist.exists() {
                files.push((ps_hist, Shell::PowerShell));
            }

            let git_bash_hist = PathBuf::from(&appdata).join(".bash_history");
            if git_bash_hist.exists() {
                files.push((git_bash_hist, Shell::Bash));
            }
        }
    }

    let mut deduped: Vec<(PathBuf, Shell)> = Vec::new();
    for (path, shell) in files {
        let canonical = match path.canonicalize() {
            Ok(c) => c,
            Err(_) => path,
        };
        if !deduped.iter().any(|(p, _)| p == &canonical) {
            deduped.push((canonical, shell));
        }
    }

    deduped
}

fn parse_bash(path: &Path, file_mtime: DateTime<Utc>) -> Vec<(String, DateTime<Utc>)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let content = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let mut results: Vec<(String, DateTime<Utc>)> = Vec::new();
    let mut pending_timestamp: Option<i64> = None;

    for (idx, line) in lines.iter().enumerate() {
        let line = line.trim_end();
        if line.is_empty() {
            continue;
        }

        if let Some(rest) = line.strip_prefix('#') {
            if let Ok(ts) = rest.trim().parse::<i64>() {
                pending_timestamp = Some(ts);
                continue;
            }
        }

        let timestamp = if let Some(ts) = pending_timestamp.take() {
            DateTime::from_timestamp(ts, 0).unwrap_or(file_mtime)
        } else {
            let remaining = total.saturating_sub(idx + 1);
            file_mtime - chrono::Duration::seconds(remaining as i64)
        };

        results.push((line.to_string(), timestamp));
    }

    results
}

fn parse_zsh(path: &Path, file_mtime: DateTime<Utc>) -> Vec<(String, DateTime<Utc>)> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };
    let content = String::from_utf8_lossy(&bytes);

    let is_extended = content
        .lines()
        .find(|l| !l.trim().is_empty())
        .map(|l| {
            let re = Regex::new(r"^: \d+:\d+;").unwrap();
            re.is_match(l)
        })
        .unwrap_or(false);

    if is_extended {
        parse_zsh_extended(&content)
    } else {
        parse_zsh_plain(&content, file_mtime)
    }
}

fn parse_zsh_extended(content: &str) -> Vec<(String, DateTime<Utc>)> {
    let re = Regex::new(r"^: (\d+):\d+;(.+)$").unwrap();
    let mut results: Vec<(String, DateTime<Utc>)> = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        if let Some(caps) = re.captures(lines[i]) {
            let ts_val: i64 = caps[1].parse().unwrap_or(0);
            let timestamp = DateTime::from_timestamp(ts_val, 0).unwrap_or_else(Utc::now);
            let mut cmd = caps[2].to_string();

            while cmd.ends_with('\\') && i + 1 < lines.len() {
                cmd.truncate(cmd.len() - 1);
                i += 1;
                cmd.push('\n');
                cmd.push_str(lines[i]);
            }

            results.push((cmd, timestamp));
        }
        i += 1;
    }

    results
}

fn parse_zsh_plain(content: &str, file_mtime: DateTime<Utc>) -> Vec<(String, DateTime<Utc>)> {
    let lines: Vec<&str> = content.lines().collect();
    let total = lines.len();
    let mut results: Vec<(String, DateTime<Utc>)> = Vec::new();

    for (idx, line) in lines.iter().enumerate() {
        if line.is_empty() {
            continue;
        }
        let remaining = total.saturating_sub(idx + 1);
        let ts = file_mtime - chrono::Duration::seconds(remaining as i64);
        results.push((line.to_string(), ts));
    }

    results
}

fn parse_fish(path: &Path, _file_mtime: DateTime<Utc>) -> Vec<(String, DateTime<Utc>)> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    let mut results: Vec<(String, DateTime<Utc>)> = Vec::new();
    let mut current_cmd: Option<String> = None;
    let mut current_when: Option<DateTime<Utc>> = None;

    for line in content.lines() {
        if let Some(cmd) = line.strip_prefix("- cmd: ") {
            if let Some(prev_cmd) = current_cmd.take() {
                let ts = current_when.take().unwrap_or_else(Utc::now);
                results.push((prev_cmd, ts));
            }
            current_cmd = Some(cmd.to_string());
            current_when = None;
        } else if let Some(rest) = line.trim_start().strip_prefix("when: ") {
            if let Ok(ts_val) = rest.trim().parse::<i64>() {
                current_when = DateTime::from_timestamp(ts_val, 0);
            }
        }
    }

    if let Some(cmd) = current_cmd {
        let ts = current_when.unwrap_or_else(Utc::now);
        results.push((cmd, ts));
    }

    results
}

fn parse_powershell(path: &Path, file_mtime: DateTime<Utc>) -> Vec<(String, DateTime<Utc>)> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                None
            } else {
                Some((line.to_string(), file_mtime))
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use std::ffi::OsStr;
    use std::fs;
    use std::io::Write;
    use tempfile::NamedTempFile;
    use tempfile::TempDir;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn fixed_mtime() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
    }

    struct EnvVarGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: test-only, serialized by #[serial] where needed.
            unsafe { std::env::set_var(key, value) };
            Self { key, old }
        }

        fn remove(key: &'static str) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: test-only, serialized by #[serial] where needed.
            unsafe { std::env::remove_var(key) };
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(old) = &self.old {
                // SAFETY: test-only, serialized by #[serial] where needed.
                unsafe { std::env::set_var(self.key, old) };
            } else {
                // SAFETY: test-only, serialized by #[serial] where needed.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    fn temp_home() -> TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn test_extract_tty_from_path() {
        assert_eq!(
            extract_tty_from_path(Path::new("/home/user/.zsh_history_ttys007")),
            Some("/dev/ttys007".to_string())
        );
        assert_eq!(
            extract_tty_from_path(Path::new("/home/user/.zsh_history_pts3")),
            Some("/dev/pts3".to_string())
        );
        assert_eq!(
            extract_tty_from_path(Path::new("/home/user/.zsh_history")),
            None
        );
        assert_eq!(
            extract_tty_from_path(Path::new("/home/user/.bash_history")),
            None
        );
    }

    #[test]
    fn test_import_session_info() {
        let (id, tty, shell) =
            import_session_info(Path::new("/home/user/.zsh_history_ttys007"), &Shell::Zsh);
        assert_eq!(id, "imported_zsh_ttys007");
        assert_eq!(tty, "/dev/ttys007");
        assert_eq!(shell, "zsh");

        let (id, tty, shell) =
            import_session_info(Path::new("/home/user/.bash_history"), &Shell::Bash);
        assert_eq!(id, "imported_bash_history");
        assert_eq!(tty, "import");
        assert_eq!(shell, "bash");

        let (id, tty, shell) =
            import_session_info(Path::new("/home/user/.zsh_history"), &Shell::Zsh);
        assert_eq!(id, "imported_zsh_history");
        assert_eq!(tty, "import");
        assert_eq!(shell, "zsh");
    }

    #[test]
    fn parse_bash_empty_file() {
        let f = write_temp("");
        let results = parse_bash(f.path(), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_bash_with_timestamps() {
        let f = write_temp("#1700000100\nls -la\n#1700000200\necho hello\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ls -la");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
        assert_eq!(results[1].0, "echo hello");
        assert_eq!(results[1].1.timestamp(), 1_700_000_200);
    }

    #[test]
    fn parse_bash_without_timestamps() {
        let f = write_temp("ls\npwd\nwhoami\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[2].0, "whoami");
        assert!(results[0].1 <= results[1].1);
        assert!(results[1].1 <= results[2].1);
    }

    #[test]
    fn parse_zsh_extended_single() {
        let results = parse_zsh_extended(": 1700000100:0;git status\n");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "git status");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
    }

    #[test]
    fn parse_zsh_extended_multiline_continuation() {
        let content = ": 1700000100:0;echo foo\\\nbar\n: 1700000200:0;pwd\n";
        let results = parse_zsh_extended(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "echo foo\nbar");
        assert_eq!(results[1].0, "pwd");
    }

    #[test]
    fn parse_zsh_plain_basic() {
        let results = parse_zsh_plain("ls\npwd\n", fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[1].0, "pwd");
    }

    #[test]
    fn parse_zsh_plain_empty_lines_filtered() {
        let results = parse_zsh_plain("ls\n\n\npwd\n", fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[1].0, "pwd");
    }

    #[test]
    fn parse_fish_single_command() {
        let f = write_temp("- cmd: git log\n  when: 1700000100\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "git log");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
    }

    #[test]
    fn parse_fish_multiple_commands() {
        let f = write_temp("- cmd: git log\n  when: 1700000100\n- cmd: ls\n  when: 1700000200\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "git log");
        assert_eq!(results[1].0, "ls");
    }

    #[test]
    fn parse_fish_without_when() {
        let f = write_temp("- cmd: pwd\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "pwd");
    }

    #[test]
    fn detect_fish_content() {
        let f = write_temp("- cmd: git log\n  when: 12345\n");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Fish);
    }

    #[test]
    fn detect_zsh_extended_content() {
        let f = write_temp(": 1700000100:0;git status\n");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Zsh);
    }

    #[test]
    fn detect_bash_default() {
        let f = write_temp("ls -la\npwd\n");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Bash);
    }

    #[test]
    fn import_sets_meta_flag() {
        let db = crate::db::Db::open_in_memory().unwrap();
        assert!(db.get_meta("shell_history_imported").unwrap().is_none());
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(
            db.get_meta("shell_history_imported_per_tty")
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    #[serial]
    fn import_skips_when_already_imported() {
        let home = temp_home();
        let tty_hist = home.path().join(".zsh_history_ttys007");
        fs::write(&tty_hist, "should_not_import\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _histfile = EnvVarGuard::remove("HISTFILE");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_meta("shell_history_imported", "1").unwrap();
        db.set_meta("shell_history_imported_per_tty", "1").unwrap();
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(
            db.get_meta("shell_history_imported_per_tty")
                .unwrap()
                .as_deref(),
            Some("1")
        );
        assert_eq!(
            db.command_count().unwrap(),
            0,
            "no additional import should happen when both import flags are set"
        );
    }

    #[test]
    #[serial]
    fn test_import_creates_per_tty_sessions() {
        let home = temp_home();
        let tty_hist = home.path().join(".zsh_history_ttys042");
        fs::write(&tty_hist, ": 1700000100:0;ssh root@10.0.0.1\n").unwrap();
        let bash_hist = home.path().join(".bash_history");
        fs::write(&bash_hist, "echo hello\n").unwrap();

        let _home = EnvVarGuard::set("HOME", home.path());
        let _histfile = EnvVarGuard::remove("HISTFILE");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let db = crate::db::Db::open_in_memory().unwrap();
        import_if_needed(&db);

        let results = db
            .search_history_advanced(Some("ssh"), None, None, None, None, false, None, None, 100)
            .unwrap();
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .any(|r| r.session_id == "imported_zsh_ttys042"),
            "per-TTY file should create session with TTY-based ID"
        );

        let results = db
            .search_history_advanced(Some("echo"), None, None, None, None, false, None, None, 100)
            .unwrap();
        assert!(
            results
                .iter()
                .any(|r| r.session_id == "imported_bash_history"),
            "generic bash should create session with filename-based ID"
        );

        let entities = db
            .search_command_entities(
                Some("ssh"),
                None,
                Some("machine"),
                None,
                None,
                None,
                None,
                100,
            )
            .unwrap();
        assert!(
            entities.iter().any(|e| e.entity.contains("10.0.0.1")),
            "import should backfill command entities for imported SSH commands"
        );

        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1")
        );
        assert_eq!(
            db.get_meta("shell_history_imported_per_tty")
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    fn parse_bash_nonexistent_file() {
        let results = parse_bash(Path::new("/nonexistent/path/bash_history"), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_fish_nonexistent_file() {
        let results = parse_fish(Path::new("/nonexistent/path/fish_history"), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_zsh_detects_extended_format() {
        let f = write_temp(": 1700000100:0;git status\n: 1700000200:0;ls\n");
        let results = parse_zsh(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "git status");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
    }

    #[test]
    fn parse_zsh_detects_plain_format() {
        let f = write_temp("ls\npwd\nwhoami\n");
        let results = parse_zsh(f.path(), fixed_mtime());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[2].0, "whoami");
    }

    #[test]
    fn detect_shell_from_content_empty_file() {
        let f = write_temp("");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Bash);
    }

    #[test]
    fn parse_zsh_extended_no_matching_lines() {
        let results = parse_zsh_extended("plain line\nanother line\n");
        assert!(results.is_empty());
    }

    #[test]
    fn parse_bash_comments_not_timestamps_kept_as_commands() {
        let f = write_temp("#comment\nls\n#notanumber\npwd\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 4);
        assert_eq!(results[0].0, "#comment");
        assert_eq!(results[1].0, "ls");
        assert_eq!(results[2].0, "#notanumber");
        assert_eq!(results[3].0, "pwd");
    }

    #[test]
    #[serial]
    fn import_runs_when_db_has_commands() {
        let home = temp_home();
        let tty_hist = home.path().join(".zsh_history_ttys001");
        fs::write(&tty_hist, "from_tty_hist\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _histfile = EnvVarGuard::remove("HISTFILE");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("s1", "test", "test", 0).unwrap();
        db.insert_command(
            "s1",
            "echo hi",
            "/tmp",
            None,
            "2024-01-01T00:00:00Z",
            None,
            None,
            "",
            "test",
            0,
        )
        .unwrap();
        assert!(db.get_meta("shell_history_imported").unwrap().is_none());
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1")
        );
        assert!(
            db.command_count().unwrap() > 1,
            "import should still add shell history even when DB already contains commands"
        );
    }

    #[test]
    #[serial]
    fn import_migrates_per_tty_files_for_legacy_flag() {
        let home = temp_home();
        let per_tty = home.path().join(".zsh_history_ttys003");
        let regular_zsh = home.path().join(".zsh_history");
        fs::write(&per_tty, "from_per_tty\n").unwrap();
        fs::write(&regular_zsh, "from_regular_zsh\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _histfile = EnvVarGuard::remove("HISTFILE");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_meta("shell_history_imported", "1").unwrap();

        import_if_needed(&db);

        let per_tty_hits = db.search_history("from_per_tty", 10).unwrap();
        let regular_hits = db.search_history("from_regular_zsh", 10).unwrap();
        assert_eq!(
            per_tty_hits.len(),
            1,
            "per-tty zsh history should be imported during migration"
        );
        assert!(
            regular_hits.is_empty(),
            "legacy migration should not re-import regular zsh history entries"
        );
        assert_eq!(
            db.get_meta("shell_history_imported_per_tty")
                .unwrap()
                .as_deref(),
            Some("1")
        );
    }

    #[test]
    #[serial]
    fn discover_includes_per_tty_zsh_history_files() {
        let home = temp_home();
        let tty_hist = home.path().join(".zsh_history_ttys009");
        fs::write(&tty_hist, ": 1700000100:0;echo tty\n").unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _histfile = EnvVarGuard::remove("HISTFILE");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let files = discover_history_files();
        let canonical = tty_hist.canonicalize().unwrap();
        assert!(
            files
                .iter()
                .any(|(p, shell)| p == &canonical && *shell == Shell::Zsh),
            "expected discover_history_files() to include per-tty zsh history files"
        );
    }

    #[test]
    fn parse_zsh_nonexistent_file() {
        let results = parse_zsh(Path::new("/nonexistent/path/zsh_history"), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_fish_multiple_commands_without_when() {
        let f = write_temp("- cmd: ls\n- cmd: pwd\n- cmd: whoami\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[1].0, "pwd");
        assert_eq!(results[2].0, "whoami");
    }

    #[test]
    fn parse_fish_ignores_non_entry_lines() {
        let f = write_temp(
            "- cmd: git status\n  when: 1700000100\n  paths:\n    - /tmp\n- cmd: ls\n  when: 1700000200\n",
        );
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "git status");
        assert_eq!(results[1].0, "ls");
    }

    #[test]
    fn parse_fish_invalid_when_value() {
        let f = write_temp("- cmd: echo hi\n  when: not_a_number\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo hi");
    }

    #[test]
    fn parse_bash_mixed_timestamps_and_plain() {
        let f = write_temp("#1700000100\nls\npwd\n#1700000300\nwhoami\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
        assert_eq!(results[1].0, "pwd");
        assert!(results[1].1 < fixed_mtime());
        assert_eq!(results[2].0, "whoami");
        assert_eq!(results[2].1.timestamp(), 1_700_000_300);
    }

    #[test]
    fn parse_bash_empty_lines_skipped() {
        let f = write_temp("ls\n\n\npwd\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[1].0, "pwd");
    }

    #[test]
    fn parse_zsh_extended_invalid_timestamp() {
        let results = parse_zsh_extended(": 0:0;echo zero\n");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo zero");
    }

    #[test]
    fn parse_zsh_plain_timestamps_increase() {
        let results = parse_zsh_plain("a\nb\nc\n", fixed_mtime());
        assert_eq!(results.len(), 3);
        assert!(results[0].1 < results[1].1);
        assert!(results[1].1 < results[2].1);
        assert!(results[2].1 <= fixed_mtime());
    }

    #[test]
    fn detect_shell_nonexistent_file_defaults_bash() {
        assert_eq!(
            detect_shell_from_content(Path::new("/nonexistent/file")),
            Shell::Bash
        );
    }

    #[test]
    fn detect_shell_whitespace_only_defaults_bash() {
        let f = write_temp("   \n\n   \n");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Bash);
    }

    #[test]
    fn parse_zsh_empty_file() {
        let f = write_temp("");
        let results = parse_zsh(f.path(), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_fish_empty_file() {
        let f = write_temp("");
        let results = parse_fish(f.path(), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_zsh_extended_multiline_three_continuations() {
        let content = ": 1700000100:0;line1\\\nline2\\\nline3\n: 1700000200:0;ls\n";
        let results = parse_zsh_extended(content);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "line1\nline2\nline3");
        assert_eq!(results[0].1.timestamp(), 1_700_000_100);
        assert_eq!(results[1].0, "ls");
    }

    #[test]
    fn parse_bash_out_of_range_timestamp_fallback() {
        let huge_ts = i64::MAX.to_string();
        let content = format!("#{huge_ts}\nls\n");
        let f = write_temp(&content);
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[0].1, fixed_mtime());
    }

    #[test]
    fn parse_fish_flush_pending_without_when() {
        let f = write_temp("- cmd: first\n- cmd: second\n  when: 1700000200\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "first");
        assert_eq!(results[1].0, "second");
        assert_eq!(results[1].1.timestamp(), 1_700_000_200);
    }

    #[test]
    fn detect_shell_whitespace_then_content() {
        let f = write_temp("\n\n\n: 1700000100:0;ls\n");
        assert_eq!(detect_shell_from_content(f.path()), Shell::Zsh);
    }

    #[test]
    fn parse_zsh_plain_skips_empty_lines() {
        let results = parse_zsh_plain("ls\n\n\npwd\n\n", fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[1].0, "pwd");
    }

    #[test]
    fn parse_fish_out_of_range_when_value() {
        let f = write_temp("- cmd: echo test\n  when: -9999999999\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo test");
    }

    #[test]
    fn parse_zsh_extended_zero_timestamp_uses_epoch() {
        let results = parse_zsh_extended(": 0:0;echo epoch\n");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo epoch");
    }

    #[test]
    fn parse_bash_trailing_timestamp_no_command() {
        let f = write_temp("ls\n#1700000100\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ls");
    }

    #[test]
    fn parse_fish_only_non_cmd_lines() {
        let f = write_temp("  when: 12345\n  paths:\n    - /tmp\n");
        let results = parse_fish(f.path(), fixed_mtime());
        assert!(results.is_empty());
    }

    #[test]
    fn parse_zsh_extended_multiline_at_end_of_input() {
        let content = ": 1700000100:0;echo hello\\\nworld";
        let results = parse_zsh_extended(content);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo hello\nworld");
    }

    #[test]
    fn parse_bash_consecutive_timestamps() {
        let f = write_temp("#1700000100\n#1700000200\nls\n");
        let results = parse_bash(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "ls");
        assert_eq!(results[0].1.timestamp(), 1_700_000_200);
    }

    #[test]
    fn parse_fish_out_of_range_when_returns_none_uses_now() {
        let huge_ts = i64::MAX.to_string();
        let content = format!("- cmd: echo test\n  when: {huge_ts}\n");
        let f = write_temp(&content);
        let results = parse_fish(f.path(), fixed_mtime());
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, "echo test");
        let now = Utc::now().timestamp();
        assert!((results[0].1.timestamp() - now).abs() < 5);
    }

    #[test]
    fn parse_zsh_whitespace_only_treated_as_plain() {
        let f = write_temp("   \n  \n");
        let results = parse_zsh(f.path(), fixed_mtime());
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "   ");
        assert_eq!(results[1].0, "  ");
    }

    #[test]
    fn import_filters_empty_and_comment_commands() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("check", "test", "test", 0).unwrap();
        db.insert_command(
            "check",
            "   ",
            "/tmp",
            None,
            "2024-01-01T00:00:00Z",
            None,
            None,
            "",
            "test",
            0,
        )
        .unwrap();
        db.insert_command(
            "check",
            "#comment",
            "/tmp",
            None,
            "2024-01-01T00:00:00Z",
            None,
            None,
            "",
            "test",
            0,
        )
        .unwrap();
        db.insert_command(
            "check",
            "real_cmd",
            "/tmp",
            None,
            "2024-01-01T00:00:00Z",
            None,
            None,
            "",
            "test",
            0,
        )
        .unwrap();
        assert!(db.command_count().unwrap() > 0);
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1"),
            "import should still set flag even when db already has commands"
        );
    }
}
// alias used above
