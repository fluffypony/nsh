use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use regex::Regex;

const MAX_IMPORT_ENTRIES: usize = 10_000;
const SYNTHETIC_SESSION_ID: &str = "imported_shell_history";

#[derive(Debug, Clone, Copy, PartialEq)]
enum Shell {
    Bash,
    Zsh,
    Fish,
}

pub fn import_if_needed(db: &crate::db::Db) {
    let result: anyhow::Result<()> = (|| {
        if db.get_meta("shell_history_imported")?.is_some() {
            return Ok(());
        }

        if db.command_count()? > 0 {
            db.set_meta("shell_history_imported", "1")?;
            return Ok(());
        }

        let files = discover_history_files();
        let mut all_entries: Vec<(String, DateTime<Utc>)> = Vec::new();

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
            };
            all_entries.extend(entries);
        }

        all_entries.sort_by_key(|(_, ts)| *ts);
        let entries: Vec<_> = all_entries
            .into_iter()
            .rev()
            .take(MAX_IMPORT_ENTRIES)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();

        db.create_session(SYNTHETIC_SESSION_ID, "import", "import", 0)?;

        let home_dir_str = dirs::home_dir()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "/".to_string());

        let mut n = 0usize;
        for (cmd, ts) in &entries {
            if cmd.trim().is_empty() || cmd.starts_with('#') {
                continue;
            }
            db.insert_command(
                SYNTHETIC_SESSION_ID,
                cmd,
                &home_dir_str,
                None,
                &ts.to_rfc3339(),
                None,
                None,
                "",
                "import",
                0,
            )?;
            n += 1;
        }

        db.end_session(SYNTHETIC_SESSION_ID)?;
        db.set_meta("shell_history_imported", "1")?;
        tracing::info!("nsh: imported {n} commands from shell history");

        Ok(())
    })();

    if let Err(e) = result {
        tracing::debug!("shell history import skipped: {e}");
    }
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

    let fish_data = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| home.join(".local/share"));
    let fish_hist = fish_data.join("fish").join("fish_history");
    if fish_hist.exists() {
        files.push((fish_hist, Shell::Fish));
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
            let timestamp =
                DateTime::from_timestamp(ts_val, 0).unwrap_or_else(|| Utc::now());
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn fixed_mtime() -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000, 0).unwrap()
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
    }

    #[test]
    fn import_skips_when_already_imported() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.set_meta("shell_history_imported", "1").unwrap();
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
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
    fn import_skips_when_db_has_commands() {
        let db = crate::db::Db::open_in_memory().unwrap();
        db.create_session("s1", "test", "test", 0).unwrap();
        db.insert_command("s1", "echo hi", "/tmp", None, "2024-01-01T00:00:00Z", None, None, "", "test", 0).unwrap();
        assert!(db.get_meta("shell_history_imported").unwrap().is_none());
        import_if_needed(&db);
        assert_eq!(
            db.get_meta("shell_history_imported").unwrap().as_deref(),
            Some("1")
        );
    }
}
