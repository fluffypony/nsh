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
            let file_mtime = DateTime::<Utc>::from(std::fs::metadata(path)?.modified()?);
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

fn discover_history_files() -> Vec<(PathBuf, Shell)> {
    let mut files = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    for path in [
        std::env::var("HISTFILE").ok().map(PathBuf::from),
        Some(home.join(".bash_history")),
    ]
    .into_iter()
    .flatten()
    {
        if path.exists() && !files.iter().any(|(p, _): &(PathBuf, Shell)| p == &path) {
            files.push((path, Shell::Bash));
        }
    }

    for path in [
        std::env::var("HISTFILE").ok().map(PathBuf::from),
        Some(home.join(".zsh_history")),
        Some(home.join(".histfile")),
    ]
    .into_iter()
    .flatten()
    {
        if path.exists() && !files.iter().any(|(p, _): &(PathBuf, Shell)| p == &path) {
            files.push((path, Shell::Zsh));
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

    for (reverse_idx, line) in lines.iter().enumerate().rev() {
        if line.starts_with('#') {
            if let Ok(ts) = line[1..].trim().parse::<i64>() {
                pending_timestamp = Some(ts);
                continue;
            }
        }

        if line.is_empty() {
            continue;
        }

        let timestamp = if let Some(ts) = pending_timestamp.take() {
            DateTime::from_timestamp(ts, 0).unwrap_or(file_mtime)
        } else {
            let remaining = total.saturating_sub(reverse_idx + 1);
            file_mtime - chrono::Duration::seconds(remaining as i64)
        };

        results.push((line.to_string(), timestamp));
    }

    results.reverse();
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
