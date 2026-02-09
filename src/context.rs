use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::db::{CommandWithSummary, ConversationExchange, Db, OtherSessionSummary};

#[derive(Clone)]
struct CachedSystemInfo {
    os_info: String,
    hostname: String,
    machine_info: String,
    timezone_info: String,
    locale_info: String,
    cached_at: Instant,
}

static SYSTEM_INFO_CACHE: LazyLock<Mutex<Option<CachedSystemInfo>>> =
    LazyLock::new(|| Mutex::new(None));

fn get_cached_system_info() -> CachedSystemInfo {
    let mut cache = SYSTEM_INFO_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref cached) = *cache {
        if cached.cached_at.elapsed() < Duration::from_secs(30) {
            return cached.clone();
        }
    }
    let fresh = CachedSystemInfo {
        os_info: detect_os(),
        hostname: detect_hostname(),
        machine_info: detect_machine_info(),
        timezone_info: detect_timezone(),
        locale_info: detect_locale(),
        cached_at: Instant::now(),
    };
    let result = fresh.clone();
    *cache = Some(fresh);
    result
}

pub struct QueryContext {
    pub os_info: String,
    pub shell: String,
    pub cwd: String,
    pub username: String,
    pub conversation_history: Vec<ConversationExchange>,
    pub hostname: String,
    pub machine_info: String,
    pub datetime_info: String,
    pub timezone_info: String,
    pub locale_info: String,
    pub session_history: Vec<CommandWithSummary>,
    pub other_sessions: Vec<OtherSessionSummary>,
    pub scrollback_text: String,
    pub custom_instructions: Option<String>,
    pub project_info: ProjectInfo,
}

pub struct ProjectInfo {
    pub root: Option<String>,
    pub project_type: String,
    pub git_branch: Option<String>,
    pub git_status: Option<String>,
    pub git_commits: Vec<GitCommit>,
    pub files: Vec<FileEntry>,
}

pub struct GitCommit {
    pub hash: String,
    pub message: String,
    pub relative_time: String,
}

pub struct FileEntry {
    pub path: String,
    pub kind: String,
    pub size: String,
}

pub fn build_context(
    db: &Db,
    session_id: &str,
    config: &Config,
) -> anyhow::Result<QueryContext> {
    let sys = get_cached_system_info();

    let shell = std::env::var("SHELL")
        .unwrap_or_else(|_| "bash".into())
        .rsplit('/')
        .next()
        .unwrap_or("bash")
        .to_string();

    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    let conversation_history =
        db.get_conversations(session_id, config.context.history_limit)
            .unwrap_or_default();

    let session_history =
        db.recent_commands_with_summaries(session_id, config.context.history_summaries)
            .unwrap_or_default();

    let other_sessions = if config.context.include_other_tty {
        db.other_sessions_with_summaries(
            session_id,
            config.context.max_other_ttys,
            config.context.other_tty_summaries,
        )
        .unwrap_or_default()
    } else {
        Vec::new()
    };

    let scrollback_text = read_scrollback(session_id, config);
    let project_info = detect_project_info(&cwd, config);

    Ok(QueryContext {
        os_info: sys.os_info,
        shell,
        cwd,
        username,
        conversation_history,
        hostname: sys.hostname,
        machine_info: sys.machine_info,
        datetime_info: chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string(),
        timezone_info: sys.timezone_info,
        locale_info: sys.locale_info,
        session_history,
        other_sessions,
        scrollback_text,
        custom_instructions: config.context.custom_instructions.clone(),
        project_info,
    })
}

pub fn build_xml_context(ctx: &QueryContext, config: &Config) -> String {
    let mut xml = String::from("<context>\n");

    // Environment
    xml.push_str(&format!(
        "  <environment os=\"{}\" shell=\"{}\" cwd=\"{}\" \
         user=\"{}\" hostname=\"{}\" datetime=\"{}\" \
         timezone=\"{}\" locale=\"{}\" \
         machine=\"{}\" />\n",
        xml_escape(&ctx.os_info),
        xml_escape(&ctx.shell),
        xml_escape(&ctx.cwd),
        xml_escape(&ctx.username),
        xml_escape(&ctx.hostname),
        xml_escape(&ctx.datetime_info),
        xml_escape(&ctx.timezone_info),
        xml_escape(&ctx.locale_info),
        xml_escape(&ctx.machine_info),
    ));

    // Custom instructions
    if let Some(ref instructions) = ctx.custom_instructions {
        xml.push_str(&format!(
            "\n  <custom_instructions>\n    {}\n  </custom_instructions>\n",
            xml_escape(instructions),
        ));
    }

    // Project info
    if let Some(ref root) = ctx.project_info.root {
        xml.push_str(&format!(
            "\n  <project root=\"{}\" type=\"{}\">",
            xml_escape(root),
            xml_escape(&ctx.project_info.project_type),
        ));

        if let Some(ref branch) = ctx.project_info.git_branch {
            let status_attr = ctx.project_info.git_status.as_ref()
                .map(|s| format!(" status=\"{}\"", xml_escape(s)))
                .unwrap_or_default();
            xml.push_str(&format!("\n    <git branch=\"{}\"{}>\n", xml_escape(branch), status_attr));
            for commit in &ctx.project_info.git_commits {
                xml.push_str(&format!(
                    "      <commit hash=\"{}\" ts=\"{}\">{}</commit>\n",
                    xml_escape(&commit.hash),
                    xml_escape(&commit.relative_time),
                    xml_escape(&commit.message),
                ));
            }
            xml.push_str("    </git>\n");
        }

        if !ctx.project_info.files.is_empty() {
            xml.push_str(&format!(
                "    <files count=\"{}\">\n",
                ctx.project_info.files.len(),
            ));
            for f in &ctx.project_info.files {
                xml.push_str(&format!(
                    "      <f path=\"{}\" type=\"{}\" size=\"{}\" />\n",
                    xml_escape(&f.path),
                    xml_escape(&f.kind),
                    xml_escape(&f.size),
                ));
            }
            xml.push_str("    </files>\n");
        }

        xml.push_str("  </project>\n");
    }

    // Scrollback
    if !ctx.scrollback_text.is_empty() {
        let redacted = crate::redact::redact_secrets(&ctx.scrollback_text, &config.redaction);
        xml.push_str(&format!(
            "\n  <recent_terminal session=\"current\">\n{}\n  </recent_terminal>\n",
            xml_escape(&redacted),
        ));
    }

    // Session history with summaries
    if !ctx.session_history.is_empty() {
        let tty = std::env::var("NSH_TTY").unwrap_or_default();
        xml.push_str(&format!(
            "\n  <session_history tty=\"{}\" count=\"{}\">\n",
            xml_escape(&tty),
            ctx.session_history.len(),
        ));
        for cmd in &ctx.session_history {
            let duration_attr = cmd.duration_ms
                .map(|d| format!(" duration=\"{}ms\"", d))
                .unwrap_or_default();
            xml.push_str(&format!(
                "    <cmd ts=\"{}\" exit=\"{}\"{} cwd=\"{}\">\n",
                xml_escape(&cmd.started_at),
                cmd.exit_code.unwrap_or(-1),
                duration_attr,
                xml_escape(cmd.cwd.as_deref().unwrap_or("?")),
            ));
            xml.push_str(&format!(
                "      <input>{}</input>\n",
                xml_escape(&cmd.command),
            ));
            if let Some(ref summary) = cmd.summary {
                let redacted = crate::redact::redact_secrets(summary, &config.redaction);
                xml.push_str(&format!(
                    "      <summary>{}</summary>\n",
                    xml_escape(&redacted),
                ));
            }
            xml.push_str("    </cmd>\n");
        }
        xml.push_str("  </session_history>\n");
    }

    // Other sessions
    if !ctx.other_sessions.is_empty() {
        xml.push_str("\n  <other_sessions>\n");
        let mut current_tty = String::new();
        let mut session_open = false;
        for cmd in &ctx.other_sessions {
            if cmd.tty != current_tty {
                if session_open {
                    xml.push_str("    </session>\n");
                }
                xml.push_str(&format!(
                    "    <session tty=\"{}\" shell=\"{}\">\n",
                    xml_escape(&cmd.tty),
                    xml_escape(&cmd.shell),
                ));
                current_tty.clone_from(&cmd.tty);
                session_open = true;
            }
            xml.push_str(&format!(
                "      <cmd ts=\"{}\" exit=\"{}\">\n",
                xml_escape(&cmd.started_at),
                cmd.exit_code.unwrap_or(-1),
            ));
            xml.push_str(&format!(
                "        <input>{}</input>\n",
                xml_escape(&cmd.command),
            ));
            if let Some(ref summary) = cmd.summary {
                let redacted = crate::redact::redact_secrets(summary, &config.redaction);
                xml.push_str(&format!(
                    "        <summary>{}</summary>\n",
                    xml_escape(&redacted),
                ));
            }
            xml.push_str("      </cmd>\n");
        }
        if session_open {
            xml.push_str("    </session>\n");
        }
        xml.push_str("  </other_sessions>\n");
    }

    xml.push_str("</context>");
    xml
}

fn read_scrollback(session_id: &str, config: &Config) -> String {
    let nsh_dir = Config::nsh_dir();
    let daemon_socket = crate::daemon::daemon_socket_path(session_id);

    let max_lines = config.context.scrollback_pages * 24;

    let raw_text = if daemon_socket.exists() {
        let request = crate::daemon::DaemonRequest::Scrollback { max_lines };
        match crate::daemon_client::send_request(session_id, &request) {
            Ok(crate::daemon::DaemonResponse::Ok { data: Some(d) }) => {
                d["scrollback"].as_str().unwrap_or("").to_string()
            }
            _ => read_scrollback_file(session_id, &nsh_dir),
        }
    } else {
        read_scrollback_file(session_id, &nsh_dir)
    };

    if raw_text.is_empty() {
        return String::new();
    }

    let cleaned = crate::ansi::strip(raw_text.as_bytes());
    let lines: Vec<&str> = cleaned.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    lines[start..].join("\n")
}

fn read_scrollback_file(session_id: &str, nsh_dir: &std::path::Path) -> String {
    let file_path = nsh_dir.join(format!("scrollback_{session_id}"));
    if file_path.exists() {
        std::fs::read_to_string(&file_path).unwrap_or_default()
    } else {
        String::new()
    }
}

fn detect_project_info(cwd: &str, config: &Config) -> ProjectInfo {
    let project_type = detect_project_type(cwd);
    let root = if project_type != "unknown" { Some(cwd.to_string()) } else { None };

    let (git_branch, git_status, git_commits) = detect_git_info(cwd, config.context.git_commits);

    let files = if root.is_some() {
        list_project_files(cwd, config.context.project_files_limit)
    } else {
        Vec::new()
    };

    ProjectInfo {
        root,
        project_type,
        git_branch,
        git_status,
        git_commits,
        files,
    }
}

fn detect_project_type(cwd: &str) -> String {
    let path = std::path::Path::new(cwd);
    let mut types = Vec::new();

    if path.join("Cargo.toml").exists() { types.push("Rust/Cargo"); }
    if path.join("package.json").exists() { types.push("Node.js"); }
    if path.join("pyproject.toml").exists() || path.join("setup.py").exists() { types.push("Python"); }
    if path.join("go.mod").exists() { types.push("Go"); }
    if path.join("Makefile").exists() { types.push("Make"); }
    if path.join("Dockerfile").exists() || path.join("docker-compose.yml").exists() { types.push("Docker"); }
    if path.join("Gemfile").exists() { types.push("Ruby"); }
    if path.join("pom.xml").exists() || path.join("build.gradle").exists() { types.push("Java"); }

    if types.is_empty() {
        "unknown".into()
    } else {
        types.join(", ")
    }
}

fn detect_git_info(cwd: &str, max_commits: usize) -> (Option<String>, Option<String>, Vec<GitCommit>) {
    let branch = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());

    if branch.is_none() {
        return (None, None, Vec::new());
    }

    let status = std::process::Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            let lines = String::from_utf8_lossy(&o.stdout);
            let count = lines.lines().count();
            if count == 0 {
                "clean".to_string()
            } else {
                format!("{count} changed files")
            }
        });

    let commits_output = std::process::Command::new("git")
        .args([
            "log", "--oneline", "--no-decorate",
            &format!("-{max_commits}"),
            "--format=%h|%s|%cr",
        ])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|o| o.status.success());

    let commits = commits_output
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|line| {
                    let parts: Vec<&str> = line.splitn(3, '|').collect();
                    if parts.len() == 3 {
                        Some(GitCommit {
                            hash: parts[0].to_string(),
                            message: parts[1].to_string(),
                            relative_time: parts[2].to_string(),
                        })
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    (branch, status, commits)
}

fn list_project_files(cwd: &str, limit: usize) -> Vec<FileEntry> {
    let path = std::path::Path::new(cwd);
    let mut entries = Vec::new();

    if let Ok(dir) = std::fs::read_dir(path) {
        for entry in dir.flatten() {
            if entries.len() >= limit {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') && name != ".github" {
                continue;
            }
            let meta = entry.metadata().ok();
            let kind = if meta.as_ref().is_some_and(|m| m.is_dir()) {
                "dir".to_string()
            } else {
                "file".to_string()
            };
            let size = meta
                .map(|m| format_size(m.len()))
                .unwrap_or_default();
            entries.push(FileEntry { path: name, kind, size });
        }
    }

    entries.sort_by(|a, b| a.path.cmp(&b.path));
    entries
}

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn detect_os() -> String {
    #[cfg(target_os = "macos")]
    {
        let version_str = std::process::Command::new("sw_vers")
            .arg("-productVersion")
            .output()
            .ok()
            .map(|o| {
                String::from_utf8_lossy(&o.stdout).trim().to_string()
            })
            .unwrap_or_default();
        let version = version_str.trim();
        let arch = std::env::consts::ARCH;
        if version.is_empty() {
            "macOS (unknown version)".into()
        } else {
            format!("macOS {} {}", version, arch)
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let pretty = content
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .and_then(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".into());
            let arch = std::env::consts::ARCH;
            format!("{pretty} {arch}")
        } else {
            format!("Linux {}", std::env::consts::ARCH)
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
    }
}

fn detect_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn detect_machine_info() -> String {
    let arch = std::env::consts::ARCH;
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0);

    #[cfg(target_os = "macos")]
    let mem = {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output()
            .ok()
            .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok())
            .map(|b| format!("{:.0}GB RAM", b as f64 / 1_073_741_824.0))
            .unwrap_or_default()
    };

    #[cfg(target_os = "linux")]
    let mem = {
        std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("MemTotal:"))
                    .and_then(|l| l.split_whitespace().nth(1))
                    .and_then(|v| v.parse::<u64>().ok())
                    .map(|kb| format!("{:.0}GB RAM", kb as f64 / 1_048_576.0))
            })
            .unwrap_or_default()
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let mem = String::new();

    let mut parts = vec![arch.to_string()];
    if cpus > 0 { parts.push(format!("{cpus} cores")); }
    if !mem.is_empty() { parts.push(mem); }

    let pkg_mgrs: Vec<&str> = ["brew", "apt", "dnf", "yum", "pacman", "nix", "apk"]
        .iter()
        .filter(|cmd| which_exists(cmd))
        .copied()
        .collect();
    if !pkg_mgrs.is_empty() {
        parts.push(format!("pkg: {}", pkg_mgrs.join(", ")));
    }

    parts.join(", ")
}

fn which_exists(cmd: &str) -> bool {
    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_locale() -> String {
    std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_else(|_| "en_US.UTF-8".into())
}

fn detect_timezone() -> String {
    std::env::var("TZ").unwrap_or_else(|_| {
        std::fs::read_link("/etc/localtime")
            .ok()
            .and_then(|p| {
                let s = p.to_string_lossy().to_string();
                s.find("zoneinfo/").map(|i| s[i + 9..].to_string())
            })
            .unwrap_or_else(|| "unknown".into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_escape() {
        assert_eq!(xml_escape("a < b"), "a &lt; b");
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("a > b"), "a &gt; b");
        assert_eq!(xml_escape("a \"b\""), "a &quot;b&quot;");
        assert_eq!(xml_escape("normal"), "normal");
    }

    #[test]
    fn test_detect_project_type() {
        let tmp = std::env::temp_dir().join("nsh_test_project");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("Cargo.toml"), "").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Rust"));
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500B");
        assert_eq!(format_size(1536), "1.5KB");
        assert_eq!(format_size(1_500_000), "1.4MB");
    }

}
