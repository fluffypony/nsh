use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::daemon_db::DbAccess;
use crate::db::{CommandWithSummary, ConversationExchange, OtherSessionSummary};

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
    pub ssh_context: Option<String>,
    pub container_context: Option<String>,
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
    db: &dyn DbAccess,
    session_id: &str,
    config: &Config,
) -> anyhow::Result<QueryContext> {
    let sys = get_cached_system_info();

    let shell = detect_shell();

    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let conversation_history = db
        .get_conversations(session_id, config.context.history_limit)
        .unwrap_or_default();

    let session_history = db
        .recent_commands_with_summaries(session_id, config.context.history_summaries)
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

    let ssh_context = detect_ssh_context();
    let container_context = detect_container();

    let custom_instructions = gather_custom_instructions(config, &cwd);

    Ok(QueryContext {
        os_info: sys.os_info,
        shell,
        cwd,
        username,
        conversation_history,
        hostname: sys.hostname,
        machine_info: sys.machine_info,
        datetime_info: chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S %Z")
            .to_string(),
        timezone_info: sys.timezone_info,
        locale_info: sys.locale_info,
        session_history,
        other_sessions,
        scrollback_text,
        custom_instructions,
        project_info,
        ssh_context,
        container_context,
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

    // SSH context
    if let Some(ref ssh) = ctx.ssh_context {
        xml.push_str(&format!("  {ssh}\n"));
    }

    // Container context
    if let Some(ref container) = ctx.container_context {
        xml.push_str(&format!("  {container}\n"));
    }

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
            let status_attr = ctx
                .project_info
                .git_status
                .as_ref()
                .map(|s| format!(" status=\"{}\"", xml_escape(s)))
                .unwrap_or_default();
            xml.push_str(&format!(
                "\n    <git branch=\"{}\"{}>\n",
                xml_escape(branch),
                status_attr
            ));
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
            let duration_attr = cmd
                .duration_ms
                .map(|d| format!(" duration=\"{d}ms\""))
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
                xml_escape(&crate::redact::redact_secrets(
                    &cmd.command,
                    &config.redaction
                )),
            ));
            if let Some(ref output) = cmd.output {
                if !output.trim().is_empty() {
                    let truncated = crate::util::truncate(output, config.context.max_output_context_chars);
                    let redacted = crate::redact::redact_secrets(&truncated, &config.redaction);
                    xml.push_str(&format!(
                        "      <output>{}</output>\n",
                        xml_escape(&redacted),
                    ));
                }
            }
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
                xml_escape(&crate::redact::redact_secrets(
                    &cmd.command,
                    &config.redaction
                )),
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

    #[cfg(unix)]
    let daemon_available = daemon_socket.exists();
    #[cfg(not(unix))]
    let daemon_available = false;

    let raw_text = if daemon_available {
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

fn find_git_root(cwd: &str) -> Option<std::path::PathBuf> {
    let mut dir = std::path::PathBuf::from(cwd);
    loop {
        if dir.join(".git").exists() {
            return Some(dir);
        }
        if !dir.pop() {
            return None;
        }
    }
}

fn gather_custom_instructions(config: &Config, cwd: &str) -> Option<String> {
    let global = config.context.custom_instructions.clone();

    let project_instructions = find_git_root(cwd).and_then(|root| {
        let path = root.join(".nsh").join("instructions.md");
        if path.exists() {
            std::fs::read_to_string(&path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        } else {
            None
        }
    });

    match (global, project_instructions) {
        (Some(g), Some(p)) => Some(format!(
            "{g}\n\n--- Project-specific instructions ---\n\n{p}"
        )),
        (Some(g), None) => Some(g),
        (None, Some(p)) => Some(p),
        (None, None) => None,
    }
}

fn detect_project_info(cwd: &str, config: &Config) -> ProjectInfo {
    let project_type = detect_project_type(cwd);

    let project_root = if project_type != "unknown" {
        find_project_root(cwd)
    } else {
        None
    };

    let root = project_root
        .as_ref()
        .map(|p| p.to_string_lossy().to_string());

    let (git_branch, git_status, git_commits) = detect_git_info(cwd, config.context.git_commits);

    let files = if let Some(ref root_path) = project_root {
        let root_str = root_path.to_string_lossy();
        list_project_files(&root_str, config.context.project_files_limit)
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

fn find_project_root(cwd: &str) -> Option<std::path::PathBuf> {
    let git_root = run_git_with_timeout(&["rev-parse", "--show-toplevel"], cwd);
    if let Some(root) = git_root {
        return Some(std::path::PathBuf::from(root));
    }
    Some(std::path::PathBuf::from(cwd))
}

fn detect_project_type(cwd: &str) -> String {
    let mut types = Vec::new();
    let mut dir = std::path::PathBuf::from(cwd);

    loop {
        check_project_markers(&dir, &mut types);
        if dir.join(".git").exists() {
            break;
        }
        if !dir.pop() {
            break;
        }
    }

    types.dedup();
    if types.is_empty() {
        "unknown".into()
    } else {
        types.join(", ")
    }
}

fn check_project_markers(dir: &std::path::Path, types: &mut Vec<&'static str>) {
    if dir.join("Cargo.toml").exists() {
        types.push("Rust/Cargo");
    }
    if dir.join("package.json").exists() {
        types.push("Node.js");
    }
    if dir.join("pyproject.toml").exists() || dir.join("setup.py").exists() {
        types.push("Python");
    }
    if dir.join("go.mod").exists() {
        types.push("Go");
    }
    if dir.join("Makefile").exists() {
        types.push("Make");
    }
    if dir.join("Dockerfile").exists()
        || dir.join("docker-compose.yml").exists()
        || dir.join("compose.yml").exists()
    {
        types.push("Docker");
    }
    if dir.join("Gemfile").exists() {
        types.push("Ruby");
    }
    if dir.join("pom.xml").exists()
        || dir.join("build.gradle").exists()
        || dir.join("build.gradle.kts").exists()
    {
        types.push("Java");
    }
    if dir.join("CMakeLists.txt").exists() {
        types.push("C/C++ (CMake)");
    }
    if dir.join("flake.nix").exists() || dir.join("shell.nix").exists() {
        types.push("Nix");
    }
}

fn run_git_with_timeout(args: &[&str], cwd: &str) -> Option<String> {
    let mut child = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let timeout = Duration::from_secs(2);
    let args_display = args.join(" ");
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_status)) => {
                let output = child.wait_with_output().ok()?;
                if !output.status.success() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    tracing::warn!("git command timed out: git {args_display}");
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return None,
        }
    }
}

fn detect_git_info(
    cwd: &str,
    max_commits: usize,
) -> (Option<String>, Option<String>, Vec<GitCommit>) {
    // Check if we're inside a git work tree
    let check = run_git_with_timeout(&["rev-parse", "--is-inside-work-tree"], cwd);
    if check.as_deref() != Some("true") {
        return (None, None, Vec::new());
    }

    let branch = run_git_with_timeout(&["rev-parse", "--abbrev-ref", "HEAD"], cwd);
    if branch.is_none() {
        return (None, None, Vec::new());
    }

    let status = run_git_with_timeout(&["status", "--porcelain"], cwd).map(|output| {
        let count = output.lines().count();
        if count == 0 {
            "clean".to_string()
        } else {
            format!("{count} changed files")
        }
    });

    let limit_arg = format!("-{max_commits}");
    let commits = run_git_with_timeout(
        &[
            "log",
            "--oneline",
            "--no-decorate",
            &limit_arg,
            "--format=%h|%s|%cr",
        ],
        cwd,
    )
    .map(|output| {
        output
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

    // Try using ignore crate for .gitignore-aware walking
    if let Some(entries) = list_project_files_with_ignore(path, limit) {
        return entries;
    }

    // Fallback: manual BFS with hardcoded skip list
    list_project_files_fallback(path, limit)
}

fn list_project_files_with_ignore(
    cwd: &std::path::Path,
    max_files: usize,
) -> Option<Vec<FileEntry>> {
    use ignore::WalkBuilder;

    let walker = WalkBuilder::new(cwd)
        .max_depth(Some(5))
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .sort_by_file_name(|a, b| a.cmp(b))
        .build();

    let mut entries = Vec::new();
    let mut had_errors = false;
    for result in walker {
        if entries.len() >= max_files {
            break;
        }
        let entry = match result {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!("file walk error: {e}");
                had_errors = true;
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let rel = entry.path().strip_prefix(cwd).unwrap_or(entry.path());
        let ft = entry.file_type();
        let is_dir = ft.as_ref().is_some_and(|ft| ft.is_dir());
        let is_symlink = ft.as_ref().is_some_and(|ft| ft.is_symlink());
        let kind = if is_symlink {
            "symlink"
        } else if is_dir {
            "dir"
        } else {
            "file"
        };
        let size = if is_dir || is_symlink {
            String::new()
        } else {
            entry
                .metadata()
                .map(|m| format_size(m.len()))
                .unwrap_or_default()
        };
        entries.push(FileEntry {
            path: rel.to_string_lossy().to_string(),
            kind: kind.into(),
            size,
        });
    }

    if entries.is_empty() && had_errors {
        return None;
    }

    Some(entries)
}

fn list_project_files_fallback(cwd: &std::path::Path, max_files: usize) -> Vec<FileEntry> {
    const SKIP_DIRS: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        ".next",
        ".cache",
        "vendor",
    ];

    let mut entries = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back((cwd.to_path_buf(), 0_usize));

    while let Some((dir, depth)) = queue.pop_front() {
        if depth > 5 || entries.len() >= max_files {
            break;
        }
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut children: Vec<_> = read_dir.flatten().collect();
        children.sort_by_key(|e| e.file_name());

        for entry in children {
            if entries.len() >= max_files {
                break;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            let meta = match entry.path().symlink_metadata() {
                Ok(m) => m,
                Err(_) => continue,
            };
            let is_symlink = meta.file_type().is_symlink();
            let is_dir = meta.file_type().is_dir();

            if is_dir && SKIP_DIRS.contains(&name.as_str()) {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(cwd)
                .unwrap_or(&entry.path())
                .to_path_buf();
            let kind = if is_symlink {
                "symlink"
            } else if is_dir {
                "dir"
            } else {
                "file"
            };
            let size = if is_dir || is_symlink {
                String::new()
            } else {
                format_size(meta.len())
            };
            entries.push(FileEntry {
                path: rel.to_string_lossy().to_string(),
                kind: kind.into(),
                size,
            });

            if is_dir && !is_symlink {
                queue.push_back((entry.path(), depth + 1));
            }
        }
    }

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
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        let version = version_str.trim();
        let arch = std::env::consts::ARCH;
        if version.is_empty() {
            "macOS (unknown version)".into()
        } else {
            format!("macOS {version} {arch}")
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let mut pretty = content
                .lines()
                .find(|l| l.starts_with("PRETTY_NAME="))
                .and_then(|l| l.strip_prefix("PRETTY_NAME="))
                .map(|v| v.trim_matches('"').to_string())
                .unwrap_or_else(|| "Linux".into());
            if let Ok(version) = std::fs::read_to_string("/proc/version") {
                let lower = version.to_lowercase();
                if lower.contains("microsoft") || lower.contains("wsl") {
                    pretty.push_str(" (WSL)");
                }
            }
            if std::env::var("MSYSTEM").is_ok() {
                pretty.push_str(" (MSYS2)");
            }
            let arch = std::env::consts::ARCH;
            format!("{pretty} {arch}")
        } else {
            format!("Linux {}", std::env::consts::ARCH)
        }
    }
    #[cfg(target_os = "windows")]
    {
        let arch = std::env::consts::ARCH;
        let version = std::process::Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "Windows".to_string());
        format!("{version} {arch}")
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        format!("{} {}", std::env::consts::OS, std::env::consts::ARCH)
    }
}

fn detect_shell() -> String {
    #[cfg(windows)]
    {
        if let Ok(comspec) = std::env::var("COMSPEC") {
            let lower = comspec.to_lowercase();
            if lower.contains("powershell") || lower.contains("pwsh") {
                return "pwsh".into();
            }
            if lower.contains("cmd") {
                return "cmd".into();
            }
        }
        if which_exists("pwsh") {
            return "pwsh".into();
        }
        if which_exists("powershell") {
            return "powershell".into();
        }
        return "cmd".into();
    }

    std::env::var("SHELL")
        .unwrap_or_else(|_| "bash".into())
        .rsplit('/')
        .next()
        .unwrap_or("bash")
        .to_string()
}

fn detect_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| {
            std::env::var("COMPUTERNAME")
                .or_else(|_| std::env::var("HOSTNAME"))
                .unwrap_or_else(|_| "unknown".into())
        })
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
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
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

    #[cfg(target_os = "windows")]
    let mem = {
        std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB)",
            ])
            .output()
            .ok()
            .and_then(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .parse::<u64>()
                    .ok()
            })
            .map(|gb| format!("{gb}GB RAM"))
            .unwrap_or_default()
    };

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let mem = String::new();

    let mut parts = vec![arch.to_string()];
    if cpus > 0 {
        parts.push(format!("{cpus} cores"));
    }
    if !mem.is_empty() {
        parts.push(mem);
    }

    #[cfg(target_os = "windows")]
    let pkg_mgr_candidates: &[&str] = &["winget", "choco", "scoop"];
    #[cfg(not(target_os = "windows"))]
    let pkg_mgr_candidates: &[&str] = &["brew", "apt", "dnf", "yum", "pacman", "nix", "apk"];

    let pkg_mgrs: Vec<&str> = pkg_mgr_candidates
        .iter()
        .filter(|cmd| which_exists(cmd))
        .copied()
        .collect();
    if !pkg_mgrs.is_empty() {
        parts.push(format!("pkg: {}", pkg_mgrs.join(", ")));
    }

    let lang_pkg_mgrs: Vec<&str> = [
        "npm", "npx", "yarn", "pnpm", "bun", "deno", "pip3", "pipx", "uv", "cargo", "rustup",
        "gem", "go", "composer", "dotnet",
    ]
    .iter()
    .filter(|cmd| which_exists(cmd))
    .copied()
    .collect();
    if !lang_pkg_mgrs.is_empty() {
        parts.push(format!("lang_pkg: {}", lang_pkg_mgrs.join(", ")));
    }

    #[cfg(target_os = "windows")]
    let dev_tool_candidates: &[&str] = &["node", "python", "rustc", "pwsh", "wsl"];
    #[cfg(not(target_os = "windows"))]
    let dev_tool_candidates: &[&str] = &["node", "python3", "rustc", "ruby", "java"];

    let dev_tools: Vec<&str> = dev_tool_candidates
        .iter()
        .filter(|cmd| which_exists(cmd))
        .copied()
        .collect();
    if !dev_tools.is_empty() {
        parts.push(format!("tools: {}", dev_tools.join(", ")));
    }

    parts.join(", ")
}

fn which_exists(cmd: &str) -> bool {
    #[cfg(windows)]
    {
        return std::process::Command::new("where.exe")
            .arg(cmd)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    }

    std::process::Command::new("which")
        .arg(cmd)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn detect_locale() -> String {
    #[cfg(windows)]
    {
        if let Ok(output) = std::process::Command::new("powershell")
            .args(["-NoProfile", "-Command", "(Get-Culture).Name"])
            .output()
        {
            let locale = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !locale.is_empty() {
                return locale;
            }
        }
    }
    std::env::var("LC_ALL")
        .or_else(|_| std::env::var("LANG"))
        .unwrap_or_else(|_| "en_US.UTF-8".into())
}

fn detect_ssh_context() -> Option<String> {
    let ssh_client = std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .ok()?;
    let parts: Vec<&str> = ssh_client.split_whitespace().collect();
    let remote_ip = parts.first().unwrap_or(&"unknown");
    Some(format!("<ssh remote_ip=\"{}\" />", xml_escape(remote_ip)))
}

fn detect_container() -> Option<String> {
    #[cfg(not(unix))]
    {
        return None;
    }

    if std::path::Path::new("/.dockerenv").exists() {
        return Some("<container type=\"docker\" />".into());
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
        if cgroup.contains("docker") || cgroup.contains("containerd") {
            return Some("<container type=\"docker\" />".into());
        }
    }
    None
}

fn detect_timezone() -> String {
    #[cfg(windows)]
    {
        if let Ok(tz) = std::env::var("TZ") {
            if !tz.is_empty() {
                return tz;
            }
        }
        if let Ok(output) = std::process::Command::new("tzutil").arg("/g").output() {
            let tz = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !tz.is_empty() {
                return tz;
            }
        }
        return "unknown".into();
    }

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

    #[test]
    fn test_format_size_edge_cases() {
        assert_eq!(format_size(0), "0B");
        assert_eq!(format_size(1023), "1023B");
        assert_eq!(format_size(1024), "1.0KB");
        assert_eq!(format_size(1024 * 1024), "1.0MB");
        assert_eq!(format_size(1024 * 1024 * 10), "10.0MB");
    }

    #[test]
    fn test_xml_escape_empty() {
        assert_eq!(xml_escape(""), "");
    }

    #[test]
    fn test_xml_escape_all_special() {
        assert_eq!(xml_escape("&<>\""), "&amp;&lt;&gt;&quot;");
    }

    #[test]
    fn test_xml_escape_mixed() {
        assert_eq!(
            xml_escape("a & b < c > d \"e\""),
            "a &amp; b &lt; c &gt; d &quot;e&quot;"
        );
    }

    #[test]
    fn test_detect_locale() {
        let locale = detect_locale();
        assert!(!locale.is_empty());
    }

    #[test]
    fn test_detect_project_type_node() {
        let tmp = std::env::temp_dir().join("nsh_test_project_node");
        let _ = std::fs::create_dir_all(&tmp);
        let _ = std::fs::remove_file(tmp.join("Cargo.toml"));
        std::fs::write(tmp.join("package.json"), "{}").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Node"), "expected Node.js, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_python() {
        let tmp = std::env::temp_dir().join("nsh_test_project_python");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("pyproject.toml"), "").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Python"), "expected Python, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_go() {
        let tmp = std::env::temp_dir().join("nsh_test_project_go");
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("go.mod"), "").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Go"), "expected Go, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_unknown() {
        let tmp = std::env::temp_dir().join("nsh_test_project_unknown");
        let _ = std::fs::create_dir_all(&tmp);
        let t = detect_project_type(tmp.to_str().unwrap());
        assert_eq!(t, "unknown");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    fn make_minimal_ctx() -> QueryContext {
        QueryContext {
            os_info: "macOS 15.0".into(),
            shell: "zsh".into(),
            cwd: "/tmp".into(),
            username: "testuser".into(),
            conversation_history: vec![],
            hostname: "testhost".into(),
            machine_info: "arm64".into(),
            datetime_info: "2025-01-01 00:00:00 UTC".into(),
            timezone_info: "UTC".into(),
            locale_info: "en_US.UTF-8".into(),
            session_history: vec![],
            other_sessions: vec![],
            scrollback_text: String::new(),
            custom_instructions: None,
            project_info: ProjectInfo {
                root: None,
                project_type: "unknown".into(),
                git_branch: None,
                git_status: None,
                git_commits: vec![],
                files: vec![],
            },
            ssh_context: None,
            container_context: None,
        }
    }

    #[test]
    fn test_build_xml_context_minimal() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>"));
        assert!(xml.ends_with("</context>"));
        assert!(xml.contains("os=\"macOS 15.0\""));
        assert!(xml.contains("shell=\"zsh\""));
        assert!(xml.contains("cwd=\"/tmp\""));
        assert!(xml.contains("user=\"testuser\""));
        assert!(xml.contains("hostname=\"testhost\""));
        assert!(xml.contains("machine=\"arm64\""));
    }

    #[test]
    fn test_build_xml_context_environment_info() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<environment"));
        assert!(xml.contains("datetime=\"2025-01-01 00:00:00 UTC\""));
        assert!(xml.contains("timezone=\"UTC\""));
        assert!(xml.contains("locale=\"en_US.UTF-8\""));
    }

    #[test]
    fn test_build_xml_context_with_project_info() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/home/user/myproject".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("main".into()),
            git_status: Some("clean".into()),
            git_commits: vec![GitCommit {
                hash: "abc123".into(),
                message: "initial commit".into(),
                relative_time: "2 hours ago".into(),
            }],
            files: vec![FileEntry {
                path: "src/main.rs".into(),
                kind: "file".into(),
                size: "1.5KB".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<project root=\"/home/user/myproject\" type=\"Rust/Cargo\">"));
        assert!(xml.contains("branch=\"main\""));
        assert!(xml.contains("status=\"clean\""));
        assert!(xml.contains("hash=\"abc123\""));
        assert!(xml.contains("initial commit"));
        assert!(xml.contains("<files count=\"1\">"));
        assert!(xml.contains("path=\"src/main.rs\""));
    }

    #[test]
    fn test_build_xml_context_with_scrollback() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "$ ls\nfile1.txt  file2.txt".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<recent_terminal session=\"current\">"));
        assert!(xml.contains("file1.txt"));
    }

    #[test]
    fn test_build_xml_context_with_session_history() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "ls -la".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: Some(50),
            summary: Some("listed files".into()),
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<session_history"));
        assert!(xml.contains("<input>ls -la</input>"));
        assert!(xml.contains("<summary>listed files</summary>"));
    }

    #[test]
    fn test_build_xml_context_with_ssh_context() {
        let mut ctx = make_minimal_ctx();
        ctx.ssh_context = Some("<ssh remote_ip=\"192.168.1.1\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<ssh remote_ip=\"192.168.1.1\" />"));
    }

    #[test]
    fn test_build_xml_context_with_container_context() {
        let mut ctx = make_minimal_ctx();
        ctx.container_context = Some("<container type=\"docker\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<container type=\"docker\" />"));
    }

    #[test]
    fn test_build_xml_context_with_custom_instructions() {
        let mut ctx = make_minimal_ctx();
        ctx.custom_instructions = Some("Always use tabs for indentation.".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<custom_instructions>"));
        assert!(xml.contains("Always use tabs for indentation."));
        assert!(xml.contains("</custom_instructions>"));
    }

    #[test]
    fn test_build_xml_context_with_other_sessions() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "cargo build".into(),
            cwd: Some("/projects/foo".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:05:00Z".into(),
            summary: Some("compiled successfully".into()),
            tty: "/dev/ttys002".into(),
            shell: "zsh".into(),
            session_id: "other-session-1".into(),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<other_sessions>"));
        assert!(xml.contains("<session tty=\"/dev/ttys002\" shell=\"zsh\">"));
        assert!(xml.contains("<input>cargo build</input>"));
        assert!(xml.contains("<summary>compiled successfully</summary>"));
    }

    #[test]
    fn test_detect_os_non_empty() {
        let os = detect_os();
        assert!(!os.is_empty());
    }

    #[test]
    fn test_detect_hostname_non_empty() {
        let hostname = detect_hostname();
        assert!(!hostname.is_empty());
    }

    #[test]
    fn test_detect_machine_info_contains_arch() {
        let info = detect_machine_info();
        assert!(
            info.contains(std::env::consts::ARCH),
            "expected arch in machine info, got: {info}"
        );
    }

    #[test]
    fn test_which_exists_ls() {
        assert!(which_exists("ls"));
    }

    #[test]
    fn test_which_exists_nonexistent() {
        assert!(!which_exists("nonexistent_cmd_xyz"));
    }

    #[test]
    fn test_detect_locale_non_empty() {
        let locale = detect_locale();
        assert!(!locale.is_empty());
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_ssh_context_without_env() {
        unsafe {
            std::env::remove_var("SSH_CLIENT");
            std::env::remove_var("SSH_CONNECTION");
        }
        assert!(detect_ssh_context().is_none());
    }

    #[test]
    fn test_detect_container_on_non_container() {
        let result = detect_container();
        if !std::path::Path::new("/.dockerenv").exists() {
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_detect_timezone_non_empty() {
        let tz = detect_timezone();
        assert!(!tz.is_empty());
    }

    #[test]
    fn test_detect_project_type_multiple() {
        let tmp = std::env::temp_dir().join("nsh_test_project_multi");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("Cargo.toml"), "").unwrap();
        std::fs::write(tmp.join("package.json"), "{}").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Rust"), "expected Rust, got: {t}");
        assert!(t.contains("Node"), "expected Node.js, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_dockerfile() {
        let tmp = std::env::temp_dir().join("nsh_test_project_docker");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("Dockerfile"), "FROM alpine").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Docker"), "expected Docker, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_makefile() {
        let tmp = std::env::temp_dir().join("nsh_test_project_make");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("Makefile"), "all:").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Make"), "expected Make, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_java() {
        let tmp = std::env::temp_dir().join("nsh_test_project_java");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("pom.xml"), "<project/>").unwrap();
        let t = detect_project_type(tmp.to_str().unwrap());
        assert!(t.contains("Java"), "expected Java, got: {t}");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_detect_project_type_nonexistent_dir() {
        let t = detect_project_type("/tmp/nsh_nonexistent_dir_xyz_999");
        assert_eq!(t, "unknown");
    }

    #[test]
    fn test_gather_custom_instructions_none() {
        let config = Config::default();
        let tmp = std::env::temp_dir().join("nsh_test_no_instructions");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        let result = gather_custom_instructions(&config, tmp.to_str().unwrap());
        if config.context.custom_instructions.is_none() {
            assert!(result.is_none());
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_read_scrollback_file_missing() {
        let nsh_dir = std::env::temp_dir().join("nsh_test_scrollback_missing");
        let _ = std::fs::create_dir_all(&nsh_dir);
        let result = read_scrollback_file("nonexistent_session_xyz", &nsh_dir);
        assert!(result.is_empty());
        let _ = std::fs::remove_dir_all(&nsh_dir);
    }

    #[test]
    fn test_build_xml_context_with_conversation_history() {
        let mut ctx = make_minimal_ctx();
        ctx.conversation_history = vec![ConversationExchange {
            query: "how do I list files".into(),
            response_type: "command".into(),
            response: "ls -la".into(),
            explanation: Some("List all files".into()),
            result_exit_code: None,
            result_output_snippet: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>"));
        assert!(xml.ends_with("</context>"));
        assert_eq!(ctx.conversation_history.len(), 1);
        assert_eq!(ctx.conversation_history[0].query, "how do I list files");
        assert_eq!(ctx.conversation_history[0].response, "ls -la");
    }

    #[test]
    fn test_list_project_files_with_temp_dir() {
        let tmp = std::env::temp_dir().join("nsh_test_list_files");
        let _ = std::fs::remove_dir_all(&tmp);
        let _ = std::fs::create_dir_all(&tmp);
        std::fs::write(tmp.join("hello.txt"), "world").unwrap();
        std::fs::write(tmp.join("foo.rs"), "fn main() {}").unwrap();
        let _ = std::fs::create_dir_all(tmp.join("subdir"));
        std::fs::write(tmp.join("subdir").join("bar.txt"), "baz").unwrap();
        let entries = list_project_files(tmp.to_str().unwrap(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"hello.txt"), "missing hello.txt: {paths:?}");
        assert!(paths.contains(&"foo.rs"), "missing foo.rs: {paths:?}");
        let hello = entries.iter().find(|e| e.path == "hello.txt").unwrap();
        assert_eq!(hello.kind, "file");
        assert!(!hello.size.is_empty());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_get_cached_system_info_returns_valid_data() {
        let info = get_cached_system_info();
        assert!(!info.os_info.is_empty());
        assert!(!info.hostname.is_empty());
        assert!(!info.machine_info.is_empty());
        assert!(!info.timezone_info.is_empty());
        assert!(!info.locale_info.is_empty());
    }

    #[test]
    fn test_get_cached_system_info_caching() {
        let info1 = get_cached_system_info();
        let info2 = get_cached_system_info();
        assert_eq!(info1.os_info, info2.os_info);
        assert_eq!(info1.hostname, info2.hostname);
        assert_eq!(info1.machine_info, info2.machine_info);
    }

    #[test]
    fn test_build_xml_context_with_git_commits_and_files() {
        let config = crate::config::Config::default();
        let ctx = QueryContext {
            os_info: "macOS".into(),
            shell: "zsh".into(),
            cwd: "/tmp".into(),
            username: "test".into(),
            conversation_history: vec![],
            hostname: "test".into(),
            machine_info: "arm64".into(),
            datetime_info: "2025-01-01".into(),
            timezone_info: "UTC".into(),
            locale_info: "en_US.UTF-8".into(),
            session_history: vec![],
            other_sessions: vec![],
            scrollback_text: String::new(),
            custom_instructions: None,
            project_info: ProjectInfo {
                root: Some("/project".into()),
                project_type: "Rust".into(),
                git_branch: Some("main".into()),
                git_status: Some("3 files changed".into()),
                git_commits: vec![GitCommit {
                    hash: "abc123".into(),
                    message: "Initial commit".into(),
                    relative_time: "2 hours ago".into(),
                }],
                files: vec![FileEntry {
                    path: "src/main.rs".into(),
                    kind: "file".into(),
                    size: "1.5KB".into(),
                }],
            },
            ssh_context: None,
            container_context: None,
        };
        let xml = build_xml_context(&ctx, &config);
        assert!(xml.contains("branch=\"main\""));
        assert!(xml.contains("status=\"3 files changed\""));
        assert!(xml.contains("abc123"));
        assert!(xml.contains("Initial commit"));
        assert!(xml.contains("src/main.rs"));
    }

    #[test]
    fn test_list_project_files_with_tempdir() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file1.txt"), "content").unwrap();
        std::fs::write(tmp.path().join("file2.rs"), "fn main() {}").unwrap();
        let subdir = tmp.path().join("subdir");
        std::fs::create_dir(&subdir).unwrap();
        std::fs::write(subdir.join("nested.txt"), "nested").unwrap();
        let entries = list_project_files(tmp.path().to_str().unwrap(), 100);
        assert!(entries.len() >= 3);
    }

    #[test]
    fn test_list_project_files_fallback_skips_git_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("file1.txt"), "content").unwrap();
        let git_dir = tmp.path().join(".git");
        std::fs::create_dir(&git_dir).unwrap();
        std::fs::write(git_dir.join("config"), "git config").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains(".git")),
            "fallback should skip .git dir: {paths:?}"
        );
        assert!(
            paths.contains(&"file1.txt"),
            "should still list regular files: {paths:?}"
        );
    }

    #[test]
    fn test_list_project_files_respects_limit() {
        let tmp = tempfile::TempDir::new().unwrap();
        for i in 0..20 {
            std::fs::write(tmp.path().join(format!("file{i}.txt")), "x").unwrap();
        }
        let entries = list_project_files(tmp.path().to_str().unwrap(), 5);
        assert!(entries.len() <= 5);
    }

    #[test]
    fn test_gather_custom_instructions_with_config() {
        let mut config = crate::config::Config::default();
        config.context.custom_instructions = Some("Always use sudo".into());
        let instructions = gather_custom_instructions(&config, "/tmp");
        assert!(instructions.is_some());
        assert!(instructions.unwrap().contains("Always use sudo"));
    }

    #[test]
    fn test_detect_project_type_cmake() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("CMakeLists.txt"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("C") || t.contains("CMake") || t.contains("cmake"));
    }

    // --- XML escape ---

    #[test]
    fn test_xml_escape_all_special_chars() {
        assert_eq!(xml_escape("a & b"), "a &amp; b");
        assert_eq!(xml_escape("<tag>"), "&lt;tag&gt;");
        assert_eq!(xml_escape("say \"hello\""), "say &quot;hello&quot;");
        assert_eq!(xml_escape("no specials"), "no specials");
        assert_eq!(xml_escape(""), "");
        assert_eq!(
            xml_escape("a < b & c > d \"e\""),
            "a &lt; b &amp; c &gt; d &quot;e&quot;"
        );
    }

    // --- build_xml_context: scrollback closing tag ---

    #[test]
    fn test_build_xml_scrollback_closing_tag() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "$ ls\nfoo.rs  bar.rs\n".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("</recent_terminal>"));
    }

    // --- build_xml_context: custom_instructions escapes special chars ---

    #[test]
    fn test_build_xml_custom_instructions_escaping() {
        let mut ctx = make_minimal_ctx();
        ctx.custom_instructions = Some("Use <brackets> & \"quotes\"".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<custom_instructions>"));
        assert!(xml.contains("&lt;brackets&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;quotes&quot;"));
    }

    // --- build_xml_context: ssh + container combined ---

    #[test]
    fn test_build_xml_ssh_and_container_combined() {
        let mut ctx = make_minimal_ctx();
        ctx.ssh_context = Some("<ssh client=\"10.0.0.1\" />".into());
        ctx.container_context = Some("<container runtime=\"podman\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<ssh client=\"10.0.0.1\" />"));
        assert!(xml.contains("<container runtime=\"podman\" />"));
    }

    // --- build_xml_context: session_history with multiple entries, duration/cwd edge cases ---

    #[test]
    fn test_build_xml_session_history_edge_cases() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![
            CommandWithSummary {
                command: "cargo build".into(),
                cwd: Some("/project".into()),
                exit_code: Some(0),
                started_at: "2025-01-01T00:00:00Z".into(),
                duration_ms: Some(1234),
                summary: Some("Compiled successfully".into()),
                output: None,
            },
            CommandWithSummary {
                command: "cargo test".into(),
                cwd: None,
                exit_code: Some(1),
                started_at: "2025-01-01T00:01:00Z".into(),
                duration_ms: None,
                summary: None,
                output: None,
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"2\""));
        assert!(xml.contains("duration=\"1234ms\""));
        assert!(xml.contains("cwd=\"/project\""));
        assert!(xml.contains("<summary>Compiled successfully</summary>"));
        assert!(xml.contains("<input>cargo test</input>"));
        assert!(xml.contains("exit=\"1\""));
        assert!(xml.contains("cwd=\"?\""));
        let second_cmd_section = xml.split("<input>cargo test</input>").next().unwrap();
        assert!(
            !second_cmd_section.ends_with("duration="),
            "no duration attr when None"
        );
    }

    // --- build_xml_context: other_sessions with multiple TTYs and session grouping ---

    #[test]
    fn test_build_xml_other_sessions_multi_tty_grouping() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![
            OtherSessionSummary {
                command: "vim foo.rs".into(),
                cwd: Some("/home/user".into()),
                exit_code: Some(0),
                started_at: "2025-01-01T00:00:00Z".into(),
                summary: Some("Edited file".into()),
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "sess1".into(),
            },
            OtherSessionSummary {
                command: "make".into(),
                cwd: Some("/home/user".into()),
                exit_code: Some(2),
                started_at: "2025-01-01T00:02:00Z".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "sess1".into(),
            },
            OtherSessionSummary {
                command: "python app.py".into(),
                cwd: None,
                exit_code: None,
                started_at: "2025-01-01T00:03:00Z".into(),
                summary: Some("Started server".into()),
                tty: "/dev/ttys002".into(),
                shell: "zsh".into(),
                session_id: "sess2".into(),
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<other_sessions>"));
        assert!(xml.contains("<input>vim foo.rs</input>"));
        assert!(xml.contains("<summary>Edited file</summary>"));
        assert!(xml.contains("<input>make</input>"));
        assert!(xml.contains("exit=\"2\""));
        assert!(xml.contains("tty=\"/dev/ttys002\""));
        assert!(xml.contains("shell=\"zsh\""));
        assert!(xml.contains("<input>python app.py</input>"));
        assert!(xml.contains("<summary>Started server</summary>"));
        assert!(xml.contains("</other_sessions>"));
        let ttys001_count = xml.matches("tty=\"/dev/ttys001\"").count();
        assert_eq!(
            ttys001_count, 1,
            "should group commands under same tty session"
        );
        let session_tags = xml.matches("<session tty=").count();
        assert_eq!(session_tags, 2, "should have 2 session elements for 2 TTYs");
    }

    // --- check_project_markers for more project types ---

    #[test]
    fn test_check_project_markers_go() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("go.mod"), "module example").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Go"), "expected Go, got: {t}");
    }

    #[test]
    fn test_check_project_markers_python_pyproject() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pyproject.toml"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Python"), "expected Python, got: {t}");
    }

    #[test]
    fn test_check_project_markers_python_setup_py() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("setup.py"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Python"), "expected Python, got: {t}");
    }

    #[test]
    fn test_check_project_markers_ruby() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Gemfile"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Ruby"), "expected Ruby, got: {t}");
    }

    #[test]
    fn test_check_project_markers_nix_flake() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("flake.nix"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Nix"), "expected Nix, got: {t}");
    }

    #[test]
    fn test_check_project_markers_nix_shell() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("shell.nix"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Nix"), "expected Nix, got: {t}");
    }

    #[test]
    fn test_check_project_markers_docker_compose() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Docker"), "expected Docker, got: {t}");
    }

    #[test]
    fn test_check_project_markers_compose_yml() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("compose.yml"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Docker"), "expected Docker, got: {t}");
    }

    #[test]
    fn test_check_project_markers_gradle() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("build.gradle"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Java"), "expected Java, got: {t}");
    }

    #[test]
    fn test_check_project_markers_gradle_kts() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("build.gradle.kts"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Java"), "expected Java, got: {t}");
    }

    // --- detect_project_info ---

    #[test]
    fn test_detect_project_info_with_known_project() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(tmp.path().join("src/main.rs"), "fn main() {}").ok();
        let config = Config::default();
        let info = detect_project_info(tmp.path().to_str().unwrap(), &config);
        assert!(info.root.is_some());
        assert!(info.project_type.contains("Rust"));
    }

    #[test]
    fn test_detect_project_info_unknown_project() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = Config::default();
        let info = detect_project_info(tmp.path().to_str().unwrap(), &config);
        assert!(info.root.is_none());
        assert_eq!(info.project_type, "unknown");
        assert!(info.files.is_empty());
    }

    // --- detect_git_info / run_git_with_timeout ---

    #[test]
    fn test_detect_git_info_in_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("file.txt"), "hello").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "Initial commit"])
            .current_dir(dir)
            .output()
            .unwrap();

        let (branch, status, commits) = detect_git_info(dir, 5);
        assert!(branch.is_some());
        assert!(status.is_some());
        assert!(!commits.is_empty());
        assert_eq!(commits[0].message, "Initial commit");
    }

    #[test]
    fn test_detect_git_info_not_a_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (branch, status, commits) = detect_git_info(tmp.path().to_str().unwrap(), 5);
        assert!(branch.is_none());
        assert!(status.is_none());
        assert!(commits.is_empty());
    }

    #[test]
    fn test_run_git_with_timeout_valid_command() {
        let result = run_git_with_timeout(&["--version"], "/tmp");
        assert!(result.is_some());
        assert!(result.unwrap().contains("git version"));
    }

    #[test]
    fn test_run_git_with_timeout_invalid_command() {
        let result = run_git_with_timeout(&["nonexistent-subcommand-xyz"], "/tmp");
        assert!(result.is_none());
    }

    // --- gather_custom_instructions with project instructions ---

    #[test]
    fn test_gather_custom_instructions_project_only() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".nsh")).unwrap();
        std::fs::write(
            tmp.path().join(".nsh").join("instructions.md"),
            "Use tabs not spaces",
        )
        .unwrap();
        let config = Config::default();
        let result = gather_custom_instructions(&config, tmp.path().to_str().unwrap());
        assert!(result.is_some());
        assert!(result.unwrap().contains("Use tabs not spaces"));
    }

    #[test]
    fn test_gather_custom_instructions_global_and_project() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".nsh")).unwrap();
        std::fs::write(
            tmp.path().join(".nsh").join("instructions.md"),
            "Project rule: use tabs",
        )
        .unwrap();
        let mut config = Config::default();
        config.context.custom_instructions = Some("Global rule: be concise".into());
        let result = gather_custom_instructions(&config, tmp.path().to_str().unwrap());
        assert!(result.is_some());
        let text = result.unwrap();
        assert!(text.contains("Global rule: be concise"));
        assert!(text.contains("Project rule: use tabs"));
        assert!(text.contains("Project-specific instructions"));
    }

    #[test]
    fn test_gather_custom_instructions_empty_project_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".nsh")).unwrap();
        std::fs::write(tmp.path().join(".nsh").join("instructions.md"), "   ").unwrap();
        let config = Config::default();
        let result = gather_custom_instructions(&config, tmp.path().to_str().unwrap());
        assert!(result.is_none());
    }

    // --- build_xml_context: project without git info ---

    #[test]
    fn test_build_xml_context_project_without_git() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/project".into()),
            project_type: "Node.js".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![FileEntry {
                path: "index.js".into(),
                kind: "file".into(),
                size: "200B".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("type=\"Node.js\""));
        assert!(!xml.contains("<git"));
        assert!(xml.contains("index.js"));
    }

    // --- build_xml_context: project with git branch but no status ---

    #[test]
    fn test_build_xml_context_git_branch_without_status() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/project".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("feature-x".into()),
            git_status: None,
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("branch=\"feature-x\""));
        assert!(!xml.contains("status="));
    }

    // --- build_xml_context: project with empty files list ---

    #[test]
    fn test_build_xml_context_project_no_files() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/project".into()),
            project_type: "Go".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<project root=\"/project\" type=\"Go\">"));
        assert!(!xml.contains("<files"));
        assert!(xml.contains("</project>"));
    }

    // --- build_xml_context: multiple git commits ---

    #[test]
    fn test_build_xml_context_multiple_git_commits() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/repo".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("main".into()),
            git_status: Some("clean".into()),
            git_commits: vec![
                GitCommit {
                    hash: "aaa111".into(),
                    message: "First commit".into(),
                    relative_time: "3 hours ago".into(),
                },
                GitCommit {
                    hash: "bbb222".into(),
                    message: "Second commit".into(),
                    relative_time: "1 hour ago".into(),
                },
            ],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("hash=\"aaa111\""));
        assert!(xml.contains("First commit"));
        assert!(xml.contains("hash=\"bbb222\""));
        assert!(xml.contains("Second commit"));
    }

    // --- build_xml_context: special chars in environment fields ---

    #[test]
    fn test_build_xml_context_escapes_env_fields() {
        let mut ctx = make_minimal_ctx();
        ctx.cwd = "/tmp/dir with <special> & \"chars\"".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;special&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;chars&quot;"));
    }

    // --- build_xml_context: session_history with no summary ---

    #[test]
    fn test_build_xml_session_history_no_summary() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "echo hello".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "2025-06-01T12:00:00Z".into(),
            duration_ms: Some(10),
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<input>echo hello</input>"));
        assert!(
            !xml.contains("<summary>"),
            "no summary tag when summary is None"
        );
    }

    // --- build_xml_context: session_history with missing exit code ---

    #[test]
    fn test_build_xml_session_history_missing_exit_code() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "sleep 10".into(),
            cwd: None,
            exit_code: None,
            started_at: "2025-06-01T12:00:00Z".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(
            xml.contains("exit=\"-1\""),
            "None exit_code should render as -1"
        );
    }

    // --- build_xml_context: other_sessions with no summary ---

    #[test]
    fn test_build_xml_other_sessions_no_summary() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "top".into(),
            cwd: None,
            exit_code: None,
            started_at: "2025-06-01T12:00:00Z".into(),
            summary: None,
            tty: "/dev/ttys003".into(),
            shell: "bash".into(),
            session_id: "other1".into(),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<input>top</input>"));
        assert!(
            !xml.contains("<summary>"),
            "no summary tag when summary is None"
        );
        assert!(xml.contains("exit=\"-1\""));
    }

    // --- build_xml_context: everything combined ---

    #[test]
    fn test_build_xml_context_all_fields_populated() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "$ whoami\ntestuser".into();
        ctx.ssh_context = Some("<ssh remote_ip=\"10.0.0.1\" />".into());
        ctx.container_context = Some("<container type=\"docker\" />".into());
        ctx.custom_instructions = Some("Be concise.".into());
        ctx.session_history = vec![CommandWithSummary {
            command: "make".into(),
            cwd: Some("/project".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: Some(500),
            summary: Some("Build ok".into()),
            output: None,
        }];
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "htop".into(),
            cwd: None,
            exit_code: Some(0),
            started_at: "2025-01-01T01:00:00Z".into(),
            summary: None,
            tty: "/dev/ttys004".into(),
            shell: "zsh".into(),
            session_id: "sess-other".into(),
        }];
        ctx.project_info = ProjectInfo {
            root: Some("/myproject".into()),
            project_type: "Python".into(),
            git_branch: Some("dev".into()),
            git_status: Some("2 changed files".into()),
            git_commits: vec![GitCommit {
                hash: "def456".into(),
                message: "Add feature".into(),
                relative_time: "5 min ago".into(),
            }],
            files: vec![FileEntry {
                path: "app.py".into(),
                kind: "file".into(),
                size: "3.2KB".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>"));
        assert!(xml.ends_with("</context>"));
        assert!(xml.contains("<ssh remote_ip=\"10.0.0.1\" />"));
        assert!(xml.contains("<container type=\"docker\" />"));
        assert!(xml.contains("<custom_instructions>"));
        assert!(xml.contains("Be concise."));
        assert!(xml.contains("<recent_terminal"));
        assert!(xml.contains("<session_history"));
        assert!(xml.contains("<other_sessions>"));
        assert!(xml.contains("branch=\"dev\""));
        assert!(xml.contains("app.py"));
    }

    // --- detect_os returns string containing arch ---

    #[test]
    fn test_detect_os_contains_arch() {
        let os = detect_os();
        assert!(
            os.contains(std::env::consts::ARCH),
            "expected arch in OS string, got: {os}"
        );
    }

    // --- detect_hostname is non-empty (already tested but verify no-panic) ---

    #[test]
    fn test_detect_hostname_does_not_panic() {
        let _ = detect_hostname();
    }

    // --- detect_machine_info contains cores ---

    #[test]
    fn test_detect_machine_info_contains_cores() {
        let info = detect_machine_info();
        assert!(
            info.contains("cores"),
            "expected 'cores' in machine info, got: {info}"
        );
    }

    // --- detect_timezone is non-empty ---

    #[test]
    fn test_detect_timezone_non_empty_value() {
        let tz = detect_timezone();
        assert!(!tz.is_empty());
        assert_ne!(
            tz, "unknown",
            "timezone should be detected on CI/dev machines"
        );
    }

    // --- get_cached_system_info consistency across calls ---

    #[test]
    fn test_get_cached_system_info_all_fields_consistent() {
        let info1 = get_cached_system_info();
        let info2 = get_cached_system_info();
        assert_eq!(info1.os_info, info2.os_info);
        assert_eq!(info1.hostname, info2.hostname);
        assert_eq!(info1.machine_info, info2.machine_info);
        assert_eq!(info1.timezone_info, info2.timezone_info);
        assert_eq!(info1.locale_info, info2.locale_info);
    }

    // --- xml_escape preserves newlines and single quotes ---

    #[test]
    fn test_xml_escape_preserves_single_quotes() {
        assert_eq!(xml_escape("it's"), "it's");
    }

    #[test]
    fn test_xml_escape_preserves_newlines() {
        assert_eq!(xml_escape("line1\nline2"), "line1\nline2");
    }

    #[test]
    fn test_xml_escape_preserves_tabs_and_whitespace() {
        assert_eq!(xml_escape("a\tb"), "a\tb");
        assert_eq!(xml_escape("  leading"), "  leading");
    }

    // --- find_git_root ---

    #[test]
    fn test_find_git_root_in_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let subdir = tmp.path().join("src").join("deep");
        std::fs::create_dir_all(&subdir).unwrap();
        let root = find_git_root(subdir.to_str().unwrap());
        assert_eq!(root, Some(tmp.path().to_path_buf()));
    }

    #[test]
    fn test_find_git_root_no_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = find_git_root(tmp.path().to_str().unwrap());
        // May find a parent .git, but if tmp is truly isolated it won't
        // Just verify it doesn't panic
        let _ = result;
    }

    // --- read_scrollback_file ---

    #[test]
    fn test_read_scrollback_file_existing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "test_sess_123";
        std::fs::write(
            tmp.path().join(format!("scrollback_{session}")),
            "$ echo hello\nhello\n",
        )
        .unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, "$ echo hello\nhello\n");
    }

    // --- list_project_files_fallback skips common dirs ---

    #[test]
    fn test_list_project_files_fallback_skips_node_modules() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("app.js"), "").unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir(&nm).unwrap();
        std::fs::write(nm.join("dep.js"), "").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("node_modules")),
            "should skip node_modules: {paths:?}"
        );
        assert!(paths.contains(&"app.js"));
    }

    // --- list_project_files_fallback skips target dir ---

    #[test]
    fn test_list_project_files_fallback_skips_target() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("main.rs"), "").unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("debug"), "").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("target")),
            "should skip target: {paths:?}"
        );
    }

    // --- format_size boundary ---

    #[test]
    fn test_format_size_just_under_mb() {
        let result = format_size(1024 * 1024 - 1);
        assert!(result.ends_with("KB"), "got: {result}");
    }

    #[test]
    fn test_format_size_exactly_1kb() {
        assert_eq!(format_size(1024), "1.0KB");
    }

    // --- which_exists for common tools ---

    #[test]
    fn test_which_exists_sh() {
        assert!(which_exists("sh"), "sh should exist on any Unix system");
    }

    // --- detect_project_type dedup ---

    #[test]
    fn test_detect_project_type_no_duplicates() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        let count = t.matches("Rust/Cargo").count();
        assert_eq!(count, 1, "should not duplicate: {t}");
    }

    #[test]
    fn test_build_xml_context_multiple_commits_and_files() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/home/user/myproject".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("main".into()),
            git_status: Some("3 files changed".into()),
            git_commits: vec![
                GitCommit {
                    hash: "abc1234".into(),
                    message: "initial commit".into(),
                    relative_time: "2 hours ago".into(),
                },
                GitCommit {
                    hash: "def5678".into(),
                    message: "add feature".into(),
                    relative_time: "1 hour ago".into(),
                },
            ],
            files: vec![
                FileEntry {
                    path: "src/main.rs".into(),
                    kind: "file".into(),
                    size: "1.2KB".into(),
                },
                FileEntry {
                    path: "Cargo.toml".into(),
                    kind: "file".into(),
                    size: "512B".into(),
                },
            ],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("status=\"3 files changed\""));
        assert!(xml.contains("hash=\"abc1234\""));
        assert!(xml.contains("hash=\"def5678\""));
        assert!(xml.contains("add feature"));
        assert!(xml.contains("ts=\"2 hours ago\""));
        assert!(xml.contains("count=\"2\""));
        assert!(xml.contains("path=\"Cargo.toml\""));
        assert!(xml.contains("size=\"1.2KB\""));
    }

    #[test]
    fn test_build_xml_context_scrollback_multiline() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "$ cargo build\n   Compiling nsh v0.1.0\n    Finished".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("Compiling nsh"));
        assert!(xml.contains("Finished"));
        assert!(xml.contains("</recent_terminal>"));
    }

    #[test]
    fn test_build_xml_context_custom_instructions_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.custom_instructions = Some("Use <json> & \"strict\" mode".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<custom_instructions>"));
        assert!(xml.contains("&lt;json&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;strict&quot;"));
        assert!(xml.contains("</custom_instructions>"));
    }

    #[test]
    fn test_build_xml_context_ssh_and_container_combined() {
        let mut ctx = make_minimal_ctx();
        ctx.ssh_context = Some("<ssh host=\"remote-server\" user=\"deploy\" />".into());
        ctx.container_context =
            Some("<container runtime=\"docker\" image=\"ubuntu:22.04\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<ssh host=\"remote-server\" user=\"deploy\" />"));
        assert!(xml.contains("<container runtime=\"docker\" image=\"ubuntu:22.04\" />"));
    }

    #[test]
    fn test_build_xml_context_session_history_multiple_cmds() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![
            CommandWithSummary {
                command: "cargo test".into(),
                cwd: Some("/home/user/proj".into()),
                exit_code: Some(0),
                started_at: "2025-01-01T10:00:00Z".into(),
                duration_ms: Some(1500),
                summary: Some("all 42 tests passed".into()),
                output: None,
            },
            CommandWithSummary {
                command: "git status".into(),
                cwd: Some("/home/user/proj".into()),
                exit_code: Some(0),
                started_at: "2025-01-01T10:01:00Z".into(),
                duration_ms: None,
                summary: None,
                output: None,
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"2\""));
        assert!(xml.contains("<input>cargo test</input>"));
        assert!(xml.contains("<summary>all 42 tests passed</summary>"));
        assert!(xml.contains("duration=\"1500ms\""));
        assert!(xml.contains("cwd=\"/home/user/proj\""));
        assert!(xml.contains("<input>git status</input>"));
        assert!(
            !xml.contains("<summary></summary>"),
            "no empty summary tags for None"
        );
        assert!(xml.contains("</session_history>"));
    }

    #[test]
    fn test_build_xml_context_other_sessions_multiple_ttys() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![
            OtherSessionSummary {
                command: "npm start".into(),
                cwd: Some("/home/user/web".into()),
                exit_code: Some(0),
                started_at: "2025-01-01T09:00:00Z".into(),
                summary: Some("dev server started on port 3000".into()),
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "sess-001".into(),
            },
            OtherSessionSummary {
                command: "tail -f logs".into(),
                cwd: Some("/var/log".into()),
                exit_code: Some(1),
                started_at: "2025-01-01T09:05:00Z".into(),
                summary: None,
                tty: "/dev/ttys002".into(),
                shell: "zsh".into(),
                session_id: "sess-002".into(),
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("tty=\"/dev/ttys001\""));
        assert!(xml.contains("shell=\"bash\""));
        assert!(xml.contains("<input>npm start</input>"));
        assert!(xml.contains("<summary>dev server started on port 3000</summary>"));
        assert!(xml.contains("tty=\"/dev/ttys002\""));
        assert!(xml.contains("shell=\"zsh\""));
        assert!(xml.contains("exit=\"1\""));
        assert!(xml.contains("</other_sessions>"));
    }

    #[test]
    fn test_build_xml_context_conversation_history_multiple_exchanges() {
        let mut ctx = make_minimal_ctx();
        ctx.conversation_history = vec![
            ConversationExchange {
                query: "how do I list files?".into(),
                response_type: "command".into(),
                response: "ls -la".into(),
                explanation: Some("lists all files with details".into()),
                result_exit_code: Some(0),
                result_output_snippet: Some("total 42".into()),
            },
            ConversationExchange {
                query: "what is my IP?".into(),
                response_type: "answer".into(),
                response: "Use curl ifconfig.me".into(),
                explanation: None,
                result_exit_code: None,
                result_output_snippet: None,
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<context>"));
        assert!(xml.contains("</context>"));
        assert!(xml.contains("os=\"macOS 15.0\""));
    }

    #[test]
    fn test_format_size_zero() {
        assert_eq!(format_size(0), "0B");
    }

    #[test]
    fn test_format_size_exactly_1mb() {
        assert_eq!(format_size(1024 * 1024), "1.0MB");
    }

    #[test]
    fn test_format_size_multi_gb() {
        let five_gb = 5 * 1024 * 1024 * 1024_u64;
        let result = format_size(five_gb);
        assert!(result.ends_with("MB"), "got: {result}");
        assert!(result.contains("5120"), "expected ~5120MB, got: {result}");
    }

    #[test]
    fn test_format_size_1_byte() {
        assert_eq!(format_size(1), "1B");
    }

    #[test]
    fn test_format_size_large_kb() {
        assert_eq!(format_size(999 * 1024), "999.0KB");
    }

    #[test]
    fn test_gather_custom_instructions_global_only() {
        let mut config = Config::default();
        config.context.custom_instructions = Some("Be verbose".into());
        let result = gather_custom_instructions(&config, "/nonexistent_path_xyz");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "Be verbose");
    }

    #[test]
    fn test_gather_custom_instructions_none_when_no_config() {
        let config = Config::default();
        let result = gather_custom_instructions(&config, "/nonexistent_path_xyz");
        assert!(result.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_ssh_context_with_env() {
        unsafe {
            std::env::set_var("SSH_CLIENT", "10.0.0.5 12345 22");
        }
        let result = detect_ssh_context();
        unsafe {
            std::env::remove_var("SSH_CLIENT");
        }
        assert!(result.is_some());
        let xml = result.unwrap();
        assert!(xml.contains("10.0.0.5"));
        assert!(xml.contains("<ssh"));
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_ssh_context_with_connection_env() {
        unsafe {
            std::env::remove_var("SSH_CLIENT");
            std::env::set_var("SSH_CONNECTION", "192.168.1.100 54321 192.168.1.1 22");
        }
        let result = detect_ssh_context();
        unsafe {
            std::env::remove_var("SSH_CONNECTION");
        }
        assert!(result.is_some());
        assert!(result.unwrap().contains("192.168.1.100"));
    }

    #[test]
    fn test_detect_container_returns_option() {
        let result = detect_container();
        if let Some(ref s) = result {
            assert!(s.contains("<container"));
        }
    }

    #[test]
    fn test_build_xml_context_empty_everything() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>"));
        assert!(xml.ends_with("</context>"));
        assert!(!xml.contains("<session_history"));
        assert!(!xml.contains("<other_sessions"));
        assert!(!xml.contains("<recent_terminal"));
        assert!(!xml.contains("<custom_instructions"));
        assert!(!xml.contains("<project"));
        assert!(!xml.contains("<ssh"));
        assert!(!xml.contains("<container"));
    }

    #[test]
    fn test_build_xml_context_no_project_root() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: None,
            project_type: "unknown".into(),
            git_branch: Some("main".into()),
            git_status: Some("clean".into()),
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("<project"));
        assert!(!xml.contains("<git"));
    }

    #[test]
    fn test_detect_project_type_cmake_marker() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("CMakeLists.txt"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(
            t.contains("C/C++ (CMake)"),
            "expected C/C++ (CMake), got: {t}"
        );
    }

    #[test]
    fn test_detect_project_type_nix_combined() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("flake.nix"), "").unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Nix"), "expected Nix, got: {t}");
        assert!(t.contains("Rust"), "expected Rust, got: {t}");
    }

    #[test]
    fn test_detect_project_type_ruby_gemfile() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Gemfile"), "").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Ruby"), "got: {t}");
    }

    #[test]
    fn test_build_xml_context_only_ssh() {
        let mut ctx = make_minimal_ctx();
        ctx.ssh_context = Some("<ssh remote_ip=\"1.2.3.4\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<ssh remote_ip=\"1.2.3.4\" />"));
        assert!(!xml.contains("<container"));
    }

    #[test]
    fn test_build_xml_context_only_container() {
        let mut ctx = make_minimal_ctx();
        ctx.container_context = Some("<container type=\"podman\" />".into());
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<container type=\"podman\" />"));
        assert!(!xml.contains("<ssh"));
    }

    #[test]
    fn test_build_xml_context_empty_scrollback() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("<recent_terminal"));
    }

    #[test]
    fn test_build_xml_context_empty_session_history() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("<session_history"));
    }

    #[test]
    fn test_build_xml_context_empty_other_sessions() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("<other_sessions"));
    }

    // --- list_project_files_with_ignore ---

    #[test]
    fn test_list_project_files_with_ignore_respects_gitignore() {
        let tmp = tempfile::TempDir::new().unwrap();
        // The ignore crate needs a .git dir to honor .gitignore
        std::fs::create_dir(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join(".gitignore"), "*.log\nbuild/\n").unwrap();
        std::fs::write(tmp.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(tmp.path().join("debug.log"), "log data").unwrap();
        let build_dir = tmp.path().join("build");
        std::fs::create_dir(&build_dir).unwrap();
        std::fs::write(build_dir.join("output.o"), "").unwrap();

        let entries = list_project_files_with_ignore(tmp.path(), 100);
        assert!(entries.is_some());
        let entries = entries.unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains(&"main.rs"),
            "should include main.rs: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.ends_with(".log")),
            "should exclude .log files: {paths:?}"
        );
        assert!(
            !paths.iter().any(|p| p.starts_with("build")),
            "should exclude build/ dir: {paths:?}"
        );
    }

    #[test]
    fn test_list_project_files_with_ignore_limit() {
        let tmp = tempfile::TempDir::new().unwrap();
        for i in 0..20 {
            std::fs::write(tmp.path().join(format!("file{i:02}.txt")), "x").unwrap();
        }
        let entries = list_project_files_with_ignore(tmp.path(), 5);
        assert!(entries.is_some());
        assert!(entries.unwrap().len() <= 5);
    }

    #[test]
    fn test_list_project_files_with_ignore_classifies_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();
        std::fs::write(tmp.path().join("file.txt"), "hi").unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 100).unwrap();
        let dir_entry = entries.iter().find(|e| e.path == "subdir");
        assert!(dir_entry.is_some(), "should list subdir");
        assert_eq!(dir_entry.unwrap().kind, "dir");
        assert!(dir_entry.unwrap().size.is_empty());
        let file_entry = entries.iter().find(|e| e.path == "file.txt");
        assert!(file_entry.is_some());
        assert_eq!(file_entry.unwrap().kind, "file");
        assert!(!file_entry.unwrap().size.is_empty());
    }

    #[test]
    fn test_list_project_files_with_ignore_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 100);
        assert!(entries.is_some());
        assert!(entries.unwrap().is_empty());
    }

    // --- list_project_files_fallback depth limit ---

    #[test]
    fn test_list_project_files_fallback_depth_limit() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut deep = tmp.path().to_path_buf();
        for i in 0..8 {
            deep = deep.join(format!("level{i}"));
            std::fs::create_dir_all(&deep).unwrap();
        }
        std::fs::write(deep.join("deep_file.txt"), "deep").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 1000);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("deep_file.txt")),
            "should not traverse beyond depth 5: {paths:?}"
        );
    }

    #[test]
    fn test_list_project_files_fallback_respects_limit() {
        let tmp = tempfile::TempDir::new().unwrap();
        for i in 0..30 {
            std::fs::write(tmp.path().join(format!("f{i:02}.txt")), "x").unwrap();
        }
        let entries = list_project_files_fallback(tmp.path(), 10);
        assert!(entries.len() <= 10, "got {} entries", entries.len());
    }

    #[test]
    fn test_list_project_files_fallback_skips_all_known_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        for skip in &[
            ".git",
            "target",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".next",
            ".cache",
            "vendor",
        ] {
            let d = tmp.path().join(skip);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("file.txt"), "").unwrap();
        }
        std::fs::write(tmp.path().join("keep.txt"), "").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 1000);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(paths.contains(&"keep.txt"));
        for skip in &[
            ".git",
            "target",
            "node_modules",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".next",
            ".cache",
            "vendor",
        ] {
            assert!(
                !paths.iter().any(|p| p.starts_with(skip)),
                "should skip {skip}: {paths:?}"
            );
        }
    }

    #[test]
    fn test_list_project_files_fallback_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        assert!(entries.is_empty());
    }

    // --- detect_git_info edge cases ---

    #[test]
    fn test_detect_git_info_clean_status() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("f.txt"), "hello").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let (_branch, status, _commits) = detect_git_info(dir, 5);
        assert_eq!(status.as_deref(), Some("clean"));
    }

    #[test]
    fn test_detect_git_info_dirty_status() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("f.txt"), "hello").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("f.txt"), "changed").unwrap();
        std::fs::write(tmp.path().join("new.txt"), "new").unwrap();
        let (_branch, status, _commits) = detect_git_info(dir, 5);
        assert!(
            status.as_deref().unwrap().contains("changed files"),
            "got: {status:?}"
        );
    }

    #[test]
    fn test_detect_git_info_multiple_commits() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        for i in 0..3 {
            std::fs::write(tmp.path().join(format!("f{i}.txt")), format!("v{i}")).unwrap();
            std::process::Command::new("git")
                .args(["add", "."])
                .current_dir(dir)
                .output()
                .unwrap();
            std::process::Command::new("git")
                .args(["commit", "-m", &format!("commit {i}")])
                .current_dir(dir)
                .output()
                .unwrap();
        }
        let (_branch, _status, commits) = detect_git_info(dir, 5);
        assert_eq!(commits.len(), 3);
        assert_eq!(commits[0].message, "commit 2");
        assert_eq!(commits[2].message, "commit 0");
    }

    #[test]
    fn test_detect_git_info_limits_commits() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        for i in 0..5 {
            std::fs::write(tmp.path().join(format!("f{i}.txt")), format!("v{i}")).unwrap();
            std::process::Command::new("git")
                .args(["add", "."])
                .current_dir(dir)
                .output()
                .unwrap();
            std::process::Command::new("git")
                .args(["commit", "-m", &format!("commit {i}")])
                .current_dir(dir)
                .output()
                .unwrap();
        }
        let (_branch, _status, commits) = detect_git_info(dir, 2);
        assert_eq!(commits.len(), 2);
    }

    // --- find_project_root ---

    #[test]
    fn test_find_project_root_in_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let result = find_project_root(dir);
        assert!(result.is_some());
        let root = result.unwrap();
        assert_eq!(
            root.canonicalize().unwrap(),
            tmp.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn test_find_project_root_no_git_falls_back_to_cwd() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = find_project_root(tmp.path().to_str().unwrap());
        assert!(result.is_some());
        assert_eq!(result.unwrap(), std::path::PathBuf::from(tmp.path()));
    }

    // --- detect_project_info with git ---

    #[test]
    fn test_detect_project_info_with_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("src.rs"), "fn main() {}").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let config = Config::default();
        let info = detect_project_info(dir, &config);
        assert!(info.project_type.contains("Rust"));
        assert!(info.root.is_some());
        assert!(info.git_branch.is_some());
        assert!(info.git_status.is_some());
        assert!(!info.git_commits.is_empty());
        assert!(!info.files.is_empty());
    }

    // --- run_git_with_timeout edge cases ---

    #[test]
    fn test_run_git_with_timeout_nonexistent_dir() {
        let result = run_git_with_timeout(&["status"], "/nonexistent_dir_xyz_12345");
        assert!(result.is_none());
    }

    // --- read_scrollback_file with content ---

    #[test]
    fn test_read_scrollback_file_with_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "sess_abc";
        let content = "$ whoami\nroot\n$ ls\nfile1  file2\n";
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), content).unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, content);
    }

    #[test]
    fn test_read_scrollback_file_empty_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "sess_empty";
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), "").unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert!(result.is_empty());
    }

    // --- detect_project_type walks up to .git ---

    #[test]
    fn test_detect_project_type_walks_up_to_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let subdir = tmp.path().join("src").join("deep");
        std::fs::create_dir_all(&subdir).unwrap();
        let t = detect_project_type(subdir.to_str().unwrap());
        assert!(
            t.contains("Rust"),
            "should find Cargo.toml by walking up: {t}"
        );
    }

    #[test]
    fn test_detect_project_type_stops_at_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert_eq!(t, "unknown");
    }

    // --- list_project_files dispatches correctly ---

    #[test]
    fn test_list_project_files_includes_file_sizes() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("hello.txt"), "hello world").unwrap();
        let entries = list_project_files(tmp.path().to_str().unwrap(), 100);
        let hello = entries.iter().find(|e| e.path == "hello.txt").unwrap();
        assert_eq!(hello.kind, "file");
        assert_eq!(hello.size, "11B");
    }

    // --- find_git_root from subdirectory ---

    #[test]
    fn test_find_git_root_from_deep_subdirectory() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let deep = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        let root = find_git_root(deep.to_str().unwrap());
        assert_eq!(root, Some(tmp.path().to_path_buf()));
    }

    // --- check_project_markers directly ---

    #[test]
    fn test_check_project_markers_all_types_at_once() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        std::fs::write(tmp.path().join("package.json"), "").unwrap();
        std::fs::write(tmp.path().join("go.mod"), "").unwrap();
        std::fs::write(tmp.path().join("Makefile"), "").unwrap();
        std::fs::write(tmp.path().join("Dockerfile"), "").unwrap();
        std::fs::write(tmp.path().join("Gemfile"), "").unwrap();
        std::fs::write(tmp.path().join("pom.xml"), "").unwrap();
        std::fs::write(tmp.path().join("CMakeLists.txt"), "").unwrap();
        std::fs::write(tmp.path().join("flake.nix"), "").unwrap();
        std::fs::write(tmp.path().join("pyproject.toml"), "").unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        assert!(types.contains(&"Rust/Cargo"));
        assert!(types.contains(&"Node.js"));
        assert!(types.contains(&"Go"));
        assert!(types.contains(&"Make"));
        assert!(types.contains(&"Docker"));
        assert!(types.contains(&"Ruby"));
        assert!(types.contains(&"Java"));
        assert!(types.contains(&"C/C++ (CMake)"));
        assert!(types.contains(&"Nix"));
        assert!(types.contains(&"Python"));
    }

    #[test]
    fn test_check_project_markers_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        assert!(types.is_empty());
    }

    // --- gather_custom_instructions with .nsh/instructions.md in parent ---

    #[test]
    fn test_gather_custom_instructions_project_file_in_git_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".nsh")).unwrap();
        std::fs::write(
            tmp.path().join(".nsh").join("instructions.md"),
            "Use Rust 2024 edition",
        )
        .unwrap();
        let subdir = tmp.path().join("src").join("lib");
        std::fs::create_dir_all(&subdir).unwrap();
        let config = Config::default();
        let result = gather_custom_instructions(&config, subdir.to_str().unwrap());
        assert!(result.is_some());
        assert!(result.unwrap().contains("Use Rust 2024 edition"));
    }

    // --- detect_git_info branch name ---

    #[test]
    fn test_detect_git_info_branch_name() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init", "-b", "develop"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("f.txt"), "x").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let (branch, _status, _commits) = detect_git_info(dir, 5);
        assert_eq!(branch.as_deref(), Some("develop"));
    }

    // --- list_project_files_with_ignore handles hidden files ---

    #[test]
    fn test_list_project_files_with_ignore_includes_hidden() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join(".hidden"), "secret").unwrap();
        std::fs::write(tmp.path().join("visible.txt"), "hi").unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 100).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.contains(&".hidden"),
            "should include hidden files: {paths:?}"
        );
        assert!(paths.contains(&"visible.txt"));
    }

    // --- list_project_files_fallback handles file kinds ---

    #[test]
    fn test_list_project_files_fallback_file_kind_and_size() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("hello.txt"), "hello").unwrap();
        std::fs::create_dir(tmp.path().join("mydir")).unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let file = entries.iter().find(|e| e.path == "hello.txt").unwrap();
        assert_eq!(file.kind, "file");
        assert_eq!(file.size, "5B");
        let dir = entries.iter().find(|e| e.path == "mydir").unwrap();
        assert_eq!(dir.kind, "dir");
        assert!(dir.size.is_empty());
    }

    // --- xml_escape with unicode ---

    #[test]
    fn test_xml_escape_unicode() {
        assert_eq!(xml_escape("café & naïve"), "café &amp; naïve");
        assert_eq!(xml_escape("日本語 <テスト>"), "日本語 &lt;テスト&gt;");
        assert_eq!(xml_escape("emoji 🦀"), "emoji 🦀");
    }

    #[test]
    fn test_xml_escape_only_special_chars() {
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("\""), "&quot;");
    }

    #[test]
    fn test_xml_escape_repeated_specials() {
        assert_eq!(xml_escape("&&&&"), "&amp;&amp;&amp;&amp;");
        assert_eq!(xml_escape("<<<"), "&lt;&lt;&lt;");
    }

    // --- format_size extremes ---

    #[test]
    fn test_format_size_u64_max() {
        let result = format_size(u64::MAX);
        assert!(result.ends_with("MB"), "got: {result}");
    }

    #[test]
    fn test_format_size_just_over_kb() {
        assert_eq!(format_size(1025), "1.0KB");
    }

    #[test]
    fn test_format_size_just_under_kb() {
        assert_eq!(format_size(1023), "1023B");
    }

    // --- detect_project_type: setup.py alone ---

    #[test]
    fn test_detect_project_type_setup_py() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("setup.py"), "from setuptools import setup").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Python"), "expected Python, got: {t}");
    }

    // --- detect_project_type: docker-compose.yml ---

    #[test]
    fn test_detect_project_type_docker_compose_yml() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "version: '3'").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Docker"), "expected Docker, got: {t}");
    }

    // --- detect_git_info with max_commits=0 ---

    #[test]
    fn test_detect_git_info_zero_max_commits() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("f.txt"), "x").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let (branch, status, commits) = detect_git_info(dir, 0);
        assert!(branch.is_some());
        assert!(status.is_some());
        assert!(commits.is_empty());
    }

    // --- build_xml_context: file entries with dir and symlink kinds ---

    #[test]
    fn test_build_xml_context_file_entries_various_kinds() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![
                FileEntry {
                    path: "src".into(),
                    kind: "dir".into(),
                    size: "".into(),
                },
                FileEntry {
                    path: "link.rs".into(),
                    kind: "symlink".into(),
                    size: "".into(),
                },
                FileEntry {
                    path: "main.rs".into(),
                    kind: "file".into(),
                    size: "2.0KB".into(),
                },
            ],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"3\""));
        assert!(xml.contains("type=\"dir\""));
        assert!(xml.contains("type=\"symlink\""));
        assert!(xml.contains("type=\"file\""));
        assert!(xml.contains("size=\"2.0KB\""));
        assert!(xml.contains("size=\"\""));
    }

    // --- build_xml_context: unicode in environment fields ---

    #[test]
    fn test_build_xml_context_unicode_env_fields() {
        let mut ctx = make_minimal_ctx();
        ctx.username = "用户".into();
        ctx.hostname = "サーバー".into();
        ctx.cwd = "/home/données".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("user=\"用户\""));
        assert!(xml.contains("hostname=\"サーバー\""));
        assert!(xml.contains("cwd=\"/home/données\""));
    }

    // --- build_xml_context: XML structure ordering ---

    #[test]
    fn test_build_xml_context_ordering() {
        let mut ctx = make_minimal_ctx();
        ctx.ssh_context = Some("<ssh remote_ip=\"1.1.1.1\" />".into());
        ctx.container_context = Some("<container type=\"docker\" />".into());
        ctx.custom_instructions = Some("Be concise".into());
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Go".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![],
        };
        ctx.scrollback_text = "$ ls".into();
        ctx.session_history = vec![CommandWithSummary {
            command: "ls".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        let env_pos = xml.find("<environment").unwrap();
        let ssh_pos = xml.find("<ssh").unwrap();
        let container_pos = xml.find("<container").unwrap();
        let instructions_pos = xml.find("<custom_instructions").unwrap();
        let project_pos = xml.find("<project").unwrap();
        let terminal_pos = xml.find("<recent_terminal").unwrap();
        let history_pos = xml.find("<session_history").unwrap();

        assert!(env_pos < ssh_pos);
        assert!(ssh_pos < container_pos);
        assert!(container_pos < instructions_pos);
        assert!(instructions_pos < project_pos);
        assert!(project_pos < terminal_pos);
        assert!(terminal_pos < history_pos);
    }

    // --- list_project_files_fallback with only skip dirs ---

    #[test]
    fn test_list_project_files_fallback_only_skip_dirs() {
        let tmp = tempfile::TempDir::new().unwrap();
        for skip in &[".git", "node_modules", "target"] {
            let d = tmp.path().join(skip);
            std::fs::create_dir(&d).unwrap();
            std::fs::write(d.join("inner.txt"), "").unwrap();
        }
        let entries = list_project_files_fallback(tmp.path(), 100);
        assert!(entries.is_empty());
    }

    // --- gather_custom_instructions with whitespace-only global ---

    #[test]
    fn test_gather_custom_instructions_whitespace_global() {
        let mut config = Config::default();
        config.context.custom_instructions = Some("   \n\t  ".into());
        let result = gather_custom_instructions(&config, "/nonexistent_path_xyz");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "   \n\t  ");
    }

    // --- find_git_root returns None for isolated temp dir ---

    #[test]
    fn test_find_git_root_isolated_temp() {
        let tmp = tempfile::TempDir::new().unwrap();
        let deep = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&deep).unwrap();
        let result = find_git_root(deep.to_str().unwrap());
        if result.is_some() {
            assert!(result.unwrap().join(".git").exists());
        }
    }

    // --- build_xml_context: git branch with special characters ---

    #[test]
    fn test_build_xml_context_git_branch_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("feature/add-<thing>&more".into()),
            git_status: Some("clean".into()),
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("branch=\"feature/add-&lt;thing&gt;&amp;more\""));
    }

    // --- build_xml_context: commit message with special chars ---

    #[test]
    fn test_build_xml_context_commit_message_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("main".into()),
            git_status: None,
            git_commits: vec![GitCommit {
                hash: "abc".into(),
                message: "fix: handle <input> & \"output\"".into(),
                relative_time: "now".into(),
            }],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("fix: handle &lt;input&gt; &amp; &quot;output&quot;"));
    }

    // --- build_xml_context: session_history command with special chars ---

    #[test]
    fn test_build_xml_context_session_history_special_chars_in_command() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "echo '<hello>' & \"world\"".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;hello&gt;"));
        assert!(xml.contains("&amp;"));
    }

    // --- build_xml_context: other_sessions single entry produces correct structure ---

    #[test]
    fn test_build_xml_other_sessions_single_entry_structure() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "pwd".into(),
            cwd: Some("/home".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            summary: None,
            tty: "/dev/ttys005".into(),
            shell: "fish".into(),
            session_id: "s1".into(),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<other_sessions>"));
        assert!(xml.contains("<session tty=\"/dev/ttys005\" shell=\"fish\">"));
        assert!(xml.contains("</session>"));
        assert!(xml.contains("</other_sessions>"));
        let session_open_count = xml.matches("<session tty=").count();
        let session_close_count = xml.matches("</session>").count();
        assert_eq!(session_open_count, session_close_count);
    }

    // --- list_project_files dispatches to ignore walker for empty dir ---

    #[test]
    fn test_list_project_files_empty_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entries = list_project_files(tmp.path().to_str().unwrap(), 100);
        assert!(entries.is_empty());
    }

    // --- list_project_files_with_ignore max_depth ---

    #[test]
    fn test_list_project_files_with_ignore_max_depth() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut deep = tmp.path().to_path_buf();
        for i in 0..8 {
            deep = deep.join(format!("d{i}"));
            std::fs::create_dir_all(&deep).unwrap();
        }
        std::fs::write(deep.join("deep.txt"), "deep").unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 1000).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            !paths.iter().any(|p| p.contains("deep.txt")),
            "should respect max_depth of 5: {paths:?}"
        );
    }

    // --- check_project_markers shell.nix alone ---

    #[test]
    fn test_check_project_markers_shell_nix() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("shell.nix"), "").unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        assert!(types.contains(&"Nix"));
    }

    // --- check_project_markers both Python markers ---

    #[test]
    fn test_check_project_markers_both_python() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pyproject.toml"), "").unwrap();
        std::fs::write(tmp.path().join("setup.py"), "").unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        let python_count = types.iter().filter(|&&t| t == "Python").count();
        assert_eq!(
            python_count, 1,
            "Python should only appear once even with both markers"
        );
    }

    // --- detect_project_info with files ---

    #[test]
    fn test_detect_project_info_includes_files() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]").unwrap();
        std::fs::write(tmp.path().join("main.rs"), "fn main() {}").unwrap();
        std::fs::write(tmp.path().join("lib.rs"), "pub fn hello() {}").unwrap();
        let config = Config::default();
        let info = detect_project_info(tmp.path().to_str().unwrap(), &config);
        assert!(info.root.is_some());
        assert!(!info.files.is_empty());
        let paths: Vec<&str> = info.files.iter().map(|f| f.path.as_str()).collect();
        assert!(
            paths.contains(&"main.rs"),
            "should include main.rs: {paths:?}"
        );
    }

    // --- build_xml_context: large number of files ---

    #[test]
    fn test_build_xml_context_many_files() {
        let mut ctx = make_minimal_ctx();
        let files: Vec<FileEntry> = (0..50)
            .map(|i| FileEntry {
                path: format!("file{i:03}.txt"),
                kind: "file".into(),
                size: format!("{i}B"),
            })
            .collect();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "unknown".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files,
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"50\""));
        assert!(xml.contains("file000.txt"));
        assert!(xml.contains("file049.txt"));
    }

    // --- build_xml_context: no project root skips entire project section ---

    #[test]
    fn test_build_xml_context_no_root_skips_git_and_files() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: None,
            project_type: "Rust/Cargo".into(),
            git_branch: Some("main".into()),
            git_status: Some("clean".into()),
            git_commits: vec![GitCommit {
                hash: "abc".into(),
                message: "msg".into(),
                relative_time: "now".into(),
            }],
            files: vec![FileEntry {
                path: "f.rs".into(),
                kind: "file".into(),
                size: "1B".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("<project"));
        assert!(!xml.contains("<git"));
        assert!(!xml.contains("<files"));
        assert!(!xml.contains("<commit"));
    }

    // --- run_git_with_timeout with empty args ---

    #[test]
    fn test_run_git_with_timeout_empty_args() {
        let result = run_git_with_timeout(&[], "/tmp");
        let _ = result;
    }

    // --- detect_project_type dedup with parent markers ---

    #[test]
    fn test_detect_project_type_parent_and_child_same_marker() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join("Cargo.toml"), "").unwrap();
        let subdir = tmp.path().join("subproj");
        std::fs::create_dir_all(&subdir).unwrap();
        std::fs::write(subdir.join("Cargo.toml"), "").unwrap();
        let t = detect_project_type(subdir.to_str().unwrap());
        let count = t.matches("Rust/Cargo").count();
        assert!(count <= 1, "should dedup Rust/Cargo: {t}");
    }

    // --- gather_custom_instructions: no .nsh dir ---

    #[test]
    fn test_gather_custom_instructions_no_nsh_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let config = Config::default();
        let result = gather_custom_instructions(&config, tmp.path().to_str().unwrap());
        assert!(result.is_none());
    }

    // --- gather_custom_instructions: .nsh dir exists but no instructions.md ---

    #[test]
    fn test_gather_custom_instructions_nsh_dir_no_file() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::create_dir_all(tmp.path().join(".nsh")).unwrap();
        let config = Config::default();
        let result = gather_custom_instructions(&config, tmp.path().to_str().unwrap());
        assert!(result.is_none());
    }

    #[test]
    fn test_build_xml_context_scrollback_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "$ echo '<script>alert(1)</script>'".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;script&gt;"));
        assert!(!xml.contains("<script>"));
    }

    #[test]
    fn test_build_xml_context_project_with_git_status_and_no_commits() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("develop".into()),
            git_status: Some("5 changed files".into()),
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("branch=\"develop\""));
        assert!(xml.contains("status=\"5 changed files\""));
        assert!(xml.contains("</git>"));
    }

    #[test]
    fn test_build_xml_context_project_with_many_files() {
        let mut ctx = make_minimal_ctx();
        let files: Vec<FileEntry> = (0..10)
            .map(|i| FileEntry {
                path: format!("file{i}.rs"),
                kind: "file".into(),
                size: format!("{i}KB"),
            })
            .collect();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files,
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"10\""));
        assert!(xml.contains("file0.rs"));
        assert!(xml.contains("file9.rs"));
    }

    #[test]
    fn test_find_git_root_at_root_itself() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let root = find_git_root(tmp.path().to_str().unwrap());
        assert_eq!(root, Some(tmp.path().to_path_buf()));
    }

    #[test]
    fn test_detect_project_info_no_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        let config = Config::default();
        let info = detect_project_info(tmp.path().to_str().unwrap(), &config);
        assert!(info.root.is_some());
        assert!(info.project_type.contains("Node"));
        assert!(info.git_branch.is_none());
    }

    #[test]
    fn test_list_project_files_empty_dir_v2() {
        let tmp = tempfile::TempDir::new().unwrap();
        let entries = list_project_files(tmp.path().to_str().unwrap(), 100);
        assert!(entries.is_empty());
    }

    #[test]
    fn test_read_scrollback_file_with_content_v2() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "read_test_sess";
        let content = "line1\nline2\nline3\n";
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), content).unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, content);
    }

    #[test]
    fn test_read_scrollback_file_nonexistent_dir() {
        let result = read_scrollback_file("xyz", std::path::Path::new("/nonexistent_dir_abc_123"));
        assert!(result.is_empty());
    }

    #[test]
    fn test_build_xml_context_other_sessions_single_tty_multiple_cmds() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![
            OtherSessionSummary {
                command: "cmd1".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t1".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "s1".into(),
            },
            OtherSessionSummary {
                command: "cmd2".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t2".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "s1".into(),
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        let session_count = xml.matches("<session tty=").count();
        assert_eq!(session_count, 1, "same tty should share one session tag");
        assert!(xml.contains("<input>cmd1</input>"));
        assert!(xml.contains("<input>cmd2</input>"));
    }

    #[test]
    fn test_detect_project_type_setup_py_v2() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("setup.py"), "from setuptools import setup").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Python"), "expected Python, got: {t}");
    }

    #[test]
    fn test_find_project_root_returns_something() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = find_project_root(tmp.path().to_str().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn test_list_project_files_with_ignore_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("real.txt"), "data").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.path().join("real.txt"), tmp.path().join("link.txt"))
                .unwrap();
            let entries = list_project_files_with_ignore(tmp.path(), 100).unwrap();
            let link = entries.iter().find(|e| e.path == "link.txt");
            assert!(link.is_some(), "should list symlink");
            assert_eq!(link.unwrap().kind, "symlink");
        }
    }

    #[test]
    fn test_list_project_files_fallback_with_symlink() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("real.txt"), "data").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(tmp.path().join("real.txt"), tmp.path().join("link.txt"))
                .unwrap();
            let entries = list_project_files_fallback(tmp.path(), 100);
            let link = entries.iter().find(|e| e.path == "link.txt");
            assert!(link.is_some(), "should list symlink");
            assert_eq!(link.unwrap().kind, "symlink");
            assert!(link.unwrap().size.is_empty());
        }
    }

    #[test]
    fn test_format_size_small_kb() {
        assert_eq!(format_size(2048), "2.0KB");
        assert_eq!(format_size(1536), "1.5KB");
    }

    #[test]
    fn test_format_size_large_mb() {
        assert_eq!(format_size(10 * 1024 * 1024), "10.0MB");
    }

    #[test]
    fn test_xml_escape_unicode_v2() {
        assert_eq!(xml_escape("héllo wörld"), "héllo wörld");
        assert_eq!(xml_escape("日本語 & test"), "日本語 &amp; test");
    }

    // --- xml_escape: long strings and double-escaped ---

    #[test]
    fn test_xml_escape_already_escaped_ampersand() {
        assert_eq!(xml_escape("&amp;"), "&amp;amp;");
    }

    #[test]
    fn test_xml_escape_long_string_with_many_specials() {
        let input = "<a>&\"b\"</a> & <c>".repeat(100);
        let result = xml_escape(&input);
        assert!(!result.contains('<'));
        assert!(!result.contains('>'));
        assert!(!result.contains('"'));
        assert!(result.contains("&amp;"));
        assert!(result.contains("&lt;"));
        assert!(result.contains("&gt;"));
        assert!(result.contains("&quot;"));
    }

    #[test]
    fn test_xml_escape_only_whitespace() {
        assert_eq!(xml_escape("   "), "   ");
        assert_eq!(xml_escape("\n\n\n"), "\n\n\n");
        assert_eq!(xml_escape("\t\t"), "\t\t");
    }

    // --- format_size: additional boundaries ---

    #[test]
    fn test_format_size_exactly_at_boundaries() {
        assert_eq!(format_size(1023), "1023B");
        assert_eq!(format_size(1024), "1.0KB");
        assert_eq!(format_size(1024 * 1024 - 1), "1024.0KB");
        assert_eq!(format_size(1024 * 1024), "1.0MB");
    }

    #[test]
    fn test_format_size_fractional_kb() {
        assert_eq!(format_size(1024 + 512), "1.5KB");
        assert_eq!(format_size(1024 * 100 + 512), "100.5KB");
    }

    #[test]
    fn test_format_size_fractional_mb() {
        assert_eq!(format_size(1024 * 1024 + 1024 * 512), "1.5MB");
    }

    // --- detect_timezone: with TZ env var ---

    #[test]
    #[serial_test::serial]
    fn test_detect_timezone_with_tz_env() {
        unsafe {
            std::env::set_var("TZ", "America/New_York");
        }
        let tz = detect_timezone();
        unsafe {
            std::env::remove_var("TZ");
        }
        assert_eq!(tz, "America/New_York");
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_timezone_without_tz_env() {
        let original = std::env::var("TZ").ok();
        unsafe {
            std::env::remove_var("TZ");
        }
        let tz = detect_timezone();
        if let Some(orig) = original {
            unsafe {
                std::env::set_var("TZ", orig);
            }
        }
        assert!(!tz.is_empty());
    }

    // --- detect_locale: with env vars ---

    #[test]
    #[serial_test::serial]
    fn test_detect_locale_with_lc_all() {
        let orig_lc = std::env::var("LC_ALL").ok();
        let orig_lang = std::env::var("LANG").ok();
        unsafe {
            std::env::set_var("LC_ALL", "fr_FR.UTF-8");
        }
        let locale = detect_locale();
        unsafe {
            match orig_lc {
                Some(v) => std::env::set_var("LC_ALL", v),
                None => std::env::remove_var("LC_ALL"),
            }
            match orig_lang {
                Some(v) => std::env::set_var("LANG", v),
                None => std::env::remove_var("LANG"),
            }
        }
        assert_eq!(locale, "fr_FR.UTF-8");
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_locale_falls_back_to_lang() {
        let orig_lc = std::env::var("LC_ALL").ok();
        let orig_lang = std::env::var("LANG").ok();
        unsafe {
            std::env::remove_var("LC_ALL");
            std::env::set_var("LANG", "de_DE.UTF-8");
        }
        let locale = detect_locale();
        unsafe {
            match orig_lc {
                Some(v) => std::env::set_var("LC_ALL", v),
                None => std::env::remove_var("LC_ALL"),
            }
            match orig_lang {
                Some(v) => std::env::set_var("LANG", v),
                None => std::env::remove_var("LANG"),
            }
        }
        assert_eq!(locale, "de_DE.UTF-8");
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_locale_default_when_no_env() {
        let orig_lc = std::env::var("LC_ALL").ok();
        let orig_lang = std::env::var("LANG").ok();
        unsafe {
            std::env::remove_var("LC_ALL");
            std::env::remove_var("LANG");
        }
        let locale = detect_locale();
        unsafe {
            match orig_lc {
                Some(v) => std::env::set_var("LC_ALL", v),
                None => std::env::remove_var("LC_ALL"),
            }
            match orig_lang {
                Some(v) => std::env::set_var("LANG", v),
                None => std::env::remove_var("LANG"),
            }
        }
        assert_eq!(locale, "en_US.UTF-8");
    }

    // --- detect_ssh_context: edge cases ---

    #[test]
    #[serial_test::serial]
    fn test_detect_ssh_context_single_field() {
        unsafe {
            std::env::remove_var("SSH_CONNECTION");
            std::env::set_var("SSH_CLIENT", "8.8.8.8");
        }
        let result = detect_ssh_context();
        unsafe {
            std::env::remove_var("SSH_CLIENT");
        }
        assert!(result.is_some());
        assert!(result.unwrap().contains("8.8.8.8"));
    }

    #[test]
    #[serial_test::serial]
    fn test_detect_ssh_context_special_chars_in_ip() {
        unsafe {
            std::env::remove_var("SSH_CONNECTION");
            std::env::set_var("SSH_CLIENT", "fe80::1%eth0 12345 22");
        }
        let result = detect_ssh_context();
        unsafe {
            std::env::remove_var("SSH_CLIENT");
        }
        assert!(result.is_some());
    }

    // --- read_scrollback_file: various content types ---

    #[test]
    fn test_read_scrollback_file_with_unicode() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "unicode_sess";
        let content = "$ echo 日本語\n日本語\n$ echo 🦀\n🦀\n";
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), content).unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, content);
    }

    #[test]
    fn test_read_scrollback_file_with_long_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "long_sess";
        let content = "line\n".repeat(1000);
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), &content).unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, content);
    }

    // --- build_xml_context: session history with special chars in summary ---

    #[test]
    fn test_build_xml_session_history_summary_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "make".into(),
            cwd: Some("/proj".into()),
            exit_code: Some(1),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: Some(100),
            summary: Some("Error: <undefined> & \"missing\"".into()),
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;undefined&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;missing&quot;"));
    }

    // --- build_xml_context: other sessions with special chars ---

    #[test]
    fn test_build_xml_other_sessions_special_chars_in_command() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "echo \"hello <world>\"".into(),
            cwd: None,
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            summary: Some("Printed <world> & more".into()),
            tty: "/dev/pts/0".into(),
            shell: "bash".into(),
            session_id: "s1".into(),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;world&gt;"));
        assert!(xml.contains("&amp;"));
    }

    // --- build_xml_context: session_history exit_code edge values ---

    #[test]
    fn test_build_xml_session_history_various_exit_codes() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![
            CommandWithSummary {
                command: "true".into(),
                cwd: Some("/tmp".into()),
                exit_code: Some(0),
                started_at: "t1".into(),
                duration_ms: None,
                summary: None,
                output: None,
            },
            CommandWithSummary {
                command: "segfault".into(),
                cwd: Some("/tmp".into()),
                exit_code: Some(139),
                started_at: "t2".into(),
                duration_ms: None,
                summary: None,
                output: None,
            },
            CommandWithSummary {
                command: "killed".into(),
                cwd: Some("/tmp".into()),
                exit_code: Some(137),
                started_at: "t3".into(),
                duration_ms: None,
                summary: None,
                output: None,
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("exit=\"0\""));
        assert!(xml.contains("exit=\"139\""));
        assert!(xml.contains("exit=\"137\""));
    }

    // --- build_xml_context: project with files but no root ---

    #[test]
    fn test_build_xml_context_files_ignored_without_root() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: None,
            project_type: "unknown".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![FileEntry {
                path: "orphan.txt".into(),
                kind: "file".into(),
                size: "100B".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(!xml.contains("orphan.txt"));
        assert!(!xml.contains("<files"));
    }

    // --- build_xml_context: large duration values ---

    #[test]
    fn test_build_xml_session_history_large_duration() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "long-running".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "t1".into(),
            duration_ms: Some(3_600_000),
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("duration=\"3600000ms\""));
    }

    // --- build_xml_context: other_sessions with three different TTYs ---

    #[test]
    fn test_build_xml_other_sessions_three_ttys() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![
            OtherSessionSummary {
                command: "a".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t1".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "s1".into(),
            },
            OtherSessionSummary {
                command: "b".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t2".into(),
                summary: None,
                tty: "/dev/ttys002".into(),
                shell: "zsh".into(),
                session_id: "s2".into(),
            },
            OtherSessionSummary {
                command: "c".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t3".into(),
                summary: None,
                tty: "/dev/ttys003".into(),
                shell: "fish".into(),
                session_id: "s3".into(),
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        let session_count = xml.matches("<session tty=").count();
        assert_eq!(session_count, 3);
        let close_count = xml.matches("</session>").count();
        assert_eq!(close_count, 3);
    }

    // --- check_project_markers: both Docker markers at once ---

    #[test]
    fn test_check_project_markers_both_docker_markers() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("Dockerfile"), "").unwrap();
        std::fs::write(tmp.path().join("docker-compose.yml"), "").unwrap();
        std::fs::write(tmp.path().join("compose.yml"), "").unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        let docker_count = types.iter().filter(|&&t| t == "Docker").count();
        assert_eq!(docker_count, 1, "Docker should appear once: {types:?}");
    }

    // --- check_project_markers: both Java markers at once ---

    #[test]
    fn test_check_project_markers_both_java_markers() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), "").unwrap();
        std::fs::write(tmp.path().join("build.gradle"), "").unwrap();
        let mut types = Vec::new();
        check_project_markers(tmp.path(), &mut types);
        let java_count = types.iter().filter(|&&t| t == "Java").count();
        assert_eq!(java_count, 1, "Java should appear once: {types:?}");
    }

    // --- list_project_files_fallback: sorts children alphabetically ---

    #[test]
    fn test_list_project_files_fallback_sorted() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("zebra.txt"), "").unwrap();
        std::fs::write(tmp.path().join("apple.txt"), "").unwrap();
        std::fs::write(tmp.path().join("mango.txt"), "").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert_eq!(paths, vec!["apple.txt", "mango.txt", "zebra.txt"]);
    }

    // --- list_project_files_with_ignore: sorted output ---

    #[test]
    fn test_list_project_files_with_ignore_sorted() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("z.txt"), "").unwrap();
        std::fs::write(tmp.path().join("a.txt"), "").unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 100).unwrap();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let a_pos = paths.iter().position(|p| *p == "a.txt").unwrap();
        let z_pos = paths.iter().position(|p| *p == "z.txt").unwrap();
        assert!(a_pos < z_pos, "should be sorted: {paths:?}");
    }

    // --- detect_project_type: empty string path ---

    #[test]
    fn test_detect_project_type_empty_path() {
        let t = detect_project_type("");
        assert!(!t.is_empty());
    }

    // --- which_exists: common commands ---

    #[test]
    fn test_which_exists_cat() {
        assert!(which_exists("cat"), "cat should exist");
    }

    #[test]
    fn test_which_exists_empty_string() {
        assert!(!which_exists(""));
    }

    // --- build_xml_context: git commits with empty hash/message ---

    #[test]
    fn test_build_xml_context_git_commit_empty_fields() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Go".into(),
            git_branch: Some("main".into()),
            git_status: None,
            git_commits: vec![GitCommit {
                hash: "".into(),
                message: "".into(),
                relative_time: "".into(),
            }],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("hash=\"\""));
        assert!(xml.contains("ts=\"\""));
        assert!(xml.contains("<commit hash=\"\" ts=\"\"></commit>"));
    }

    // --- build_xml_context: file entries with special chars in path ---

    #[test]
    fn test_build_xml_context_file_path_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "Node.js".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![FileEntry {
                path: "dir/file with <name> & \"quotes\".txt".into(),
                kind: "file".into(),
                size: "10B".into(),
            }],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;name&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;quotes&quot;"));
    }

    #[test]
    fn test_read_scrollback_file_returns_full_content_when_exists() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "scrollback_full_test";
        let mut big = String::new();
        for i in 0..50 {
            big.push_str(&format!("$ command_{i}\noutput_{i}\n"));
        }
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), &big).unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result.lines().count(), big.lines().count());
    }

    #[test]
    fn test_read_scrollback_file_special_session_id() {
        let tmp = tempfile::TempDir::new().unwrap();
        let session = "sess-with.dots_and-dashes";
        std::fs::write(tmp.path().join(format!("scrollback_{session}")), "content").unwrap();
        let result = read_scrollback_file(session, tmp.path());
        assert_eq!(result, "content");
    }

    #[test]
    fn test_build_xml_context_session_history_duration_zero() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "true".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: Some(0),
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("duration=\"0ms\""));
    }

    #[test]
    fn test_build_xml_context_session_history_negative_exit() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "crash".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(-11),
            started_at: "2025-01-01T00:00:00Z".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("exit=\"-11\""));
    }

    #[test]
    fn test_build_xml_context_other_sessions_switching_back_to_same_tty() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![
            OtherSessionSummary {
                command: "a".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t1".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "s1".into(),
            },
            OtherSessionSummary {
                command: "b".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t2".into(),
                summary: None,
                tty: "/dev/ttys002".into(),
                shell: "zsh".into(),
                session_id: "s2".into(),
            },
            OtherSessionSummary {
                command: "c".into(),
                cwd: None,
                exit_code: Some(0),
                started_at: "t3".into(),
                summary: None,
                tty: "/dev/ttys001".into(),
                shell: "bash".into(),
                session_id: "s1".into(),
            },
        ];
        let xml = build_xml_context(&ctx, &Config::default());
        let session_count = xml.matches("<session tty=").count();
        assert_eq!(
            session_count, 3,
            "switching back to same tty opens new session tag"
        );
        let close_count = xml.matches("</session>").count();
        assert_eq!(close_count, 3);
    }

    #[test]
    fn test_build_xml_context_other_sessions_summary_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = vec![OtherSessionSummary {
            command: "make".into(),
            cwd: None,
            exit_code: Some(2),
            started_at: "t1".into(),
            summary: Some("Error: <missing> & \"file\"".into()),
            tty: "/dev/ttys001".into(),
            shell: "bash".into(),
            session_id: "s1".into(),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("&lt;missing&gt;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&quot;file&quot;"));
    }

    #[test]
    fn test_build_xml_context_scrollback_empty_after_strip() {
        let mut ctx = make_minimal_ctx();
        ctx.scrollback_text = "   \n  \n  ".into();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<recent_terminal"));
    }

    #[test]
    fn test_build_xml_context_session_history_cwd_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "ls".into(),
            cwd: Some("/path/<with>&\"chars\"".into()),
            exit_code: Some(0),
            started_at: "t1".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("cwd=\"/path/&lt;with&gt;&amp;&quot;chars&quot;\""));
    }

    #[test]
    fn test_build_xml_context_session_history_empty_command() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "t1".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<input></input>"));
    }

    #[test]
    fn test_build_xml_context_project_root_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/path/<project>&\"name\"".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("root=\"/path/&lt;project&gt;&amp;&quot;name&quot;\""));
    }

    #[test]
    fn test_build_xml_context_large_session_history() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = (0..50)
            .map(|i| CommandWithSummary {
                command: format!("cmd_{i}"),
                cwd: Some("/tmp".into()),
                exit_code: Some(i % 3),
                started_at: format!("2025-01-01T{i:02}:00:00Z"),
                duration_ms: Some(i as i64 * 100),
                summary: if i % 2 == 0 {
                    Some(format!("summary_{i}"))
                } else {
                    None
                },
                output: None,
            })
            .collect();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("count=\"50\""));
        assert!(xml.contains("cmd_0"));
        assert!(xml.contains("cmd_49"));
    }

    #[test]
    fn test_build_xml_context_large_other_sessions() {
        let mut ctx = make_minimal_ctx();
        ctx.other_sessions = (0..20)
            .map(|i| OtherSessionSummary {
                command: format!("other_cmd_{i}"),
                cwd: Some("/tmp".into()),
                exit_code: Some(0),
                started_at: format!("t{i}"),
                summary: None,
                tty: format!("/dev/ttys{i:03}"),
                shell: "bash".into(),
                session_id: format!("s{i}"),
            })
            .collect();
        let xml = build_xml_context(&ctx, &Config::default());
        let session_count = xml.matches("<session tty=").count();
        assert_eq!(session_count, 20);
        assert!(xml.contains("other_cmd_0"));
        assert!(xml.contains("other_cmd_19"));
    }

    #[test]
    fn test_detect_container_no_dockerenv() {
        if !std::path::Path::new("/.dockerenv").exists() {
            let result = detect_container();
            #[cfg(not(target_os = "linux"))]
            assert!(result.is_none());
        }
    }

    #[test]
    fn test_list_project_files_with_ignore_returns_none_on_errors_only() {
        let entries =
            list_project_files_with_ignore(std::path::Path::new("/nonexistent_abc_xyz"), 100);
        if let Some(e) = entries {
            assert!(e.is_empty());
        }
    }

    #[test]
    fn test_list_project_files_dispatches_to_fallback() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("test.txt"), "hello").unwrap();
        let entries = list_project_files(tmp.path().to_str().unwrap(), 100);
        assert!(!entries.is_empty());
        let f = entries.iter().find(|e| e.path == "test.txt").unwrap();
        assert_eq!(f.kind, "file");
    }

    #[test]
    fn test_build_xml_context_project_type_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/proj".into()),
            project_type: "C/C++ (CMake)".into(),
            git_branch: None,
            git_status: None,
            git_commits: vec![],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("type=\"C/C++ (CMake)\""));
    }

    #[test]
    fn test_build_xml_context_all_optional_none() {
        let ctx = QueryContext {
            os_info: "Linux".into(),
            shell: "sh".into(),
            cwd: "/".into(),
            username: "root".into(),
            conversation_history: vec![],
            hostname: "localhost".into(),
            machine_info: "x86_64".into(),
            datetime_info: "2025-01-01".into(),
            timezone_info: "UTC".into(),
            locale_info: "C".into(),
            session_history: vec![],
            other_sessions: vec![],
            scrollback_text: String::new(),
            custom_instructions: None,
            project_info: ProjectInfo {
                root: None,
                project_type: "unknown".into(),
                git_branch: None,
                git_status: None,
                git_commits: vec![],
                files: vec![],
            },
            ssh_context: None,
            container_context: None,
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>\n  <environment"));
        assert!(xml.ends_with("</context>"));
        assert_eq!(xml.matches('\n').count(), 2);
    }

    #[test]
    fn test_build_xml_context_conversation_history_not_rendered_in_xml() {
        let mut ctx = make_minimal_ctx();
        ctx.conversation_history = vec![ConversationExchange {
            query: "unique_query_marker_12345".into(),
            response_type: "command".into(),
            response: "unique_response_marker_67890".into(),
            explanation: Some("unique_explanation_marker".into()),
            result_exit_code: Some(0),
            result_output_snippet: Some("unique_snippet".into()),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(
            !xml.contains("unique_query_marker_12345"),
            "conversation history should not be rendered directly in XML context"
        );
    }

    #[test]
    fn test_build_xml_context_tty_env_in_session_history() {
        let mut ctx = make_minimal_ctx();
        ctx.session_history = vec![CommandWithSummary {
            command: "whoami".into(),
            cwd: Some("/tmp".into()),
            exit_code: Some(0),
            started_at: "t1".into(),
            duration_ms: None,
            summary: None,
            output: None,
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("<session_history tty="));
    }

    #[test]
    fn test_detect_project_type_pom_xml() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("pom.xml"), "<project/>").unwrap();
        let t = detect_project_type(tmp.path().to_str().unwrap());
        assert!(t.contains("Java"), "expected Java for pom.xml, got: {t}");
    }

    #[test]
    fn test_find_project_root_with_git_repo() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        let subdir = tmp.path().join("src").join("lib");
        std::fs::create_dir_all(&subdir).unwrap();
        let result = find_project_root(subdir.to_str().unwrap());
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().canonicalize().unwrap(),
            tmp.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn test_list_project_files_fallback_subdir_recursion() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sub = tmp.path().join("a").join("b");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(sub.join("deep.txt"), "deep").unwrap();
        let entries = list_project_files_fallback(tmp.path(), 100);
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        assert!(
            paths.iter().any(|p| p.contains("deep.txt")),
            "should find files in subdirs: {paths:?}"
        );
    }

    #[test]
    fn test_detect_git_info_status_format() {
        let tmp = tempfile::TempDir::new().unwrap();
        let dir = tmp.path().to_str().unwrap();
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.email", "t@t.com"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["config", "user.name", "T"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("a.txt"), "a").unwrap();
        std::process::Command::new("git")
            .args(["add", "."])
            .current_dir(dir)
            .output()
            .unwrap();
        std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .output()
            .unwrap();
        std::fs::write(tmp.path().join("b.txt"), "b").unwrap();
        let (_branch, status, _commits) = detect_git_info(dir, 5);
        assert_eq!(status.as_deref(), Some("1 changed files"));
    }

    #[test]
    fn test_xml_escape_multiple_ampersands() {
        assert_eq!(xml_escape("a&b&c&d"), "a&amp;b&amp;c&amp;d");
    }

    #[test]
    fn test_xml_escape_nested_xml_tags() {
        assert_eq!(
            xml_escape("<div attr=\"val\">text & more</div>"),
            "&lt;div attr=&quot;val&quot;&gt;text &amp; more&lt;/div&gt;"
        );
    }

    #[test]
    fn test_build_xml_context_no_optional_sections() {
        let ctx = make_minimal_ctx();
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.starts_with("<context>"));
        assert!(xml.ends_with("</context>"));
        assert!(!xml.contains("<ssh"));
        assert!(!xml.contains("<container"));
        assert!(!xml.contains("<custom_instructions>"));
        assert!(!xml.contains("<recent_terminal"));
        assert!(!xml.contains("<session_history"));
        assert!(!xml.contains("<other_sessions>"));
    }

    #[test]
    fn test_build_xml_context_conversation_history_not_in_xml() {
        let mut ctx = make_minimal_ctx();
        ctx.conversation_history = vec![ConversationExchange {
            query: "list files".into(),
            response_type: "command".into(),
            response: "ls -la".into(),
            explanation: Some("list all files".into()),
            result_exit_code: Some(0),
            result_output_snippet: Some("total 42".into()),
        }];
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(
            !xml.contains("list files"),
            "conversation history is replayed as messages, not in XML context"
        );
        assert_eq!(ctx.conversation_history.len(), 1);
        assert_eq!(ctx.conversation_history[0].query, "list files");
        assert_eq!(ctx.conversation_history[0].response, "ls -la");
        assert_eq!(
            ctx.conversation_history[0].explanation.as_deref(),
            Some("list all files")
        );
        assert_eq!(ctx.conversation_history[0].result_exit_code, Some(0));
    }

    #[test]
    fn test_read_scrollback_file_nonexistent_session() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = read_scrollback_file("nonexistent_session_xyz", tmp.path());
        assert!(result.is_empty());
    }

    #[test]
    fn test_find_git_root_nested_subdirectory() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        let deep = tmp.path().join("a").join("b").join("c");
        std::fs::create_dir_all(&deep).unwrap();
        let root = find_git_root(deep.to_str().unwrap());
        assert_eq!(root, Some(tmp.path().to_path_buf()));
    }

    #[test]
    fn test_xml_escape_consecutive_special_chars() {
        assert_eq!(xml_escape("&&&"), "&amp;&amp;&amp;");
        assert_eq!(xml_escape("<<<>>>"), "&lt;&lt;&lt;&gt;&gt;&gt;");
        assert_eq!(xml_escape("\"\"\""), "&quot;&quot;&quot;");
        assert_eq!(
            xml_escape("<script>alert(\"xss\")&</script>"),
            "&lt;script&gt;alert(&quot;xss&quot;)&amp;&lt;/script&gt;"
        );
    }

    #[test]
    fn test_detect_project_type_stops_at_git_boundary() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::create_dir_all(tmp.path().join(".git")).unwrap();
        std::fs::write(tmp.path().join("package.json"), "{}").unwrap();
        let child = tmp.path().join("subproject");
        std::fs::create_dir_all(&child).unwrap();
        std::fs::write(child.join("Cargo.toml"), "").unwrap();
        let t = detect_project_type(child.to_str().unwrap());
        assert!(t.contains("Rust"), "child should detect Rust, got: {t}");
        assert!(
            t.contains("Node"),
            "should walk up to git root and detect Node, got: {t}"
        );
    }

    #[test]
    fn test_find_project_root_returns_cwd_when_no_git() {
        let tmp = tempfile::TempDir::new().unwrap();
        let result = find_project_root(tmp.path().to_str().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn test_build_xml_context_git_commit_with_special_chars() {
        let mut ctx = make_minimal_ctx();
        ctx.project_info = ProjectInfo {
            root: Some("/repo".into()),
            project_type: "Rust/Cargo".into(),
            git_branch: Some("feature/add-<thing>".into()),
            git_status: Some("1 changed files".into()),
            git_commits: vec![GitCommit {
                hash: "abc123".into(),
                message: "fix: handle \"edge\" & <corner> cases".into(),
                relative_time: "5 min ago".into(),
            }],
            files: vec![],
        };
        let xml = build_xml_context(&ctx, &Config::default());
        assert!(xml.contains("branch=\"feature/add-&lt;thing&gt;\""));
        assert!(xml.contains("&quot;edge&quot;"));
        assert!(xml.contains("&amp;"));
        assert!(xml.contains("&lt;corner&gt;"));
    }

    #[cfg(unix)]
    #[test]
    fn test_list_project_files_with_ignore_symlinks() {
        let tmp = tempfile::TempDir::new().unwrap();
        std::fs::write(tmp.path().join("real.txt"), "content").unwrap();
        std::os::unix::fs::symlink(tmp.path().join("real.txt"), tmp.path().join("link.txt"))
            .unwrap();
        let entries = list_project_files_with_ignore(tmp.path(), 100).unwrap();
        let link_entry = entries.iter().find(|e| e.path == "link.txt");
        assert!(
            link_entry.is_some(),
            "should list symlink: {:?}",
            entries.iter().map(|e| &e.path).collect::<Vec<_>>()
        );
        assert_eq!(link_entry.unwrap().kind, "symlink");
        assert!(
            link_entry.unwrap().size.is_empty(),
            "symlinks should have empty size"
        );
    }
}
