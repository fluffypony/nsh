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

pub fn build_context(db: &Db, session_id: &str, config: &Config) -> anyhow::Result<QueryContext> {
    let sys = get_cached_system_info();

    let shell = std::env::var("SHELL")
        .unwrap_or_else(|_| "bash".into())
        .rsplit('/')
        .next()
        .unwrap_or("bash")
        .to_string();

    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let username = std::env::var("USER").unwrap_or_else(|_| "unknown".into());

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
    let root = if project_type != "unknown" {
        Some(cwd.to_string())
    } else {
        None
    };

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
    let child = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;

    let timeout = Duration::from_secs(2);
    let args_display = args.join(" ");
    let handle = std::thread::spawn(move || child.wait_with_output());

    let start = Instant::now();
    loop {
        if handle.is_finished() {
            let output = handle.join().ok()?.ok()?;
            if !output.status.success() {
                return None;
            }
            return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
        }
        if start.elapsed() >= timeout {
            tracing::warn!("git command timed out: git {args_display}");
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
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

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let mem = String::new();

    let mut parts = vec![arch.to_string()];
    if cpus > 0 {
        parts.push(format!("{cpus} cores"));
    }
    if !mem.is_empty() {
        parts.push(mem);
    }

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

fn detect_ssh_context() -> Option<String> {
    let ssh_client = std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .ok()?;
    let parts: Vec<&str> = ssh_client.split_whitespace().collect();
    let remote_ip = parts.first().unwrap_or(&"unknown");
    Some(format!("<ssh remote_ip=\"{}\" />", xml_escape(remote_ip)))
}

fn detect_container() -> Option<String> {
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
}
