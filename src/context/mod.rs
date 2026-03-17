//! Environmental context building for LLM queries.
//!
//! Organized by domain:
//! - `system_info`: System detection (OS, hardware, network) + tiered caching
//! - `project`: Project detection, git info, file listing
//! - This module: QueryContext types, build_context, build_xml_context

pub(crate) mod project;
pub(crate) mod system_info;

use std::time::{Duration, Instant};

use crate::config::Config;
use crate::daemon_db::DbAccess;
use crate::db::{CommandWithSummary, ConversationExchange, OtherSessionSummary};

pub use system_info::{
    DiskInfo, MachineDetails, MemoryUsage, NetworkInterface, SemiDynamicInfo,
    SemiDynamicInfoSnapshot, StaticSystemInfo, StaticSystemInfoSnapshot, SystemInfoBundle,
    xml_escape,
};
pub(crate) use system_info::{
    load_or_refresh_semi_dynamic_info, load_or_refresh_static_info, load_or_sample_volatile_info,
};
use system_info::{detect_container, detect_shell, detect_ssh_context};
use project::{collect_cwd_listing, detect_project_info};

pub struct EnvironmentContext {
    pub os_info: String,
    pub hostname: String,
    pub datetime_info: String,
    pub timezone_info: String,
    pub locale_info: String,
    pub locale_detail: String,
    pub machine_details: MachineDetails,
    pub cpu_model: String,
    pub gpu_info: String,
    pub disk_info: Vec<DiskInfo>,
    pub memory_usage: MemoryUsage,
    pub load_average: String,
    pub cpu_samples: String,
    pub network_info: Vec<NetworkInterface>,
    pub uptime: String,
}

pub struct TerminalContext {
    pub shell: String,
    pub cwd: String,
    pub username: String,
    pub cwd_listing: Vec<CwdListingEntry>,
    pub scrollback_text: String,
}

pub struct HistoryContext {
    pub conversation_history: Vec<ConversationExchange>,
    pub session_history: Vec<CommandWithSummary>,
    pub other_sessions: Vec<OtherSessionSummary>,
}

pub struct QueryContext {
    pub environment: EnvironmentContext,
    pub terminal: TerminalContext,
    pub history: HistoryContext,
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

pub struct CwdListingEntry {
    pub path: String,
    pub kind: String,
}

pub fn build_context(
    db: &dyn DbAccess,
    session_id: &str,
    config: &Config,
) -> anyhow::Result<QueryContext> {
    let (static_info, semi_dynamic, cpu_samples, memory_usage, load_average) =
        match crate::daemon_client::get_system_info() {
            Ok(daemon_data) => (
                StaticSystemInfo {
                    os_info: daemon_data.static_info.os_info,
                    hostname: daemon_data.static_info.hostname,
                    machine_details: daemon_data.static_info.machine_details,
                    cpu_model: daemon_data.static_info.cpu_model,
                    gpu_info: daemon_data.static_info.gpu_info,
                    timezone_info: daemon_data.static_info.timezone_info,
                    locale_info: daemon_data.static_info.locale_info,
                    locale_detail: daemon_data.static_info.locale_detail,
                    cached_at: Instant::now(),
                },
                SemiDynamicInfo {
                    disk_info: daemon_data.semi_dynamic.disk_info,
                    network_info: daemon_data.semi_dynamic.network_info,
                    uptime: daemon_data.semi_dynamic.uptime,
                    cached_at: Instant::now(),
                },
                daemon_data.cpu_samples,
                daemon_data.memory_usage,
                daemon_data.load_average,
            ),
            Err(_) => {
                let s = load_or_refresh_static_info();
                let sd = load_or_refresh_semi_dynamic_info();
                let (cpu_s, mem, load) = load_or_sample_volatile_info();
                (s, sd, cpu_s, mem, load)
            }
        };

    let shell = detect_shell();

    let cwd = std::env::current_dir()?.to_string_lossy().to_string();
    let username = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());

    let conversation_history = db
        .get_conversations(session_id, config.context.history_limit)
        .unwrap_or_default();

    let cwd_listing = collect_cwd_listing(&cwd, 100);

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
        environment: EnvironmentContext {
            os_info: static_info.os_info,
            hostname: static_info.hostname,
            datetime_info: chrono::Local::now()
                .format("%Y-%m-%d %H:%M:%S %Z")
                .to_string(),
            timezone_info: static_info.timezone_info,
            locale_info: static_info.locale_info,
            locale_detail: static_info.locale_detail,
            machine_details: static_info.machine_details,
            cpu_model: static_info.cpu_model,
            gpu_info: static_info.gpu_info,
            disk_info: semi_dynamic.disk_info,
            memory_usage,
            load_average,
            cpu_samples,
            network_info: semi_dynamic.network_info,
            uptime: semi_dynamic.uptime,
        },
        terminal: TerminalContext {
            shell,
            cwd,
            username,
            cwd_listing,
            scrollback_text,
        },
        history: HistoryContext {
            conversation_history,
            session_history,
            other_sessions,
        },
        custom_instructions,
        project_info,
        ssh_context,
        container_context,
    })
}

pub fn build_xml_context(ctx: &QueryContext, config: &Config) -> String {
    let env = &ctx.environment;
    let terminal = &ctx.terminal;
    let history = &ctx.history;
    let mut xml = String::from("<context>\n");

    // Environment
    xml.push_str("  <environment>\n");
    xml.push_str(&format!(
        "    <system os=\"{}\" shell=\"{}\" cwd=\"{}\" user=\"{}\" hostname=\"{}\" />\n",
        xml_escape(&env.os_info),
        xml_escape(&terminal.shell),
        xml_escape(&terminal.cwd),
        xml_escape(&terminal.username),
        xml_escape(&env.hostname),
    ));
    xml.push_str(&format!(
        "    <temporal datetime=\"{}\" timezone=\"{}\" uptime=\"{}\" />\n",
        xml_escape(&env.datetime_info),
        xml_escape(&env.timezone_info),
        xml_escape(&env.uptime),
    ));
    xml.push_str(&format!(
        "    <locale lang=\"{}\"",
        xml_escape(&env.locale_info),
    ));
    if !env.locale_detail.is_empty() {
        xml.push_str(&format!(" detail=\"{}\"", xml_escape(&env.locale_detail)));
    }
    xml.push_str(" />\n");
    xml.push_str(&format!(
        "    <hardware cpu=\"{}\" arch=\"{}\" cores=\"{}\" ram_total=\"{}\"",
        xml_escape(&env.cpu_model),
        xml_escape(&env.machine_details.arch),
        env.machine_details.cores,
        xml_escape(&env.machine_details.total_ram),
    ));
    if !env.gpu_info.is_empty() {
        xml.push_str(&format!(" gpu=\"{}\"", xml_escape(&env.gpu_info)));
    }
    xml.push_str(" />\n");
    xml.push_str(&format!(
        "    <utilization load_avg=\"{}\" memory_used=\"{}\" memory_available=\"{}\"",
        xml_escape(&env.load_average),
        xml_escape(&env.memory_usage.used),
        xml_escape(&env.memory_usage.available),
    ));
    if !env.cpu_samples.is_empty() {
        xml.push_str(&format!(
            " cpu_samples=\"{}\"",
            xml_escape(&env.cpu_samples)
        ));
    }
    xml.push_str(" />\n");

    if !env.disk_info.is_empty() {
        xml.push_str("    <disks>\n");
        for disk in &env.disk_info {
            xml.push_str(&format!(
                "      <disk mount=\"{}\" fs=\"{}\" total=\"{}\" available=\"{}\" use_pct=\"{}\" />\n",
                xml_escape(&disk.mount),
                xml_escape(&disk.fs_type),
                xml_escape(&disk.total),
                xml_escape(&disk.available),
                xml_escape(&disk.use_pct),
            ));
        }
        xml.push_str("    </disks>\n");
    }

    if !env.network_info.is_empty() {
        xml.push_str("    <network>\n");
        for iface in &env.network_info {
            xml.push_str(&format!(
                "      <iface name=\"{}\" ip=\"{}\" type=\"{}\" />\n",
                xml_escape(&iface.name),
                xml_escape(&iface.ip),
                xml_escape(&iface.kind),
            ));
        }
        xml.push_str("    </network>\n");
    }

    xml.push_str(&format!(
        "    <tools pkg=\"{}\" lang_pkg=\"{}\" dev=\"{}\" />\n",
        xml_escape(&env.machine_details.pkg_managers),
        xml_escape(&env.machine_details.lang_pkg_managers),
        xml_escape(&env.machine_details.dev_tools),
    ));
    xml.push_str("  </environment>\n");

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
            let files_limit = config.context.project_files_limit;
            let files_truncated = ctx.project_info.files.len() >= files_limit;
            xml.push_str(&format!(
                "    <files count=\"{}\" limit=\"{}\" truncated=\"{}\">\n",
                ctx.project_info.files.len(),
                files_limit,
                files_truncated,
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

    // CWD listing (hidden + recursive, capped)
    let cwd_limit = 100;
    let cwd_truncated = terminal.cwd_listing.len() >= cwd_limit;
    xml.push_str(&format!(
        "\n  <cwd_listing path=\"{}\" count=\"{}\" recursive=\"true\" max_entries=\"{}\" truncated=\"{}\">\n",
        xml_escape(&terminal.cwd),
        terminal.cwd_listing.len(),
        cwd_limit,
        cwd_truncated,
    ));
    for entry in &terminal.cwd_listing {
        xml.push_str(&format!(
            "    <entry path=\"{}\" type=\"{}\" />\n",
            xml_escape(&entry.path),
            xml_escape(&entry.kind),
        ));
    }
    xml.push_str("  </cwd_listing>\n");

    // Scrollback
    if !terminal.scrollback_text.is_empty() {
        let redacted = crate::redact::redact_secrets(&terminal.scrollback_text, &config.redaction);
        xml.push_str(&format!(
            "\n  <recent_terminal session=\"current\">\n{}\n  </recent_terminal>\n",
            xml_escape(&redacted),
        ));
    }

    // Session history with summaries
    if !history.session_history.is_empty() {
        let tty = std::env::var("NSH_TTY").unwrap_or_default();
        xml.push_str(&format!(
            "\n  <session_history tty=\"{}\" count=\"{}\">\n",
            xml_escape(&tty),
            history.session_history.len(),
        ));
        for cmd in &history.session_history {
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
            if let Some(ref output) = cmd.output
                && !output.trim().is_empty()
            {
                let truncated =
                    crate::util::truncate(output, config.context.max_output_context_chars);
                let redacted = crate::redact::redact_secrets(&truncated, &config.redaction);
                xml.push_str(&format!(
                    "      <output>{}</output>\n",
                    xml_escape(&redacted),
                ));
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

    // Recent nsh queries (conversation exchanges in this session)
    if !history.conversation_history.is_empty() {
        xml.push_str(&format!(
            "\n  <recent_nsh_queries session=\"current\" count=\"{}\" note=\"These are recent AI assistant interactions in this session. Use for conversational continuity and self-correction.\">\n",
            history.conversation_history.len(),
        ));
        // conversation_history is already in chronological order (oldest first)
        for exchange in history.conversation_history.iter() {
            let ts_attr = exchange
                .created_at
                .as_ref()
                .map(|t| format!(" ts=\"{}\"", xml_escape(t)))
                .unwrap_or_default();
            let result_attr = exchange
                .result_exit_code
                .map(|c| format!(" result_exit_code=\"{c}\""))
                .unwrap_or_default();
            let response_preview = crate::util::truncate(
                &crate::redact::redact_secrets(&exchange.response, &config.redaction),
                500,
            );
            xml.push_str(&format!(
                "    <exchange type=\"{}\"{ts_attr}{result_attr}>\n      <user_query>{}</user_query>\n      <assistant_response>{}</assistant_response>\n    </exchange>\n",
                xml_escape(exchange.response_type.as_str()),
                xml_escape(&crate::redact::redact_secrets(&exchange.query, &config.redaction)),
                xml_escape(&response_preview),
            ));
        }
        xml.push_str("  </recent_nsh_queries>\n");
    }

    // Other sessions
    if !history.other_sessions.is_empty() {
        xml.push_str("\n  <other_sessions>\n");
        let mut current_tty = String::new();
        let mut session_open = false;
        for cmd in &history.other_sessions {
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
    let fallback_daemon_socket = crate::daemon::daemon_socket_path("default");

    let max_lines = config.context.scrollback_pages * 24;

    #[cfg(unix)]
    let daemon_available = daemon_socket.exists();
    #[cfg(unix)]
    let fallback_daemon_available = session_id != "default" && fallback_daemon_socket.exists();
    #[cfg(not(unix))]
    let daemon_available = false;
    #[cfg(not(unix))]
    let fallback_daemon_available = false;

    let raw_text = if daemon_available {
        let request = crate::daemon::DaemonRequest::Scrollback { max_lines };
        match crate::daemon_client::send_request(session_id, &request) {
            Ok(crate::daemon::DaemonResponse::Ok { data: Some(d) }) => {
                d["scrollback"].as_str().unwrap_or("").to_string()
            }
            _ => read_scrollback_file(session_id, &nsh_dir),
        }
    } else if fallback_daemon_available {
        let request = crate::daemon::DaemonRequest::Scrollback { max_lines };
        match crate::daemon_client::send_request("default", &request) {
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
    } else if session_id != "default" {
        let fallback = nsh_dir.join("scrollback_default");
        if fallback.exists() {
            std::fs::read_to_string(fallback).unwrap_or_default()
        } else {
            String::new()
        }
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

fn instruction_candidates() -> &'static [&'static str] {
    &[
        "AGENTS.md",
        "AGENT.md",
        "CLAUDE.md",
        "CLAUDE.local.md",
        ".claude/instructions.md",
        "GEMINI.md",
        "COPILOT.md",
        ".github/copilot-instructions.md",
        ".cursorrules",
        ".cursor/rules",
        ".clinerules/rules",
        ".roorules/rules",
        "CONVENTIONS.md",
        "AI.md",
        "LLM.md",
        ".ai/instructions.md",
        ".nsh/instructions.md",
    ]
}

fn gather_instruction_file_contents(base_dir: &std::path::Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for rel in instruction_candidates() {
        let candidate = base_dir.join(rel);
        if !candidate.exists() {
            continue;
        }

        if candidate.is_file() {
            if let Ok(raw) = std::fs::read_to_string(&candidate) {
                let trimmed = raw.trim();
                if !trimmed.is_empty() {
                    out.push((candidate.to_string_lossy().to_string(), trimmed.to_string()));
                }
            }
            continue;
        }

        if candidate.is_dir() {
            let mut files = Vec::new();
            let walker = ignore::WalkBuilder::new(&candidate)
                .hidden(false)
                .git_ignore(false)
                .git_global(false)
                .max_depth(Some(4))
                .sort_by_file_name(|a, b| a.cmp(b))
                .build();
            for entry in walker.flatten() {
                if entry.file_type().is_some_and(|ft| ft.is_file()) {
                    files.push(entry.into_path());
                }
            }
            files.sort();
            for path in files {
                if let Ok(raw) = std::fs::read_to_string(&path) {
                    let trimmed = raw.trim();
                    if !trimmed.is_empty() {
                        out.push((path.to_string_lossy().to_string(), trimmed.to_string()));
                    }
                }
            }
        }
    }
    out
}

pub(crate) fn gather_custom_instructions(config: &Config, cwd: &str) -> Option<String> {
    let mut chunks = Vec::new();

    if let Some(global) = config.context.custom_instructions.clone() {
        chunks.push(global);
    }

    let mut scan_roots = Vec::new();
    if let Some(root) = find_git_root(cwd) {
        scan_roots.push(root);
    }
    let cwd_path = std::path::PathBuf::from(cwd);
    if !scan_roots.iter().any(|p| p == &cwd_path) {
        scan_roots.push(cwd_path);
    }

    let mut seen_paths = std::collections::HashSet::new();
    for root in scan_roots {
        for (path, content) in gather_instruction_file_contents(&root) {
            if !seen_paths.insert(path.clone()) {
                continue;
            }
            chunks.push(format!("--- {path} ---\n{content}"));
        }
    }

    if chunks.is_empty() {
        return None;
    }

    let joined = chunks.join("\n\n");
    if joined.chars().count() <= 8192 {
        Some(joined)
    } else {
        let truncated: String = joined.chars().take(8192).collect();
        Some(format!(
            "{truncated}\n\n[custom instructions truncated to 8192 characters]"
        ))
    }
}


#[cfg(test)]
mod tests;
