use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::db::{ConversationExchange, Db};

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
    pub other_tty_context: String,
    pub hostname: String,
    pub machine_info: String,
    pub datetime_info: String,
    pub timezone_info: String,
    pub locale_info: String,
}

pub fn build_context(
    db: &Db,
    session_id: &str,
    config: &Config,
) -> anyhow::Result<QueryContext> {
    let sys = get_cached_system_info();
    let os_info = sys.os_info;

    let shell = std::env::var("SHELL")
        .unwrap_or_else(|_| "bash".into())
        .rsplit('/')
        .next()
        .unwrap_or("bash")
        .to_string();

    let cwd =
        std::env::current_dir()?.to_string_lossy().to_string();

    let username =
        std::env::var("USER").unwrap_or_else(|_| "unknown".into());

    let conversation_history =
        db.get_conversations(session_id, config.context.history_limit)
            .unwrap_or_default();

    let other_cmds = db
        .recent_commands_other_sessions(session_id, 20)
        .unwrap_or_default();

    let other_tty_context = if other_cmds.is_empty() {
        String::new()
    } else {
        let mut ctx = String::new();
        let mut current_tty = String::new();
        for cmd in &other_cmds {
            if cmd.tty != current_tty {
                ctx.push_str(&format!("\n[TTY: {}]\n", cmd.tty));
                current_tty.clone_from(&cmd.tty);
            }
            let status = match cmd.exit_code {
                Some(0) | None => "\u{2713}",
                _ => "\u{2717}",
            };
            ctx.push_str(&format!(
                "  {} {} [{}] {}\n",
                status,
                cmd.command,
                cmd.cwd.as_deref().unwrap_or("?"),
                cmd.started_at,
            ));
        }
        ctx
    };

    let other_tty_context =
        crate::redact::redact_secrets(&other_tty_context, &config.redaction);

    let hostname = sys.hostname;
    let machine_info = sys.machine_info;
    let datetime_info = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z").to_string();
    let timezone_info = sys.timezone_info;
    let locale_info = sys.locale_info;

    Ok(QueryContext {
        os_info,
        shell,
        cwd,
        username,
        conversation_history,
        other_tty_context,
        hostname,
        machine_info,
        datetime_info,
        timezone_info,
        locale_info,
    })
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
