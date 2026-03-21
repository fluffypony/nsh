use std::collections::VecDeque;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Tier 1: Static — effectively never changes during a session.
/// TTL: 300 seconds (5 minutes)
#[derive(Clone, Debug)]
pub struct StaticSystemInfo {
    pub(crate) os_info: String,
    pub(crate) hostname: String,
    pub(crate) machine_details: MachineDetails,
    pub(crate) cpu_model: String,
    pub(crate) gpu_info: String,
    pub(crate) timezone_info: String,
    pub(crate) locale_info: String,
    pub(crate) locale_detail: String,
    pub(crate) cached_at: Instant,
}

/// Tier 2: Semi-dynamic — changes occasionally (new disks mounted, IP changes).
/// TTL: 30 seconds
#[derive(Clone, Debug)]
pub struct SemiDynamicInfo {
    pub(crate) disk_info: Vec<DiskInfo>,
    pub(crate) network_info: Vec<NetworkInterface>,
    pub(crate) uptime: String,
    pub(crate) cached_at: Instant,
}

/// Tier 3: Volatile — changes frequently, rolling window.
/// TTL: 10 seconds per sample, keep last 6 in VecDeque.
#[derive(Clone, Debug)]
pub(crate) struct VolatileInfo {
    pub(crate) cpu_samples: VecDeque<(Instant, f32)>,
    pub(crate) memory_usage: MemoryUsage,
    pub(crate) load_average: String,
    pub(crate) last_sampled: Instant,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DiskInfo {
    pub mount: String,
    pub device: String,
    pub fs_type: String,
    pub total: String,
    pub available: String,
    pub use_pct: String,
    pub free_bytes: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct NetworkInterface {
    pub name: String,
    pub ip: String,
    pub kind: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MemoryUsage {
    pub total: String,
    pub used: String,
    pub available: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct MachineDetails {
    pub arch: String,
    pub cores: usize,
    pub total_ram: String,
    pub pkg_managers: String,
    pub lang_pkg_managers: String,
    pub dev_tools: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StaticSystemInfoSnapshot {
    pub os_info: String,
    pub hostname: String,
    pub machine_details: MachineDetails,
    pub cpu_model: String,
    pub gpu_info: String,
    pub timezone_info: String,
    pub locale_info: String,
    pub locale_detail: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SemiDynamicInfoSnapshot {
    pub disk_info: Vec<DiskInfo>,
    pub network_info: Vec<NetworkInterface>,
    pub uptime: String,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct StaticSystemInfoFile {
    os_info: String,
    hostname: String,
    machine_details: MachineDetails,
    cpu_model: String,
    gpu_info: String,
    timezone_info: String,
    locale_info: String,
    locale_detail: String,
    cached_at_epoch: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SystemInfoBundle {
    pub static_info: StaticSystemInfoSnapshot,
    pub semi_dynamic: SemiDynamicInfoSnapshot,
    pub cpu_samples: String,
    pub memory_usage: MemoryUsage,
    pub load_average: String,
}

// The global daemon (nshd) maintains rolling CPU/memory samples and shared
// static/semi-dynamic caches. When available, sessions query the daemon to
// avoid redundant subprocess spawning across concurrent terminal sessions.
// If the daemon is unreachable, each session falls back to process-local
// detection with identical tiered TTLs.
static STATIC_CACHE: LazyLock<Mutex<Option<StaticSystemInfo>>> = LazyLock::new(|| Mutex::new(None));
static SEMI_DYNAMIC_CACHE: LazyLock<Mutex<Option<SemiDynamicInfo>>> =
    LazyLock::new(|| Mutex::new(None));
pub(crate) static VOLATILE_CACHE: LazyLock<Mutex<Option<VolatileInfo>>> = LazyLock::new(|| Mutex::new(None));

pub(crate) const STATIC_TTL: Duration = Duration::from_secs(300);
pub(crate) const SEMI_DYNAMIC_TTL: Duration = Duration::from_secs(30);
pub(crate) const VOLATILE_TTL: Duration = Duration::from_secs(10);

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl StaticSystemInfo {
    pub(crate) fn to_snapshot(&self) -> StaticSystemInfoSnapshot {
        StaticSystemInfoSnapshot {
            os_info: self.os_info.clone(),
            hostname: self.hostname.clone(),
            machine_details: self.machine_details.clone(),
            cpu_model: self.cpu_model.clone(),
            gpu_info: self.gpu_info.clone(),
            timezone_info: self.timezone_info.clone(),
            locale_info: self.locale_info.clone(),
            locale_detail: self.locale_detail.clone(),
        }
    }
}

impl SemiDynamicInfo {
    pub(crate) fn to_snapshot(&self) -> SemiDynamicInfoSnapshot {
        SemiDynamicInfoSnapshot {
            disk_info: self.disk_info.clone(),
            network_info: self.network_info.clone(),
            uptime: self.uptime.clone(),
        }
    }
}

impl From<&StaticSystemInfo> for StaticSystemInfoFile {
    fn from(value: &StaticSystemInfo) -> Self {
        Self {
            os_info: value.os_info.clone(),
            hostname: value.hostname.clone(),
            machine_details: value.machine_details.clone(),
            cpu_model: value.cpu_model.clone(),
            gpu_info: value.gpu_info.clone(),
            timezone_info: value.timezone_info.clone(),
            locale_info: value.locale_info.clone(),
            locale_detail: value.locale_detail.clone(),
            cached_at_epoch: now_epoch(),
        }
    }
}

impl StaticSystemInfoFile {
    fn into_static_system_info(self) -> StaticSystemInfo {
        StaticSystemInfo {
            os_info: self.os_info,
            hostname: self.hostname,
            machine_details: self.machine_details,
            cpu_model: self.cpu_model,
            gpu_info: self.gpu_info,
            timezone_info: self.timezone_info,
            locale_info: self.locale_info,
            locale_detail: self.locale_detail,
            cached_at: Instant::now(),
        }
    }
}

pub(crate) fn load_or_refresh_static_info() -> StaticSystemInfo {
    let mut cache = STATIC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref cached) = *cache
        && cached.cached_at.elapsed() < STATIC_TTL
    {
        return cached.clone();
    }

    let cache_path = crate::config::Config::nsh_dir()
        .join("cache")
        .join("static_system_info.json");
    if let Ok(contents) = std::fs::read_to_string(&cache_path)
        && let Ok(file_cached) = serde_json::from_str::<StaticSystemInfoFile>(&contents)
        && file_cached.cached_at_epoch + STATIC_TTL.as_secs() > now_epoch()
    {
        let info = file_cached.into_static_system_info();
        let result = info.clone();
        *cache = Some(info);
        return result;
    }

    let fresh = StaticSystemInfo {
        os_info: detect_os(),
        hostname: detect_hostname(),
        machine_details: detect_machine_info(),
        cpu_model: detect_cpu_model(),
        gpu_info: detect_gpu_info(),
        timezone_info: detect_timezone(),
        locale_info: detect_locale(),
        locale_detail: detect_locale_detail(),
        cached_at: Instant::now(),
    };

    if let Some(parent) = cache_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(file) = std::fs::File::create(&cache_path) {
        let _ = serde_json::to_writer(file, &StaticSystemInfoFile::from(&fresh));
    }

    let result = fresh.clone();
    *cache = Some(fresh);
    result
}

#[cfg(test)]
pub(crate) fn load_or_refresh_static_info_for_tests() -> StaticSystemInfo {
    load_or_refresh_static_info()
}

pub(crate) fn load_or_refresh_semi_dynamic_info() -> SemiDynamicInfo {
    let mut cache = SEMI_DYNAMIC_CACHE.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(ref cached) = *cache
        && cached.cached_at.elapsed() < SEMI_DYNAMIC_TTL
    {
        return cached.clone();
    }
    let fresh = SemiDynamicInfo {
        disk_info: detect_disk_info(),
        network_info: detect_network_info(),
        uptime: detect_uptime(),
        cached_at: Instant::now(),
    };
    let result = fresh.clone();
    *cache = Some(fresh);
    result
}

pub(crate) fn load_or_sample_volatile_info() -> (String, MemoryUsage, String) {
    let mut cache = VOLATILE_CACHE.lock().unwrap_or_else(|e| e.into_inner());

    let needs_sample = match &*cache {
        Some(v) => v.last_sampled.elapsed() >= VOLATILE_TTL,
        None => true,
    };

    if needs_sample {
        let cpu_pct = measure_cpu_percent(cache.as_ref());
        let mem = detect_memory_usage();
        let load = detect_load_average();

        let vol = cache.get_or_insert_with(|| VolatileInfo {
            cpu_samples: VecDeque::with_capacity(6),
            memory_usage: mem.clone(),
            load_average: load.clone(),
            last_sampled: Instant::now(),
        });

        vol.cpu_samples.push_back((Instant::now(), cpu_pct));
        while vol.cpu_samples.len() > 6 {
            let _ = vol.cpu_samples.pop_front();
        }
        vol.memory_usage = mem;
        vol.load_average = load;
        vol.last_sampled = Instant::now();
    }

    let vol = cache.as_ref().expect("volatile cache initialized");
    let cpu_str = vol
        .cpu_samples
        .iter()
        .map(|(_, pct)| format!("{pct:.0}%"))
        .collect::<Vec<_>>()
        .join(",");
    (cpu_str, vol.memory_usage.clone(), vol.load_average.clone())
}

pub(crate) fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

/// Re-exported from [`crate::util::xml_escape`] for local convenience.
pub use crate::util::xml_escape;

pub(crate) fn detect_os() -> String {
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

pub(crate) fn detect_shell() -> String {
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

pub(crate) fn detect_hostname() -> String {
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

fn run_command_with_timeout(command: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let mut child = std::process::Command::new(command)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let output = child.wait_with_output().ok()?;
                if !output.status.success() {
                    return None;
                }
                return Some(String::from_utf8_lossy(&output.stdout).trim().to_string());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}

#[cfg(target_os = "linux")]
fn run_shell_with_timeout(script: &str, timeout: Duration) -> Option<String> {
    run_command_with_timeout("sh", &["-c", script], timeout)
}

pub(crate) fn format_size_human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0B".into();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit <= 1 {
        format!("{value:.0}{}", UNITS[unit])
    } else {
        format!("{value:.1}{}", UNITS[unit])
    }
}

fn parse_uptime_seconds(total_seconds: u64) -> String {
    let days = total_seconds / 86_400;
    let hours = (total_seconds % 86_400) / 3_600;
    let minutes = (total_seconds % 3_600) / 60;
    if days > 0 {
        format!("{days} days, {hours}:{minutes:02}")
    } else {
        format!("{hours}:{minutes:02}")
    }
}

pub(crate) fn detect_machine_info() -> MachineDetails {
    let arch = std::env::consts::ARCH.to_string();
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let total_ram = detect_memory_usage().total;

    #[cfg(target_os = "windows")]
    let pkg_mgr_candidates: &[&str] = &["winget", "choco", "scoop"];
    #[cfg(not(target_os = "windows"))]
    let pkg_mgr_candidates: &[&str] = &["brew", "apt", "dnf", "yum", "pacman", "nix", "apk", "pkg"];

    let pkg_managers = pkg_mgr_candidates
        .iter()
        .filter(|cmd| which_exists(cmd))
        .copied()
        .collect::<Vec<_>>()
        .join(", ");

    let lang_pkg_managers = [
        "npm", "npx", "yarn", "pnpm", "bun", "deno", "pip3", "pipx", "uv", "cargo", "rustup",
        "gem", "go", "composer", "dotnet",
    ]
    .iter()
    .filter(|cmd| which_exists(cmd))
    .copied()
    .collect::<Vec<_>>()
    .join(", ");

    #[cfg(target_os = "windows")]
    let dev_tool_candidates: &[&str] = &["node", "python", "rustc", "pwsh", "wsl"];
    #[cfg(not(target_os = "windows"))]
    let dev_tool_candidates: &[&str] = &["node", "python3", "rustc", "ruby", "java"];

    let dev_tools = dev_tool_candidates
        .iter()
        .filter(|cmd| which_exists(cmd))
        .copied()
        .collect::<Vec<_>>()
        .join(", ");

    MachineDetails {
        arch,
        cores,
        total_ram,
        pkg_managers,
        lang_pkg_managers,
        dev_tools,
    }
}

fn detect_cpu_model() -> String {
    #[cfg(target_os = "macos")]
    {
        return run_command_with_timeout(
            "sysctl",
            &["-n", "machdep.cpu.brand_string"],
            Duration::from_secs(2),
        )
        .unwrap_or_default();
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if let Some(name) = line.strip_prefix("model name") {
                    let val = name.split(':').nth(1).unwrap_or("").trim();
                    if !val.is_empty() {
                        return val.to_string();
                    }
                }
            }
        }
        return String::new();
    }
    #[cfg(target_os = "freebsd")]
    {
        return run_command_with_timeout("sysctl", &["-n", "hw.model"], Duration::from_secs(2))
            .unwrap_or_default();
    }
    #[cfg(target_os = "windows")]
    {
        let wmic = run_command_with_timeout(
            "wmic",
            &["cpu", "get", "name", "/value"],
            Duration::from_secs(2),
        );
        if let Some(out) = wmic {
            if let Some(value) = out.lines().find_map(|l| l.strip_prefix("Name=")) {
                return value.trim().to_string();
            }
        }
        return run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor).Name",
            ],
            Duration::from_secs(2),
        )
        .unwrap_or_default();
    }
    #[allow(unreachable_code)]
    String::new()
}

fn detect_gpu_info() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Some(out) = run_command_with_timeout(
            "system_profiler",
            &["SPDisplaysDataType", "-detailLevel", "mini"],
            Duration::from_secs(2),
        ) {
            let mut chipset = String::new();
            let mut vram = String::new();
            for line in out.lines() {
                let trimmed = line.trim();
                if let Some(v) = trimmed.strip_prefix("Chipset Model:") {
                    chipset = v.trim().to_string();
                }
                if let Some(v) = trimmed.strip_prefix("VRAM") {
                    vram = v.split(':').nth(1).unwrap_or("").trim().to_string();
                }
            }
            if !chipset.is_empty() && !vram.is_empty() {
                return format!("{chipset} ({vram})");
            }
            if !chipset.is_empty() {
                return chipset;
            }
        }
        return String::new();
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(out) = run_command_with_timeout(
            "nvidia-smi",
            &["--query-gpu=name", "--format=csv,noheader"],
            Duration::from_secs(2),
        ) {
            let first = out.lines().next().unwrap_or("").trim();
            if !first.is_empty() {
                return first.to_string();
            }
        }
        if let Some(out) = run_shell_with_timeout(
            "lspci 2>/dev/null | grep -Ei 'vga|3d|display'",
            Duration::from_secs(2),
        ) && let Some(line) = out.lines().next()
        {
            return line
                .splitn(3, ':')
                .last()
                .unwrap_or(line)
                .trim()
                .to_string();
        }
        return String::new();
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_command_with_timeout(
            "wmic",
            &["path", "win32_VideoController", "get", "name", "/value"],
            Duration::from_secs(2),
        ) {
            return out
                .lines()
                .find_map(|line| line.strip_prefix("Name=").map(|v| v.trim().to_string()))
                .unwrap_or_default();
        }
        return String::new();
    }
    #[allow(unreachable_code)]
    String::new()
}

pub(crate) fn detect_disk_info() -> Vec<DiskInfo> {
    #[cfg(target_os = "linux")]
    {
        let mut out = Vec::new();
        if let Some(df) = run_command_with_timeout("df", &["-P", "-T"], Duration::from_secs(2)) {
            for line in df.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 7 {
                    continue;
                }
                let device = parts[0].to_string();
                let fs_type = parts[1].to_string();
                let total_kb = parts[2].parse::<u64>().ok();
                let available_kb = parts[4].parse::<u64>().ok();
                let use_pct = parts[5].to_string();
                let mount = parts[6].to_string();
                if !(device.starts_with("/dev/")
                    || fs_type.contains("nfs")
                    || fs_type.contains("smb"))
                {
                    continue;
                }
                if ["tmpfs", "devtmpfs", "squashfs", "overlay"].contains(&fs_type.as_str()) {
                    continue;
                }
                if mount.starts_with("/snap") || mount.contains("docker") {
                    continue;
                }
                let (Some(total_kb), Some(available_kb)) = (total_kb, available_kb) else {
                    continue;
                };
                let total_bytes = total_kb.saturating_mul(1024);
                let free_bytes = available_kb.saturating_mul(1024);
                out.push(DiskInfo {
                    mount,
                    device,
                    fs_type,
                    total: format_size_human(total_bytes),
                    available: format_size_human(free_bytes),
                    use_pct,
                    free_bytes,
                });
            }
        }
        return out;
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        let mut out = Vec::new();
        if let Some(df) = run_command_with_timeout("df", &["-P"], Duration::from_secs(2)) {
            for line in df.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 6 {
                    continue;
                }
                let device = parts[0].to_string();
                let total_kb = parts[1].parse::<u64>().ok();
                let available_kb = parts[3].parse::<u64>().ok();
                let use_pct = parts[4].to_string();
                let mount = parts[5].to_string();
                if !device.starts_with("/dev/") {
                    continue;
                }
                let (Some(total_kb), Some(available_kb)) = (total_kb, available_kb) else {
                    continue;
                };
                let total_bytes = total_kb.saturating_mul(512);
                let free_bytes = available_kb.saturating_mul(512);
                out.push(DiskInfo {
                    mount,
                    device,
                    fs_type: String::new(),
                    total: format_size_human(total_bytes),
                    available: format_size_human(free_bytes),
                    use_pct,
                    free_bytes,
                });
            }
        }
        return out;
    }
    #[cfg(target_os = "windows")]
    {
        let mut out = Vec::new();
        if let Some(ps) = run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-PSDrive -PSProvider FileSystem | ForEach-Object {\"$($_.Name)|$($_.Used)|$($_.Free)\"}",
            ],
            Duration::from_secs(2),
        ) {
            for line in ps.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() != 3 {
                    continue;
                }
                let used = parts[1].trim().parse::<u64>().ok().unwrap_or(0);
                let free = parts[2].trim().parse::<u64>().ok().unwrap_or(0);
                let total = used.saturating_add(free);
                let use_pct = if total > 0 {
                    format!("{}%", (used as f64 * 100.0 / total as f64).round() as u64)
                } else {
                    String::new()
                };
                out.push(DiskInfo {
                    mount: format!("{}:\\", parts[0].trim()),
                    device: parts[0].trim().to_string(),
                    fs_type: String::new(),
                    total: format_size_human(total),
                    available: format_size_human(free),
                    use_pct,
                    free_bytes: free,
                });
            }
        }
        return out;
    }
    #[allow(unreachable_code)]
    Vec::new()
}

fn detect_memory_usage() -> MemoryUsage {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            let mut total_kb = 0_u64;
            let mut available_kb = 0_u64;
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    total_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                }
                if line.starts_with("MemAvailable:") {
                    available_kb = line
                        .split_whitespace()
                        .nth(1)
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                }
            }
            let total = total_kb.saturating_mul(1024);
            let available = available_kb.saturating_mul(1024);
            let used = total.saturating_sub(available);
            return MemoryUsage {
                total: format_size_human(total),
                used: format_size_human(used),
                available: format_size_human(available),
            };
        }
        return MemoryUsage {
            total: String::new(),
            used: String::new(),
            available: String::new(),
        };
    }
    #[cfg(target_os = "macos")]
    {
        let total =
            run_command_with_timeout("sysctl", &["-n", "hw.memsize"], Duration::from_secs(2))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
        let mut available = 0_u64;
        if let Some(vm_stat) = run_command_with_timeout("vm_stat", &[], Duration::from_secs(2)) {
            let page_size = vm_stat
                .lines()
                .next()
                .and_then(|line| line.split("page size of ").nth(1))
                .and_then(|v| v.split(' ').next())
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(4096);
            let mut pages = 0_u64;
            for line in vm_stat.lines() {
                if line.starts_with("Pages free")
                    || line.starts_with("Pages inactive")
                    || line.starts_with("Pages speculative")
                {
                    let count = line
                        .split(':')
                        .nth(1)
                        .map(|v| v.trim().trim_end_matches('.'))
                        .and_then(|v| v.parse::<u64>().ok())
                        .unwrap_or(0);
                    pages = pages.saturating_add(count);
                }
            }
            available = pages.saturating_mul(page_size);
        }
        let used = total.saturating_sub(available);
        return MemoryUsage {
            total: format_size_human(total),
            used: format_size_human(used),
            available: format_size_human(available),
        };
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_OperatingSystem) | ForEach-Object {\"$($_.TotalVisibleMemorySize)|$($_.FreePhysicalMemory)\"}",
            ],
            Duration::from_secs(2),
        ) {
            let parts: Vec<&str> = out.trim().split('|').collect();
            if parts.len() == 2 {
                let total = parts[0]
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .unwrap_or(0)
                    .saturating_mul(1024);
                let free = parts[1]
                    .trim()
                    .parse::<u64>()
                    .ok()
                    .unwrap_or(0)
                    .saturating_mul(1024);
                let used = total.saturating_sub(free);
                return MemoryUsage {
                    total: format_size_human(total),
                    used: format_size_human(used),
                    available: format_size_human(free),
                };
            }
        }
        return MemoryUsage {
            total: String::new(),
            used: String::new(),
            available: String::new(),
        };
    }
    #[allow(unreachable_code)]
    MemoryUsage {
        total: String::new(),
        used: String::new(),
        available: String::new(),
    }
}

pub(crate) fn detect_load_average() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(loadavg) = std::fs::read_to_string("/proc/loadavg") {
            let parts: Vec<&str> = loadavg.split_whitespace().take(3).collect();
            if parts.len() == 3 {
                return parts.join(" ");
            }
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        if let Some(out) =
            run_command_with_timeout("sysctl", &["-n", "vm.loadavg"], Duration::from_secs(2))
        {
            let trimmed = out
                .trim()
                .trim_matches('{')
                .trim_matches('}')
                .replace('"', "");
            let parts: Vec<&str> = trimmed.split_whitespace().take(3).collect();
            if parts.len() == 3 {
                return parts.join(" ");
            }
        }
    }
    if let Some(out) = run_command_with_timeout("uptime", &[], Duration::from_secs(2))
        && let Some(idx) = out.find("load average")
    {
        return out[idx..]
            .split(':')
            .nth(1)
            .map(|s| s.trim().replace(",", ""))
            .unwrap_or_default();
    }
    String::new()
}

fn classify_interface(name: &str) -> String {
    let n = name.to_lowercase();
    if n == "lo" || n.starts_with("lo") {
        "loopback".into()
    } else if n.starts_with("utun") || n.starts_with("tun") || n.starts_with("wg") {
        "vpn".into()
    } else if n.starts_with("wlan") || n.starts_with("wl") || n.starts_with("wifi") {
        "wifi".into()
    } else if n.starts_with("eth") || n.starts_with("enp") || n.starts_with("eno") {
        "ethernet".into()
    } else if n.starts_with("en") {
        "wifi".into()
    } else {
        "unknown".into()
    }
}

fn is_filtered_ip(ip: &str) -> bool {
    ip.starts_with("127.") || ip.starts_with("169.254.") || ip.starts_with("fe80:")
}

fn detect_network_info() -> Vec<NetworkInterface> {
    #[cfg(target_os = "linux")]
    {
        let mut entries = Vec::new();
        if let Some(out) =
            run_shell_with_timeout("ip -brief addr 2>/dev/null", Duration::from_secs(2))
        {
            for line in out.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 3 {
                    continue;
                }
                let name = parts[0].to_string();
                for token in &parts[2..] {
                    let ip = token.split('/').next().unwrap_or("").trim();
                    if ip.is_empty() || ip.contains(':') || is_filtered_ip(ip) {
                        continue;
                    }
                    entries.push(NetworkInterface {
                        name: name.clone(),
                        ip: ip.to_string(),
                        kind: classify_interface(&name),
                    });
                    break;
                }
            }
        }
        entries.truncate(5);
        return entries;
    }
    #[cfg(target_os = "macos")]
    {
        let mut entries = Vec::new();
        if let Some(out) = run_command_with_timeout("ifconfig", &[], Duration::from_secs(2)) {
            let mut current_if = String::new();
            for line in out.lines() {
                if !line.starts_with('\t') && line.contains(':') {
                    current_if = line.split(':').next().unwrap_or("").to_string();
                } else if line.trim_start().starts_with("inet ") {
                    let ip = line
                        .split_whitespace()
                        .nth(1)
                        .unwrap_or("")
                        .trim()
                        .to_string();
                    if ip.is_empty() || is_filtered_ip(&ip) {
                        continue;
                    }
                    entries.push(NetworkInterface {
                        name: current_if.clone(),
                        ip,
                        kind: classify_interface(&current_if),
                    });
                }
            }
        }
        entries.truncate(5);
        return entries;
    }
    #[cfg(target_os = "windows")]
    {
        let mut entries = Vec::new();
        if let Some(out) = run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "Get-NetIPAddress -AddressFamily IPv4 | ForEach-Object {\"$($_.InterfaceAlias)|$($_.IPAddress)\"}",
            ],
            Duration::from_secs(2),
        ) {
            for line in out.lines() {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() != 2 {
                    continue;
                }
                let ip = parts[1].trim();
                if ip.is_empty() || is_filtered_ip(ip) {
                    continue;
                }
                let name = parts[0].trim().to_string();
                entries.push(NetworkInterface {
                    kind: classify_interface(&name),
                    name,
                    ip: ip.to_string(),
                });
            }
        }
        entries.truncate(5);
        return entries;
    }
    #[allow(unreachable_code)]
    Vec::new()
}

pub(crate) fn detect_locale_detail() -> String {
    #[cfg(not(target_os = "windows"))]
    {
        let fallback = std::env::var("LC_ALL")
            .ok()
            .filter(|v| !v.is_empty())
            .or_else(|| std::env::var("LANG").ok())
            .unwrap_or_default();
        let parts = ["LC_TIME", "LC_NUMERIC", "LC_MONETARY", "LC_COLLATE"]
            .iter()
            .filter_map(|key| {
                let value = std::env::var(key).ok().filter(|v| !v.is_empty());
                let value = value.or_else(|| {
                    if fallback.is_empty() {
                        None
                    } else {
                        Some(fallback.clone())
                    }
                })?;
                Some(format!("{key}={value}"))
            })
            .collect::<Vec<_>>();
        return parts.join(" ");
    }
    #[cfg(target_os = "windows")]
    {
        return run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "$c = Get-Culture; \"LC_TIME=$($c.Name) LC_NUMERIC=$($c.NumberFormat.NumberDecimalSeparator)\"",
            ],
            Duration::from_secs(2),
        )
        .unwrap_or_default();
    }
    #[allow(unreachable_code)]
    String::new()
}

fn detect_uptime() -> String {
    #[cfg(target_os = "linux")]
    {
        if let Ok(raw) = std::fs::read_to_string("/proc/uptime")
            && let Some(first) = raw.split_whitespace().next()
            && let Ok(secs) = first.parse::<f64>()
        {
            return parse_uptime_seconds(secs as u64);
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        if let Some(out) =
            run_command_with_timeout("sysctl", &["-n", "kern.boottime"], Duration::from_secs(2))
            && let Some(sec_field) = out.split(',').find(|f| f.contains("sec"))
            && let Some(sec_str) = sec_field.split('=').nth(1)
            && let Ok(boot_secs) = sec_str.trim().parse::<u64>()
        {
            let now = now_epoch();
            if now > boot_secs {
                return parse_uptime_seconds(now - boot_secs);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(New-TimeSpan -Start (Get-CimInstance Win32_OperatingSystem).LastBootUpTime -End (Get-Date)).TotalSeconds",
            ],
            Duration::from_secs(2),
        ) && let Ok(secs) = out.trim().parse::<f64>()
        {
            return parse_uptime_seconds(secs as u64);
        }
    }
    if let Some(out) = run_command_with_timeout("uptime", &[], Duration::from_secs(2)) {
        return out;
    }
    String::new()
}

fn measure_cpu_percent(_existing: Option<&VolatileInfo>) -> f32 {
    #[cfg(target_os = "linux")]
    {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as f32)
            .unwrap_or(1.0);
        let load1 = detect_load_average()
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0.0);
        return (load1 / cores * 100.0).clamp(0.0, 100.0);
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(out) =
            run_command_with_timeout("top", &["-l", "1", "-n", "0"], Duration::from_secs(2))
            && let Some(line) = out.lines().find(|l| l.contains("CPU usage"))
        {
            let user = line
                .split('%')
                .next()
                .and_then(|prefix| prefix.split_whitespace().last())
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            let sys = line
                .split("sys")
                .next()
                .and_then(|prefix| prefix.split_whitespace().last())
                .and_then(|v| v.parse::<f32>().ok())
                .unwrap_or(0.0);
            return (user + sys).clamp(0.0, 100.0);
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(out) = run_command_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor).LoadPercentage",
            ],
            Duration::from_secs(2),
        ) && let Ok(v) = out.trim().parse::<f32>()
        {
            return v.clamp(0.0, 100.0);
        }
    }
    0.0
}

pub(crate) fn which_exists(cmd: &str) -> bool {
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

pub(crate) fn detect_locale() -> String {
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

pub(crate) fn detect_ssh_context() -> Option<String> {
    let ssh_client = std::env::var("SSH_CLIENT")
        .or_else(|_| std::env::var("SSH_CONNECTION"))
        .ok()?;
    let parts: Vec<&str> = ssh_client.split_whitespace().collect();
    let remote_ip = parts.first().unwrap_or(&"unknown");
    Some(format!("<ssh remote_ip=\"{}\" />", xml_escape(remote_ip)))
}

pub(crate) fn detect_container() -> Option<String> {
    #[cfg(not(unix))]
    {
        return None;
    }

    if std::path::Path::new("/.dockerenv").exists() {
        return Some("<container type=\"docker\" />".into());
    }
    if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup")
        && (cgroup.contains("docker") || cgroup.contains("containerd"))
    {
        return Some("<container type=\"docker\" />".into());
    }
    None
}

pub(crate) fn detect_timezone() -> String {
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

