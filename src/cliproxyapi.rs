//! CLIProxyAPI Plus sidecar lifecycle and helpers.
//!
//! Minimal integration to enable routing providers through a local
//! OpenAI-compatible endpoint exposed by the sidecar.
//! This module intentionally keeps configuration light so it can be
//! introduced without broad config schema changes. It uses `~/.nsh` for
//! path state and simple files for pid/port/version.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

pub const CLIPROXYAPI_RELEASES_URL: &str =
    "https://api.github.com/repos/router-for-me/CLIProxyAPIPlus/releases/latest";

// ── Path helpers ─────────────────────────────────────────────────────────────

pub fn nsh_dir() -> PathBuf {
    crate::config::Config::nsh_dir()
}

pub fn bin_dir() -> PathBuf {
    nsh_dir().join("bin")
}

pub fn exe_path() -> PathBuf {
    #[cfg(windows)]
    { bin_dir().join("cliproxyapi.exe") }
    #[cfg(not(windows))]
    { bin_dir().join("cliproxyapi") }
}

pub fn port_file() -> PathBuf {
    nsh_dir().join("cliproxyapi.port")
}

pub fn pid_file() -> PathBuf {
    nsh_dir().join("cliproxyapi.pid")
}

pub fn version_file() -> PathBuf {
    nsh_dir().join("cliproxyapi.version")
}

pub fn config_file() -> PathBuf {
    nsh_dir().join("cliproxyapi-config.yaml")
}

pub fn auth_dir() -> PathBuf {
    nsh_dir().join("cliproxyapi-auth")
}

pub fn log_file() -> PathBuf {
    let logs = nsh_dir().join("logs");
    let _ = std::fs::create_dir_all(&logs);
    logs.join("cliproxyapi.log")
}

pub fn last_check_file() -> PathBuf {
    nsh_dir().join("cliproxyapi-last-check")
}

// ── Platform detection ───────────────────────────────────────────────────────

/// Map host platform to asset name fragment used by releases.
pub fn detect_platform_asset() -> Option<String> {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let target = match (os, arch) {
        ("macos", "aarch64") => "darwin-arm64",
        ("macos", "x86_64") => "darwin-amd64",
        ("linux", "x86_64") => "linux-amd64",
        ("linux", "aarch64") => "linux-arm64",
        ("windows", "x86_64") => "windows-amd64.exe",
        ("windows", "aarch64") => "windows-arm64.exe",
        _ => return None,
    };
    Some(target.to_string())
}

// ── Update checking and install ─────────────────────────────────────────────

/// Check GitHub for a newer sidecar release. Returns (url, tag) if newer.
pub async fn check_for_update() -> Result<Option<(String, String)>> {
    let client = reqwest::Client::builder()
        .user_agent("nsh-daemon")
        .timeout(Duration::from_secs(30))
        .build()?;

    let resp = client
        .get(CLIPROXYAPI_RELEASES_URL)
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    let new_version = resp["tag_name"].as_str().unwrap_or("").to_string();
    if new_version.is_empty() {
        return Ok(None);
    }
    let current_version = std::fs::read_to_string(version_file()).unwrap_or_default();
    if new_version.trim() == current_version.trim() {
        return Ok(None);
    }

    let target = match detect_platform_asset() {
        Some(t) => t,
        None => return Ok(None),
    };

    let empty: Vec<serde_json::Value> = Vec::new();
    let assets = resp["assets"].as_array().unwrap_or(&empty);
    let asset = match assets.iter().find(|a| {
        a["name"].as_str().unwrap_or("").contains(&target)
    }) {
        Some(a) => a,
        None => return Ok(None),
    };
    let url = asset["browser_download_url"].as_str().unwrap_or("").to_string();
    if url.is_empty() {
        return Ok(None);
    }
    Ok(Some((url, new_version)))
}

/// Download and write the sidecar binary atomically.
pub async fn download_and_install(url: &str, version: &str) -> Result<PathBuf> {
    let client = reqwest::Client::builder()
        .user_agent("nsh-daemon")
        .timeout(Duration::from_secs(120))
        .build()?;
    std::fs::create_dir_all(bin_dir())?;
    let dest = exe_path();
    let tmp_path = dest.with_extension("tmp");
    let bytes = client.get(url).send().await?.bytes().await?;

    // If a tarball, try to extract the binary entry; else write directly
    if url.ends_with(".tar.gz") || url.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(&bytes[..]);
        let mut archive = tar::Archive::new(decoder);
        let mut written = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?.to_path_buf();
            if path
                .file_name()
                .map(|n| {
                    let s = n.to_string_lossy();
                    s.starts_with("CLIProxyAPI") || s == "cliproxyapi" || s == "cli-proxy-api"
                })
                .unwrap_or(false)
            {
                let mut file = std::fs::File::create(&tmp_path)?;
                std::io::copy(&mut entry, &mut file)?;
                written = true;
                break;
            }
        }
        if !written {
            anyhow::bail!("sidecar binary not found in archive");
        }
    } else {
        std::fs::write(&tmp_path, &bytes)?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755));
    }

    std::fs::rename(&tmp_path, &dest)?;
    let _ = std::fs::write(version_file(), version);
    let _ = std::fs::write(last_check_file(), chrono::Utc::now().to_rfc3339());
    Ok(dest)
}

pub fn is_installed() -> bool { exe_path().exists() }

// ── Port helpers ────────────────────────────────────────────────────────────

pub fn pick_random_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

pub fn get_port() -> Option<u16> {
    std::fs::read_to_string(port_file())
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

/// Convenience base URL like `http://127.0.0.1:{port}/v1`.
pub fn base_url() -> Option<String> { get_port().map(|p| format!("http://127.0.0.1:{p}/v1")) }

// ── Config file ─────────────────────────────────────────────────────────────

pub fn generate_config(port: u16) -> Result<PathBuf> {
    let auth = auth_dir();
    std::fs::create_dir_all(&auth)?;
    let path = config_file();
    let content = format!(
        r#"host: "127.0.0.1"
port: {port}
auth-dir: "{}"
api-keys:
  - "nsh-internal"
debug: false
"#,
        auth.display()
    );
    std::fs::write(&path, content)?;
    Ok(path)
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

pub fn start_sidecar(port: u16) -> Result<Child> {
    let exe = exe_path();
    if !exe.exists() {
        anyhow::bail!("CLIProxyAPI binary not found at {}", exe.display());
    }
    let cfg = generate_config(port)?;
    let log = log_file();
    let out = std::fs::File::create(&log)?;
    let err = out.try_clone()?;
    let child = Command::new(&exe)
        .arg("--config")
        .arg(&cfg)
        .arg("--port")
        .arg(port.to_string())
        .stdout(std::process::Stdio::from(out))
        .stderr(std::process::Stdio::from(err))
        .spawn()
        .context("Failed to spawn CLIProxyAPI")?;
    let _ = std::fs::write(pid_file(), child.id().to_string());
    let _ = std::fs::write(port_file(), port.to_string());
    Ok(child)
}

pub fn stop_sidecar() -> Result<()> {
    if let Ok(pid_str) = std::fs::read_to_string(pid_file()) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            #[cfg(unix)]
            unsafe { libc::kill(pid, libc::SIGTERM); }
            #[cfg(windows)]
            {
                let _ = Command::new("taskkill").args(["/PID", &pid.to_string(), "/F"]).output();
            }
        }
    }
    let _ = std::fs::remove_file(pid_file());
    let _ = std::fs::remove_file(port_file());
    Ok(())
}

pub fn is_sidecar_running() -> bool {
    if let Ok(pid_str) = std::fs::read_to_string(pid_file()) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            #[cfg(unix)]
            unsafe { return libc::kill(pid, 0) == 0; }
            #[cfg(not(unix))]
            { return port_file().exists(); }
        }
    }
    false
}

pub fn ensure_running() -> Result<u16> {
    if is_sidecar_running() {
        if let Some(p) = get_port() { return Ok(p); }
    }
    let port = pick_random_port()?;
    let _ = start_sidecar(port)?;
    Ok(port)
}

// ── Health check / simple test ─────────────────────────────────────────────

pub async fn health_check(port: u16) -> bool {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/v1/models");
    client
        .get(&url)
        .header("Authorization", "Bearer nsh-internal")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

pub async fn test_provider(port: u16, model: &str) -> Result<bool> {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{port}/v1/chat/completions");
    let body = serde_json::json!({
        "model": model,
        "messages": [{"role": "user", "content": "Say ok"}],
        "max_tokens": 5,
    });
    let resp = client
        .post(&url)
        .header("Authorization", "Bearer nsh-internal")
        .json(&body)
        .timeout(Duration::from_secs(15))
        .send()
        .await?;
    Ok(resp.status().is_success())
}

// ── OAuth login flag mapping and runner ─────────────────────────────────────

pub fn login_flag_for_provider(provider: &str) -> Option<&'static str> {
    match provider {
        "copilot" => Some("--github-copilot-login"),
        "claude_sub" => Some("--claude-login"),
        "codex_sub" => Some("--codex-login"),
        "gemini_sub" => Some("--login"),
        "kiro" => Some("--kiro-login"),
        "qwen" => Some("--qwen-login"),
        "iflow" => Some("--iflow-login"),
        _ => None,
    }
}

pub fn run_oauth_login(provider: &str) -> Result<bool> {
    let exe = exe_path();
    if !exe.exists() {
        anyhow::bail!("CLIProxyAPI binary not found. The daemon should download it shortly.");
    }
    let flag = login_flag_for_provider(provider)
        .ok_or_else(|| anyhow::anyhow!("No login flow defined for provider '{provider}'"))?;
    let mut child = Command::new(&exe)
        .arg(flag)
        .arg("--no-browser")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .context("Failed to spawn CLIProxyAPI login")?;
    match child.wait() {
        Ok(s) if s.success() => Ok(true),
        _ => Ok(false),
    }
}

#[derive(Debug, Clone)]
pub struct DetectedOAuthProvider {
    pub provider: String,
    pub source: String,
    pub authenticated: bool,
}

/// Best-effort scan of common OAuth token locations used by CLIProxyAPI or tools.
pub fn detect_existing_oauth_tokens() -> Vec<DetectedOAuthProvider> {
    let mut found = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // Sidecar auth dirs
    for dir in [auth_dir(), home.join(".cli-proxy-api"), home.join(".config/cliproxyapi")] {
        if dir.is_dir() {
            if let Ok(rd) = std::fs::read_dir(&dir) {
                for ent in rd.flatten() {
                    let name = ent.file_name().to_string_lossy().to_string();
                    if !name.ends_with(".json") { continue; }
                    let provider = if name.starts_with("codex-") || name.starts_with("copilot-") {
                        "copilot"
                    } else if name.starts_with("claude-") {
                        "claude_sub"
                    } else if name.starts_with("gemini-") {
                        "gemini_sub"
                    } else if name.starts_with("qwen-") {
                        "qwen"
                    } else if name.starts_with("iflow-") {
                        "iflow"
                    } else if name.starts_with("kiro-") {
                        "kiro"
                    } else { continue };
                    found.push(DetectedOAuthProvider {
                        provider: provider.to_string(),
                        source: format!("{}", dir.join(&name).display()),
                        authenticated: true,
                    });
                }
            }
        }
    }

    // Copilot
    for p in [
        home.join(".config/github-copilot/hosts.json"),
        home.join(".config/github-copilot/apps.json"),
    ] {
        if p.exists() {
            found.push(DetectedOAuthProvider {
                provider: "copilot".into(),
                source: format!("{}", p.display()),
                authenticated: true,
            });
        }
    }

    // Claude Code
    for p in [
        home.join(".claude/credentials.json"),
        home.join(".config/claude-code/credentials.json"),
        home.join(".config/claude-code/config.json"),
        home.join(".claude/settings.json"),
    ] {
        if p.exists() {
            found.push(DetectedOAuthProvider {
                provider: "claude_sub".into(),
                source: format!("{}", p.display()),
                authenticated: true,
            });
        }
    }

    found.dedup_by(|a, b| a.provider == b.provider);
    found
}
