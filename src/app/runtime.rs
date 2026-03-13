use sha2::{Digest, Sha256};

pub(super) fn handle_autoconfigure_command(interactive: bool) -> anyhow::Result<()> {
    crate::autoconfigure::run_autoconfigure(interactive)?;
    Ok(())
}

pub(super) fn handle_restart_command() -> anyhow::Result<()> {
    eprint!("nsh: signaling daemon restart...");
    super::daemon_runtime::signal_daemon_restart();
    std::thread::sleep(std::time::Duration::from_millis(1000));
    crate::daemon_client::ensure_global_daemon_running()?;
    eprintln!(" done");
    Ok(())
}

pub(super) async fn handle_update_command() -> anyhow::Result<()> {
    eprintln!("nsh: checking for updates...");

    let target = match current_target_triple() {
        Some(target) => target,
        None => {
            let arch = std::env::consts::ARCH;
            let os = std::env::consts::OS;
            eprintln!("nsh: unsupported platform {os}/{arch}. Build from source:");
            eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
            std::process::exit(1);
        }
    };

    let records = match resolve_update_txt().await {
        Ok(records) => records,
        Err(error) => {
            eprintln!("nsh: DNS lookup failed: {error}");
            eprintln!("  Falling back to dig...");
            match resolve_update_txt_fallback() {
                Ok(records) => records,
                Err(fallback_error) => {
                    eprintln!("nsh: DNS fallback also failed: {fallback_error}");
                    std::process::exit(1);
                }
            }
        }
    };

    let (version, expected_sha) = match find_latest_for_target(&records, target) {
        Some(found) => found,
        None => {
            eprintln!("nsh: no release found for {target} in DNS records");
            std::process::exit(1);
        }
    };

    let current_version = env!("CARGO_PKG_VERSION");
    if crate::util::compare_versions(&version, current_version) != std::cmp::Ordering::Greater {
        eprintln!("nsh: already up to date (v{current_version})");
        return Ok(());
    }

    eprintln!("nsh: v{version} available (current: v{current_version})");

    let url = format!(
        "https://github.com/fluffypony/nsh/releases/download/v{version}/nsh-{target}.tar.gz"
    );
    eprintln!("nsh: downloading {target}...");
    let client = reqwest::Client::new();
    let download_response = client.get(&url).send().await?;
    if !download_response.status().is_success() {
        eprintln!("nsh: no pre-built binary available. Build from source:");
        eprintln!("  cargo install --git https://github.com/fluffypony/nsh");
        std::process::exit(1);
    }

    let bytes = download_response.bytes().await?;

    let staging_dir = crate::config::Config::nsh_dir().join("updates");
    std::fs::create_dir_all(&staging_dir)?;
    let staged_path = staging_dir.join(format!("nsh-{version}-{target}"));

    let decoder = flate2::read::GzDecoder::new(&bytes[..]);
    let mut archive = tar::Archive::new(decoder);
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.to_path_buf();
        if path.file_name().map(|name| name == "nsh").unwrap_or(false) {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&staged_path)?;
            std::io::copy(&mut entry, &mut file)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&staged_path, std::fs::Permissions::from_mode(0o755))?;
            }
            found = true;
            break;
        }
    }

    if !found {
        let _ = std::fs::remove_file(&staged_path);
        eprintln!("nsh: binary not found in archive");
        std::process::exit(1);
    }

    let actual_sha = sha256_file(&staged_path)?;
    if actual_sha != expected_sha {
        let _ = std::fs::remove_file(&staged_path);
        eprintln!("nsh: SHA256 verification failed!");
        eprintln!("  Expected: {expected_sha}");
        eprintln!("  Got:      {actual_sha}");
        std::process::exit(1);
    }
    eprintln!("nsh: SHA256 verified (DNS ✓)");

    let current_exe = std::env::current_exe()?;
    let pending_path = crate::config::Config::nsh_dir().join("update_pending");
    let pending_info = serde_json::json!({
        "version": version,
        "staged_path": staged_path.to_string_lossy(),
        "target_binary": current_exe.to_string_lossy(),
        "sha256": expected_sha,
        "downloaded_at": chrono::Utc::now().to_rfc3339(),
    });
    atomic_write(
        &pending_path,
        serde_json::to_string_pretty(&pending_info)?.as_bytes(),
    )?;

    apply_pending_update(false);
    super::daemon_runtime::signal_daemon_restart();
    eprintln!("nsh: update applied, daemon will restart gracefully");
    Ok(())
}

fn parse_dns_txt_records(raw: &str) -> Vec<(String, String, String)> {
    fn valid_version(version: &str) -> bool {
        !version.is_empty()
            && version
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c == '-')
    }

    fn valid_target(target: &str) -> bool {
        !target.is_empty()
            && target
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }

    raw.lines()
        .filter_map(|line| {
            let cleaned = line.trim().trim_matches('"');
            let parts: Vec<&str> = cleaned.splitn(3, ':').collect();
            if parts.len() == 3 {
                let (version, target, sha) = (parts[0], parts[1], parts[2]);
                if valid_version(version)
                    && valid_target(target)
                    && sha.len() == 64
                    && sha.chars().all(|c| c.is_ascii_hexdigit())
                {
                    return Some((version.to_string(), target.to_string(), sha.to_string()));
                }
            }
            None
        })
        .collect()
}

async fn resolve_update_txt() -> anyhow::Result<Vec<(String, String, String)>> {
    use hickory_resolver::Resolver;

    let resolver = Resolver::builder_tokio()?.build();
    let response = resolver.txt_lookup("update.nsh.tools").await?;
    let mut raw = String::new();
    for record in response.iter() {
        let txt = record.to_string();
        raw.push_str(txt.trim().trim_matches('"'));
        raw.push('\n');
    }
    let records = parse_dns_txt_records(&raw);
    if records.is_empty() {
        anyhow::bail!("no valid version:target:sha256 records found in DNS TXT");
    }
    Ok(records)
}

fn resolve_update_txt_fallback() -> anyhow::Result<Vec<(String, String, String)>> {
    let output = std::process::Command::new("dig")
        .args(["+short", "TXT", "update.nsh.tools"])
        .output()?;
    if !output.status.success() {
        anyhow::bail!("dig command failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let records = parse_dns_txt_records(&text);
    if records.is_empty() {
        anyhow::bail!("no valid version:target:sha256 records in dig output");
    }
    Ok(records)
}

fn current_target_triple() -> Option<&'static str> {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    match (os, arch) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        ("freebsd", "x86") => Some("i686-unknown-freebsd"),
        ("freebsd", "x86_64") => Some("x86_64-unknown-freebsd"),
        ("linux", "x86") => Some("i686-unknown-linux-gnu"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("linux", "riscv64") => Some("riscv64gc-unknown-linux-gnu"),
        ("windows", "x86_64") => Some("x86_64-pc-windows-msvc"),
        ("windows", "aarch64") => Some("aarch64-pc-windows-msvc"),
        _ => None,
    }
}

fn find_latest_for_target(
    records: &[(String, String, String)],
    target: &str,
) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for (version, record_target, sha) in records {
        if record_target == target {
            match &best {
                Some((best_version, _)) => {
                    if crate::util::compare_versions(version, best_version)
                        == std::cmp::Ordering::Greater
                    {
                        best = Some((version.clone(), sha.clone()));
                    }
                }
                None => best = Some((version.clone(), sha.clone())),
            }
        }
    }
    best
}

fn sha256_file(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(super) fn apply_pending_update(_reexec: bool) {
    let result = (|| -> anyhow::Result<()> {
        let pending_path = crate::config::Config::nsh_dir().join("update_pending");
        if !pending_path.exists() {
            return Ok(());
        }
        let content = std::fs::read_to_string(&pending_path)?;
        let info: serde_json::Value = match serde_json::from_str(&content) {
            Ok(value) => value,
            Err(_) => {
                let _ = std::fs::remove_file(&pending_path);
                anyhow::bail!("corrupt update_pending file, removed");
            }
        };

        let version = info["version"].as_str().unwrap_or("");
        let staged_path_str = info["staged_path"].as_str().unwrap_or("");
        let expected_sha = info["sha256"].as_str().unwrap_or("");

        let staged_path = std::path::PathBuf::from(staged_path_str);
        if !staged_path.exists() {
            let _ = std::fs::remove_file(&pending_path);
            return Ok(());
        }

        if expected_sha.is_empty() {
            let _ = std::fs::remove_file(&pending_path);
            anyhow::bail!("update_pending missing sha256");
        }
        let actual_sha = sha256_file(&staged_path)?;
        if actual_sha != expected_sha {
            let _ = std::fs::remove_file(&pending_path);
            let _ = std::fs::remove_file(&staged_path);
            anyhow::bail!("staged binary SHA mismatch");
        }

        let core_dir = crate::config::Config::nsh_dir().join("bin");
        std::fs::create_dir_all(&core_dir)?;
        let core_path = core_dir.join("nsh-core");
        let tmp_path = core_dir.join("nsh-core.tmp");
        std::fs::copy(&staged_path, &tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))?;
        }
        std::fs::rename(&tmp_path, &core_path)?;

        let _ = std::fs::remove_file(&pending_path);
        let _ = std::fs::remove_file(&staged_path);

        eprintln!("nsh: updated to v{version}");

        let notice_path = crate::config::Config::nsh_dir().join("update_notice");
        let _ = std::fs::write(
            &notice_path,
            format!(
                "v{version} installed — queries active immediately, shell hooks refresh on next terminal"
            ),
        );

        super::daemon_runtime::signal_daemon_restart();
        Ok(())
    })();
    if let Err(error) = result {
        tracing::debug!("apply_pending_update failed: {error}");
    }
}

fn atomic_write(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}
