use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let target_os = match std::env::var("CARGO_CFG_TARGET_OS") {
        Ok(os) if os == "windows" => "windows".to_string(),
        Ok(os) => os,
        Err(_) => "unknown-os".into(),
    };
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "unknown-arch".into());
    let target = format!("{target_os}/{target_arch}");

    let git_sha = git_short_sha().unwrap_or_else(|| "nogit".to_string());
    let dirty = git_is_dirty().unwrap_or(false);
    let dirty_suffix = if dirty { ".dirty" } else { "" };

    let short = if git_sha == "nogit" {
        format!("{pkg_version}+{target_os}-{target_arch}")
    } else {
        format!("{pkg_version}+{target_os}-{target_arch}.{git_sha}{dirty_suffix}")
    };
    let long =
        format!("{short}\npackage: {pkg_version}\ntarget: {target}\ngit: {git_sha}{dirty_suffix}");

    println!("cargo:rustc-env=NSH_BUILD_VERSION={short}");
    println!("cargo:rustc-env=NSH_BUILD_LONG_VERSION={long}");

    // Per-build timestamp so even non-git builds get a unique fingerprint
    let build_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| format!("{}", d.as_millis()))
        .unwrap_or_else(|_| "0".to_string());
    println!("cargo:rustc-env=NSH_BUILD_NONCE={build_nonce}");

    // Composite fingerprint: git_sha + dirty + timestamp
    println!("cargo:rustc-env=NSH_BUILD_FINGERPRINT={git_sha}{dirty_suffix}.{build_nonce}");

    // Manually bump when wrapper protocol changes
    println!("cargo:rustc-env=NSH_WRAPPER_PROTOCOL_VERSION=1");

    // Shim protocol version and core discriminator (for future-proofing)
    println!("cargo:rustc-env=NSH_SHIM_PROTOCOL_VERSION=1");
    let is_core = std::env::var("NSH_BUILD_CORE").is_ok();
    println!(
        "cargo:rustc-env=NSH_IS_CORE={}",
        if is_core { "1" } else { "0" }
    );

    // Compute a hash of shell hook templates so we can detect when hooks changed
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    for shell_file in &[
        "shell/nsh.zsh",
        "shell/nsh.bash",
        "shell/nsh.fish",
        "shell/nsh.ps1",
    ] {
        if let Ok(content) = std::fs::read_to_string(shell_file) {
            content.hash(&mut hasher);
        }
    }
    let hook_hash = format!("{:016x}", hasher.finish());
    println!("cargo:rustc-env=NSH_HOOK_HASH={hook_hash}");

    // Re-run build script if shell scripts change
    println!("cargo:rerun-if-changed=shell/nsh.zsh");
    println!("cargo:rerun-if-changed=shell/nsh.bash");
    println!("cargo:rerun-if-changed=shell/nsh.fish");
    println!("cargo:rerun-if-changed=shell/nsh.ps1");
}

fn git_short_sha() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let sha = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if sha.is_empty() { None } else { Some(sha) }
}

fn git_is_dirty() -> Option<bool> {
    let output = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(!output.stdout.is_empty())
}
