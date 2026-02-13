use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/index");

    let pkg_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".to_string());
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_else(|_| "unknown-os".into());
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
