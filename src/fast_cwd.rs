use std::path::PathBuf;

fn cwd_path_for_tty(tty: &str) -> PathBuf {
    let safe_name = tty.replace('/', "_");
    crate::config::Config::nsh_dir().join(format!("cwd_{safe_name}"))
}

pub fn update_tty_cwd(tty: &str, cwd: &str) -> std::io::Result<()> {
    let tty = tty.trim();
    let cwd = cwd.trim();
    if tty.is_empty() || cwd.is_empty() {
        return Ok(());
    }
    let path = cwd_path_for_tty(tty);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, cwd)?;
    // On Windows, rename fails if target exists; remove it first.
    #[cfg(windows)]
    let _ = std::fs::remove_file(&path);
    std::fs::rename(tmp, path)
}

pub fn get_tty_cwd(tty: &str) -> Option<String> {
    let tty = tty.trim();
    if tty.is_empty() {
        return None;
    }
    std::fs::read_to_string(cwd_path_for_tty(tty))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn remove_tty_cwd(tty: &str) {
    let tty = tty.trim();
    if tty.is_empty() {
        return;
    }
    let _ = std::fs::remove_file(cwd_path_for_tty(tty));
    let _ = std::fs::remove_file(cwd_path_for_tty(tty).with_extension("tmp"));
}
