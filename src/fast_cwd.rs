use std::collections::HashMap;
use std::path::PathBuf;

fn index_path() -> PathBuf {
    crate::config::Config::nsh_dir().join("tty_last_cwd")
}

fn lock_path() -> PathBuf {
    crate::config::Config::nsh_dir().join("tty_last_cwd.lock")
}

fn read_map() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Ok(content) = std::fs::read_to_string(index_path()) else {
        return map;
    };
    for line in content.lines() {
        let mut parts = line.splitn(2, '\t');
        let Some(tty) = parts.next() else {
            continue;
        };
        let Some(cwd) = parts.next() else {
            continue;
        };
        if !tty.is_empty() && !cwd.is_empty() {
            map.insert(tty.to_string(), cwd.to_string());
        }
    }
    map
}

fn write_map(map: &HashMap<String, String>) -> std::io::Result<()> {
    let path = index_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    let mut lines: Vec<String> = map.iter().map(|(k, v)| format!("{k}\t{v}")).collect();
    lines.sort();
    let mut body = lines.join("\n");
    if !body.is_empty() {
        body.push('\n');
    }
    std::fs::write(&tmp, body)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(tmp, path)
}

#[cfg(unix)]
fn with_lock<T>(f: impl FnOnce() -> T) -> T {
    use std::os::fd::AsRawFd;
    let file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(lock_path());
    if let Ok(file) = file {
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_EX);
        }
        let out = f();
        unsafe {
            libc::flock(file.as_raw_fd(), libc::LOCK_UN);
        }
        out
    } else {
        f()
    }
}

#[cfg(not(unix))]
fn with_lock<T>(f: impl FnOnce() -> T) -> T {
    f()
}

pub fn update_tty_cwd(tty: &str, cwd: &str) -> std::io::Result<()> {
    let tty = tty.trim();
    let cwd = cwd.trim();
    if tty.is_empty() || cwd.is_empty() || tty.contains('\n') || cwd.contains('\n') {
        return Ok(());
    }
    if tty.contains('\t') || cwd.contains('\t') {
        return Ok(());
    }

    with_lock(|| {
        let mut map = read_map();
        map.insert(tty.to_string(), cwd.to_string());
        write_map(&map)
    })
}

pub fn get_tty_cwd(tty: &str) -> Option<String> {
    let tty = tty.trim().to_string();
    if tty.is_empty() {
        return None;
    }
    with_lock(|| read_map().get(&tty).cloned())
}
