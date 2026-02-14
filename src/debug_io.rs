use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(false);
static COUNTER: AtomicU64 = AtomicU64::new(0);

pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn begin(provider: &str, request: &serde_json::Value) -> Option<PathBuf> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }

    let dir = crate::config::Config::nsh_dir().join("debug");
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f");
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let file = dir.join(format!("{ts}-{seq}.log"));

    let mut body = String::new();
    body.push_str(&format!("provider: {provider}\n"));
    body.push_str("=== raw_llm_call ===\n");
    body.push_str(&serde_json::to_string_pretty(request).unwrap_or_else(|_| request.to_string()));
    body.push_str("\n\n");

    if std::fs::write(&file, body).is_ok() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
        }
        Some(file)
    } else {
        None
    }
}

pub fn append(path: &Path, section: &str, content: &str) {
    let mut f = match std::fs::OpenOptions::new().append(true).open(path) {
        Ok(f) => f,
        Err(_) => return,
    };
    use std::io::Write;
    let _ = writeln!(f, "=== {section} ===");
    let _ = writeln!(f, "{content}");
    let _ = writeln!(f);
}
