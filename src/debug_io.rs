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

pub fn begin_named(name: &str, request: &serde_json::Value) -> Option<PathBuf> {
    if !ENABLED.load(Ordering::Relaxed) {
        return None;
    }

    let dir = crate::config::Config::nsh_dir().join("debug");
    if std::fs::create_dir_all(&dir).is_err() {
        return None;
    }

    let ts = chrono::Utc::now().format("%Y%m%dT%H%M%S%.3f");
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let safe_name: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let file = dir.join(format!("{ts}-{safe_name}-{seq}.log"));

    let mut body = String::new();
    body.push_str(&format!("name: {name}\n"));
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

pub fn daemon_log(path: &str, section: &str, content: &str) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    let dir = crate::config::Config::nsh_dir().join("debug");
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let file = dir.join(path);
    let mut f = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&file)
    {
        Ok(f) => f,
        Err(_) => return,
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
    }
    use std::io::Write;
    let ts = chrono::Utc::now().to_rfc3339();
    let _ = writeln!(f, "[{ts}] {section}");
    let _ = writeln!(f, "{content}");
    let _ = writeln!(f);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    struct EnvVarGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set<K: Into<String>, V: AsRef<str>>(key: K, value: V) -> Self {
            let key = key.into();
            let original = std::env::var(&key).ok();
            unsafe {
                std::env::set_var(&key, value.as_ref());
            }
            Self { key, original }
        }

        fn remove<K: Into<String>>(key: K) -> Self {
            let key = key.into();
            let original = std::env::var(&key).ok();
            unsafe {
                std::env::remove_var(&key);
            }
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                unsafe {
                    std::env::set_var(&self.key, value);
                }
            } else {
                unsafe {
                    std::env::remove_var(&self.key);
                }
            }
        }
    }

    fn setup_test_home() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().expect("temp home");
        let home_guard = EnvVarGuard::set("HOME", home.path().to_string_lossy());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    #[test]
    #[serial]
    fn begin_returns_none_when_disabled() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();
        set_enabled(false);
        let path = begin("openrouter", &serde_json::json!({"hello": "world"}));
        assert!(path.is_none());
    }

    #[test]
    #[serial]
    fn begin_named_sanitizes_filename_and_writes_content() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();
        set_enabled(true);

        let path = begin_named("ask/user:step#1", &serde_json::json!({"a": 1}))
            .expect("debug log path should be created");

        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        assert!(
            file_name.contains("ask-user-step-1"),
            "unexpected sanitized filename: {file_name}"
        );

        let body = std::fs::read_to_string(&path).expect("read debug log file");
        assert!(body.contains("name: ask/user:step#1"));
        assert!(body.contains("=== raw_llm_call ==="));
        assert!(body.contains("\"a\": 1"));

        set_enabled(false);
    }

    #[test]
    #[serial]
    fn append_and_daemon_log_write_expected_sections() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();
        set_enabled(true);

        let path = begin("openrouter", &serde_json::json!({"q": "test"}))
            .expect("begin should create file");
        append(&path, "response", "ok");

        let body = std::fs::read_to_string(&path).expect("read appended log");
        assert!(body.contains("provider: openrouter"));
        assert!(body.contains("=== response ==="));
        assert!(body.contains("ok"));

        daemon_log("daemon-test.log", "daemon.section", "payload");
        let daemon_path = crate::config::Config::nsh_dir().join("debug").join("daemon-test.log");
        let daemon_body = std::fs::read_to_string(&daemon_path).expect("read daemon log");
        assert!(daemon_body.contains("daemon.section"));
        assert!(daemon_body.contains("payload"));

        set_enabled(false);
    }

    #[cfg(unix)]
    #[test]
    #[serial]
    fn begin_sets_permissions_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();
        set_enabled(true);

        let path = begin("openrouter", &serde_json::json!({"perm": true}))
            .expect("begin should create file");
        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "expected mode 600, got {mode:o}");

        set_enabled(false);
    }
}
