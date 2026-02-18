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
    fn update_and_get_round_trip_with_tty_sanitization() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();

        update_tty_cwd(" /dev/pts/7 ", " /tmp/project ").expect("update should work");

        assert_eq!(get_tty_cwd("/dev/pts/7").as_deref(), Some("/tmp/project"));

        let expected_path = crate::config::Config::nsh_dir().join("cwd__dev_pts_7");
        assert!(expected_path.exists(), "expected cwd cache file to exist");
    }

    #[test]
    #[serial]
    fn update_ignores_empty_inputs() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();

        update_tty_cwd("   ", "/tmp/ignored").expect("empty tty should be no-op");
        update_tty_cwd("/dev/pts/8", "   ").expect("empty cwd should be no-op");

        assert!(get_tty_cwd("/dev/pts/8").is_none());
    }

    #[test]
    #[serial]
    fn remove_cleans_cache_file_and_temp_file() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = setup_test_home();

        update_tty_cwd("/dev/pts/9", "/tmp/path").expect("update should work");
        let cache_path = crate::config::Config::nsh_dir().join("cwd__dev_pts_9");
        std::fs::write(cache_path.with_extension("tmp"), "stale").expect("write temp file");

        remove_tty_cwd("/dev/pts/9");

        assert!(!cache_path.exists());
        assert!(!cache_path.with_extension("tmp").exists());
        assert!(get_tty_cwd("/dev/pts/9").is_none());
    }
}
