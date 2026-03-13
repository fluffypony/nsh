//! nsh – stable shim (~frozen, rarely updated). Resolves ~/.nsh/bin/nsh-core and execs it.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The shim handles `wrap` directly to freeze the PTY boundary for a session
    let is_wrap = args.get(1).map(|s| s == "wrap").unwrap_or(false);
    if is_wrap {
        seed_wrap_contract_env();
        nsh::shim::run_wrap(args);
        return;
    }

    // For all other commands, try to exec nsh-core
    if let Some(core_path) = resolve_core() {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            let err = std::process::Command::new(&core_path)
                .args(&args[1..])
                .exec();
            eprintln!(
                "nsh: failed to exec nsh-core at {}: {}",
                core_path.display(),
                err
            );
            // Fall through to built-in
        }

        #[cfg(windows)]
        {
            match std::process::Command::new(&core_path)
                .args(&args[1..])
                .status()
            {
                Ok(status) => std::process::exit(status.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("nsh: failed to exec nsh-core: {}", e);
                    // Fall through to built-in
                }
            }
        }
    }

    // Fallback: nsh-core not found or exec failed — run built-in (single-binary installs)
    if let Err(e) = nsh::main_inner() {
        eprintln!("nsh: {e}");
        std::process::exit(1);
    }
}

fn seed_wrap_contract_env() {
    let config = nsh::config::Config::load().unwrap_or_default();
    nsh::shim::seed_wrap_contract_env_from_config(&config);
}

fn resolve_core() -> Option<std::path::PathBuf> {
    let core_name = if cfg!(windows) {
        "nsh-core.exe"
    } else {
        "nsh-core"
    };

    let find_core = |dir: &std::path::Path| -> Option<std::path::PathBuf> {
        let p = dir.join(core_name);
        if p.is_file() { Some(p) } else { None }
    };

    // Primary managed location: Config::nsh_dir()/bin/nsh-core
    let managed_dir = nsh::config::Config::nsh_dir().join("bin");
    let managed_core = find_core(&managed_dir);

    // Sibling to current exe (cargo install puts nsh + nsh-core in the same dir)
    let sibling_core = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.to_path_buf()))
        .and_then(|d| find_core(&d));

    // If both exist and are different paths, prefer the newer one and sync to managed location
    let core_path = match (&managed_core, &sibling_core) {
        (Some(managed), Some(sibling)) if managed != sibling => {
            let managed_mtime = std::fs::metadata(managed).and_then(|m| m.modified()).ok();
            let sibling_mtime = std::fs::metadata(sibling).and_then(|m| m.modified()).ok();

            match (managed_mtime, sibling_mtime) {
                (Some(m_t), Some(s_t)) if s_t > m_t => {
                    // Sibling is newer (cargo install case) — sync to managed
                    let _ = std::fs::create_dir_all(&managed_dir);
                    let tmp = managed.with_extension("tmp");
                    let synced = std::fs::copy(sibling, &tmp).is_ok() && {
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = std::fs::set_permissions(
                                &tmp,
                                std::fs::Permissions::from_mode(0o755),
                            );
                        }
                        std::fs::rename(&tmp, managed).is_ok()
                    };
                    // If sync succeeded, use managed; otherwise use sibling directly
                    if synced {
                        managed.clone()
                    } else {
                        sibling.clone()
                    }
                }
                _ => managed.clone(), // Managed is newer or same (self-update case)
            }
        }
        (Some(managed), _) => managed.clone(),
        (None, Some(sibling)) => {
            // No managed core yet — install sibling as managed
            let _ = std::fs::create_dir_all(&managed_dir);
            let managed_path = managed_dir.join(core_name);
            let tmp = managed_path.with_extension("tmp");
            let installed = std::fs::copy(sibling, &tmp).is_ok() && {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
                }
                std::fs::rename(&tmp, &managed_path).is_ok()
            };
            if installed {
                managed_path
            } else {
                sibling.clone()
            }
        }
        (None, None) => return None,
    };

    Some(core_path)
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::{resolve_core, seed_wrap_contract_env};
    use serial_test::serial;
    use std::ffi::{OsStr, OsString};

    struct EnvVarGuard {
        key: String,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn set<K, V>(key: K, value: V) -> Self
        where
            K: Into<String>,
            V: AsRef<OsStr>,
        {
            let key = key.into();
            let original = std::env::var_os(&key);
            // SAFETY: test-only env mutation guarded by serial execution.
            unsafe { std::env::set_var(&key, value.as_ref()) };
            Self { key, original }
        }

        fn remove<K: Into<String>>(key: K) -> Self {
            let key = key.into();
            let original = std::env::var_os(&key);
            // SAFETY: test-only env mutation guarded by serial execution.
            unsafe { std::env::remove_var(&key) };
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = &self.original {
                // SAFETY: test-only env mutation guarded by serial execution.
                unsafe { std::env::set_var(&self.key, value) };
            } else {
                // SAFETY: test-only env mutation guarded by serial execution.
                unsafe { std::env::remove_var(&self.key) };
            }
        }
    }

    fn temp_home_env() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    fn clear_wrap_env() -> [EnvVarGuard; 6] {
        [
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_LINES"),
            EnvVarGuard::remove("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES"),
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS"),
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS"),
            EnvVarGuard::remove("NSH_WRAP_CAPTURE_MODE"),
            EnvVarGuard::remove("NSH_WRAP_ALT_SCREEN_MODE"),
        ]
    }

    #[test]
    #[serial]
    fn seed_wrap_contract_env_loads_default_contract_values() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let _wrap_guards = clear_wrap_env();

        seed_wrap_contract_env();

        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_LINES").ok().as_deref(),
            Some("1000")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES").ok().as_deref(),
            Some("65536")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS").ok().as_deref(),
            Some("10485760")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS")
                .ok()
                .as_deref(),
            Some("2")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_CAPTURE_MODE").ok().as_deref(),
            Some("vt100")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_ALT_SCREEN_MODE").ok().as_deref(),
            Some("drop")
        );
    }

    #[test]
    #[serial]
    fn resolve_core_uses_managed_binary_when_present() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let sibling_core = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("nsh-core");
        if sibling_core.exists() {
            return;
        }

        let managed_dir = home.path().join(".nsh").join("bin");
        let managed_core = managed_dir.join("nsh-core");
        std::fs::create_dir_all(&managed_dir).unwrap();
        std::fs::write(&managed_core, b"#!/bin/sh\n").unwrap();

        assert_eq!(resolve_core(), Some(managed_core));
    }
}
