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

    // Canonicalize to dedupe candidates that resolve to the same file via symlinks
    // or relative/absolute variants. Falls back to the original path on error.
    let canon = |p: &std::path::Path| -> std::path::PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    };

    // Any candidate that canonicalizes to the running shim itself must be
    // discarded — exec'ing ourselves as nsh-core would infinite-loop.
    let current_exe_canon = std::env::current_exe().ok().map(|p| canon(&p));
    let is_self = |p: &std::path::Path| -> bool {
        current_exe_canon
            .as_ref()
            .map(|c| canon(p) == *c)
            .unwrap_or(false)
    };

    // Primary managed location: Config::nsh_dir()/bin/nsh-core
    let managed_dir = nsh::config::Config::nsh_dir().join("bin");
    let managed_core = find_core(&managed_dir).filter(|p| !is_self(p));

    // Sibling to current exe (cargo install puts nsh + nsh-core in the same dir).
    // Guard against the unusual case where the shim binary is itself named
    // "nsh-core" or is symlinked/copied to a sibling path.
    let sibling_core = std::env::current_exe()
        .ok()
        .and_then(|e| e.parent().map(|d| d.to_path_buf()))
        .and_then(|d| find_core(&d))
        .filter(|p| !is_self(p));

    // PATH lookup: picks up a fresh nsh-core the user has installed in $PATH
    // even when it is not the sibling of the running shim (e.g. the shim is
    // stale in one dir but a rebuilt nsh-core lives elsewhere in PATH).
    let path_core = which::which(core_name).ok().filter(|p| !is_self(p));

    // Collect non-managed candidates, deduplicating by canonicalized path
    // so sibling and PATH pointing at the same binary are not double-counted.
    let mut non_managed: Vec<std::path::PathBuf> = Vec::new();
    let mut seen: Vec<std::path::PathBuf> = Vec::new();
    for candidate in [sibling_core.clone(), path_core.clone()]
        .into_iter()
        .flatten()
    {
        let c = canon(&candidate);
        if seen.iter().any(|s| *s == c) {
            continue;
        }
        seen.push(c);
        non_managed.push(candidate);
    }
    // Exclude any non-managed candidate whose canonical path equals the managed
    // path (i.e. managed IS the sibling/PATH entry — nothing to sync).
    if let Some(managed) = managed_core.as_ref() {
        let managed_canon = canon(managed);
        non_managed.retain(|p| canon(p) != managed_canon);
    }

    let mtime = |p: &std::path::Path| std::fs::metadata(p).and_then(|m| m.modified()).ok();

    // Pick the non-managed candidate with the newest mtime.
    let newest_non_managed: Option<std::path::PathBuf> = non_managed
        .into_iter()
        .max_by_key(|p| mtime(p).unwrap_or(std::time::UNIX_EPOCH));

    let sync_to_managed = |src: &std::path::Path| -> Option<std::path::PathBuf> {
        let _ = std::fs::create_dir_all(&managed_dir);
        let dest = managed_dir.join(core_name);
        let tmp = dest.with_extension("tmp");
        let ok = std::fs::copy(src, &tmp).is_ok() && {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
            }
            std::fs::rename(&tmp, &dest).is_ok()
        };
        if ok { Some(dest) } else { None }
    };

    let core_path = match (managed_core.as_ref(), newest_non_managed.as_ref()) {
        (Some(managed), Some(candidate)) => {
            // Only replace managed when a non-managed candidate is STRICTLY newer.
            // This preserves self-update semantics: a freshly self-updated managed
            // binary with the same mtime as the sibling will not be clobbered.
            match (mtime(managed), mtime(candidate)) {
                (Some(m_t), Some(c_t)) if c_t > m_t => {
                    sync_to_managed(candidate).unwrap_or_else(|| candidate.clone())
                }
                _ => managed.clone(),
            }
        }
        (Some(managed), None) => managed.clone(),
        (None, Some(candidate)) => {
            // No managed core yet — install the freshest non-managed candidate.
            sync_to_managed(candidate).unwrap_or_else(|| candidate.clone())
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

        // Isolate PATH so `which::which("nsh-core")` can't pick up a candidate
        // outside the test's control.
        let isolated_path = home.path().join("emptybin");
        std::fs::create_dir_all(&isolated_path).unwrap();
        let _path_guard = EnvVarGuard::set("PATH", &isolated_path);

        let managed_dir = home.path().join(".nsh").join("bin");
        let managed_core = managed_dir.join("nsh-core");
        std::fs::create_dir_all(&managed_dir).unwrap();
        std::fs::write(&managed_core, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&managed_core, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }

        assert_eq!(resolve_core(), Some(managed_core));
    }

    fn make_fake_core(path: &std::path::Path) {
        std::fs::write(path, b"#!/bin/sh\necho fake\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    }

    // Sets a file's atime/mtime to a chosen absolute SystemTime, used to build
    // well-defined "older" and "newer" fixtures independent of wall-clock races.
    fn set_mtime(path: &std::path::Path, t: std::time::SystemTime) {
        let secs = t
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as libc::time_t;
        let tv = [
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
            libc::timeval {
                tv_sec: secs,
                tv_usec: 0,
            },
        ];
        let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: utimes is a standard POSIX call; tv is a valid 2-element array
        // of timeval (access time then modification time); c is a valid path CStr.
        let rc = unsafe { libc::utimes(c.as_ptr(), tv.as_ptr()) };
        assert_eq!(rc, 0, "utimes failed for {}", path.display());
    }

    #[test]
    #[serial]
    fn resolve_core_picks_path_candidate_when_strictly_newer_than_managed() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();

        // Skip if an unrelated sibling exists — we can't remove it.
        let sibling_core = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("nsh-core");
        if sibling_core.exists() {
            return;
        }

        // Old managed binary.
        let managed_dir = home.path().join(".nsh").join("bin");
        std::fs::create_dir_all(&managed_dir).unwrap();
        let managed_core = managed_dir.join("nsh-core");
        make_fake_core(&managed_core);
        set_mtime(
            &managed_core,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000),
        );

        // Fresh PATH candidate in an isolated bin dir.
        let path_dir = home.path().join("freshbin");
        std::fs::create_dir_all(&path_dir).unwrap();
        let path_core = path_dir.join("nsh-core");
        make_fake_core(&path_core);
        set_mtime(
            &path_core,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000),
        );

        let _path_guard = EnvVarGuard::set("PATH", &path_dir);

        // Expect: sync PATH → managed, return managed path.
        let resolved = resolve_core().expect("resolve should find a core");
        assert_eq!(resolved, managed_core);
        // Managed should have been refreshed from the PATH candidate.
        let managed_bytes = std::fs::read(&managed_core).unwrap();
        let path_bytes = std::fs::read(&path_core).unwrap();
        assert_eq!(managed_bytes, path_bytes, "managed should be synced from PATH");
    }

    #[test]
    #[serial]
    fn resolve_core_keeps_managed_when_path_candidate_is_not_strictly_newer() {
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
        std::fs::create_dir_all(&managed_dir).unwrap();
        let managed_core = managed_dir.join("nsh-core");
        std::fs::write(&managed_core, b"managed-content").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&managed_core, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        set_mtime(
            &managed_core,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_000_000),
        );

        let path_dir = home.path().join("staleb");
        std::fs::create_dir_all(&path_dir).unwrap();
        let path_core = path_dir.join("nsh-core");
        std::fs::write(&path_core, b"path-content").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path_core, std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        set_mtime(
            &path_core,
            std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000),
        );

        let _path_guard = EnvVarGuard::set("PATH", &path_dir);

        let resolved = resolve_core().expect("resolve should find a core");
        assert_eq!(resolved, managed_core);
        // Managed content should be untouched (self-update semantics preserved).
        assert_eq!(std::fs::read(&managed_core).unwrap(), b"managed-content");
    }

    #[test]
    #[serial]
    fn resolve_core_rejects_self_as_sibling_or_path_or_managed() {
        // If a candidate (sibling, PATH, or managed) canonicalizes to the
        // running shim binary itself — which can happen via a symlink named
        // `nsh-core` pointing at the shim — resolve_core must NOT select it;
        // exec'ing ourselves as nsh-core would infinite-loop.
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let current_exe = std::env::current_exe().unwrap();
        let current_exe_canon = std::fs::canonicalize(&current_exe).unwrap();

        // Managed: symlink to current_exe.
        let managed_dir = home.path().join(".nsh").join("bin");
        std::fs::create_dir_all(&managed_dir).unwrap();
        let managed_self = managed_dir.join("nsh-core");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&current_exe, &managed_self).unwrap();
        assert_eq!(
            std::fs::canonicalize(&managed_self).unwrap(),
            current_exe_canon,
            "precondition: symlink should canonicalize to current_exe"
        );

        // PATH: another symlink to current_exe in an isolated bin dir.
        let path_dir = home.path().join("self_on_path");
        std::fs::create_dir_all(&path_dir).unwrap();
        let path_self = path_dir.join("nsh-core");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&current_exe, &path_self).unwrap();
        let _path_guard = EnvVarGuard::set("PATH", &path_dir);

        // With only self-aliases available, resolve_core must NOT return any
        // path that canonicalizes to the running shim. (It may return None or
        // a pre-existing real sibling nsh-core in the cargo target dir —
        // either is acceptable here; the invariant is no self-recursion.)
        let resolved = resolve_core();
        if let Some(p) = resolved.as_ref()
            && let Ok(canon) = std::fs::canonicalize(p)
        {
            assert_ne!(
                canon, current_exe_canon,
                "resolve_core must never return a path that canonicalizes to the running shim"
            );
        }
    }

    #[test]
    #[serial]
    fn resolve_core_installs_path_candidate_when_no_managed() {
        let (home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();

        let sibling_core = std::env::current_exe()
            .unwrap()
            .parent()
            .unwrap()
            .join("nsh-core");
        if sibling_core.exists() {
            return;
        }

        let path_dir = home.path().join("freshbin2");
        std::fs::create_dir_all(&path_dir).unwrap();
        let path_core = path_dir.join("nsh-core");
        make_fake_core(&path_core);

        let _path_guard = EnvVarGuard::set("PATH", &path_dir);

        let resolved = resolve_core().expect("resolve should find a core via PATH");
        let expected_managed = home.path().join(".nsh").join("bin").join("nsh-core");
        assert_eq!(resolved, expected_managed);
        assert!(expected_managed.exists(), "PATH candidate should be copied to managed");
    }
}
