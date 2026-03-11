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
