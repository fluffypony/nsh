//! nsh – stable shim (~frozen, rarely updated). Resolves ~/.nsh/bin/nsh-core and execs it.

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // The shim handles `wrap` directly to freeze the PTY boundary for a session
    let is_wrap = args.get(1).map(|s| s == "wrap").unwrap_or(false);
    if is_wrap {
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

fn resolve_core() -> Option<std::path::PathBuf> {
    // Primary: ~/.nsh/bin/nsh-core
    if let Ok(home) = std::env::var("HOME") {
        let p = std::path::PathBuf::from(home)
            .join(".nsh")
            .join("bin")
            .join("nsh-core");
        if p.is_file() {
            return Some(p);
        }
    }

    // Also check via Config::nsh_dir() for non-standard locations
    let config_path = nsh::config::Config::nsh_dir().join("bin").join("nsh-core");
    if config_path.is_file() {
        return Some(config_path);
    }

    // Fallback: nsh-core alongside this binary
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("nsh-core");
            if p.is_file() {
                return Some(p);
            }
        }
    }

    None
}
