use super::config::ShimWrapConfig;
use std::process::Stdio;

fn parse_wrap_shell(args: &[String]) -> Option<String> {
    if let Some(index) = args.iter().position(|arg| arg == "--shell") {
        return args
            .get(index + 1)
            .cloned()
            .filter(|value| !value.is_empty());
    }

    args.iter()
        .position(|arg| arg == "wrap")
        .and_then(|index| args.get(index + 1))
        .filter(|value| value.as_str() != "--shell" && !value.is_empty())
        .cloned()
}

fn parent_bootstrap(wrap_config: &ShimWrapConfig) -> Option<fn()> {
    if wrap_config.daemon_autostart {
        Some(spawn_global_daemon_process)
    } else {
        None
    }
}

fn spawn_global_daemon_process() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };

    let _ = std::process::Command::new(exe)
        .arg("nshd")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

pub fn run_wrap(args: Vec<String>) {
    let shell = parse_wrap_shell(&args)
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let wrap_config = ShimWrapConfig::from_env();

    if let Err(error) =
        crate::pty::run_wrapped_shell(&shell, &wrap_config, parent_bootstrap(&wrap_config))
    {
        eprintln!("nsh wrap error: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::{parent_bootstrap, parse_wrap_shell};
    use crate::shim::ShimWrapConfig;

    #[test]
    fn parse_wrap_shell_prefers_flag_value() {
        let args = vec![
            "nsh".to_string(),
            "wrap".to_string(),
            "--shell".to_string(),
            "zsh".to_string(),
        ];
        assert_eq!(parse_wrap_shell(&args).as_deref(), Some("zsh"));
    }

    #[test]
    fn parse_wrap_shell_falls_back_to_positional_value() {
        let args = vec!["nsh".to_string(), "wrap".to_string(), "fish".to_string()];
        assert_eq!(parse_wrap_shell(&args).as_deref(), Some("fish"));
    }

    #[test]
    fn parent_bootstrap_only_enables_daemon_autostart_when_requested() {
        let disabled = ShimWrapConfig::default();
        assert!(parent_bootstrap(&disabled).is_none());

        let enabled = ShimWrapConfig {
            daemon_autostart: true,
            ..ShimWrapConfig::default()
        };
        assert!(parent_bootstrap(&enabled).is_some());
    }
}
