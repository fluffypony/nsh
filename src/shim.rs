//! Stable shim boundary — PTY wrapper, pump loop, and capture engine.
//!
//! Code in this module is part of the "frozen" shim binary (`nsh`).
//! It persists for the lifetime of a terminal session and should
//! change extremely rarely. Any change here requires users to
//! restart their terminal.
//!
//! Dependencies: pty.rs, pump.rs — these are also part of the stable boundary.

pub use crate::pty;
pub use crate::pump;

#[derive(Debug, Clone)]
pub struct ShimWrapConfig {
    pub scrollback_lines: usize,
    pub max_output_storage_bytes: usize,
    pub scrollback_rate_limit_bps: usize,
    pub scrollback_pause_seconds: u64,
    pub capture_mode: String,
    pub alt_screen_mode: String,
    pub daemon_autostart: bool,
}

impl Default for ShimWrapConfig {
    fn default() -> Self {
        Self {
            scrollback_lines: 1000,
            max_output_storage_bytes: 65536,
            scrollback_rate_limit_bps: 10_485_760,
            scrollback_pause_seconds: 2,
            capture_mode: "vt100".to_string(),
            alt_screen_mode: "drop".to_string(),
            daemon_autostart: false,
        }
    }
}

impl ShimWrapConfig {
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            scrollback_lines: read_env_usize("NSH_WRAP_SCROLLBACK_LINES")
                .unwrap_or(defaults.scrollback_lines),
            max_output_storage_bytes: read_env_usize("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES")
                .unwrap_or(defaults.max_output_storage_bytes),
            scrollback_rate_limit_bps: read_env_usize("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS")
                .unwrap_or(defaults.scrollback_rate_limit_bps),
            scrollback_pause_seconds: read_env_u64("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS")
                .unwrap_or(defaults.scrollback_pause_seconds),
            capture_mode: std::env::var("NSH_WRAP_CAPTURE_MODE")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.capture_mode),
            alt_screen_mode: std::env::var("NSH_WRAP_ALT_SCREEN_MODE")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(defaults.alt_screen_mode),
            daemon_autostart: read_env_bool("NSH_WRAP_DAEMON_AUTOSTART")
                .unwrap_or(defaults.daemon_autostart),
        }
    }
}

fn read_env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.trim().parse::<usize>().ok()
}

fn read_env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.trim().parse::<u64>().ok()
}

fn read_env_bool(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub fn seed_wrap_contract_env_from_config(config: &crate::config::Config) {
    unsafe {
        std::env::set_var(
            "NSH_WRAP_SCROLLBACK_LINES",
            config.context.scrollback_lines.max(1000).to_string(),
        );
        std::env::set_var(
            "NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES",
            config.context.max_output_storage_bytes.to_string(),
        );
        std::env::set_var(
            "NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS",
            config.context.scrollback_rate_limit_bps.to_string(),
        );
        std::env::set_var(
            "NSH_WRAP_SCROLLBACK_PAUSE_SECONDS",
            config.context.scrollback_pause_seconds.to_string(),
        );
        std::env::set_var("NSH_WRAP_CAPTURE_MODE", &config.capture.mode);
        std::env::set_var("NSH_WRAP_ALT_SCREEN_MODE", &config.capture.alt_screen);
    }
}

/// Commands that the shim handles directly (not delegated to nsh-core).
pub fn is_shim_command(arg: &str) -> bool {
    matches!(arg, "wrap")
}

/// Shim-level wrap handler — called directly from shim_main.
/// Re-implements the `wrap` command to keep the shim self-contained.
pub fn run_wrap(args: Vec<String>) {
    // Determine shell from args or $SHELL
    let shell = args
        .iter()
        .position(|a| a == "wrap")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_string());

    let wrap_config = ShimWrapConfig::from_env();

    if let Err(e) = crate::pty::run_wrapped_shell(&shell, &wrap_config) {
        eprintln!("nsh wrap error: {e}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_wrap_env() {
        unsafe {
            std::env::remove_var("NSH_WRAP_SCROLLBACK_LINES");
            std::env::remove_var("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES");
            std::env::remove_var("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS");
            std::env::remove_var("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS");
            std::env::remove_var("NSH_WRAP_CAPTURE_MODE");
            std::env::remove_var("NSH_WRAP_ALT_SCREEN_MODE");
            std::env::remove_var("NSH_WRAP_DAEMON_AUTOSTART");
        }
    }

    #[test]
    fn shim_wrap_config_defaults_when_env_missing() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_wrap_env();
        let cfg = ShimWrapConfig::from_env();
        assert_eq!(cfg.scrollback_lines, 1000);
        assert!(!cfg.daemon_autostart);
    }

    #[test]
    fn shim_wrap_config_reads_overrides_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_wrap_env();
        unsafe {
            std::env::set_var("NSH_WRAP_SCROLLBACK_LINES", "222");
            std::env::set_var("NSH_WRAP_DAEMON_AUTOSTART", "true");
        }
        let cfg = ShimWrapConfig::from_env();
        assert_eq!(cfg.scrollback_lines, 222);
        assert!(cfg.daemon_autostart);
        clear_wrap_env();
    }

    #[test]
    fn seed_wrap_contract_env_from_config_sets_expected_values() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_wrap_env();

        let mut config = crate::config::Config::default();
        config.context.scrollback_lines = 321;
        config.context.max_output_storage_bytes = 11111;
        config.context.scrollback_rate_limit_bps = 22222;
        config.context.scrollback_pause_seconds = 7;
        config.capture.mode = "raw".into();
        config.capture.alt_screen = "snapshot".into();

        seed_wrap_contract_env_from_config(&config);

        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_LINES").ok().as_deref(),
            Some("1000")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES")
                .ok()
                .as_deref(),
            Some("11111")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS")
                .ok()
                .as_deref(),
            Some("22222")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS")
                .ok()
                .as_deref(),
            Some("7")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_CAPTURE_MODE").ok().as_deref(),
            Some("raw")
        );
        assert_eq!(
            std::env::var("NSH_WRAP_ALT_SCREEN_MODE").ok().as_deref(),
            Some("snapshot")
        );

        clear_wrap_env();
    }

    #[test]
    fn seed_wrap_contract_preserves_explicit_daemon_autostart_override() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        clear_wrap_env();
        unsafe {
            std::env::set_var("NSH_WRAP_DAEMON_AUTOSTART", "1");
        }

        let config = crate::config::Config::default();
        seed_wrap_contract_env_from_config(&config);

        assert_eq!(
            std::env::var("NSH_WRAP_DAEMON_AUTOSTART").ok().as_deref(),
            Some("1")
        );

        clear_wrap_env();
    }
}
