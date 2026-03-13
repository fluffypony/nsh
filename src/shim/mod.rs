//! Stable shim boundary — PTY wrapper, pump loop, and capture engine.
//!
//! Code in this module is part of the "frozen" shim binary (`nsh`).
//! It persists for the lifetime of a terminal session and should
//! change extremely rarely. Any change here requires users to
//! restart their terminal.
//!
//! Dependencies: pty.rs, pump.rs — these are also part of the stable boundary.

mod config;
pub mod pump;
#[cfg(unix)]
pub mod pty;
#[cfg(windows)]
#[path = "../pty_windows.rs"]
pub mod pty;
mod wrap;

pub use config::{ShimWrapConfig, seed_wrap_contract_env_from_config};
pub use wrap::run_wrap;

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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
        clear_wrap_env();
        let cfg = ShimWrapConfig::from_env();
        assert_eq!(cfg.scrollback_lines, 1000);
        assert!(!cfg.daemon_autostart);
    }

    #[test]
    fn shim_wrap_config_reads_overrides_from_env() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
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
        let _guard = ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner());
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
