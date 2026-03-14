#[derive(Debug, Clone)]
pub struct ShimWrapConfig {
    pub scrollback_lines: usize,
    pub max_output_storage_bytes: usize,
    pub scrollback_rate_limit_bps: usize,
    pub scrollback_pause_seconds: u64,
    pub capture_mode: crate::config::CaptureMode,
    pub alt_screen_mode: crate::config::AltScreenMode,
    pub daemon_autostart: bool,
}

impl Default for ShimWrapConfig {
    fn default() -> Self {
        Self {
            scrollback_lines: 1000,
            max_output_storage_bytes: 65536,
            scrollback_rate_limit_bps: 10_485_760,
            scrollback_pause_seconds: 2,
            capture_mode: crate::config::CaptureMode::Vt100,
            alt_screen_mode: crate::config::AltScreenMode::Drop,
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
            capture_mode: read_env_capture_mode("NSH_WRAP_CAPTURE_MODE")
                .unwrap_or(defaults.capture_mode),
            alt_screen_mode: read_env_alt_screen_mode("NSH_WRAP_ALT_SCREEN_MODE")
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

fn read_env_capture_mode(key: &str) -> Option<crate::config::CaptureMode> {
    let raw = std::env::var(key).ok()?;
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => None,
        "raw" => Some(crate::config::CaptureMode::Raw),
        "vt100" => Some(crate::config::CaptureMode::Vt100),
        _ => {
            tracing::warn!("ignoring invalid {key} value: {}", raw.trim());
            None
        }
    }
}

fn read_env_alt_screen_mode(key: &str) -> Option<crate::config::AltScreenMode> {
    let raw = std::env::var(key).ok()?;
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => None,
        "capture" => Some(crate::config::AltScreenMode::Capture),
        "drop" => Some(crate::config::AltScreenMode::Drop),
        "snapshot" => Some(crate::config::AltScreenMode::Snapshot),
        _ => {
            tracing::warn!("ignoring invalid {key} value: {}", raw.trim());
            None
        }
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
        std::env::set_var("NSH_WRAP_CAPTURE_MODE", config.capture.mode.as_str());
        std::env::set_var(
            "NSH_WRAP_ALT_SCREEN_MODE",
            config.capture.alt_screen.as_str(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::{ShimWrapConfig, seed_wrap_contract_env_from_config};
    use crate::config::{AltScreenMode, CaptureMode, Config};
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    fn clear_wrap_env() -> [EnvVarGuard; 7] {
        [
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_LINES"),
            EnvVarGuard::remove("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES"),
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS"),
            EnvVarGuard::remove("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS"),
            EnvVarGuard::remove("NSH_WRAP_CAPTURE_MODE"),
            EnvVarGuard::remove("NSH_WRAP_ALT_SCREEN_MODE"),
            EnvVarGuard::remove("NSH_WRAP_DAEMON_AUTOSTART"),
        ]
    }

    #[test]
    #[serial]
    fn from_env_uses_defaults_for_missing_and_invalid_values() {
        let _guards = clear_wrap_env();
        // SAFETY: test-only env mutation guarded by serial execution.
        unsafe {
            std::env::set_var("NSH_WRAP_SCROLLBACK_LINES", "not-a-number");
            std::env::set_var("NSH_WRAP_CAPTURE_MODE", "");
            std::env::set_var("NSH_WRAP_DAEMON_AUTOSTART", "maybe");
        }

        let config = ShimWrapConfig::from_env();

        assert_eq!(config.scrollback_lines, 1000);
        assert_eq!(config.capture_mode, CaptureMode::Vt100);
        assert_eq!(config.alt_screen_mode, AltScreenMode::Drop);
        assert!(!config.daemon_autostart);
    }

    #[test]
    #[serial]
    fn from_env_reads_valid_overrides() {
        let _guards = clear_wrap_env();
        // SAFETY: test-only env mutation guarded by serial execution.
        unsafe {
            std::env::set_var("NSH_WRAP_SCROLLBACK_LINES", "2048");
            std::env::set_var("NSH_WRAP_MAX_OUTPUT_STORAGE_BYTES", "8192");
            std::env::set_var("NSH_WRAP_SCROLLBACK_RATE_LIMIT_BPS", "4096");
            std::env::set_var("NSH_WRAP_SCROLLBACK_PAUSE_SECONDS", "9");
            std::env::set_var("NSH_WRAP_CAPTURE_MODE", "raw");
            std::env::set_var("NSH_WRAP_ALT_SCREEN_MODE", "snapshot");
            std::env::set_var("NSH_WRAP_DAEMON_AUTOSTART", "true");
        }

        let config = ShimWrapConfig::from_env();

        assert_eq!(config.scrollback_lines, 2048);
        assert_eq!(config.max_output_storage_bytes, 8192);
        assert_eq!(config.scrollback_rate_limit_bps, 4096);
        assert_eq!(config.scrollback_pause_seconds, 9);
        assert_eq!(config.capture_mode, CaptureMode::Raw);
        assert_eq!(config.alt_screen_mode, AltScreenMode::Snapshot);
        assert!(config.daemon_autostart);
    }

    #[test]
    #[serial]
    fn seed_wrap_contract_env_from_config_sets_expected_values() {
        let _guards = clear_wrap_env();
        let mut config = Config::default();
        config.context.scrollback_lines = 321;
        config.context.max_output_storage_bytes = 11111;
        config.context.scrollback_rate_limit_bps = 22222;
        config.context.scrollback_pause_seconds = 7;
        config.capture.mode = CaptureMode::Raw;
        config.capture.alt_screen = AltScreenMode::Snapshot;

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
    }
}
