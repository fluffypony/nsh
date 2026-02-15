//! Shell hook-related constants and helpers.

/// Marker used to identify nsh-generated pending commands.
pub const PENDING_CMD_PREFIX: &str = "pending_cmd_";
pub const PENDING_FLAG_PREFIX: &str = "pending_flag_";
pub const PENDING_AUTORUN_PREFIX: &str = "pending_autorun_";

/// Clean up pending files for a session.
pub fn cleanup_pending_files(session_id: &str) {
    let dir = crate::config::Config::nsh_dir();
    let _ = std::fs::remove_file(dir.join(format!("{PENDING_CMD_PREFIX}{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("{PENDING_FLAG_PREFIX}{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("{PENDING_AUTORUN_PREFIX}{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("scrollback_{session_id}")));
    #[cfg(unix)]
    let _ = std::fs::remove_file(dir.join(format!("scrollback_{session_id}.sock")));
    #[cfg(unix)]
    let _ = std::fs::remove_file(dir.join(format!("daemon_{session_id}.sock")));
    let _ = std::fs::remove_file(dir.join(format!("daemon_{session_id}.pid")));
    let _ = std::fs::remove_file(dir.join(format!("redact_next_{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("redact_active_{session_id}")));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    struct EnvVarGuard {
        key: &'static str,
        old: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let old = std::env::var(key).ok();
            // SAFETY: test-only; this test is serialized.
            unsafe { std::env::set_var(key, value) };
            Self { key, old }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(old) = &self.old {
                // SAFETY: test-only; this test is serialized.
                unsafe { std::env::set_var(self.key, old) };
            } else {
                // SAFETY: test-only; this test is serialized.
                unsafe { std::env::remove_var(self.key) };
            }
        }
    }

    #[test]
    fn test_pending_cmd_prefix() {
        assert_eq!(PENDING_CMD_PREFIX, "pending_cmd_");
    }

    #[test]
    fn test_pending_flag_prefix() {
        assert_eq!(PENDING_FLAG_PREFIX, "pending_flag_");
    }

    #[test]
    fn test_pending_autorun_prefix() {
        assert_eq!(PENDING_AUTORUN_PREFIX, "pending_autorun_");
    }

    #[test]
    #[serial_test::serial]
    fn test_cleanup_pending_files_no_panic() {
        let home = tempfile::tempdir().unwrap();
        let _home_guard = EnvVarGuard::set("HOME", home.path());
        cleanup_pending_files("nonexistent-session-id-12345");
    }
}
