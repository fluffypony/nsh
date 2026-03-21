//! Shell hook-related constants and helpers.
//!
//! ## Future Architecture: Persistent Socket Event Subscription
//!
//! The current `pending_{session}.json` file approach can be replaced with
//! a persistent Unix socket subscription from the shell process to the
//! per-session daemon. The shell would connect once at init and receive
//! push-based events (pending commands, hook reload notices, notifications)
//! as framed messages, eliminating filesystem polling and race conditions.
//!
//! Protocol sketch:
//!   - Shell connects to `~/.nsh/events_{session_id}.sock` at init
//!   - Daemon pushes: `{"type":"pending_command","command":"...","autorun":true}`
//!   - Shell reads from fd in prompt hook (non-blocking)
//!   - Bash: coproc; Zsh: zpty/zle -F; Fish: background job
//!
//! This naturally evolves the JSON file approach without requiring a
//! separate transport layer for each future real-time feature.

/// Clean up pending files for a session.
pub fn cleanup_pending_files(session_id: &str) {
    let dir = crate::config::Config::nsh_dir();
    let _ = std::fs::remove_file(dir.join(format!("pending_{session_id}.json")));
    let _ = std::fs::remove_file(dir.join(format!("scrollback_{session_id}")));
    #[cfg(unix)]
    let _ = std::fs::remove_file(dir.join(format!("scrollback_{session_id}.sock")));
    #[cfg(unix)]
    let _ = std::fs::remove_file(dir.join(format!("daemon_{session_id}.sock")));
    let _ = std::fs::remove_file(dir.join(format!("daemon_{session_id}.pid")));
    let _ = std::fs::remove_file(dir.join(format!("redact_next_{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("redact_active_{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("nsh_msg_{session_id}")));
    let _ = std::fs::remove_file(dir.join(format!("last_update_notice_{session_id}")));

    // Clean up per-TTY CWD file (only if this process owns the session)
    if let Ok(env_session) = std::env::var("NSH_SESSION_ID")
        && env_session == session_id
        && let Ok(tty) = std::env::var("NSH_TTY")
    {
        crate::fast_cwd::remove_tty_cwd(&tty);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;

    #[test]
    #[serial_test::serial]
    fn test_cleanup_pending_files_no_panic() {
        let home = tempfile::tempdir().unwrap();
        let _home_guard = EnvVarGuard::set("HOME", home.path());
        cleanup_pending_files("nonexistent-session-id-12345");
    }
}
