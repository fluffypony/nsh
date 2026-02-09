/// Shell hook-related constants and helpers.

/// Marker used to identify nsh-generated pending commands.
pub const PENDING_CMD_PREFIX: &str = "pending_cmd_";
pub const PENDING_FLAG_PREFIX: &str = "pending_flag_";

/// Clean up pending files for a session.
pub fn cleanup_pending_files(session_id: &str) {
    let dir = crate::config::Config::nsh_dir();
    let _ = std::fs::remove_file(
        dir.join(format!("{PENDING_CMD_PREFIX}{session_id}")),
    );
    let _ = std::fs::remove_file(
        dir.join(format!("{PENDING_FLAG_PREFIX}{session_id}")),
    );
    let _ = std::fs::remove_file(
        dir.join(format!("scrollback_{session_id}")),
    );
    let _ = std::fs::remove_file(
        dir.join(format!("scrollback_{session_id}.sock")),
    );
    let _ = std::fs::remove_file(
        dir.join(format!("redact_next_{session_id}")),
    );
    let _ = std::fs::remove_file(
        dir.join(format!("redact_active_{session_id}")),
    );
}
