use std::sync::OnceLock;
use std::time::SystemTime;

/// Fingerprint captured at process start: (file_size, mtime)
static STARTUP_META: OnceLock<Option<(u64, SystemTime)>> = OnceLock::new();

/// Snapshot the current binary's metadata at process start. Call early in main().
pub fn snapshot_binary_meta() {
    STARTUP_META.get_or_init(|| {
        std::env::current_exe()
            .ok()
            .and_then(|p| std::fs::metadata(&p).ok())
            .and_then(|m| {
                let size = m.len();
                let mtime = m.modified().ok()?;
                Some((size, mtime))
            })
    });
}

/// Check if the on-disk binary differs from the one at startup.
pub fn has_binary_changed() -> bool {
    let startup = match STARTUP_META.get().and_then(|o| o.as_ref()) {
        Some(s) => s,
        None => return false,
    };
    let current = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(&p).ok())
        .and_then(|m| {
            let size = m.len();
            let mtime = m.modified().ok()?;
            Some((size, mtime))
        });
    match current {
        Some(c) => c != *startup,
        None => false,
    }
}

/// Version compiled into this binary
pub fn running_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Build fingerprint compiled into this binary
pub fn running_fingerprint() -> &'static str {
    env!("NSH_BUILD_FINGERPRINT")
}

/// Wrapper protocol version compiled into this binary
pub fn running_wrapper_protocol() -> &'static str {
    env!("NSH_WRAPPER_PROTOCOL_VERSION")
}

/// Hook hash compiled into this binary
pub fn running_hook_hash() -> &'static str {
    env!("NSH_HOOK_HASH")
}

/// Determine what kind of restart is needed based on daemon response data
pub enum UpdateAction {
    None,
    DaemonRestartOnly,
    // With shim/core split the wrapper is frozen; terminal restart no longer required.
    TerminalRestartNeeded,
}

/// Compare a daemon's reported protocol version against ours
pub fn classify_update(daemon_protocol: u64) -> UpdateAction {
    let our_protocol: u64 = env!("NSH_WRAPPER_PROTOCOL_VERSION").parse().unwrap_or(1);
    if daemon_protocol == our_protocol {
        UpdateAction::None
    } else {
        // No-op with shim/core split; keep variant for compatibility
        UpdateAction::TerminalRestartNeeded
    }
}
