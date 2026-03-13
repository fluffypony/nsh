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

#[cfg(test)]
mod tests {
    use super::{
        has_binary_changed, running_fingerprint, running_hook_hash, running_version,
        running_wrapper_protocol, snapshot_binary_meta,
    };

    #[test]
    fn running_build_metadata_is_embedded() {
        assert!(!running_version().is_empty());
        assert!(!running_fingerprint().is_empty());
        assert!(!running_wrapper_protocol().is_empty());
        assert!(!running_hook_hash().is_empty());
    }

    #[test]
    fn snapshot_binary_meta_matches_current_binary() {
        snapshot_binary_meta();
        assert!(!has_binary_changed());
    }
}
