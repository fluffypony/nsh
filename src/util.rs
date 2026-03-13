/// Truncate a string to at most `max_chars` characters, appending
/// an ellipsis indicator if truncated.
pub fn truncate(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max_chars).collect();
        format!("{truncated}\n[... truncated]")
    }
}

pub fn truncate_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn compare_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> Vec<u32> {
        s.split('.')
            .map(|p| p.parse::<u32>().unwrap_or(0))
            .collect()
    };
    let a_parts = parse(a);
    let b_parts = parse(b);
    let len = a_parts.len().max(b_parts.len());
    for i in 0..len {
        let av = a_parts.get(i).copied().unwrap_or(0);
        let bv = b_parts.get(i).copied().unwrap_or(0);
        match av.cmp(&bv) {
            std::cmp::Ordering::Equal => continue,
            ord => return ord,
        }
    }
    std::cmp::Ordering::Equal
}

pub(crate) fn human_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.0}{unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.0}PB")
}

#[cfg(unix)]
pub(crate) fn check_peer_uid(
    stream: &std::os::unix::net::UnixStream,
    log_rejection: bool,
) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            if log_rejection {
                tracing::warn!("Rejecting daemon connection: SO_PEERCRED failed");
            }
            return false;
        }
        if cred.uid != unsafe { libc::getuid() } {
            if log_rejection {
                tracing::warn!("Rejecting daemon connection from uid {}", cred.uid);
            }
            return false;
        }
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    {
        use std::os::fd::AsRawFd;
        let mut euid: libc::uid_t = 0;
        let mut egid: libc::gid_t = 0;
        let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut euid, &mut egid) };
        if rc != 0 {
            if log_rejection {
                tracing::warn!("Rejecting daemon connection: getpeereid failed");
            }
            return false;
        }
        if euid != unsafe { libc::getuid() } {
            if log_rejection {
                tracing::warn!("Rejecting daemon connection from uid {}", euid);
            }
            return false;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "freebsd")))]
    {
        tracing::warn!(
            "Peer UID check not implemented for this platform, relying on socket permissions"
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_short_string() {
        let result = truncate("hello", 10);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_long_string() {
        let result = truncate("hello world", 5);
        assert_eq!(result, "hello\n[... truncated]");
    }

    #[test]
    fn test_truncate_exact_boundary() {
        let result = truncate("hello", 5);
        assert_eq!(result, "hello");
    }

    #[test]
    fn test_truncate_multibyte() {
        let emoji = "😀😀😀😀😀";
        let result = truncate(emoji, 3);
        assert_eq!(result, "😀😀😀\n[... truncated]");

        let no_trunc = truncate(emoji, 5);
        assert_eq!(no_trunc, emoji);
    }

    #[test]
    fn test_truncate_bytes_short() {
        assert_eq!(truncate_bytes("hello", 10), "hello");
    }

    #[test]
    fn test_truncate_bytes_exact() {
        assert_eq!(truncate_bytes("hello", 5), "hello");
    }

    #[test]
    fn test_truncate_bytes_cuts() {
        assert_eq!(truncate_bytes("hello world", 5), "hello");
    }

    #[test]
    fn test_truncate_bytes_multibyte_boundary() {
        let emoji = "😀😀";
        assert_eq!(truncate_bytes(emoji, 5), "😀");
        assert_eq!(truncate_bytes(emoji, 4), "😀");
        assert_eq!(truncate_bytes(emoji, 3), "");
    }

    #[test]
    fn test_truncate_bytes_mid_multibyte_produces_valid_utf8() {
        let input = "🎉🎊🎈";
        for cut in 1..=12 {
            let result = truncate_bytes(input, cut);
            assert!(
                result.len() <= cut,
                "truncate_bytes at {cut} produced {} bytes",
                result.len()
            );
            assert!(
                result.is_empty() || result.chars().last().is_some(),
                "truncate_bytes at {cut} produced invalid UTF-8 boundary"
            );
        }
        assert_eq!(truncate_bytes("😀abc", 1), "");
        assert_eq!(truncate_bytes("😀abc", 2), "");
        assert_eq!(truncate_bytes("😀abc", 3), "");
        assert_eq!(truncate_bytes("😀abc", 4), "😀");
        assert_eq!(truncate_bytes("😀abc", 5), "😀a");
    }

    #[test]
    fn test_truncate_empty_string() {
        assert_eq!(truncate("", 10), "");
        assert_eq!(truncate("", 0), "");
    }

    #[test]
    fn test_truncate_shorter_than_limit() {
        assert_eq!(truncate("hi", 100), "hi");
    }

    #[test]
    fn test_truncate_exactly_at_limit() {
        assert_eq!(truncate("abcde", 5), "abcde");
    }

    #[test]
    fn test_truncate_longer_than_limit() {
        let result = truncate("abcdefghij", 3);
        assert_eq!(result, "abc\n[... truncated]");
    }

    #[test]
    fn test_truncate_unicode_mixed() {
        let input = "aé日😀";
        let result = truncate(input, 2);
        assert_eq!(result, "aé\n[... truncated]");
        let result = truncate(input, 4);
        assert_eq!(result, input);
    }

    #[test]
    fn test_truncate_bytes_empty() {
        assert_eq!(truncate_bytes("", 0), "");
        assert_eq!(truncate_bytes("", 10), "");
    }

    #[test]
    fn test_truncate_bytes_zero_limit() {
        assert_eq!(truncate_bytes("hello", 0), "");
    }

    #[test]
    fn test_compare_versions_equal() {
        assert_eq!(
            compare_versions("1.2.3", "1.2.3"),
            std::cmp::Ordering::Equal
        );
    }

    #[test]
    fn test_compare_versions_newer_minor() {
        assert_eq!(
            compare_versions("0.2.0", "0.1.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_versions("0.1.0", "0.2.0"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_compare_versions_newer_major() {
        assert_eq!(
            compare_versions("2.0.0", "1.9.9"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_versions("1.0.0", "2.0.0"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_compare_versions_newer_patch() {
        assert_eq!(
            compare_versions("1.0.1", "1.0.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(compare_versions("1.0.0", "1.0.1"), std::cmp::Ordering::Less);
    }

    #[test]
    fn test_compare_versions_different_length() {
        assert_eq!(compare_versions("1.0", "1.0.0"), std::cmp::Ordering::Equal);
        assert_eq!(compare_versions("1.0", "1.0.1"), std::cmp::Ordering::Less);
        assert_eq!(
            compare_versions("1.0.1", "1.0"),
            std::cmp::Ordering::Greater
        );
    }
}
