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
