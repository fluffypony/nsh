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
}
