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
}
