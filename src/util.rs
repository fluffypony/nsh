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
}
