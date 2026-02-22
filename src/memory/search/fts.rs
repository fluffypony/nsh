pub fn build_fts5_query(query: &str) -> String {
    let words: Vec<&str> = query
        .split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
        .filter(|w| w.len() > 1)
        .collect();
    if words.is_empty() {
        return String::new();
    }
    words
        .iter()
        .map(|w| format!("\"{w}\" OR {w}*"))
        .collect::<Vec<_>>()
        .join(" OR ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_fts5_query_basic() {
        let result = build_fts5_query("cargo build");
        assert!(result.contains("\"cargo\""));
        assert!(result.contains("\"build\""));
        assert!(result.contains("cargo*"));
        assert!(result.contains("build*"));
    }

    #[test]
    fn build_fts5_query_empty() {
        assert_eq!(build_fts5_query(""), "");
        assert_eq!(build_fts5_query("a"), ""); // single char filtered
    }

    #[test]
    fn build_fts5_query_special_chars() {
        let result = build_fts5_query("hello.world foo@bar");
        assert!(result.contains("\"hello\""));
        assert!(result.contains("\"world\""));
        assert!(result.contains("\"foo\""));
        assert!(result.contains("\"bar\""));
    }

    #[test]
    fn build_fts5_query_underscores_preserved() {
        let result = build_fts5_query("my_function");
        assert!(result.contains("\"my_function\""));
    }

    #[test]
    fn build_fts5_query_dashes_preserved() {
        let result = build_fts5_query("my-function");
        assert!(result.contains("\"my-function\""));
        assert!(result.contains("my-function*"));
    }

    #[test]
    fn build_fts5_query_single_word() {
        let result = build_fts5_query("cargo");
        assert_eq!(result, "\"cargo\" OR cargo*");
    }

    #[test]
    fn build_fts5_query_multiple_or_clauses() {
        let result = build_fts5_query("cargo build test");
        // Each word should have exact + prefix
        let parts: Vec<&str> = result.split(" OR ").collect();
        // 3 words * 2 (exact+prefix) = 6 parts
        assert_eq!(parts.len(), 6);
    }

    #[test]
    fn build_fts5_query_filters_short_tokens() {
        let result = build_fts5_query("I a x");
        // "I", "a", "x" are all 1 char — all filtered out by len() > 1
        assert_eq!(result, "");
    }

    #[test]
    fn build_fts5_query_numbers() {
        let result = build_fts5_query("error 404 timeout");
        assert!(result.contains("\"error\""));
        assert!(result.contains("\"404\""));
        assert!(result.contains("\"timeout\""));
    }

    #[test]
    fn build_fts5_query_mixed_punctuation() {
        let result = build_fts5_query("user@host.com:8080/path");
        // Should split on @, ., :, /
        assert!(result.contains("\"user\""));
        assert!(result.contains("\"host\""));
        assert!(result.contains("\"com\""));
        assert!(result.contains("\"8080\""));
        assert!(result.contains("\"path\""));
    }

    #[test]
    fn build_fts5_query_duplicates() {
        // Duplicate words should still work (FTS5 handles it)
        let result = build_fts5_query("cargo cargo");
        assert!(result.contains("\"cargo\""));
    }

    #[test]
    fn build_fts5_query_whitespace_only() {
        assert_eq!(build_fts5_query("   "), "");
    }

    #[test]
    fn build_fts5_query_long_input() {
        let result = build_fts5_query(
            "this is a very long query with many words that should all be processed correctly",
        );
        assert!(result.contains("\"very\""));
        assert!(result.contains("\"long\""));
        assert!(result.contains("\"query\""));
    }
}
