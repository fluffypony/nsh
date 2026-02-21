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
        .map(|w| format!("\"{}\" OR {}*", w, w))
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
}
