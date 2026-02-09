use std::sync::LazyLock;

use crate::config::RedactionConfig;

static COMPILED_DEFAULTS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    RedactionConfig::default()
        .patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
});

pub fn redact_secrets(text: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return text.to_string();
    }

    let regexes: Vec<regex::Regex>;
    let patterns = if config.patterns == RedactionConfig::default().patterns {
        &*COMPILED_DEFAULTS
    } else {
        regexes = config
            .patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        &regexes
    };

    let mut result = text.to_string();
    for re in patterns {
        result = re.replace_all(&result, config.replacement.as_str()).to_string();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_redact_sk_pattern() {
        let config = RedactionConfig::default();
        let input = "my key is sk-abc123def456ghi789jkl012mno";
        let result = redact_secrets(input, &config);
        assert!(
            !result.contains("sk-abc123"),
            "sk- pattern should be redacted, got: {result}"
        );
        assert!(
            result.contains("[REDACTED]"),
            "should contain [REDACTED] marker, got: {result}"
        );
    }

    #[test]
    fn test_redact_ghp_pattern() {
        let config = RedactionConfig::default();
        let input = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        let result = redact_secrets(input, &config);
        assert!(
            !result.contains("ghp_"),
            "ghp_ pattern should be redacted, got: {result}"
        );
        assert!(
            result.contains("[REDACTED]"),
            "should contain [REDACTED] marker, got: {result}"
        );
    }

    #[test]
    fn test_redact_aws_key_pattern() {
        let config = RedactionConfig::default();
        let input = "aws key: AKIAIOSFODNN7EXAMPLE";
        let result = redact_secrets(input, &config);
        assert!(
            !result.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key pattern should be redacted, got: {result}"
        );
    }

    #[test]
    fn test_redact_disabled() {
        let mut config = RedactionConfig::default();
        config.enabled = false;
        let input = "my key is sk-abc123def456ghi789jkl012mno";
        let result = redact_secrets(input, &config);
        assert_eq!(result, input, "redaction should be skipped when disabled");
    }

    #[test]
    fn test_redact_no_secrets_unchanged() {
        let config = RedactionConfig::default();
        let input = "just a normal string with no secrets";
        let result = redact_secrets(input, &config);
        assert_eq!(result, input, "text without secrets should be unchanged");
    }
}
