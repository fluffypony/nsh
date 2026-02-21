use crate::memory::types::DetectedSecret;

pub fn is_ignored_path(path: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
            if glob_pattern.matches(path) {
                return true;
            }
        }
    }
    false
}

pub fn load_ignore_patterns() -> Vec<String> {
    let ignore_path = crate::config::Config::nsh_dir().join("memory_ignore");
    if !ignore_path.exists() {
        return Vec::new();
    }
    match std::fs::read_to_string(&ignore_path) {
        Ok(content) => content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(|l| l.to_string())
            .collect(),
        Err(_) => Vec::new(),
    }
}

pub fn redact_secrets_for_memory(text: &str) -> (String, Vec<DetectedSecret>) {
    let config = crate::config::RedactionConfig {
        enabled: true,
        patterns: vec![],
        replacement: String::new(),
        disable_builtin: false,
    };
    let redacted = crate::redact::redact_secrets(text, &config);

    let mut detected = Vec::new();
    let mut search_start = 0;
    while let Some(start) = redacted[search_start..].find("[REDACTED:") {
        let abs_start = search_start + start;
        if let Some(end) = redacted[abs_start..].find(']') {
            let label = redacted[abs_start + 10..abs_start + end].to_string();
            detected.push(DetectedSecret {
                label,
                value: String::new(), // don't store the actual value here
                position: abs_start,
            });
            search_start = abs_start + end + 1;
        } else {
            break;
        }
    }

    (redacted, detected)
}

pub fn should_skip_output(output: &str) -> bool {
    // Skip binary-looking output
    if output.bytes().any(|b| b == 0) {
        return true;
    }
    // Skip very large output (>50KB)
    if output.len() > 50_000 {
        return true;
    }
    false
}

pub fn is_password_prompt(text: &str) -> bool {
    let lower = text.to_lowercase();
    let prompts = [
        "password:", "passphrase:", "enter pin:",
        "password for", "authentication required",
    ];
    prompts.iter().any(|p| lower.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ignore_pattern_matching() {
        let patterns = vec![
            "*.secret".to_string(),
            "/tmp/*".to_string(),
            "*.env".to_string(),
        ];
        assert!(is_ignored_path("config.secret", &patterns));
        assert!(is_ignored_path("/tmp/test", &patterns));
        assert!(is_ignored_path(".env", &patterns));
        assert!(!is_ignored_path("main.rs", &patterns));
    }

    #[test]
    fn should_skip_binary_output() {
        assert!(should_skip_output("hello\x00world"));
        assert!(!should_skip_output("hello world"));
    }

    #[test]
    fn should_skip_large_output() {
        let large = "x".repeat(60_000);
        assert!(should_skip_output(&large));
    }

    #[test]
    fn password_prompt_detection() {
        assert!(is_password_prompt("Password:"));
        assert!(is_password_prompt("Enter passphrase:"));
        assert!(is_password_prompt("[sudo] password for user:"));
        assert!(!is_password_prompt("Enter your name:"));
    }

    #[test]
    fn redact_secrets_detects_patterns() {
        let (redacted, _secrets) = redact_secrets_for_memory("just normal text");
        assert_eq!(redacted, "just normal text");
    }
}
