pub fn extract_json(input: &str) -> Option<serde_json::Value> {
    // 1. Direct parse
    if let Ok(val) = serde_json::from_str(input) {
        return Some(val);
    }
    // 2. Strip thinking tags
    let cleaned = strip_thinking_tags(input);
    let trimmed = cleaned.trim();
    if let Ok(val) = serde_json::from_str(trimmed) {
        return Some(val);
    }
    // 3. Extract from code fences
    if let Some(json_str) = extract_from_code_fence(trimmed) {
        if let Ok(val) = serde_json::from_str(json_str.trim()) {
            return Some(val);
        }
    }
    // 4. Find first { and last matching }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            if let Ok(val) = serde_json::from_str(&trimmed[start..=end]) {
                return Some(val);
            }
        }
    }
    // 5. Same for arrays
    if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if start < end {
            if let Ok(val) = serde_json::from_str(&trimmed[start..=end]) {
                return Some(val);
            }
        }
    }
    None
}

fn strip_thinking_tags(text: &str) -> String {
    let tags = &[
        "thinking",
        "think",
        "antThinking",
        "reasoning",
        "reflection",
        "scratchpad",
        "analysis",
    ];
    let mut patterns = Vec::new();
    for tag in tags {
        // Self-closing: <tag/>, <tag />, <tag  />, case-insensitive
        patterns.push(regex::Regex::new(&format!(r"(?i)<{tag}\s*/>")).unwrap());
        // Paired: <tag>...</tag> or <tag ...>...</tag>, case-insensitive, non-greedy
        patterns.push(regex::Regex::new(&format!(r"(?is)<{tag}(\s[^>]*)?>.*?</{tag}>")).unwrap());
        // Unclosed: <tag> with no closing tag — remove from open tag onwards
        patterns.push(regex::Regex::new(&format!(r"(?is)<{tag}(\s[^>]*)?>.*$")).unwrap());
    }
    let mut result = text.to_string();
    for pat in &patterns {
        result = pat.replace_all(&result, "").to_string();
    }
    result
}

fn extract_from_code_fence(text: &str) -> Option<&str> {
    let fence_starts = ["```json\n", "```json\r\n", "```JSON\n", "```\n", "```\r\n"];
    for marker in &fence_starts {
        if let Some(start) = text.find(marker) {
            let content_start = start + marker.len();
            if let Some(end) = text[content_start..].find("```") {
                return Some(text[content_start..content_start + end].trim());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_direct_json() {
        let v = extract_json(r#"{"command": "ls -la"}"#).unwrap();
        assert_eq!(v["command"].as_str(), Some("ls -la"));
    }

    #[test]
    fn test_thinking_tags() {
        let input = "<thinking>Let me think about this...</thinking>\n{\"command\": \"pwd\"}";
        let v = extract_json(input).unwrap();
        assert_eq!(v["command"].as_str(), Some("pwd"));
    }

    #[test]
    fn test_self_closing_thinking_tags() {
        let input = "<thinking/>\n{\"command\": \"pwd\"}";
        let v = extract_json(input).unwrap();
        assert_eq!(v["command"].as_str(), Some("pwd"));

        let input2 = "<think />\n{\"command\": \"ls\"}";
        let v2 = extract_json(input2).unwrap();
        assert_eq!(v2["command"].as_str(), Some("ls"));
    }

    #[test]
    fn test_markdown_fence() {
        let input = "Here's the JSON:\n```json\n{\"command\": \"echo hi\"}\n```\nDone!";
        let v = extract_json(input).unwrap();
        assert_eq!(v["command"].as_str(), Some("echo hi"));
    }

    #[test]
    fn test_preamble_postamble() {
        let input = "Sure, here's the output:\n{\"command\": \"df -h\"}\nThis shows disk usage.";
        let v = extract_json(input).unwrap();
        assert_eq!(v["command"].as_str(), Some("df -h"));
    }

    #[test]
    fn test_no_json() {
        assert!(extract_json("just plain text").is_none());
    }

    #[test]
    fn test_nested_json() {
        let input = r#"{"a": {"b": [1, 2, {"c": 3}]}}"#;
        let v = extract_json(input).unwrap();
        assert_eq!(v["a"]["b"][2]["c"].as_i64().unwrap(), 3);
    }

    #[test]
    fn test_all_thinking_tag_variants() {
        for tag in &[
            "thinking",
            "think",
            "antThinking",
            "reasoning",
            "reflection",
            "scratchpad",
            "analysis",
        ] {
            let input = format!("<{tag}>some inner text</{tag}>{{\"command\": \"test\"}}");
            let v = extract_json(&input).unwrap();
            assert_eq!(v["command"].as_str(), Some("test"), "Failed for tag: {tag}");
        }
    }

    #[test]
    fn test_extract_json_array_with_preamble() {
        let input = "Here are the results:\n[1, 2, 3]\nDone!";
        let v = extract_json(input).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 3);
    }

    #[test]
    fn test_extract_json_array_direct() {
        let input = "[\"a\", \"b\", \"c\"]";
        let v = extract_json(input).unwrap();
        assert!(v.is_array());
    }

    #[test]
    fn test_extract_from_code_fence_plain() {
        let input = "```\n{\"key\": \"val\"}\n```";
        let v = extract_json(input).unwrap();
        assert_eq!(v["key"].as_str(), Some("val"));
    }

    #[test]
    fn test_extract_json_empty_string() {
        assert!(extract_json("").is_none());
    }

    #[test]
    fn test_extract_json_whitespace_only() {
        assert!(extract_json("   \n\t  ").is_none());
    }
}
