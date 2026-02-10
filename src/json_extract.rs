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
    let mut result = text.to_string();
    let tags = &[
        "thinking", "think", "antThinking", "reasoning",
        "reflection", "scratchpad", "analysis",
    ];
    for tag in tags {
        // Remove self-closing variants: <tag/> or <tag />
        let self_closing1 = format!("<{tag}/>");
        let self_closing2 = format!("<{tag} />");
        result = result.replace(&self_closing1, "");
        result = result.replace(&self_closing2, "");

        // Remove paired tags and their content
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        loop {
            if let Some(start) = result.find(&open) {
                if let Some(end) = result[start..].find(&close) {
                    result.replace_range(start..start + end + close.len(), "");
                    continue;
                }
                // Unclosed tag — remove everything from open tag onwards
                result = result[..start].to_string();
            }
            break;
        }
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
        for tag in &["thinking", "think", "antThinking", "reasoning", "reflection", "scratchpad", "analysis"] {
            let input = format!("<{tag}>some inner text</{tag}>{{\"command\": \"test\"}}");
            let v = extract_json(&input).unwrap();
            assert_eq!(v["command"].as_str(), Some("test"), "Failed for tag: {tag}");
        }
    }
}
