pub fn extract_json(input: &str) -> Option<serde_json::Value> {
    if let Ok(val) = serde_json::from_str(input) {
        return Some(val);
    }

    let cleaned = strip_thinking_tags(input);
    let trimmed = cleaned.trim();

    if let Ok(val) = serde_json::from_str(trimmed) {
        return Some(val);
    }

    if let Some(json_str) = extract_from_code_fence(trimmed) {
        if let Ok(val) = serde_json::from_str(json_str.trim()) {
            return Some(val);
        }
    }

    if let Some(val) = extract_braced(trimmed, '{', '}') {
        return Some(val);
    }
    if let Some(val) = extract_braced(trimmed, '[', ']') {
        return Some(val);
    }

    None
}

fn strip_thinking_tags(text: &str) -> String {
    let mut result = text.to_string();
    for tag in &["thinking", "think", "antThinking", "reflection", "reasoning", "scratchpad", "analysis"] {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        loop {
            if let Some(start) = result.find(&open) {
                if let Some(end) = result[start..].find(&close) {
                    result.replace_range(start..start + end + close.len(), "");
                    continue;
                }
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

fn extract_braced(text: &str, open: char, close: char) -> Option<serde_json::Value> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == open {
            let start = i;
            let mut depth = 1;
            let mut in_string = false;
            let mut escape = false;
            i += 1;
            while i < chars.len() && depth > 0 {
                if escape {
                    escape = false;
                } else if chars[i] == '\\' && in_string {
                    escape = true;
                } else if chars[i] == '"' {
                    in_string = !in_string;
                } else if !in_string {
                    if chars[i] == open { depth += 1; }
                    if chars[i] == close { depth -= 1; }
                }
                i += 1;
            }
            if depth == 0 {
                let substr: String = chars[start..i].iter().collect();
                if let Ok(val) = serde_json::from_str(&substr) {
                    return Some(val);
                }
            }
        } else {
            i += 1;
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
}
