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
    // 4. Find outermost { ... } (try progressively shorter tails)
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            // Try from outermost first
            if let Ok(val) = serde_json::from_str(&trimmed[start..=end]) {
                return Some(val);
            }
            // Try progressively smaller substrings (handle trailing junk)
            for scan_end in (start + 1..=end).rev() {
                if trimmed.as_bytes()[scan_end] == b'}' {
                    if let Ok(val) = serde_json::from_str(&trimmed[start..=scan_end]) {
                        return Some(val);
                    }
                }
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

/// Represents a required key path in JSON. Keys must exist; values may be null.
#[derive(Debug, Clone)]
pub struct RequiredKeyPath(pub Vec<String>);

impl RequiredKeyPath {
    pub fn new(segments: &[&str]) -> Self {
        Self(segments.iter().map(|s| s.to_string()).collect())
    }
    pub fn exists_in(&self, value: &serde_json::Value) -> bool {
        let mut cur = value;
        for seg in &self.0 {
            match cur.get(seg) {
                Some(v) => cur = v,
                None => return false,
            }
        }
        true
    }
    pub fn arrow(&self) -> String { self.0.join("->") }
}

/// Extract JSON and validate required keys exist; return Err(list_of_missing) on failure.
pub fn extract_and_validate(
    input: &str,
    required: &[RequiredKeyPath],
) -> Result<serde_json::Value, Vec<String>> {
    let value = extract_json(input).ok_or_else(|| vec!["(no valid JSON found in response)".to_string()])?;
    let missing: Vec<String> = required
        .iter()
        .filter(|k| !k.exists_in(&value))
        .map(|k| k.arrow())
        .collect();
    if missing.is_empty() { Ok(value) } else { Err(missing) }
}

/// Build a terse feedback prompt for missing keys.
pub fn missing_keys_prompt(missing: &[String]) -> String {
    format!(
        "RESPOND ONLY WITH VALID JSON. Do NOT include any text before or after the JSON. \
         No markdown fences. No preamble. No explanation after the JSON.\n\
         Your previous response was missing these required key(s): {}.\n\
         Include ALL of them, even if the value is null.",
        missing.join(", ")
    )
}

/// Call the model, extract JSON, and retry up to max_retries if required keys are missing.
pub async fn extract_with_retry<P: crate::provider::LlmProvider + ?Sized>(
    provider: &P,
    mut request: crate::provider::ChatRequest,
    required: &[RequiredKeyPath],
    max_retries: u32,
) -> anyhow::Result<serde_json::Value> {
    let mut attempts = 0u32;
    loop {
        let resp = provider.complete(request.clone()).await?;
        let text = resp
            .content
            .iter()
            .filter_map(|b| match b { crate::provider::ContentBlock::Text { text } => Some(text.as_str()), _ => None })
            .collect::<Vec<_>>()
            .join("");
        match extract_and_validate(&text, required) {
            Ok(v) => return Ok(v),
            Err(missing) => {
                if attempts >= max_retries { anyhow::bail!("missing keys after retries: {}", missing.join(", ")); }
                attempts += 1;
                // Push feedback as a user message and retry
                request.messages.push(crate::provider::Message {
                    role: crate::provider::Role::User,
                    content: vec![crate::provider::ContentBlock::Text { text: missing_keys_prompt(&missing) }],
                });
            }
        }
    }
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
    use crate::provider::{self, ChatRequest, ContentBlock, Message, Role, ToolChoice};
    use std::sync::{Arc, Mutex};

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

    struct StubProvider {
        responses: Arc<Mutex<Vec<Message>>>,
        captured_requests: Arc<Mutex<Vec<ChatRequest>>>,
    }

    #[async_trait::async_trait]
    impl provider::LlmProvider for StubProvider {
        async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
            self.captured_requests.lock().unwrap().push(request);
            let msg = self
                .responses
                .lock()
                .unwrap()
                .remove(0);
            Ok(msg)
        }

        async fn stream(
            &self,
            _request: ChatRequest,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<provider::StreamEvent>> {
            anyhow::bail!("not used in tests")
        }
    }

    fn mk_text_message(text: &str) -> Message {
        Message { role: Role::Assistant, content: vec![ContentBlock::Text { text: text.to_string() }] }
    }

    #[tokio::test]
    async fn extract_with_retry_succeeds_on_second_attempt() {
        let required = [RequiredKeyPath::new(&["tool"]), RequiredKeyPath::new(&["input"])];
        // First response missing keys, second response correct JSON
        let responses = vec![
            mk_text_message("{}"),
            mk_text_message("{\"tool\":\"command\",\"input\":{\"command\":\"echo hi\"}}"),
        ];
        let provider = StubProvider { responses: Arc::new(Mutex::new(responses)), captured_requests: Arc::new(Mutex::new(Vec::new())) };
        let req = ChatRequest {
            model: "test-model".into(),
            system: "json only".into(),
            messages: vec![Message { role: Role::User, content: vec![ContentBlock::Text { text: "make json".into() }] }],
            tools: vec![],
            tool_choice: ToolChoice::None,
            max_tokens: 256,
            stream: false,
            extra_body: None,
        };
        let out = extract_with_retry(&provider, req, &required, 2).await.expect("should succeed");
        assert_eq!(out["tool"].as_str(), Some("command"));
        assert!(provider.captured_requests.lock().unwrap().len() >= 2);
    }

    #[tokio::test]
    async fn extract_with_retry_fails_after_max_attempts() {
        let required = [RequiredKeyPath::new(&["tool"]), RequiredKeyPath::new(&["input"])];
        let responses = vec![mk_text_message("{}"), mk_text_message("{}")];
        let provider = StubProvider { responses: Arc::new(Mutex::new(responses)), captured_requests: Arc::new(Mutex::new(Vec::new())) };
        let req = ChatRequest {
            model: "test-model".into(),
            system: "json only".into(),
            messages: vec![Message { role: Role::User, content: vec![ContentBlock::Text { text: "make json".into() }] }],
            tools: vec![],
            tool_choice: ToolChoice::None,
            max_tokens: 128,
            stream: false,
            extra_body: None,
        };
        let err = extract_with_retry(&provider, req, &required, 1).await.err().expect("should fail");
        assert!(err.to_string().contains("missing keys"));
    }
}
