use reqwest::Client;
use serde_json::json;
use zeroize::Zeroizing;

use crate::provider::*;

pub struct OpenAICompatProvider {
    client: Client,
    api_key: Zeroizing<String>,
    base_url: String,
    fallback_model: Option<String>,
    extra_headers: Vec<(String, String)>,
}

impl OpenAICompatProvider {
    pub fn new(
        api_key: Zeroizing<String>,
        base_url: String,
        fallback_model: Option<String>,
        extra_headers: Vec<(String, String)>,
        timeout_seconds: u64,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(timeout_seconds))
                .build()?,
            api_key,
            base_url,
            fallback_model,
            extra_headers,
        })
    }

    fn build_request_body(&self, request: &ChatRequest) -> serde_json::Value {
        let model = request.model.as_str();
        let anthropic = is_anthropic_model(model);

        let messages = if anthropic {
            build_openai_messages(&request.messages, "")
        } else {
            build_openai_messages(&request.messages, &request.system)
        };
        let mut tools = build_openai_tools(&request.tools);

        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": request.stream,
        });

        if !tools.is_empty() {
            if anthropic {
                if let Some(last) = tools.last_mut() {
                    last["cache_control"] = json!({"type": "ephemeral"});
                }
            }
            body["tools"] = json!(tools);
        }

        match request.tool_choice {
            ToolChoice::Required => {
                body["tool_choice"] = json!("required");
            }
            ToolChoice::None => {
                body["tool_choice"] = json!("none");
            }
            ToolChoice::Auto => {
                body["tool_choice"] = json!("auto");
            }
        }

        if anthropic {
            body["system"] = json!([{
                "type": "text",
                "text": &request.system,
                "cache_control": {"type": "ephemeral"}
            }]);
        }

        if let Some(serde_json::Value::Object(map)) = &request.extra_body {
            for (k, v) in map {
                body[k] = v.clone();
            }
        }

        body
    }

    fn build_http_request(&self, body: &serde_json::Value, model: &str) -> reqwest::RequestBuilder {
        // reqwest internally copies the value into its own buffer, so zeroization is best-effort
        let auth_value = Zeroizing::new(format!("Bearer {}", &*self.api_key));
        let mut header_val = reqwest::header::HeaderValue::from_str(&auth_value)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
        header_val.set_sensitive(true);
        let mut req = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", header_val)
            .json(body);
        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if is_anthropic_model(model) && self.base_url.contains("openrouter") {
            req = req.header("anthropic-beta", "prompt-caching-2024-07-31");
        }
        req
    }
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn is_anthropic_model(model: &str) -> bool {
    model.contains("claude") || model.starts_with("anthropic/")
}

pub fn apply_thinking_mode(body: &mut serde_json::Value, model: &str, think: bool) {
    if !think {
        if model.starts_with("google/gemini-3") {
            body["reasoning"] = json!({"effort": "low"});
        }
        return;
    }
    if model.starts_with("google/gemini-3") {
        body["reasoning"] = json!({"effort": "high"});
    } else if model.contains("claude") && model.contains("sonnet") {
        body["reasoning"] = json!({"enabled": true, "budget_tokens": 32768});
    }
}

pub fn thinking_model_name(model: &str, think: bool) -> String {
    if think && model.starts_with("google/gemini-2.5") && !model.ends_with(":thinking") {
        format!("{model}:thinking")
    } else {
        model.to_string()
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAICompatProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        let model = request.model.clone();
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(false);
        let resp = self.build_http_request(&body, &model).send().await?;
        let status = resp.status();

        if !status.is_success() {
            if is_retryable(status) {
                if let Some(fallback) = &self.fallback_model {
                    tracing::warn!("Primary model failed ({status}), trying fallback: {fallback}");
                    let mut fb = body.clone();
                    fb["model"] = json!(fallback);
                    let resp2 = self.build_http_request(&fb, fallback).send().await?;
                    let status2 = resp2.status();
                    if !status2.is_success() {
                        let text = resp2.text().await.unwrap_or_default();
                        anyhow::bail!("API error (fallback {status2}): {text}");
                    }
                    return parse_openai_response(&resp2.json().await?);
                }
            }
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({status}): {text}");
        }

        parse_openai_response(&resp.json().await?)
    }

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        let model = request.model.clone();
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(true);

        let resp = self.build_http_request(&body, &model).send().await?;
        let status = resp.status();

        if !status.is_success() {
            if is_retryable(status) {
                if let Some(fallback) = &self.fallback_model {
                    tracing::warn!("Primary failed ({status}), stream fallback: {fallback}");
                    let mut fb = body.clone();
                    fb["model"] = json!(fallback);
                    let resp2 = self.build_http_request(&fb, fallback).send().await?;
                    let status2 = resp2.status();
                    if !status2.is_success() {
                        let text = resp2.text().await.unwrap_or_default();
                        anyhow::bail!("API error (fallback {status2}): {text}");
                    }
                    return spawn_openai_stream(resp2);
                }
            }
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("API error ({status}): {text}");
        }
        spawn_openai_stream(resp)
    }
}

pub fn build_openai_messages(messages: &[Message], system: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }
    for msg in messages {
        match msg.role {
            Role::User => {
                let text: String = msg
                    .content
                    .iter()
                    .filter_map(|c| {
                        if let ContentBlock::Text { text } = c {
                            Some(text.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.push(json!({"role": "user", "content": text}));
            }
            Role::Assistant => {
                let mut tool_calls = vec![];
                let mut text_parts = vec![];
                for block in &msg.content {
                    match block {
                        ContentBlock::ToolUse { id, name, input } => {
                            tool_calls.push(json!({
                                "id": id, "type": "function",
                                "function": {"name": name, "arguments": input.to_string()}
                            }));
                        }
                        ContentBlock::Text { text } => {
                            text_parts.push(text.as_str());
                        }
                        _ => {}
                    }
                }
                let mut msg_json = json!({"role": "assistant"});
                if !text_parts.is_empty() {
                    msg_json["content"] = json!(text_parts.join("\n"));
                }
                if !tool_calls.is_empty() {
                    msg_json["tool_calls"] = json!(tool_calls);
                }
                out.push(msg_json);
            }
            Role::Tool => {
                for block in &msg.content {
                    if let ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        out.push(json!({"role": "tool", "tool_call_id": tool_use_id, "content": content}));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub fn build_openai_tools(tools: &[crate::tools::ToolDefinition]) -> Vec<serde_json::Value> {
    tools.iter().map(|t| json!({
        "type": "function",
        "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
    })).collect()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::provider::{ContentBlock, Message, Role};
    use crate::tools::ToolDefinition;
    use serde_json::json;

    #[test]
    fn build_openai_messages_user() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "user");
        assert_eq!(result[0]["content"], "hello");
    }

    #[test]
    fn build_openai_messages_with_system() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hi".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "You are helpful");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[0]["content"], "You are helpful");
        assert_eq!(result[1]["role"], "user");
    }

    #[test]
    fn build_openai_messages_assistant_text_and_tool_calls() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "thinking".into(),
                },
                ContentBlock::ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: json!({"path": "/tmp"}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert_eq!(result[0]["content"], "thinking");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "c1");
        assert_eq!(tc[0]["type"], "function");
        assert_eq!(tc[0]["function"]["name"], "read_file");
    }

    #[test]
    fn build_openai_messages_tool_result() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "c1".into(),
                content: "file contents".into(),
                is_error: false,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "tool");
        assert_eq!(result[0]["tool_call_id"], "c1");
        assert_eq!(result[0]["content"], "file contents");
    }

    #[test]
    fn build_openai_tools_basic() {
        let tools = vec![ToolDefinition {
            name: "test_tool".into(),
            description: "A test tool".into(),
            parameters: json!({"type": "object", "properties": {}}),
        }];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["type"], "function");
        assert_eq!(result[0]["function"]["name"], "test_tool");
        assert_eq!(result[0]["function"]["description"], "A test tool");
    }

    #[test]
    fn build_openai_tools_empty() {
        let result = build_openai_tools(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn is_anthropic_model_claude() {
        assert!(is_anthropic_model("claude-3.5-sonnet"));
        assert!(is_anthropic_model("claude-3-opus"));
        assert!(is_anthropic_model("anthropic/claude-3.5-sonnet"));
    }

    #[test]
    fn is_anthropic_model_non_claude() {
        assert!(!is_anthropic_model("gpt-4"));
        assert!(!is_anthropic_model("gemini-pro"));
        assert!(!is_anthropic_model("llama-3"));
    }

    #[test]
    fn apply_thinking_mode_gemini3_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", false);
        assert_eq!(body["reasoning"]["effort"], "low");
    }

    #[test]
    fn apply_thinking_mode_gemini3_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", true);
        assert_eq!(body["reasoning"]["effort"], "high");
    }

    #[test]
    fn apply_thinking_mode_claude_sonnet_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["reasoning"]["budget_tokens"], 32768);
    }

    #[test]
    fn apply_thinking_mode_claude_sonnet_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_other_model_no_change() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "gpt-4", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn thinking_model_name_gemini_25_think() {
        let result = thinking_model_name("google/gemini-2.5-pro", true);
        assert_eq!(result, "google/gemini-2.5-pro:thinking");
    }

    #[test]
    fn thinking_model_name_gemini_25_already_thinking() {
        let result = thinking_model_name("google/gemini-2.5-pro:thinking", true);
        assert_eq!(result, "google/gemini-2.5-pro:thinking");
    }

    #[test]
    fn thinking_model_name_gemini_25_no_think() {
        let result = thinking_model_name("google/gemini-2.5-pro", false);
        assert_eq!(result, "google/gemini-2.5-pro");
    }

    #[test]
    fn thinking_model_name_non_gemini() {
        let result = thinking_model_name("gpt-4", true);
        assert_eq!(result, "gpt-4");
    }

    #[test]
    fn build_openai_messages_empty() {
        let result = build_openai_messages(&[], "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_empty_with_system() {
        let result = build_openai_messages(&[], "sys prompt");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[0]["content"], "sys prompt");
    }

    #[test]
    fn build_openai_messages_user_multiple_text_blocks() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text { text: "line1".into() },
                ContentBlock::Text { text: "line2".into() },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "line1\nline2");
    }

    #[test]
    fn build_openai_messages_user_filters_non_text() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text { text: "hello".into() },
                ContentBlock::ToolUse {
                    id: "x".into(),
                    name: "y".into(),
                    input: json!({}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result[0]["content"], "hello");
    }

    #[test]
    fn build_openai_messages_assistant_tool_only() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "run".into(),
                input: json!({"cmd": "ls"}),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["function"]["name"], "run");
        assert_eq!(tc[0]["function"]["arguments"], r#"{"cmd":"ls"}"#);
    }

    #[test]
    fn build_openai_messages_assistant_multiple_tool_calls() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::ToolUse {
                    id: "a".into(),
                    name: "foo".into(),
                    input: json!({}),
                },
                ContentBlock::ToolUse {
                    id: "b".into(),
                    name: "bar".into(),
                    input: json!({"x": 1}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 2);
        assert_eq!(tc[0]["id"], "a");
        assert_eq!(tc[1]["id"], "b");
    }

    #[test]
    fn build_openai_messages_tool_multiple_results() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![
                ContentBlock::ToolResult {
                    tool_use_id: "c1".into(),
                    content: "result1".into(),
                    is_error: false,
                },
                ContentBlock::ToolResult {
                    tool_use_id: "c2".into(),
                    content: "result2".into(),
                    is_error: true,
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["tool_call_id"], "c1");
        assert_eq!(result[0]["content"], "result1");
        assert_eq!(result[1]["tool_call_id"], "c2");
        assert_eq!(result[1]["content"], "result2");
    }

    #[test]
    fn build_openai_messages_tool_ignores_non_tool_result() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::Text {
                text: "ignored".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_system_role_ignored() {
        let msgs = vec![Message {
            role: Role::System,
            content: vec![ContentBlock::Text {
                text: "sys".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_mixed_conversation() {
        let msgs = vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "question".into(),
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text {
                        text: "let me check".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "search".into(),
                        input: json!({"q": "test"}),
                    },
                ],
            },
            Message {
                role: Role::Tool,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "found it".into(),
                    is_error: false,
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "here you go".into(),
                }],
            },
        ];
        let result = build_openai_messages(&msgs, "Be helpful");
        assert_eq!(result.len(), 5); // system + 4 messages
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[1]["role"], "user");
        assert_eq!(result[2]["role"], "assistant");
        assert_eq!(result[3]["role"], "tool");
        assert_eq!(result[4]["role"], "assistant");
    }

    #[test]
    fn build_openai_tools_multiple() {
        let tools = vec![
            ToolDefinition {
                name: "alpha".into(),
                description: "First".into(),
                parameters: json!({"type": "object"}),
            },
            ToolDefinition {
                name: "beta".into(),
                description: "Second".into(),
                parameters: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            },
        ];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["function"]["name"], "alpha");
        assert_eq!(result[1]["function"]["name"], "beta");
        assert_eq!(
            result[1]["function"]["parameters"]["properties"]["x"]["type"],
            "string"
        );
    }

    #[test]
    fn is_retryable_429() {
        assert!(is_retryable(reqwest::StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn is_retryable_500() {
        assert!(is_retryable(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn is_retryable_502() {
        assert!(is_retryable(reqwest::StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn is_retryable_200_false() {
        assert!(!is_retryable(reqwest::StatusCode::OK));
    }

    #[test]
    fn is_retryable_400_false() {
        assert!(!is_retryable(reqwest::StatusCode::BAD_REQUEST));
    }

    #[test]
    fn is_retryable_401_false() {
        assert!(!is_retryable(reqwest::StatusCode::UNAUTHORIZED));
    }

    fn make_provider() -> OpenAICompatProvider {
        OpenAICompatProvider::new(
            Zeroizing::new("test-key".into()),
            "https://api.example.com".into(),
            None,
            vec![],
            30,
        )
        .unwrap()
    }

    fn make_chat_request(
        model: &str,
        system: &str,
        messages: Vec<Message>,
        tools: Vec<ToolDefinition>,
        tool_choice: ToolChoice,
        extra_body: Option<serde_json::Value>,
    ) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            system: system.into(),
            messages,
            tools,
            tool_choice,
            max_tokens: 1024,
            stream: false,
            extra_body,
        }
    }

    #[test]
    fn build_request_body_basic() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "Be helpful",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hi".into(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["stream"], false);
        assert_eq!(body["tool_choice"], "auto");
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "Be helpful");
        assert_eq!(msgs[1]["role"], "user");
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn build_request_body_with_tools() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "do it".into(),
                }],
            }],
            vec![ToolDefinition {
                name: "my_tool".into(),
                description: "does stuff".into(),
                parameters: json!({"type": "object"}),
            }],
            ToolChoice::Required,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["function"]["name"], "my_tool");
    }

    #[test]
    fn build_request_body_tool_choice_none() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::None,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "none");
    }

    #[test]
    fn build_request_body_anthropic_system_as_array() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "You are an assistant",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hello".into(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys.len(), 1);
        assert_eq!(sys[0]["type"], "text");
        assert_eq!(sys[0]["text"], "You are an assistant");
        assert_eq!(sys[0]["cache_control"]["type"], "ephemeral");
        let msgs = body["messages"].as_array().unwrap();
        assert!(
            !msgs.iter().any(|m| m["role"] == "system"),
            "anthropic model should not have system in messages"
        );
    }

    #[test]
    fn build_request_body_anthropic_tool_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-opus",
            "sys",
            vec![],
            vec![
                ToolDefinition {
                    name: "first".into(),
                    description: "d1".into(),
                    parameters: json!({}),
                },
                ToolDefinition {
                    name: "second".into(),
                    description: "d2".into(),
                    parameters: json!({}),
                },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools[0].get("cache_control").is_none());
        assert_eq!(tools[1]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_request_body_extra_body_merged() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"temperature": 0.5, "top_p": 0.9})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["top_p"], 0.9);
    }

    #[test]
    fn build_request_body_extra_body_none() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn apply_thinking_mode_non_gemini3_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "gpt-4", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_claude_opus_think_no_reasoning() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3-opus", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn thinking_model_name_gemini_3_not_affected() {
        let result = thinking_model_name("google/gemini-3-pro", true);
        assert_eq!(result, "google/gemini-3-pro");
    }

    #[test]
    fn is_anthropic_model_edge_cases() {
        assert!(is_anthropic_model("anthropic/something-else"));
        assert!(!is_anthropic_model("not-anthropic-model"));
        assert!(!is_anthropic_model(""));
        assert!(is_anthropic_model("my-claude-variant"));
    }

    #[test]
    fn is_retryable_503() {
        assert!(is_retryable(reqwest::StatusCode::SERVICE_UNAVAILABLE));
    }

    #[test]
    fn is_retryable_504() {
        assert!(is_retryable(reqwest::StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn is_retryable_403_not() {
        assert!(!is_retryable(reqwest::StatusCode::FORBIDDEN));
    }

    #[test]
    fn is_retryable_404_not() {
        assert!(!is_retryable(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn thinking_model_name_gemini25_flash_think() {
        let result = thinking_model_name("google/gemini-2.5-flash", true);
        assert_eq!(result, "google/gemini-2.5-flash:thinking");
    }

    #[test]
    fn thinking_model_name_gemini25_flash_no_think() {
        let result = thinking_model_name("google/gemini-2.5-flash", false);
        assert_eq!(result, "google/gemini-2.5-flash");
    }

    #[test]
    fn thinking_model_name_gemini25_flash_already_thinking() {
        let result = thinking_model_name("google/gemini-2.5-flash:thinking", true);
        assert_eq!(result, "google/gemini-2.5-flash:thinking");
    }

    #[test]
    fn apply_thinking_mode_anthropic_prefixed_claude_sonnet() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "anthropic/claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["reasoning"]["budget_tokens"], 32768);
    }

    #[test]
    fn apply_thinking_mode_gemini3_flash_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-flash", false);
        assert_eq!(body["reasoning"]["effort"], "low");
    }

    #[test]
    fn apply_thinking_mode_gemini3_flash_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-flash", true);
        assert_eq!(body["reasoning"]["effort"], "high");
    }

    #[test]
    fn build_openai_messages_assistant_text_only() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "just text".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert_eq!(result[0]["content"], "just text");
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn build_openai_messages_assistant_multiple_text_blocks() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "part1".into(),
                },
                ContentBlock::Text {
                    text: "part2".into(),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result[0]["content"], "part1\npart2");
    }

    #[test]
    fn build_openai_messages_tool_result_error_still_included() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "e1".into(),
                content: "something broke".into(),
                is_error: true,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "tool");
        assert_eq!(result[0]["tool_call_id"], "e1");
        assert_eq!(result[0]["content"], "something broke");
    }

    #[test]
    fn build_openai_tools_preserves_parameters() {
        let tools = vec![ToolDefinition {
            name: "search".into(),
            description: "Search things".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"}
                },
                "required": ["query"]
            }),
        }];
        let result = build_openai_tools(&tools);
        assert_eq!(result[0]["function"]["parameters"]["properties"]["query"]["type"], "string");
        assert_eq!(result[0]["function"]["parameters"]["required"][0], "query");
    }

    #[test]
    fn build_request_body_anthropic_no_system_in_messages() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-haiku",
            "system prompt here",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hi".into(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        for m in msgs {
            assert_ne!(m["role"], "system");
        }
        assert!(body["system"].is_array());
    }

    #[test]
    fn build_request_body_non_anthropic_system_in_messages() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4o",
            "system prompt",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hi".into(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "system prompt");
        assert!(body.get("system").is_none());
    }

    #[test]
    fn build_request_body_extra_body_overrides() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"max_tokens": 2048})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["max_tokens"], 2048);
    }

    #[test]
    fn build_request_body_empty_tools_not_included() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn is_anthropic_model_prefix_only() {
        assert!(is_anthropic_model("anthropic/llama"));
    }

    #[test]
    fn is_anthropic_model_claude_substring() {
        assert!(is_anthropic_model("openrouter/claude-3.5-sonnet"));
    }

    #[test]
    fn build_request_body_anthropic_cache_control_on_system() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3-haiku",
            "be brief",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["cache_control"]["type"], "ephemeral");
        assert_eq!(sys[0]["text"], "be brief");
    }

    #[test]
    fn build_request_body_extra_body_map_multiple_keys() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"temperature": 0.7, "frequency_penalty": 1.2, "custom_field": "abc"})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["frequency_penalty"], 1.2);
        assert_eq!(body["custom_field"], "abc");
    }

    #[test]
    fn build_request_body_tool_choice_required() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![ToolDefinition {
                name: "t".into(),
                description: "d".into(),
                parameters: json!({}),
            }],
            ToolChoice::Required,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
    }

    #[test]
    fn build_request_body_tool_choice_none_value() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::None, None);
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "none");
    }

    #[test]
    fn build_request_body_tool_choice_auto_value() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "auto");
    }

    #[test]
    fn build_openai_tools_multiple_preserves_all() {
        let tools = vec![
            ToolDefinition {
                name: "tool_a".into(),
                description: "desc a".into(),
                parameters: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            },
            ToolDefinition {
                name: "tool_b".into(),
                description: "desc b".into(),
                parameters: json!({"type": "object", "properties": {"y": {"type": "integer"}}}),
            },
            ToolDefinition {
                name: "tool_c".into(),
                description: "desc c".into(),
                parameters: json!({"type": "object"}),
            },
        ];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0]["function"]["name"], "tool_a");
        assert_eq!(result[1]["function"]["name"], "tool_b");
        assert_eq!(result[2]["function"]["name"], "tool_c");
        assert_eq!(result[0]["function"]["parameters"]["properties"]["x"]["type"], "string");
        assert_eq!(result[1]["function"]["parameters"]["properties"]["y"]["type"], "integer");
    }

    #[test]
    fn build_openai_messages_empty_content_blocks() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "user");
        assert_eq!(result[0]["content"], "");
    }

    #[test]
    fn build_openai_messages_assistant_empty_content() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn is_anthropic_model_various_strings() {
        assert!(is_anthropic_model("claude-instant"));
        assert!(is_anthropic_model("anthropic/gemma"));
        assert!(!is_anthropic_model("gpt-3.5-turbo"));
        assert!(!is_anthropic_model("mistral-large"));
        assert!(!is_anthropic_model("deepseek-coder"));
    }

    #[test]
    fn thinking_model_name_non_google_no_change() {
        assert_eq!(thinking_model_name("claude-3-opus", true), "claude-3-opus");
        assert_eq!(thinking_model_name("gpt-4o", false), "gpt-4o");
    }

    #[test]
    fn apply_thinking_mode_no_think_non_gemini3() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_think_claude_non_sonnet_no_reasoning() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3-haiku", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn provider_new_constructs_successfully() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "https://api.example.com".into(),
            Some("fallback-model".into()),
            vec![("X-Custom".into(), "val".into())],
            60,
        );
        assert!(provider.is_ok());
    }

    #[test]
    fn provider_new_zero_timeout() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "http://localhost".into(),
            None,
            vec![],
            0,
        );
        assert!(provider.is_ok());
    }

    #[test]
    fn build_request_body_anthropic_no_system_message_in_messages_array() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys prompt",
            vec![
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "q".into() }],
                },
            ],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_non_anthropic_empty_system_no_system_message() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_anthropic_tools_cache_control_only_last() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys",
            vec![],
            vec![
                ToolDefinition { name: "a".into(), description: "".into(), parameters: json!({}) },
                ToolDefinition { name: "b".into(), description: "".into(), parameters: json!({}) },
                ToolDefinition { name: "c".into(), description: "".into(), parameters: json!({}) },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);
        assert!(tools[0].get("cache_control").is_none());
        assert!(tools[1].get("cache_control").is_none());
        assert_eq!(tools[2]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_request_body_non_anthropic_tools_no_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![
                ToolDefinition { name: "a".into(), description: "".into(), parameters: json!({}) },
                ToolDefinition { name: "b".into(), description: "".into(), parameters: json!({}) },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool.get("cache_control").is_none());
        }
    }

    #[test]
    fn build_request_body_extra_body_non_object_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!("not an object")),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    #[test]
    fn build_request_body_stream_field_set() {
        let provider = make_provider();
        let mut req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        req.stream = true;
        let body = provider.build_request_body(&req);
        assert_eq!(body["stream"], true);

        req.stream = false;
        let body = provider.build_request_body(&req);
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn build_openai_messages_multiple_users_in_sequence() {
        let msgs = vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "first".into() }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "second".into() }],
            },
        ];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["content"], "first");
        assert_eq!(result[1]["content"], "second");
    }

    #[test]
    fn build_openai_messages_tool_result_with_non_tool_result_blocks() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![
                ContentBlock::Text { text: "ignored".into() },
                ContentBlock::ToolResult {
                    tool_use_id: "c1".into(),
                    content: "result".into(),
                    is_error: false,
                },
                ContentBlock::Text { text: "also ignored".into() },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["tool_call_id"], "c1");
    }

    #[test]
    fn is_retryable_201_not() {
        assert!(!is_retryable(reqwest::StatusCode::CREATED));
    }

    #[test]
    fn is_retryable_301_not() {
        assert!(!is_retryable(reqwest::StatusCode::MOVED_PERMANENTLY));
    }

    #[test]
    fn thinking_model_name_gemini_20_not_affected() {
        assert_eq!(thinking_model_name("google/gemini-2.0-pro", true), "google/gemini-2.0-pro");
    }

    #[test]
    fn apply_thinking_mode_gemini3_with_existing_body_fields() {
        let mut body = json!({"temperature": 0.5});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", true);
        assert_eq!(body["reasoning"]["effort"], "high");
        assert_eq!(body["temperature"], 0.5);
    }

    #[test]
    fn apply_thinking_mode_claude_sonnet_think_does_not_remove_other_fields() {
        let mut body = json!({"some_field": 42});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["some_field"], 42);
    }

    #[test]
    fn build_request_body_model_field_matches_request() {
        let provider = make_provider();
        for model in &["gpt-4", "claude-3.5-sonnet", "anthropic/claude-3-haiku", "google/gemini-3-pro"] {
            let req = make_chat_request(model, "", vec![], vec![], ToolChoice::Auto, None);
            let body = provider.build_request_body(&req);
            assert_eq!(body["model"], *model);
        }
    }

    #[test]
    fn build_request_body_max_tokens_from_request() {
        let provider = make_provider();
        let mut req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        req.max_tokens = 4096;
        let body = provider.build_request_body(&req);
        assert_eq!(body["max_tokens"], 4096);
    }

    #[test]
    fn build_openai_messages_assistant_ignores_tool_result_block() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text { text: "thinking".into() },
                ContentBlock::ToolResult {
                    tool_use_id: "tr1".into(),
                    content: "should be ignored".into(),
                    is_error: false,
                },
                ContentBlock::ToolUse {
                    id: "tu1".into(),
                    name: "search".into(),
                    input: json!({"q": "test"}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "thinking");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "tu1");
    }

    #[test]
    fn build_openai_messages_assistant_only_tool_result_ignored() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "tr1".into(),
                content: "ignored".into(),
                is_error: false,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn provider_new_with_fallback_and_extra_headers() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("sk-test".into()),
            "https://openrouter.ai/api/v1".into(),
            Some("gpt-3.5-turbo".into()),
            vec![
                ("X-Title".into(), "MyApp".into()),
                ("HTTP-Referer".into(), "https://example.com".into()),
            ],
            120,
        );
        assert!(provider.is_ok());
        let p = provider.unwrap();
        assert_eq!(p.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(p.fallback_model.as_deref(), Some("gpt-3.5-turbo"));
        assert_eq!(p.extra_headers.len(), 2);
        assert_eq!(p.extra_headers[0].0, "X-Title");
    }

    #[test]
    fn build_request_body_anthropic_with_empty_system() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert!(body["system"].is_array());
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["text"], "");
    }

    #[test]
    fn build_request_body_anthropic_with_tools_and_extra_body() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-sonnet",
            "system text",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hello".into() }],
            }],
            vec![ToolDefinition {
                name: "my_tool".into(),
                description: "desc".into(),
                parameters: json!({"type": "object"}),
            }],
            ToolChoice::Required,
            Some(json!({"temperature": 0.3})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
        assert_eq!(body["temperature"], 0.3);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools[0]["cache_control"]["type"], "ephemeral");
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["text"], "system text");
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_single_anthropic_tool_gets_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys",
            vec![],
            vec![ToolDefinition {
                name: "only_tool".into(),
                description: "d".into(),
                parameters: json!({}),
            }],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_http_request_sets_authorization_and_extra_headers() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("test-api-key".into()),
            "https://api.example.com".into(),
            None,
            vec![("X-Custom".into(), "custom-val".into())],
            30,
        )
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert_eq!(
            built.url().as_str(),
            "https://api.example.com/chat/completions"
        );
        assert!(built.headers().get("Authorization").is_some());
        assert!(built.headers()["Authorization"].is_sensitive());
        assert_eq!(built.headers().get("X-Custom").unwrap(), "custom-val");
    }

    #[test]
    fn build_http_request_anthropic_openrouter_adds_beta_header() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "https://openrouter.ai/api/v1".into(),
            None,
            vec![],
            30,
        )
        .unwrap();
        let body = json!({"model": "claude-3.5-sonnet"});
        let req = provider.build_http_request(&body, "claude-3.5-sonnet");
        let built = req.build().unwrap();
        assert_eq!(
            built.headers().get("anthropic-beta").unwrap(),
            "prompt-caching-2024-07-31"
        );
    }

    #[test]
    fn build_http_request_anthropic_non_openrouter_no_beta_header() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "https://api.anthropic.com".into(),
            None,
            vec![],
            30,
        )
        .unwrap();
        let body = json!({"model": "claude-3.5-sonnet"});
        let req = provider.build_http_request(&body, "claude-3.5-sonnet");
        let built = req.build().unwrap();
        assert!(built.headers().get("anthropic-beta").is_none());
    }

    #[test]
    fn build_http_request_non_anthropic_openrouter_no_beta_header() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "https://openrouter.ai/api/v1".into(),
            None,
            vec![],
            30,
        )
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert!(built.headers().get("anthropic-beta").is_none());
    }

    #[test]
    fn build_http_request_multiple_extra_headers() {
        let provider = OpenAICompatProvider::new(
            Zeroizing::new("key".into()),
            "https://api.example.com".into(),
            None,
            vec![
                ("X-First".into(), "one".into()),
                ("X-Second".into(), "two".into()),
                ("X-Third".into(), "three".into()),
            ],
            30,
        )
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert_eq!(built.headers().get("X-First").unwrap(), "one");
        assert_eq!(built.headers().get("X-Second").unwrap(), "two");
        assert_eq!(built.headers().get("X-Third").unwrap(), "three");
    }

    #[test]
    fn build_request_body_extra_body_empty_object() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    #[test]
    fn build_request_body_extra_body_array_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!([1, 2, 3])),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
        assert!(body.get("0").is_none());
    }

    #[test]
    fn build_request_body_extra_body_null_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(serde_json::Value::Null),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    async fn start_sse_server(body: &str) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let response_body = body.to_string();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{response_body}",
            );
            let _ = socket.write_all(http.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        (url, handle)
    }

    #[tokio::test]
    async fn spawn_openai_stream_text_delta() {
        let sse = "data: {\"id\":\"gen-1\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"id\":\"gen-1\",\"choices\":[{\"finish_reason\":\"stop\",\"delta\":{}}]}\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::GenerationId(id) if id == "gen-1"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "hello"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_tool_use() {
        let sse = concat!(
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tc1\",\"function\":{\"name\":\"search\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"q\\\"\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"test\\\"}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { name, .. } if name == "search"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseDelta(s) if s == "{\"q\""));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseDelta(s) if s == ":\"test\"}"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_multiple_tool_calls() {
        let sse = concat!(
            "data: {\"id\":\"gen-3\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tc1\",\"function\":{\"name\":\"foo\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-3\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"tc2\",\"function\":{\"name\":\"bar\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-3\",\"choices\":[{\"finish_reason\":\"tool_calls\",\"delta\":{}}]}\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { ref name, .. } if name == "foo"));
        let _ = rx.recv().await.unwrap(); // ToolUseDelta("{}")
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd)); // end of first tool
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { ref name, .. } if name == "bar"));
        let _ = rx.recv().await.unwrap(); // ToolUseDelta("{}")
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd)); // end of second tool (from finish_reason)
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_done_marker() {
        let sse = "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // TextDelta
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_empty_content_skipped() {
        let sse = concat!(
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"real\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "real"));
    }

    #[tokio::test]
    async fn spawn_openai_stream_invalid_json_skipped() {
        let sse = "data: not-json\n\ndata: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "ok"));
    }

    #[tokio::test]
    async fn spawn_openai_stream_tool_with_done_closes_tool() {
        let sse = concat!(
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"t1\",\"function\":{\"name\":\"fn1\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // ToolUseStart
        let _ = rx.recv().await.unwrap(); // ToolUseDelta
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_error_event() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let _handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let http = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
            let _ = socket.write_all(http.as_bytes()).await;
            socket.shutdown().await.unwrap();
        });
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // TextDelta "hi"
        let ev = rx.recv().await;
        assert!(ev.is_none() || matches!(ev, Some(StreamEvent::Error(_)) | Some(StreamEvent::Done { .. })));
    }

    #[test]
    fn build_openai_messages_assistant_with_tool_result_block_ignored() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "response".into(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "tr1".into(),
                    content: "should be ignored".into(),
                    is_error: false,
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "response");
        assert!(result[0].get("tool_calls").is_none());
    }
}

pub fn spawn_openai_stream(
    resp: reqwest::Response,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        use eventsource_stream::Eventsource;
        use futures::StreamExt;
        let mut stream = resp.bytes_stream().eventsource();
        let mut current_tool_index: Option<usize> = None;
        let mut generation_id: Option<String> = None;
        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(e) => e,
                Err(e) => {
                    let _ = tx.send(StreamEvent::Error(e.to_string())).await;
                    break;
                }
            };
            if event.data == "[DONE]" {
                if current_tool_index.is_some() {
                    let _ = tx.send(StreamEvent::ToolUseEnd).await;
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
                break;
            }
            let chunk: serde_json::Value = match serde_json::from_str(&event.data) {
                Ok(v) => v,
                Err(_) => continue,
            };

            if generation_id.is_none() {
                if let Some(id) = chunk["id"].as_str() {
                    let _ = tx.send(StreamEvent::GenerationId(id.to_string())).await;
                    generation_id = Some(id.to_string());
                }
            }

            let delta = &chunk["choices"][0]["delta"];
            if let Some(content) = delta["content"].as_str() {
                if !content.is_empty() {
                    let _ = tx.send(StreamEvent::TextDelta(content.to_string())).await;
                }
            }
            if let Some(tool_calls) = delta["tool_calls"].as_array() {
                for tc in tool_calls {
                    let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                    if current_tool_index != Some(idx) {
                        if current_tool_index.is_some() {
                            let _ = tx.send(StreamEvent::ToolUseEnd).await;
                        }
                        current_tool_index = Some(idx);
                        let id = tc["id"].as_str().unwrap_or("").to_string();
                        let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
                        if !name.is_empty() {
                            let _ = tx.send(StreamEvent::ToolUseStart { id, name }).await;
                        }
                    }
                    if let Some(args) = tc["function"]["arguments"].as_str() {
                        if !args.is_empty() {
                            let _ = tx.send(StreamEvent::ToolUseDelta(args.to_string())).await;
                        }
                    }
                }
            }
            if chunk["choices"][0]["finish_reason"].as_str().is_some() {
                if current_tool_index.is_some() {
                    let _ = tx.send(StreamEvent::ToolUseEnd).await;
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
                break;
            }
        }
    });
    Ok(rx)
}
