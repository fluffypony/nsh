use reqwest::Client;
use serde_json::json;
use zeroize::Zeroizing;

use crate::provider::*;

pub struct AnthropicProvider {
    client: Client,
    api_key: Zeroizing<String>,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .anthropic
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Anthropic not configured"))?;
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(
                    config.provider.timeout_seconds,
                ))
                .build()?,
            api_key: auth.resolve_api_key("anthropic")?,
            base_url: auth
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.anthropic.com".into()),
        })
    }

    fn build_body(&self, request: &ChatRequest) -> serde_json::Value {
        let mut messages = Vec::new();
        for msg in &request.messages {
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
                    messages.push(json!({"role": "user", "content": text}));
                }
                Role::Assistant => {
                    let content: Vec<serde_json::Value> = msg
                        .content
                        .iter()
                        .filter_map(|b| match b {
                            ContentBlock::Text { text } => {
                                Some(json!({"type": "text", "text": text}))
                            }
                            ContentBlock::ToolUse { id, name, input } => Some(
                                json!({"type": "tool_use", "id": id, "name": name, "input": input}),
                            ),
                            _ => None,
                        })
                        .collect();
                    messages.push(json!({"role": "assistant", "content": content}));
                }
                Role::Tool => {
                    let mut content = Vec::new();
                    for block in &msg.content {
                        if let ContentBlock::ToolResult {
                            tool_use_id,
                            content: c,
                            is_error,
                        } = block
                        {
                            content.push(json!({
                                "type": "tool_result", "tool_use_id": tool_use_id,
                                "content": c, "is_error": is_error,
                            }));
                        }
                    }
                    messages.push(json!({"role": "user", "content": content}));
                }
                _ => {}
            }
        }

        let tools: Vec<serde_json::Value> = request
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name, "description": t.description, "input_schema": t.parameters,
                })
            })
            .collect();

        let mut body = json!({
            "model": request.model,
            "system": request.system,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": request.stream,
        });

        if !tools.is_empty() {
            body["tools"] = json!(tools);
            match request.tool_choice {
                ToolChoice::Required => {
                    body["tool_choice"] = json!({"type": "any"});
                }
                ToolChoice::Auto => {
                    body["tool_choice"] = json!({"type": "auto"});
                }
                ToolChoice::None => {}
            }
        }
        body
    }
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        let mut body = self.build_body(&request);
        body["stream"] = json!(false);
        // reqwest internally copies the value into its own buffer, so zeroization is best-effort
        let api_key_val = Zeroizing::new(self.api_key.to_string());
        let mut header_val = reqwest::header::HeaderValue::from_str(&api_key_val)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
        header_val.set_sensitive(true);
        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", header_val)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Anthropic API error ({status}): {text}");
        }
        let json: serde_json::Value = resp.json().await?;
        let mut content = Vec::new();
        if let Some(blocks) = json["content"].as_array() {
            for block in blocks {
                match block["type"].as_str() {
                    Some("text") => {
                        if let Some(text) = block["text"].as_str() {
                            content.push(ContentBlock::Text {
                                text: text.to_string(),
                            });
                        }
                    }
                    Some("tool_use") => {
                        content.push(ContentBlock::ToolUse {
                            id: block["id"].as_str().unwrap_or("").to_string(),
                            name: block["name"].as_str().unwrap_or("").to_string(),
                            input: block["input"].clone(),
                        });
                    }
                    _ => {}
                }
            }
        }
        Ok(Message {
            role: Role::Assistant,
            content,
        })
    }

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        let mut body = self.build_body(&request);
        body["stream"] = json!(true);
        let api_key_val = Zeroizing::new(self.api_key.to_string());
        let mut header_val = reqwest::header::HeaderValue::from_str(&api_key_val)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
        header_val.set_sensitive(true);
        let resp = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", header_val)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Anthropic API error ({status}): {text}");
        }

        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            use eventsource_stream::Eventsource;
            use futures::StreamExt;
            let mut stream = resp.bytes_stream().eventsource();
            let mut in_tool_use = false;

            while let Some(event) = stream.next().await {
                let event = match event {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = tx.send(StreamEvent::Error(e.to_string())).await;
                        break;
                    }
                };
                let data: serde_json::Value = match serde_json::from_str(&event.data) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                match event.event.as_str() {
                    "content_block_start" => {
                        let block = &data["content_block"];
                        if block["type"].as_str() == Some("tool_use") {
                            in_tool_use = true;
                            let _ = tx
                                .send(StreamEvent::ToolUseStart {
                                    id: block["id"].as_str().unwrap_or("").to_string(),
                                    name: block["name"].as_str().unwrap_or("").to_string(),
                                })
                                .await;
                        }
                    }
                    "content_block_delta" => {
                        let delta = &data["delta"];
                        match delta["type"].as_str() {
                            Some("text_delta") => {
                                if let Some(text) = delta["text"].as_str() {
                                    let _ = tx.send(StreamEvent::TextDelta(text.to_string())).await;
                                }
                            }
                            Some("input_json_delta") => {
                                if let Some(json) = delta["partial_json"].as_str() {
                                    let _ =
                                        tx.send(StreamEvent::ToolUseDelta(json.to_string())).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    "content_block_stop" => {
                        if in_tool_use {
                            let _ = tx.send(StreamEvent::ToolUseEnd).await;
                            in_tool_use = false;
                        }
                    }
                    "message_stop" => {
                        if in_tool_use {
                            let _ = tx.send(StreamEvent::ToolUseEnd).await;
                        }
                        let _ = tx.send(StreamEvent::Done { usage: None }).await;
                        break;
                    }
                    "error" => {
                        let msg = data["error"]["message"].as_str().unwrap_or("Unknown error");
                        let _ = tx.send(StreamEvent::Error(msg.to_string())).await;
                        break;
                    }
                    _ => {}
                }
            }
        });
        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::ToolDefinition;
    use serde_json::json;

    fn make_provider() -> AnthropicProvider {
        let mut config = crate::config::Config::default();
        config.provider.anthropic = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        AnthropicProvider::new(&config).unwrap()
    }

    fn make_request(messages: Vec<Message>, tools: Vec<ToolDefinition>, tool_choice: ToolChoice) -> ChatRequest {
        ChatRequest {
            model: "claude-3-haiku".into(),
            system: "You are helpful".into(),
            messages,
            tools,
            tool_choice,
            max_tokens: 1024,
            stream: false,
            extra_body: None,
        }
    }

    #[test]
    fn test_build_body_empty_messages() {
        let provider = make_provider();
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let body = provider.build_body(&req);
        assert_eq!(body["model"], "claude-3-haiku");
        assert_eq!(body["system"], "You are helpful");
        assert_eq!(body["max_tokens"], 1024);
        assert!(body["messages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_build_body_user_message() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hello".into() }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "hello");
    }

    #[test]
    fn test_build_body_assistant_message_with_text() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text { text: "sure thing".into() }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "assistant");
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "sure thing");
    }

    #[test]
    fn test_build_body_assistant_with_tool_use() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "tu1".into(),
                    name: "search".into(),
                    input: json!({"q": "test"}),
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "tool_use");
        assert_eq!(content[0]["name"], "search");
        assert_eq!(content[0]["input"]["q"], "test");
    }

    #[test]
    fn test_build_body_tool_result_message() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "tu1".into(),
                    content: "result data".into(),
                    is_error: false,
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "user");
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "tool_result");
        assert_eq!(content[0]["tool_use_id"], "tu1");
        assert_eq!(content[0]["is_error"], false);
    }

    #[test]
    fn test_build_body_with_tools() {
        let provider = make_provider();
        let req = make_request(
            vec![],
            vec![ToolDefinition {
                name: "run_command".into(),
                description: "Run a command".into(),
                parameters: json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
            }],
            ToolChoice::Required,
        );
        let body = provider.build_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "run_command");
        assert_eq!(body["tool_choice"]["type"], "any");
    }

    #[test]
    fn test_build_body_tool_choice_auto() {
        let provider = make_provider();
        let req = make_request(vec![], vec![ToolDefinition {
            name: "t".into(),
            description: "d".into(),
            parameters: json!({}),
        }], ToolChoice::Auto);
        let body = provider.build_body(&req);
        assert_eq!(body["tool_choice"]["type"], "auto");
    }

    #[test]
    fn test_build_body_tool_choice_none() {
        let provider = make_provider();
        let req = make_request(vec![], vec![ToolDefinition {
            name: "t".into(),
            description: "d".into(),
            parameters: json!({}),
        }], ToolChoice::None);
        let body = provider.build_body(&req);
        assert!(body.get("tool_choice").is_none());
    }

    #[test]
    fn test_build_body_no_tools_no_tool_choice() {
        let provider = make_provider();
        let req = make_request(vec![], vec![], ToolChoice::Required);
        let body = provider.build_body(&req);
        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
    }

    #[test]
    fn test_build_body_system_role_ignored() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::System,
                content: vec![ContentBlock::Text { text: "system msg".into() }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        assert!(body["messages"].as_array().unwrap().is_empty());
    }

    #[test]
    fn test_new_missing_config() {
        let mut config = crate::config::Config::default();
        config.provider.anthropic = None;
        let result = AnthropicProvider::new(&config);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_body_multiple_text_in_user_joined() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![
                    ContentBlock::Text { text: "hello".into() },
                    ContentBlock::Text { text: "world".into() },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["content"], "hello\nworld");
    }

    #[test]
    fn test_build_body_tool_result_is_error_true() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "tu1".into(),
                    content: "command failed".into(),
                    is_error: true,
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["type"], "tool_result");
        assert_eq!(content[0]["is_error"], true);
        assert_eq!(content[0]["content"], "command failed");
    }

    #[test]
    fn test_build_body_multiple_tool_results_in_one_message() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "tu1".into(),
                        content: "result one".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "tu2".into(),
                        content: "result two".into(),
                        is_error: true,
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["tool_use_id"], "tu1");
        assert_eq!(content[0]["is_error"], false);
        assert_eq!(content[1]["tool_use_id"], "tu2");
        assert_eq!(content[1]["is_error"], true);
    }

    #[test]
    fn test_build_body_mixed_text_and_tool_use_in_assistant() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text { text: "Let me check".into() },
                    ContentBlock::ToolUse {
                        id: "tu1".into(),
                        name: "search".into(),
                        input: json!({"q": "test"}),
                    },
                    ContentBlock::Text { text: "Also this".into() },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 3);
        assert_eq!(content[0]["type"], "text");
        assert_eq!(content[0]["text"], "Let me check");
        assert_eq!(content[1]["type"], "tool_use");
        assert_eq!(content[1]["name"], "search");
        assert_eq!(content[2]["type"], "text");
        assert_eq!(content[2]["text"], "Also this");
    }

    #[test]
    fn test_build_body_user_filters_non_text_content() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![
                    ContentBlock::Text { text: "hello".into() },
                    ContentBlock::ToolUse {
                        id: "x".into(),
                        name: "y".into(),
                        input: json!({}),
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["content"], "hello");
    }

    #[test]
    fn test_build_body_assistant_filters_tool_result_blocks() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text { text: "response".into() },
                    ContentBlock::ToolResult {
                        tool_use_id: "tr1".into(),
                        content: "ignored".into(),
                        is_error: false,
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "text");
    }

    #[test]
    fn test_build_body_empty_tools_no_tool_choice() {
        let provider = make_provider();
        let req = make_request(vec![], vec![], ToolChoice::Required);
        let body = provider.build_body(&req);
        assert!(body.get("tools").is_none());
        assert!(body.get("tool_choice").is_none());
    }

    #[test]
    fn test_build_body_stream_field_preserved() {
        let provider = make_provider();
        let mut req = make_request(vec![], vec![], ToolChoice::Auto);
        req.stream = true;
        let body = provider.build_body(&req);
        assert_eq!(body["stream"], true);

        req.stream = false;
        let body = provider.build_body(&req);
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn test_build_body_max_tokens_field() {
        let provider = make_provider();
        let mut req = make_request(vec![], vec![], ToolChoice::Auto);
        req.max_tokens = 4096;
        let body = provider.build_body(&req);
        assert_eq!(body["max_tokens"], 4096);
    }

    #[test]
    fn test_build_body_model_and_system_fields() {
        let provider = make_provider();
        let mut req = make_request(vec![], vec![], ToolChoice::Auto);
        req.model = "claude-3-opus".into();
        req.system = "You are a pirate".into();
        let body = provider.build_body(&req);
        assert_eq!(body["model"], "claude-3-opus");
        assert_eq!(body["system"], "You are a pirate");
    }

    #[test]
    fn test_custom_base_url() {
        let mut config = crate::config::Config::default();
        config.provider.anthropic = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: Some("https://custom.proxy.example.com".into()),
        });
        let provider = AnthropicProvider::new(&config).unwrap();
        assert_eq!(provider.base_url, "https://custom.proxy.example.com");
    }

    #[test]
    fn test_default_base_url() {
        let provider = make_provider();
        assert_eq!(provider.base_url, "https://api.anthropic.com");
    }

    #[test]
    fn test_build_body_multi_turn_conversation() {
        let provider = make_provider();
        let req = make_request(
            vec![
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "What is 2+2?".into() }],
                },
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text { text: "4".into() }],
                },
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "And 3+3?".into() }],
                },
            ],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "What is 2+2?");
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"], "And 3+3?");
    }

    #[test]
    fn test_build_body_tool_use_round_trip_conversation() {
        let provider = make_provider();
        let req = make_request(
            vec![
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "List files".into() }],
                },
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "tu1".into(),
                        name: "run_command".into(),
                        input: json!({"cmd": "ls"}),
                    }],
                },
                Message {
                    role: Role::Tool,
                    content: vec![ContentBlock::ToolResult {
                        tool_use_id: "tu1".into(),
                        content: "file1.txt\nfile2.txt".into(),
                        is_error: false,
                    }],
                },
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "I found two files".into(),
                    }],
                },
            ],
            vec![ToolDefinition {
                name: "run_command".into(),
                description: "Run a shell command".into(),
                parameters: json!({"type": "object", "properties": {"cmd": {"type": "string"}}}),
            }],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 4);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[2]["role"], "user");
        let tool_result = msgs[2]["content"].as_array().unwrap();
        assert_eq!(tool_result[0]["type"], "tool_result");
        assert_eq!(msgs[3]["role"], "assistant");
    }

    #[test]
    fn test_build_body_tool_message_ignores_non_tool_result_blocks() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![
                    ContentBlock::Text { text: "stray text".into() },
                    ContentBlock::ToolResult {
                        tool_use_id: "tu1".into(),
                        content: "ok".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolUse {
                        id: "x".into(),
                        name: "y".into(),
                        input: json!({}),
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 1);
        assert_eq!(content[0]["type"], "tool_result");
        assert_eq!(content[0]["tool_use_id"], "tu1");
    }

    #[test]
    fn test_build_body_user_empty_content() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["content"], "");
    }

    #[test]
    fn test_build_body_assistant_empty_content() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_build_body_tool_empty_content() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert!(content.is_empty());
    }

    #[test]
    fn test_build_body_multiple_tools() {
        let provider = make_provider();
        let req = make_request(
            vec![],
            vec![
                ToolDefinition {
                    name: "tool_a".into(),
                    description: "Does A".into(),
                    parameters: json!({"type": "object"}),
                },
                ToolDefinition {
                    name: "tool_b".into(),
                    description: "Does B".into(),
                    parameters: json!({"type": "object", "properties": {"x": {"type": "number"}}}),
                },
            ],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "tool_a");
        assert_eq!(tools[0]["description"], "Does A");
        assert_eq!(tools[1]["name"], "tool_b");
        assert_eq!(tools[1]["description"], "Does B");
        assert_eq!(tools[1]["input_schema"]["properties"]["x"]["type"], "number");
    }

    #[test]
    fn test_build_body_tool_use_complex_input() {
        let provider = make_provider();
        let complex_input = json!({
            "nested": {"a": [1, 2, 3]},
            "flag": true,
            "value": null,
        });
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "tu1".into(),
                    name: "complex_tool".into(),
                    input: complex_input.clone(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["input"], complex_input);
    }

    #[test]
    fn test_build_body_preserves_message_order() {
        let provider = make_provider();
        let req = make_request(
            vec![
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "first".into() }],
                },
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text { text: "second".into() }],
                },
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "third".into() }],
                },
                Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text { text: "fourth".into() }],
                },
                Message {
                    role: Role::User,
                    content: vec![ContentBlock::Text { text: "fifth".into() }],
                },
            ],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 5);
        assert_eq!(msgs[0]["content"], "first");
        assert_eq!(msgs[1]["content"].as_array().unwrap()[0]["text"], "second");
        assert_eq!(msgs[2]["content"], "third");
        assert_eq!(msgs[3]["content"].as_array().unwrap()[0]["text"], "fourth");
        assert_eq!(msgs[4]["content"], "fifth");
    }

    #[test]
    fn test_build_body_tool_result_empty_content_string() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "tu1".into(),
                    content: "".into(),
                    is_error: false,
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["content"], "");
        assert_eq!(content[0]["is_error"], false);
    }

    #[test]
    fn test_build_body_user_non_text_blocks_filtered_out() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "tr1".into(),
                        content: "should be ignored".into(),
                        is_error: false,
                    },
                    ContentBlock::Text { text: "kept".into() },
                    ContentBlock::ToolUse {
                        id: "tu1".into(),
                        name: "x".into(),
                        input: json!({}),
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["content"], "kept");
    }

    #[test]
    fn test_build_body_tool_result_is_error_field_values() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Tool,
                content: vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "t1".into(),
                        content: "ok".into(),
                        is_error: false,
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "t2".into(),
                        content: "fail".into(),
                        is_error: true,
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let content = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(content[0]["is_error"], false);
        assert_eq!(content[1]["is_error"], true);
    }

    #[test]
    fn test_build_body_assistant_mixed_tool_use_and_tool_result_filters_result() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::ToolUse {
                        id: "tu1".into(),
                        name: "cmd".into(),
                        input: json!({"a": 1}),
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "tr1".into(),
                        content: "filtered out".into(),
                        is_error: false,
                    },
                    ContentBlock::Text { text: "ok".into() },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let content = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[0]["type"], "tool_use");
        assert_eq!(content[1]["type"], "text");
    }

    #[test]
    fn test_build_body_tool_choice_required_with_tools() {
        let provider = make_provider();
        let req = make_request(
            vec![],
            vec![ToolDefinition {
                name: "a".into(),
                description: "b".into(),
                parameters: json!({}),
            }],
            ToolChoice::Required,
        );
        let body = provider.build_body(&req);
        assert_eq!(body["tool_choice"]["type"], "any");
    }

    #[test]
    fn test_build_body_tool_choice_none_with_tools_no_tool_choice_field() {
        let provider = make_provider();
        let req = make_request(
            vec![],
            vec![ToolDefinition {
                name: "t".into(),
                description: "d".into(),
                parameters: json!({}),
            }],
            ToolChoice::None,
        );
        let body = provider.build_body(&req);
        assert!(body.get("tool_choice").is_none());
    }

    #[test]
    fn test_build_body_extra_body_not_applied() {
        let provider = make_provider();
        let mut req = make_request(vec![], vec![], ToolChoice::Auto);
        req.extra_body = Some(json!({"response_format": {"type": "json_object"}}));
        let body = provider.build_body(&req);
        assert!(body.get("response_format").is_none());
    }

    #[test]
    fn test_build_body_user_multiple_non_text_returns_empty_string() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![
                    ContentBlock::ToolUse {
                        id: "x".into(),
                        name: "y".into(),
                        input: json!({}),
                    },
                    ContentBlock::ToolResult {
                        tool_use_id: "z".into(),
                        content: "c".into(),
                        is_error: false,
                    },
                ],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["content"], "");
    }

    #[test]
    fn test_build_body_tool_description_and_input_schema() {
        let provider = make_provider();
        let params = json!({"type": "object", "properties": {"q": {"type": "string"}}, "required": ["q"]});
        let req = make_request(
            vec![],
            vec![ToolDefinition {
                name: "search".into(),
                description: "Search things".into(),
                parameters: params.clone(),
            }],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools[0]["name"], "search");
        assert_eq!(tools[0]["description"], "Search things");
        assert_eq!(tools[0]["input_schema"], params);
    }

    fn make_provider_with_base_url(base_url: &str) -> AnthropicProvider {
        AnthropicProvider {
            client: reqwest::Client::new(),
            api_key: Zeroizing::new("test-key".into()),
            base_url: base_url.to_string(),
        }
    }

    #[tokio::test]
    async fn test_complete_text_response() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [
                    {"type": "text", "text": "Hello world"}
                ]
            })))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let msg = provider.complete(req).await.unwrap();
        assert!(matches!(msg.role, Role::Assistant));
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello world"),
            _ => panic!("expected Text"),
        }
    }

    #[tokio::test]
    async fn test_complete_tool_use_response() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [
                    {
                        "type": "tool_use",
                        "id": "toolu_123",
                        "name": "search",
                        "input": {"query": "test"}
                    }
                ]
            })))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let msg = provider.complete(req).await.unwrap();
        match &msg.content[0] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "toolu_123");
                assert_eq!(name, "search");
                assert_eq!(input["query"], "test");
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[tokio::test]
    async fn test_complete_mixed_content_blocks() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": [
                    {"type": "text", "text": "thinking..."},
                    {"type": "tool_use", "id": "t1", "name": "cmd", "input": {}},
                    {"type": "unknown_type", "data": "ignored"}
                ]
            })))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let msg = provider.complete(req).await.unwrap();
        assert_eq!(msg.content.len(), 2);
    }

    #[tokio::test]
    async fn test_complete_empty_content() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "content": []
            })))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let msg = provider.complete(req).await.unwrap();
        assert!(msg.content.is_empty());
    }

    #[tokio::test]
    async fn test_complete_no_content_field() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": "msg_123"
            })))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let msg = provider.complete(req).await.unwrap();
        assert!(msg.content.is_empty());
    }

    #[tokio::test]
    async fn test_complete_api_error() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(429).set_body_string("rate limited"))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let err = provider.complete(req).await.unwrap_err();
        assert!(err.to_string().contains("429"));
        assert!(err.to_string().contains("rate limited"));
    }

    #[tokio::test]
    async fn test_stream_api_error() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let err = provider.stream(req).await.unwrap_err();
        assert!(err.to_string().contains("500"));
    }

    #[tokio::test]
    async fn test_stream_text_delta_and_done() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;

        let sse_body = [
            "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
            "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n",
            "event: message_stop\ndata: {}\n\n",
        ].concat();

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse_body)
            )
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let mut rx = provider.stream(req).await.unwrap();

        let mut texts = Vec::new();
        let mut got_done = false;
        while let Some(event) = rx.recv().await {
            match event {
                StreamEvent::TextDelta(t) => texts.push(t),
                StreamEvent::Done { .. } => { got_done = true; break; }
                _ => {}
            }
        }
        assert_eq!(texts, vec!["Hello", " world"]);
        assert!(got_done);
    }

    #[tokio::test]
    async fn test_stream_tool_use_events() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;

        let sse_body = [
            "event: content_block_start\ndata: {\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"search\"}}\n\n",
            "event: content_block_delta\ndata: {\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"q\\\":\"}}\n\n",
            "event: content_block_delta\ndata: {\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"test\\\"}\"}}\n\n",
            "event: content_block_stop\ndata: {}\n\n",
            "event: message_stop\ndata: {}\n\n",
        ].concat();

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse_body)
            )
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let mut rx = provider.stream(req).await.unwrap();

        let mut events_log = Vec::new();
        while let Some(event) = rx.recv().await {
            match &event {
                StreamEvent::ToolUseStart { id, name } => {
                    events_log.push(format!("start:{id}:{name}"));
                }
                StreamEvent::ToolUseDelta(json) => {
                    events_log.push(format!("delta:{json}"));
                }
                StreamEvent::ToolUseEnd => {
                    events_log.push("end".into());
                }
                StreamEvent::Done { .. } => {
                    events_log.push("done".into());
                    break;
                }
                _ => {}
            }
        }
        assert_eq!(events_log[0], "start:tu_1:search");
        assert!(events_log.contains(&"end".to_string()));
        assert!(events_log.last().unwrap() == "done");
    }

    #[tokio::test]
    async fn test_stream_error_event() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;

        let sse_body = "event: error\ndata: {\"error\":{\"message\":\"overloaded\"}}\n\n";

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse_body)
            )
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let mut rx = provider.stream(req).await.unwrap();

        let event = rx.recv().await.unwrap();
        match event {
            StreamEvent::Error(msg) => assert_eq!(msg, "overloaded"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_stream_content_block_start_text_not_tool_use() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;

        let sse_body = [
            "event: content_block_start\ndata: {\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
            "event: content_block_delta\ndata: {\"delta\":{\"type\":\"text_delta\",\"text\":\"Hi\"}}\n\n",
            "event: content_block_stop\ndata: {}\n\n",
            "event: message_stop\ndata: {}\n\n",
        ].concat();

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse_body)
            )
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let mut rx = provider.stream(req).await.unwrap();

        let mut got_tool_start = false;
        let mut got_tool_end = false;
        while let Some(event) = rx.recv().await {
            match event {
                StreamEvent::ToolUseStart { .. } => got_tool_start = true,
                StreamEvent::ToolUseEnd => got_tool_end = true,
                StreamEvent::Done { .. } => break,
                _ => {}
            }
        }
        assert!(!got_tool_start);
        assert!(!got_tool_end);
    }

    #[tokio::test]
    async fn test_stream_message_stop_closes_open_tool_use() {
        use wiremock::{Mock, MockServer, ResponseTemplate, matchers};
        let server = MockServer::start().await;

        let sse_body = [
            "event: content_block_start\ndata: {\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_2\",\"name\":\"cmd\"}}\n\n",
            "event: message_stop\ndata: {}\n\n",
        ].concat();

        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/messages"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "text/event-stream")
                    .set_body_string(sse_body)
            )
            .mount(&server)
            .await;

        let provider = make_provider_with_base_url(&server.uri());
        let req = make_request(vec![], vec![], ToolChoice::Auto);
        let mut rx = provider.stream(req).await.unwrap();

        let mut got_tool_end = false;
        while let Some(event) = rx.recv().await {
            match event {
                StreamEvent::ToolUseEnd => got_tool_end = true,
                StreamEvent::Done { .. } => break,
                _ => {}
            }
        }
        assert!(got_tool_end);
    }

    #[test]
    fn test_build_body_assistant_tool_use_id_preserved() {
        let provider = make_provider();
        let req = make_request(
            vec![Message {
                role: Role::Assistant,
                content: vec![ContentBlock::ToolUse {
                    id: "toolu_01XYZ".into(),
                    name: "my_tool".into(),
                    input: json!({}),
                }],
            }],
            vec![],
            ToolChoice::Auto,
        );
        let body = provider.build_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        let content = msgs[0]["content"].as_array().unwrap();
        assert_eq!(content[0]["id"], "toolu_01XYZ");
    }
}
