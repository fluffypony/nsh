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
    use crate::provider::*;
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
}
