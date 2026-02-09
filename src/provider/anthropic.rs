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
        let auth = config.provider.anthropic.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Anthropic not configured"))?;
        Ok(Self {
            client: Client::builder().timeout(std::time::Duration::from_secs(120)).build()?,
            api_key: auth.resolve_api_key("anthropic")?,
            base_url: auth.base_url.clone()
                .unwrap_or_else(|| "https://api.anthropic.com".into()),
        })
    }

    fn build_body(&self, request: &ChatRequest) -> serde_json::Value {
        let mut messages = Vec::new();
        for msg in &request.messages {
            match msg.role {
                Role::User => {
                    let text: String = msg.content.iter()
                        .filter_map(|c| if let ContentBlock::Text { text } = c { Some(text.as_str()) } else { None })
                        .collect::<Vec<_>>().join("\n");
                    messages.push(json!({"role": "user", "content": text}));
                }
                Role::Assistant => {
                    let content: Vec<serde_json::Value> = msg.content.iter().filter_map(|b| match b {
                        ContentBlock::Text { text } => Some(json!({"type": "text", "text": text})),
                        ContentBlock::ToolUse { id, name, input } =>
                            Some(json!({"type": "tool_use", "id": id, "name": name, "input": input})),
                        _ => None,
                    }).collect();
                    messages.push(json!({"role": "assistant", "content": content}));
                }
                Role::Tool => {
                    let mut content = Vec::new();
                    for block in &msg.content {
                        if let ContentBlock::ToolResult { tool_use_id, content: c, is_error } = block {
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

        let tools: Vec<serde_json::Value> = request.tools.iter().map(|t| json!({
            "name": t.name, "description": t.description, "input_schema": t.parameters,
        })).collect();

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
                ToolChoice::Required => { body["tool_choice"] = json!({"type": "any"}); }
                ToolChoice::Auto => { body["tool_choice"] = json!({"type": "auto"}); }
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
        let resp = self.client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &*self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body).send().await?;
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
                            content.push(ContentBlock::Text { text: text.to_string() });
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
        Ok(Message { role: Role::Assistant, content })
    }

    async fn stream(&self, request: ChatRequest) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        let mut body = self.build_body(&request);
        body["stream"] = json!(true);
        let resp = self.client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &*self.api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body).send().await?;
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
                    Err(e) => { let _ = tx.send(StreamEvent::Error(e.to_string())).await; break; }
                };
                let data: serde_json::Value = match serde_json::from_str(&event.data) {
                    Ok(v) => v, Err(_) => continue,
                };
                match event.event.as_str() {
                    "content_block_start" => {
                        let block = &data["content_block"];
                        if block["type"].as_str() == Some("tool_use") {
                            in_tool_use = true;
                            let _ = tx.send(StreamEvent::ToolUseStart {
                                id: block["id"].as_str().unwrap_or("").to_string(),
                                name: block["name"].as_str().unwrap_or("").to_string(),
                            }).await;
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
                                    let _ = tx.send(StreamEvent::ToolUseDelta(json.to_string())).await;
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
                            in_tool_use = false;
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
