use reqwest::Client;
use serde_json::json;
use zeroize::Zeroizing;

use crate::provider::*;

pub struct OpenRouterProvider {
    client: Client,
    api_key: Zeroizing<String>,
    base_url: String,
}

impl OpenRouterProvider {
    pub fn new(
        config: &crate::config::Config,
    ) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .openrouter
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("OpenRouter not configured")
            })?;
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_key: auth.resolve_api_key()?,
            base_url: auth
                .base_url
                .clone()
                .unwrap_or_else(|| {
                    "https://openrouter.ai/api/v1".into()
                }),
        })
    }

    fn build_request_body(
        &self,
        request: &ChatRequest,
    ) -> serde_json::Value {
        let messages = self
            .convert_messages(&request.messages, &request.system);
        let tools = self.convert_tools(&request.tools);

        let mut body = json!({
            "model": request.model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": request.stream,
        });

        if !tools.is_empty() {
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

        body
    }

    fn convert_messages(
        &self,
        messages: &[Message],
        system: &str,
    ) -> Vec<serde_json::Value> {
        let mut out = vec![json!({
            "role": "system",
            "content": system,
        })];

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
                    out.push(
                        json!({"role": "user", "content": text}),
                    );
                }
                Role::Assistant => {
                    let mut tool_calls = vec![];
                    let mut text_parts = vec![];
                    for block in &msg.content {
                        match block {
                            ContentBlock::ToolUse {
                                id,
                                name,
                                input,
                            } => {
                                tool_calls.push(json!({
                                    "id": id,
                                    "type": "function",
                                    "function": {
                                        "name": name,
                                        "arguments":
                                            input.to_string(),
                                    }
                                }));
                            }
                            ContentBlock::Text { text } => {
                                text_parts.push(text.as_str());
                            }
                            _ => {}
                        }
                    }
                    let mut msg_json =
                        json!({"role": "assistant"});
                    if !text_parts.is_empty() {
                        msg_json["content"] =
                            json!(text_parts.join("\n"));
                    }
                    if !tool_calls.is_empty() {
                        msg_json["tool_calls"] =
                            json!(tool_calls);
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
                            out.push(json!({
                                "role": "tool",
                                "tool_call_id": tool_use_id,
                                "content": content,
                            }));
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    fn convert_tools(
        &self,
        tools: &[crate::tools::ToolDefinition],
    ) -> Vec<serde_json::Value> {
        tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect()
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenRouterProvider {
    async fn complete(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<Message> {
        let body = self.build_request_body(&request);
        let resp = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header(
                "Authorization",
                format!("Bearer {}", &*self.api_key),
            )
            .header(
                "HTTP-Referer",
                "https://github.com/ArcticBear/nsh",
            )
            .header("X-Title", "nsh")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "OpenRouter API error ({status}): {text}"
            );
        }

        let json: serde_json::Value = resp.json().await?;
        parse_openai_response(&json)
    }

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<
        tokio::sync::mpsc::Receiver<StreamEvent>,
    > {
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(true);

        let resp = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header(
                "Authorization",
                format!("Bearer {}", &*self.api_key),
            )
            .header(
                "HTTP-Referer",
                "https://github.com/ArcticBear/nsh",
            )
            .header("X-Title", "nsh")
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!(
                "OpenRouter API error ({status}): {text}"
            );
        }

        let (tx, rx) = tokio::sync::mpsc::channel(64);

        tokio::spawn(async move {
            use eventsource_stream::Eventsource;
            use futures::StreamExt;

            let mut stream = resp.bytes_stream().eventsource();
            let mut current_tool_index: Option<usize> = None;

            while let Some(event) = stream.next().await {
                let event = match event {
                    Ok(e) => e,
                    Err(e) => {
                        let _ = tx
                            .send(StreamEvent::Error(
                                e.to_string(),
                            ))
                            .await;
                        break;
                    }
                };

                if event.data == "[DONE]" {
                    let _ =
                        tx.send(StreamEvent::Done { usage: None })
                            .await;
                    break;
                }

                let chunk: serde_json::Value =
                    match serde_json::from_str(&event.data) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };

                let delta = &chunk["choices"][0]["delta"];

                // Text content
                if let Some(content) = delta["content"].as_str() {
                    if !content.is_empty() {
                        let _ = tx
                            .send(StreamEvent::TextDelta(
                                content.to_string(),
                            ))
                            .await;
                    }
                }

                // Tool calls
                if let Some(tool_calls) =
                    delta["tool_calls"].as_array()
                {
                    for tc in tool_calls {
                        let idx =
                            tc["index"].as_u64().unwrap_or(0)
                                as usize;

                        // New tool call
                        if current_tool_index != Some(idx) {
                            if current_tool_index.is_some() {
                                let _ = tx
                                    .send(
                                        StreamEvent::ToolUseEnd,
                                    )
                                    .await;
                            }
                            current_tool_index = Some(idx);
                            let id = tc["id"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            let name = tc["function"]["name"]
                                .as_str()
                                .unwrap_or("")
                                .to_string();
                            if !name.is_empty() {
                                let _ = tx
                                    .send(
                                    StreamEvent::ToolUseStart {
                                        id,
                                        name,
                                    },
                                )
                                    .await;
                            }
                        }

                        // Arguments delta
                        if let Some(args) =
                            tc["function"]["arguments"].as_str()
                        {
                            if !args.is_empty() {
                                let _ = tx
                                    .send(
                                    StreamEvent::ToolUseDelta(
                                        args.to_string(),
                                    ),
                                )
                                    .await;
                            }
                        }
                    }
                }

                // Finish reason
                if chunk["choices"][0]["finish_reason"]
                    .as_str()
                    .is_some()
                {
                    if current_tool_index.is_some() {
                        let _ = tx
                            .send(StreamEvent::ToolUseEnd)
                            .await;
                    }
                    let _ = tx
                        .send(StreamEvent::Done { usage: None })
                        .await;
                    break;
                }
            }
        });

        Ok(rx)
    }
}
