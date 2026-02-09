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
    ) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()?,
            api_key,
            base_url,
            fallback_model,
            extra_headers,
        })
    }

    fn build_request_body(&self, request: &ChatRequest) -> serde_json::Value {
        let messages = build_openai_messages(&request.messages, &request.system);
        let tools = build_openai_tools(&request.tools);

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
            ToolChoice::Required => { body["tool_choice"] = json!("required"); }
            ToolChoice::None => { body["tool_choice"] = json!("none"); }
            ToolChoice::Auto => { body["tool_choice"] = json!("auto"); }
        }

        body
    }

    fn build_http_request(&self, body: &serde_json::Value) -> reqwest::RequestBuilder {
        let mut req = self.client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", format!("Bearer {}", &*self.api_key))
            .json(body);
        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    }
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

#[async_trait::async_trait]
impl LlmProvider for OpenAICompatProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        let body = self.build_request_body(&request);
        let resp = self.build_http_request(&body).send().await?;
        let status = resp.status();

        if !status.is_success() {
            if is_retryable(status) {
                if let Some(fallback) = &self.fallback_model {
                    tracing::warn!("Primary model failed ({status}), trying fallback: {fallback}");
                    let mut fb = body.clone();
                    fb["model"] = json!(fallback);
                    let resp2 = self.build_http_request(&fb).send().await?;
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

    async fn stream(&self, request: ChatRequest) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(true);

        let resp = self.build_http_request(&body).send().await?;
        let status = resp.status();

        if !status.is_success() {
            if is_retryable(status) {
                if let Some(fallback) = &self.fallback_model {
                    tracing::warn!("Primary failed ({status}), stream fallback: {fallback}");
                    let mut fb = body.clone();
                    fb["model"] = json!(fallback);
                    let resp2 = self.build_http_request(&fb).send().await?;
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
    let mut out = vec![json!({"role": "system", "content": system})];
    for msg in messages {
        match msg.role {
            Role::User => {
                let text: String = msg.content.iter()
                    .filter_map(|c| if let ContentBlock::Text { text } = c { Some(text.as_str()) } else { None })
                    .collect::<Vec<_>>().join("\n");
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
                        ContentBlock::Text { text } => { text_parts.push(text.as_str()); }
                        _ => {}
                    }
                }
                let mut msg_json = json!({"role": "assistant"});
                if !text_parts.is_empty() { msg_json["content"] = json!(text_parts.join("\n")); }
                if !tool_calls.is_empty() { msg_json["tool_calls"] = json!(tool_calls); }
                out.push(msg_json);
            }
            Role::Tool => {
                for block in &msg.content {
                    if let ContentBlock::ToolResult { tool_use_id, content, .. } = block {
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

pub fn spawn_openai_stream(resp: reqwest::Response) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        use eventsource_stream::Eventsource;
        use futures::StreamExt;
        let mut stream = resp.bytes_stream().eventsource();
        let mut current_tool_index: Option<usize> = None;
        while let Some(event) = stream.next().await {
            let event = match event {
                Ok(e) => e,
                Err(e) => { let _ = tx.send(StreamEvent::Error(e.to_string())).await; break; }
            };
            if event.data == "[DONE]" {
                if current_tool_index.is_some() {
                    let _ = tx.send(StreamEvent::ToolUseEnd).await;
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
                break;
            }
            let chunk: serde_json::Value = match serde_json::from_str(&event.data) {
                Ok(v) => v, Err(_) => continue,
            };
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
