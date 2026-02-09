pub mod anthropic;
pub mod openai;
pub mod openai_compat;
pub mod openrouter;

use serde::{Deserialize, Serialize};

/// Unified message format — providers translate to their wire format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: Role,
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        content: String,
        is_error: bool,
    },
}

#[derive(Debug)]
pub struct ChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<crate::tools::ToolDefinition>,
    pub tool_choice: ToolChoice,
    pub max_tokens: u32,
    pub stream: bool,
}

#[derive(Debug)]
pub enum ToolChoice {
    Auto,
    Required,
    None,
}

#[derive(Debug)]
pub enum StreamEvent {
    TextDelta(String),
    ToolUseStart { id: String, name: String },
    ToolUseDelta(String),
    ToolUseEnd,
    Done { usage: Option<Usage> },
    Error(String),
}

#[derive(Debug)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<Message>;

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>>;
}

/// Factory: create a provider by name.
pub fn create_provider(
    provider_name: &str,
    config: &crate::config::Config,
) -> anyhow::Result<Box<dyn LlmProvider>> {
    match provider_name {
        "openrouter" => Ok(Box::new(
            openrouter::OpenRouterProvider::new(config)?,
        )),
        "anthropic" => Ok(Box::new(
            anthropic::AnthropicProvider::new(config)?,
        )),
        "openai" => {
            Ok(Box::new(openai::OpenAIProvider::new(config)?))
        }
        _ => anyhow::bail!("Unknown provider: {provider_name}"),
    }
}

/// Parse an OpenAI-format JSON response into our Message type.
pub fn parse_openai_response(
    json: &serde_json::Value,
) -> anyhow::Result<Message> {
    let choice = json["choices"]
        .get(0)
        .ok_or_else(|| anyhow::anyhow!("No choices in response"))?;
    let msg = &choice["message"];

    let mut content = Vec::new();

    // Text content
    if let Some(text) = msg["content"].as_str() {
        if !text.is_empty() {
            content.push(ContentBlock::Text {
                text: text.to_string(),
            });
        }
    }

    // Tool calls
    if let Some(tool_calls) = msg["tool_calls"].as_array() {
        for tc in tool_calls {
            let id = tc["id"].as_str().unwrap_or("").to_string();
            let name = tc["function"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let args_str = tc["function"]["arguments"]
                .as_str()
                .unwrap_or("{}");
            let input: serde_json::Value =
                serde_json::from_str(args_str).unwrap_or_default();
            content.push(ContentBlock::ToolUse { id, name, input });
        }
    }

    Ok(Message {
        role: Role::Assistant,
        content,
    })
}
