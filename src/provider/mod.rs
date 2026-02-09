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

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub model: String,
    pub system: String,
    pub messages: Vec<Message>,
    pub tools: Vec<crate::tools::ToolDefinition>,
    pub tool_choice: ToolChoice,
    pub max_tokens: u32,
    pub stream: bool,
    pub extra_body: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
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
    GenerationId(String),
    Done { usage: Option<Usage> },
    Error(String),
}

#[derive(Debug, Clone)]
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
        "gemini" => {
            let auth = config.provider.gemini.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Gemini not configured"))?;
            Ok(Box::new(openai_compat::OpenAICompatProvider::new(
                auth.resolve_api_key("gemini")?,
                "https://generativelanguage.googleapis.com/v1beta/openai".into(),
                None,
                vec![],
                config.provider.timeout_seconds,
            )?))
        }
        "ollama" => {
            let auth = config.provider.ollama.as_ref();
            let base_url = auth
                .and_then(|a| a.base_url.clone())
                .unwrap_or_else(|| "http://localhost:11434/v1".into());
            let api_key = auth
                .and_then(|a| a.resolve_api_key("ollama").ok())
                .unwrap_or_else(|| zeroize::Zeroizing::new("ollama".into()));
            Ok(Box::new(openai_compat::OpenAICompatProvider::new(
                api_key, base_url, config.provider.fallback_model.clone(), vec![],
                config.provider.timeout_seconds,
            )?))
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
