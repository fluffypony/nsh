pub mod anthropic;
pub mod chain;
pub mod openai;
pub mod openai_compat;
pub mod openrouter;
pub mod policy;
pub mod routing;

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

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum ToolChoice {
    Auto,
    Required,
    None,
}

#[derive(Debug)]
pub enum StreamEvent {
    TextDelta(String),
    ToolUseStart {
        id: String,
        name: String,
    },
    ToolUseDelta(String),
    ToolUseEnd,
    #[allow(dead_code)]
    GenerationId(String),
    #[allow(dead_code)]
    Done {
        usage: Option<Usage>,
    },
    Error(String),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Usage {
    pub input_tokens: u32,
    pub output_tokens: u32,
}

#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message>;

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>>;
}

#[derive(Debug, Clone)]
pub struct ProviderFactoryConfig {
    pub default: String,
    pub provider: crate::config::ProviderConfig,
}

impl ProviderFactoryConfig {
    pub fn from_config(config: &crate::config::Config) -> Self {
        Self {
            default: config.provider.default.clone(),
            provider: config.provider.clone(),
        }
    }
}

/// Factory: create a provider by name.
pub fn create_provider(
    provider_name: &str,
    config: &ProviderFactoryConfig,
) -> anyhow::Result<Box<dyn LlmProvider>> {
    if let Some(openai_cfg) = routing::resolve_openai_compat_config(provider_name, config)? {
        return Ok(Box::new(openai_compat::OpenAICompatProvider::new(
            openai_cfg,
        )?));
    }

    match provider_name {
        "anthropic" => Ok(Box::new(anthropic::AnthropicProvider::new(
            &config.provider,
        )?)),
        _ => anyhow::bail!("Unknown provider: {provider_name}"),
    }
}

pub fn with_transport_base_url(request: &ChatRequest, base_url: &str) -> ChatRequest {
    let mut out = request.clone();
    let mut extra = out
        .extra_body
        .take()
        .unwrap_or_else(|| serde_json::json!({}));
    if let serde_json::Value::Object(map) = &mut extra {
        map.insert(
            "_transport_base_url".to_string(),
            serde_json::Value::String(base_url.to_string()),
        );
        out.extra_body = Some(extra);
    }
    out
}

/// Parse an OpenAI-format JSON response into our Message type.
pub fn parse_openai_response(json: &serde_json::Value) -> anyhow::Result<Message> {
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
            let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
            let args_str = tc["function"]["arguments"].as_str().ok_or_else(|| {
                anyhow::anyhow!(
                    "Tool call arguments for tool '{name}' (id '{id}') must be a JSON string"
                )
            })?;
            let input: serde_json::Value = serde_json::from_str(args_str).map_err(|e| {
                let preview: String = args_str.chars().take(200).collect();
                anyhow::anyhow!(
                    "Failed to parse tool call arguments for tool '{name}' (id '{id}'): {e}; raw: {preview}"
                )
            })?;
            content.push(ContentBlock::ToolUse { id, name, input });
        }
    }

    Ok(Message {
        role: Role::Assistant,
        content,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_openai_response_text_content() {
        let resp = json!({
            "choices": [{"message": {"content": "Hello world", "role": "assistant"}}]
        });
        let msg = parse_openai_response(&resp).unwrap();
        assert!(matches!(msg.role, Role::Assistant));
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            ContentBlock::Text { text } => assert_eq!(text, "Hello world"),
            _ => panic!("expected Text block"),
        }
    }

    #[test]
    fn parse_openai_response_tool_calls() {
        let resp = json!({
            "choices": [{"message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "function": {"name": "run_command", "arguments": "{\"cmd\":\"ls\"}"}
                }]
            }}]
        });
        let msg = parse_openai_response(&resp).unwrap();
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "call_1");
                assert_eq!(name, "run_command");
                assert_eq!(input, &json!({"cmd": "ls"}));
            }
            _ => panic!("expected ToolUse block"),
        }
    }

    #[test]
    fn parse_openai_response_text_and_tool_calls() {
        let resp = json!({
            "choices": [{"message": {
                "content": "Let me run that",
                "tool_calls": [{
                    "id": "call_2",
                    "function": {"name": "read_file", "arguments": "{\"path\":\"/tmp/f\"}"}
                }]
            }}]
        });
        let msg = parse_openai_response(&resp).unwrap();
        assert_eq!(msg.content.len(), 2);
        assert!(
            matches!(&msg.content[0], ContentBlock::Text { text } if text == "Let me run that")
        );
        assert!(
            matches!(&msg.content[1], ContentBlock::ToolUse { name, .. } if name == "read_file")
        );
    }

    #[test]
    fn parse_openai_response_empty_choices() {
        let resp = json!({"choices": []});
        assert!(parse_openai_response(&resp).is_err());
    }

    #[test]
    fn parse_openai_response_invalid_arguments_is_error() {
        let resp = json!({
            "choices": [{"message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_3",
                    "function": {"name": "test", "arguments": "not json{{{"}
                }]
            }}]
        });
        let err = parse_openai_response(&resp)
            .expect_err("invalid tool-call arguments should fail parser");
        assert!(
            err.to_string()
                .contains("Failed to parse tool call arguments for tool 'test'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_openai_response_non_string_arguments_is_error() {
        let resp = json!({
            "choices": [{"message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_4",
                    "function": {"name": "test", "arguments": {"cmd": "ls"}}
                }]
            }}]
        });
        let err = parse_openai_response(&resp)
            .expect_err("non-string tool-call arguments should fail parser");
        assert!(
            err.to_string().contains(
                "Tool call arguments for tool 'test' (id 'call_4') must be a JSON string"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_openai_response_missing_arguments_is_error() {
        let resp = json!({
            "choices": [{"message": {
                "content": null,
                "tool_calls": [{
                    "id": "call_5",
                    "function": {"name": "test"}
                }]
            }}]
        });
        let err = parse_openai_response(&resp)
            .expect_err("missing tool-call arguments should fail parser");
        assert!(
            err.to_string().contains(
                "Tool call arguments for tool 'test' (id 'call_5') must be a JSON string"
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn message_serialization_roundtrip() {
        let msg = Message {
            role: Role::User,
            content: vec![ContentBlock::Text { text: "hi".into() }],
        };
        let serialized = serde_json::to_string(&msg).unwrap();
        let deserialized: Message = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized.role, Role::User));
        assert_eq!(deserialized.content.len(), 1);
    }

    #[test]
    fn role_serialization_roundtrip() {
        for (role, expected) in [
            (Role::System, "\"system\""),
            (Role::User, "\"user\""),
            (Role::Assistant, "\"assistant\""),
            (Role::Tool, "\"tool\""),
        ] {
            let s = serde_json::to_string(&role).unwrap();
            assert_eq!(s, expected);
            let back: Role = serde_json::from_str(&s).unwrap();
            assert_eq!(std::mem::discriminant(&role), std::mem::discriminant(&back));
        }
    }

    #[test]
    fn create_provider_unknown_name_returns_error() {
        let config = ProviderFactoryConfig::from_config(&crate::config::Config::default());
        let result = create_provider("nonexistent", &config);
        let err = result.err().expect("should be an error");
        assert!(err.to_string().contains("Unknown provider"));
    }

    #[test]
    fn create_provider_openrouter_with_api_key() {
        let mut config = crate::config::Config::default();
        config.provider.openrouter = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("openrouter", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_anthropic_with_api_key() {
        let mut config = crate::config::Config::default();
        config.provider.anthropic = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("anthropic", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_openai_with_api_key() {
        let mut config = crate::config::Config::default();
        config.provider.openai = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("openai", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_gemini_without_config_returns_error() {
        let mut config = crate::config::Config::default();
        config.provider.gemini = None;
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("gemini", &provider_config);
        let err = result.err().expect("should be an error");
        assert!(err.to_string().contains("Gemini not configured"));
    }

    #[test]
    fn create_provider_ollama_without_config_uses_defaults() {
        let mut config = crate::config::Config::default();
        config.provider.ollama = None;
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("ollama", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_gemini_with_api_key() {
        let mut config = crate::config::Config::default();
        config.provider.gemini = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("gemini", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn create_provider_sidecar_provider_uses_openai_compat_path() {
        let config = crate::config::Config::default();
        let provider_config = ProviderFactoryConfig::from_config(&config);
        let result = create_provider("copilot", &provider_config);
        assert!(result.is_ok());
    }

    #[test]
    fn with_transport_base_url_adds_marker_without_removing_existing_extra_body() {
        let request = ChatRequest {
            model: "m".into(),
            system: "s".into(),
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::Auto,
            max_tokens: 1,
            stream: false,
            extra_body: Some(json!({"existing": true})),
        };

        let out = with_transport_base_url(&request, "http://127.0.0.1:8317/v1");
        assert_eq!(out.extra_body.as_ref().unwrap()["existing"], json!(true));
        assert_eq!(
            out.extra_body.as_ref().unwrap()["_transport_base_url"],
            json!("http://127.0.0.1:8317/v1")
        );
    }

    #[test]
    fn content_block_serialization_roundtrip() {
        let blocks = vec![
            ContentBlock::Text {
                text: "hello".into(),
            },
            ContentBlock::ToolUse {
                id: "id1".into(),
                name: "fn1".into(),
                input: json!({"key": "val"}),
            },
            ContentBlock::ToolResult {
                tool_use_id: "id1".into(),
                content: "result".into(),
                is_error: false,
            },
        ];
        for block in &blocks {
            let s = serde_json::to_string(block).unwrap();
            let back: ContentBlock = serde_json::from_str(&s).unwrap();
            let s2 = serde_json::to_string(&back).unwrap();
            assert_eq!(s, s2);
        }
    }
}
