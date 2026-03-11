#[async_trait::async_trait]
pub trait MemoryLlmClient: Send + Sync {
    async fn complete_json(&self, prompt: &str) -> anyhow::Result<serde_json::Value>;
}

pub struct ProviderLlmClient {
    config: crate::config::Config,
}

impl ProviderLlmClient {
    pub fn new(config: &crate::config::Config) -> Self {
        Self {
            config: config.clone(),
        }
    }

    fn fast_model(&self) -> String {
        self.config
            .models
            .fast
            .first()
            .cloned()
            .unwrap_or_else(|| self.config.provider.model.clone())
    }
}

#[async_trait::async_trait]
impl MemoryLlmClient for ProviderLlmClient {
    async fn complete_json(&self, prompt: &str) -> anyhow::Result<serde_json::Value> {
        let provider =
            crate::provider::create_provider(&self.config.provider.default, &self.config)?;
        let model = self.fast_model();
        let request = crate::provider::ChatRequest {
            model,
            system: "You are a memory extraction assistant. Respond only with valid JSON.".into(),
            messages: vec![crate::provider::Message {
                role: crate::provider::Role::User,
                content: vec![crate::provider::ContentBlock::Text {
                    text: prompt.to_string(),
                }],
            }],
            tools: vec![],
            tool_choice: crate::provider::ToolChoice::None,
            max_tokens: 4096,
            stream: false,
            extra_body: None,
        };

        let response = provider.complete(request).await?;
        let mut text = String::new();
        for block in &response.content {
            if let crate::provider::ContentBlock::Text { text: t } = block {
                text.push_str(t);
            }
        }
        crate::json_extract::extract_json(&text)
            .ok_or_else(|| anyhow::anyhow!("memory llm returned invalid JSON"))
    }
}
