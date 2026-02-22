#[async_trait::async_trait]
pub trait MemoryLlmClient: Send + Sync {
    async fn complete_json(&self, prompt: &str) -> anyhow::Result<String>;
    #[allow(unused)]
    async fn complete(&self, system: &str, user: &str) -> anyhow::Result<String>;
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
    async fn complete_json(&self, prompt: &str) -> anyhow::Result<String> {
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
        Ok(text)
    }

    async fn complete(&self, system: &str, user: &str) -> anyhow::Result<String> {
        let provider =
            crate::provider::create_provider(&self.config.provider.default, &self.config)?;
        let model = self.fast_model();
        let request = crate::provider::ChatRequest {
            model,
            system: system.to_string(),
            messages: vec![crate::provider::Message {
                role: crate::provider::Role::User,
                content: vec![crate::provider::ContentBlock::Text {
                    text: user.to_string(),
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
        Ok(text)
    }
}
