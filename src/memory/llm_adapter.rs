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
        let provider_cfg = crate::provider::ProviderFactoryConfig::from_config(&self.config);
        let provider = crate::provider::create_provider(&provider_cfg.default, &provider_cfg)?;
        let transport_base_url = crate::provider::routing::resolve_openai_compat_config(
            &provider_cfg.default,
            &provider_cfg,
        )?
        .map(|cfg| cfg.base_url);
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
        let request = if let Some(base_url) = transport_base_url.as_deref() {
            crate::provider::with_transport_base_url(&request, base_url)
        } else {
            request
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_model_prefers_configured_fast_model() {
        let mut config = crate::config::Config::default();
        config.models.fast = vec!["fast-model".into()];
        config.provider.model = "fallback-model".into();

        let client = ProviderLlmClient::new(&config);

        assert_eq!(client.fast_model(), "fast-model");
    }

    #[test]
    fn fast_model_falls_back_to_provider_model() {
        let mut config = crate::config::Config::default();
        config.models.fast.clear();
        config.provider.model = "fallback-model".into();

        let client = ProviderLlmClient::new(&config);

        assert_eq!(client.fast_model(), "fallback-model");
    }
}
