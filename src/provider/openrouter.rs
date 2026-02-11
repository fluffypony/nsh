use super::openai_compat::OpenAICompatProvider;
use crate::provider::*;

pub struct OpenRouterProvider(OpenAICompatProvider);

impl OpenRouterProvider {
    pub fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .openrouter
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenRouter not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            auth.resolve_api_key("openrouter")?,
            auth.base_url
                .clone()
                .unwrap_or_else(|| "https://openrouter.ai/api/v1".into()),
            config.provider.fallback_model.clone(),
            vec![
                (
                    "HTTP-Referer".into(),
                    "https://github.com/fluffypony/nsh".into(),
                ),
                ("X-Title".into(), "nsh".into()),
            ],
            config.provider.timeout_seconds,
        )?))
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenRouterProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        self.0.complete(request).await
    }

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        self.0.stream(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_fails_when_openrouter_not_configured() {
        let mut config = crate::config::Config::default();
        config.provider.openrouter = None;
        let result = OpenRouterProvider::new(&config);
        let err = result.err().expect("should fail when openrouter is None");
        assert!(err.to_string().contains("OpenRouter not configured"));
    }

    #[test]
    fn new_uses_custom_base_url_when_provided() {
        let mut config = crate::config::Config::default();
        config.provider.openrouter = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: Some("https://custom.example.com/v1".into()),
        });
        let result = OpenRouterProvider::new(&config);
        assert!(result.is_ok());
    }
}
