use super::openai_compat::{OpenAICompatProvider, OpenAICompatProviderConfig};
use crate::config::ProviderConfig;
use crate::provider::*;

pub struct OpenRouterProvider(OpenAICompatProvider);

impl OpenRouterProvider {
    pub fn new(provider: &ProviderConfig) -> anyhow::Result<Self> {
        let auth = provider
            .openrouter
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenRouter not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            OpenAICompatProviderConfig {
                api_key: auth.resolve_api_key("openrouter")?,
                base_url: auth
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://openrouter.ai/api/v1".into()),
                fallback_model: provider.fallback_model.clone(),
                extra_headers: vec![
                    (
                        "HTTP-Referer".into(),
                        "https://github.com/fluffypony/nsh".into(),
                    ),
                    ("X-Title".into(), "nsh".into()),
                ],
                timeout_seconds: provider.timeout_seconds,
                debug_provider_name: "openrouter".to_string(),
            },
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
        let mut provider = crate::config::ProviderConfig::default();
        provider.openrouter = None;
        let result = OpenRouterProvider::new(&provider);
        let err = result.err().expect("should fail when openrouter is None");
        assert!(err.to_string().contains("OpenRouter not configured"));
    }

    #[test]
    fn new_uses_custom_base_url_when_provided() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openrouter = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: Some("https://custom.example.com/v1".into()),
        });
        let result = OpenRouterProvider::new(&provider);
        assert!(result.is_ok());
    }
}
