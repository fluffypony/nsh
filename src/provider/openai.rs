use super::openai_compat::{OpenAICompatProvider, OpenAICompatProviderConfig};
use crate::config::ProviderConfig;
use crate::provider::*;

pub struct OpenAIProvider(OpenAICompatProvider);

impl OpenAIProvider {
    pub fn new(provider: &ProviderConfig) -> anyhow::Result<Self> {
        let auth = provider
            .openai
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenAI not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            OpenAICompatProviderConfig {
                api_key: auth.resolve_api_key("openai")?,
                base_url: auth
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "https://api.openai.com/v1".into()),
                fallback_model: provider.fallback_model.clone(),
                extra_headers: vec![],
                timeout_seconds: provider.timeout_seconds,
                debug_provider_name: "openai".to_string(),
            },
        )?))
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAIProvider {
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
    fn new_fails_when_openai_not_configured() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openai = None;
        let result = OpenAIProvider::new(&provider);
        let err = result.err().expect("should fail when openai is None");
        assert!(err.to_string().contains("OpenAI not configured"));
    }
}
