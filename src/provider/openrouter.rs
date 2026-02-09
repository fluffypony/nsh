use crate::provider::*;
use super::openai_compat::OpenAICompatProvider;

pub struct OpenRouterProvider(OpenAICompatProvider);

impl OpenRouterProvider {
    pub fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
        let auth = config.provider.openrouter.as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenRouter not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            auth.resolve_api_key("openrouter")?,
            auth.base_url.clone().unwrap_or_else(|| "https://openrouter.ai/api/v1".into()),
            config.provider.fallback_model.clone(),
            vec![
                ("HTTP-Referer".into(), "https://github.com/fluffypony/nsh".into()),
                ("X-Title".into(), "nsh".into()),
            ],
        )?))
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenRouterProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        self.0.complete(request).await
    }

    async fn stream(&self, request: ChatRequest) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        self.0.stream(request).await
    }
}
