use crate::provider::*;
use super::openai_compat::OpenAICompatProvider;

pub struct OpenAIProvider(OpenAICompatProvider);

impl OpenAIProvider {
    pub fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
        let auth = config.provider.openai.as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenAI not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            auth.resolve_api_key("openai")?,
            auth.base_url.clone().unwrap_or_else(|| "https://api.openai.com/v1".into()),
            config.provider.fallback_model.clone(),
            vec![],
        )?))
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAIProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        self.0.complete(request).await
    }

    async fn stream(&self, request: ChatRequest) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        self.0.stream(request).await
    }
}
