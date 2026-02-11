use super::openai_compat::OpenAICompatProvider;
use crate::provider::*;

pub struct OpenAIProvider(OpenAICompatProvider);

impl OpenAIProvider {
    pub fn new(config: &crate::config::Config) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .openai
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("OpenAI not configured"))?;
        Ok(Self(OpenAICompatProvider::new(
            auth.resolve_api_key("openai")?,
            auth.base_url
                .clone()
                .unwrap_or_else(|| "https://api.openai.com/v1".into()),
            config.provider.fallback_model.clone(),
            vec![],
            config.provider.timeout_seconds,
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
        let mut config = crate::config::Config::default();
        config.provider.openai = None;
        let result = OpenAIProvider::new(&config);
        let err = result.err().expect("should fail when openai is None");
        assert!(err.to_string().contains("OpenAI not configured"));
    }
}
