use crate::provider::*;

pub struct AnthropicProvider {
    client: reqwest::Client,
    api_key: String,
    base_url: String,
}

impl AnthropicProvider {
    pub fn new(
        config: &crate::config::Config,
    ) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .anthropic
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("Anthropic not configured")
            })?;
        Ok(Self {
            client: reqwest::Client::new(),
            api_key: auth.resolve_api_key()?,
            base_url: auth
                .base_url
                .clone()
                .unwrap_or_else(|| {
                    "https://api.anthropic.com".into()
                }),
        })
    }
}

#[async_trait::async_trait]
impl LlmProvider for AnthropicProvider {
    async fn complete(
        &self,
        _request: ChatRequest,
    ) -> anyhow::Result<Message> {
        // TODO: Implement Anthropic native Messages API
        // POST /v1/messages with anthropic-version header
        anyhow::bail!(
            "Anthropic native API not yet implemented. \
             Use OpenRouter with an Anthropic model instead."
        )
    }

    async fn stream(
        &self,
        _request: ChatRequest,
    ) -> anyhow::Result<
        tokio::sync::mpsc::Receiver<StreamEvent>,
    > {
        anyhow::bail!(
            "Anthropic native API not yet implemented. \
             Use OpenRouter with an Anthropic model instead."
        )
    }
}
