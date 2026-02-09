use zeroize::Zeroizing;

use crate::provider::*;

pub struct OpenAIProvider {
    client: reqwest::Client,
    api_key: Zeroizing<String>,
    base_url: String,
}

impl OpenAIProvider {
    pub fn new(
        config: &crate::config::Config,
    ) -> anyhow::Result<Self> {
        let auth = config
            .provider
            .openai
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!("OpenAI not configured")
            })?;
        Ok(Self {
            client: reqwest::Client::new(),
            api_key: auth.resolve_api_key()?,
            base_url: auth
                .base_url
                .clone()
                .unwrap_or_else(|| {
                    "https://api.openai.com".into()
                }),
        })
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAIProvider {
    async fn complete(
        &self,
        _request: ChatRequest,
    ) -> anyhow::Result<Message> {
        // TODO: Implement — very similar to OpenRouter since
        // OpenRouter uses the OpenAI-compatible format.
        anyhow::bail!(
            "OpenAI native API not yet implemented. \
             Use OpenRouter with an OpenAI model instead."
        )
    }

    async fn stream(
        &self,
        _request: ChatRequest,
    ) -> anyhow::Result<
        tokio::sync::mpsc::Receiver<StreamEvent>,
    > {
        anyhow::bail!(
            "OpenAI native API not yet implemented. \
             Use OpenRouter with an OpenAI model instead."
        )
    }
}
