use super::openai_compat::OpenAICompatProviderConfig;
use crate::config::ProviderConfig;

pub fn build_openai_compat_config(
    provider: &ProviderConfig,
) -> anyhow::Result<OpenAICompatProviderConfig> {
    let auth = provider
        .openai
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OpenAI not configured"))?;
    Ok(OpenAICompatProviderConfig {
        api_key: auth.resolve_api_key("openai")?,
        base_url: auth
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.openai.com/v1".into()),
        fallback_model: provider.fallback_model.clone(),
        extra_headers: vec![],
        timeout_seconds: provider.timeout_seconds,
        debug_provider_name: "openai".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_fails_when_openai_not_configured() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openai = None;
        let result = build_openai_compat_config(&provider);
        let err = result.err().expect("should fail when openai is None");
        assert!(err.to_string().contains("OpenAI not configured"));
    }

    #[test]
    fn build_config_uses_default_base_url() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openai = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let cfg = build_openai_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://api.openai.com/v1");
        assert_eq!(cfg.debug_provider_name, "openai");
    }
}
