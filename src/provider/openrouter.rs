use super::openai_compat::OpenAICompatProviderConfig;
use crate::config::ProviderConfig;
pub fn build_openrouter_compat_config(
    provider: &ProviderConfig,
) -> anyhow::Result<OpenAICompatProviderConfig> {
    let auth = provider
        .openrouter
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OpenRouter not configured"))?;
    Ok(OpenAICompatProviderConfig {
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
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_fails_when_openrouter_not_configured() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openrouter = None;
        let result = build_openrouter_compat_config(&provider);
        let err = result.err().expect("should fail when openrouter is None");
        assert!(err.to_string().contains("OpenRouter not configured"));
    }

    #[test]
    fn build_config_uses_custom_base_url_when_provided() {
        let mut provider = crate::config::ProviderConfig::default();
        provider.openrouter = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: Some("https://custom.example.com/v1".into()),
        });
        let cfg = build_openrouter_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://custom.example.com/v1");
        assert_eq!(cfg.debug_provider_name, "openrouter");
    }
}
