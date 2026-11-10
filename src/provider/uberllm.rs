use super::openai_compat::OpenAICompatProviderConfig;
use crate::config::ProviderConfig;
pub fn build_uberllm_compat_config(
    provider: &ProviderConfig,
) -> anyhow::Result<OpenAICompatProviderConfig> {
    let auth = provider
        .uberllm
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("UberLLM not configured"))?;
    Ok(OpenAICompatProviderConfig {
        api_key: auth.resolve_api_key("uberllm")?,
        base_url: auth
            .base_url
            .clone()
            .unwrap_or_else(|| "https://api.uberllm.dev/v1".into()),
        strip_provider_prefix: false,
        fallback_model: provider.fallback_model.clone(),
        extra_headers: vec![
            (
                "HTTP-Referer".into(),
                "https://github.com/fluffypony/nsh".into(),
            ),
            ("X-Title".into(), "nsh".into()),
        ],
        timeout_seconds: provider.timeout_seconds,
        debug_provider_name: "uberllm".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_fails_when_uberllm_not_configured() {
        let provider = crate::config::ProviderConfig {
            uberllm: None,
            ..Default::default()
        };
        let result = build_uberllm_compat_config(&provider);
        let err = result.err().expect("should fail when uberllm is None");
        assert!(err.to_string().contains("UberLLM not configured"));
    }

    #[test]
    fn build_config_uses_custom_base_url_when_provided() {
        let provider = crate::config::ProviderConfig {
            uberllm: Some(crate::config::ProviderAuth {
                api_key: Some("test-key".into()),
                api_key_cmd: None,
                base_url: Some("https://custom.example.com/v1".into()),
            }),
            ..Default::default()
        };
        let cfg = build_uberllm_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://custom.example.com/v1");
        assert_eq!(cfg.debug_provider_name, "uberllm");
    }

    #[test]
    fn build_config_uses_default_base_url() {
        let provider = crate::config::ProviderConfig {
            uberllm: Some(crate::config::ProviderAuth {
                api_key: Some("test-key".into()),
                api_key_cmd: None,
                base_url: None,
            }),
            ..Default::default()
        };
        let cfg = build_uberllm_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://api.uberllm.dev/v1");
        assert_eq!(cfg.debug_provider_name, "uberllm");
    }
}
