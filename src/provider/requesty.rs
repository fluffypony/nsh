use super::openai_compat::OpenAICompatProviderConfig;
use crate::config::ProviderConfig;
pub fn build_requesty_compat_config(
    provider: &ProviderConfig,
) -> anyhow::Result<OpenAICompatProviderConfig> {
    let auth = provider
        .requesty
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Requesty not configured"))?;
    Ok(OpenAICompatProviderConfig {
        api_key: auth.resolve_api_key("requesty")?,
        base_url: auth
            .base_url
            .clone()
            .unwrap_or_else(|| "https://router.requesty.ai/v1".into()),
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
        debug_provider_name: "requesty".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_config_fails_when_requesty_not_configured() {
        let provider = crate::config::ProviderConfig {
            requesty: None,
            ..Default::default()
        };
        let result = build_requesty_compat_config(&provider);
        let err = result.err().expect("should fail when requesty is None");
        assert!(err.to_string().contains("Requesty not configured"));
    }

    #[test]
    fn build_config_uses_custom_base_url_when_provided() {
        let provider = crate::config::ProviderConfig {
            requesty: Some(crate::config::ProviderAuth {
                api_key: Some("test-key".into()),
                api_key_cmd: None,
                base_url: Some("https://custom.example.com/v1".into()),
            }),
            ..Default::default()
        };
        let cfg = build_requesty_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://custom.example.com/v1");
        assert_eq!(cfg.debug_provider_name, "requesty");
    }

    #[test]
    fn build_config_uses_default_base_url() {
        let provider = crate::config::ProviderConfig {
            requesty: Some(crate::config::ProviderAuth {
                api_key: Some("test-key".into()),
                api_key_cmd: None,
                base_url: None,
            }),
            ..Default::default()
        };
        let cfg = build_requesty_compat_config(&provider).expect("config should build");
        assert_eq!(cfg.base_url, "https://router.requesty.ai/v1");
        assert_eq!(cfg.debug_provider_name, "requesty");
    }
}
