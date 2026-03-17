use super::openai_compat::OpenAICompatProviderConfig;
use crate::config::ProviderAuth;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportHint {
    pub base_url: String,
    pub strip_provider_prefix: bool,
}

pub fn model_name_for_transport(original_model: &str, strip_provider_prefix: bool) -> String {
    if strip_provider_prefix && let Some((_, plain)) = original_model.split_once('/') {
        return plain.to_string();
    }
    original_model.to_string()
}

pub fn transport_hint_from_openai_config(config: &OpenAICompatProviderConfig) -> TransportHint {
    TransportHint {
        base_url: config.base_url.clone(),
        strip_provider_prefix: config.strip_provider_prefix,
    }
}

pub fn resolve_openai_compat_config(
    provider_name: &str,
    config: &super::ProviderFactoryConfig,
) -> anyhow::Result<Option<OpenAICompatProviderConfig>> {
    let cfg = match provider_name {
        "openrouter" => {
            return Ok(Some(super::openrouter::build_openrouter_compat_config(
                &config.provider,
            )?));
        }
        "openai" => {
            return Ok(Some(super::openai::build_openai_compat_config(
                &config.provider,
            )?));
        }
        "gemini" => {
            let auth = config
                .provider
                .gemini
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Gemini not configured"))?;
            OpenAICompatProviderConfig {
                api_key: auth.resolve_api_key("gemini")?,
                base_url: "https://generativelanguage.googleapis.com/v1beta/openai".into(),
                strip_provider_prefix: false,
                fallback_model: None,
                extra_headers: vec![],
                timeout_seconds: config.provider.timeout_seconds,
                debug_provider_name: "gemini".to_string(),
            }
        }
        "ollama" => {
            let auth = config.provider.ollama.as_ref();
            let base_url = auth
                .and_then(|a| a.base_url.clone())
                .unwrap_or_else(|| "http://localhost:11434/v1".into());
            let api_key = auth
                .and_then(|a| a.resolve_api_key("ollama").ok())
                .unwrap_or_else(|| zeroize::Zeroizing::new("ollama".into()));
            OpenAICompatProviderConfig {
                api_key,
                base_url,
                strip_provider_prefix: false,
                fallback_model: config.provider.fallback_model.clone(),
                extra_headers: vec![],
                timeout_seconds: config.provider.timeout_seconds,
                debug_provider_name: "ollama".to_string(),
            }
        }
        "copilot" | "kiro" | "qwen" | "iflow" | "claude_sub" | "codex_sub" | "gemini_sub" => {
            OpenAICompatProviderConfig {
                api_key: zeroize::Zeroizing::new("nsh-internal".into()),
                base_url: config.cliproxy_base_url.clone(),
                strip_provider_prefix: true,
                fallback_model: config.provider.fallback_model.clone(),
                extra_headers: vec![],
                timeout_seconds: config.provider.timeout_seconds,
                debug_provider_name: provider_name.to_string(),
            }
        }
        "z_ai" | "minimax" | "kimi" | "deepseek" => {
            let auth = provider_auth(provider_name, &config.provider);
            let (transport, api_key) =
                resolve_byok_or_sidecar(provider_name, auth, &config.cliproxy_base_url)?;
            OpenAICompatProviderConfig {
                api_key,
                base_url: transport.base_url,
                strip_provider_prefix: transport.strip_provider_prefix,
                fallback_model: config.provider.fallback_model.clone(),
                extra_headers: vec![],
                timeout_seconds: config.provider.timeout_seconds,
                debug_provider_name: provider_name.to_string(),
            }
        }
        _ => return Ok(None),
    };

    Ok(Some(cfg))
}

fn provider_auth<'a>(
    provider_name: &str,
    provider: &'a crate::config::ProviderConfig,
) -> Option<&'a ProviderAuth> {
    match provider_name {
        "z_ai" => provider.z_ai.as_ref(),
        "minimax" => provider.minimax.as_ref(),
        "kimi" => provider.kimi.as_ref(),
        "deepseek" => provider.deepseek.as_ref(),
        _ => None,
    }
}

fn resolve_byok_or_sidecar(
    provider_name: &str,
    auth: Option<&ProviderAuth>,
    cliproxy_base_url: &str,
) -> anyhow::Result<(TransportHint, zeroize::Zeroizing<String>)> {
    if let Some(a) = auth {
        let k = a.resolve_api_key(provider_name)?;
        let url = a.base_url.clone().unwrap_or_else(|| match provider_name {
            "z_ai" => "https://api.x.ai/v1".into(),
            "minimax" => "https://api.minimaxi.chat/v1".into(),
            "kimi" => "https://api.moonshot.cn/v1".into(),
            "deepseek" => "https://api.deepseek.com/v1".into(),
            _ => "https://api.openai.com/v1".into(),
        });
        return Ok((
            TransportHint {
                base_url: url,
                strip_provider_prefix: false,
            },
            k,
        ));
    }
    Ok((
        TransportHint {
            base_url: cliproxy_base_url.to_string(),
            strip_provider_prefix: true,
        },
        zeroize::Zeroizing::new("nsh-internal".into()),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_from(config: crate::config::Config) -> crate::provider::ProviderFactoryConfig {
        crate::provider::bootstrap::provider_factory_config(&config)
    }

    #[test]
    fn resolve_openai_compat_config_returns_none_for_anthropic() {
        let mut config = crate::config::Config::default();
        config.provider.anthropic = Some(crate::config::ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let cfg = cfg_from(config);

        let resolved =
            resolve_openai_compat_config("anthropic", &cfg).expect("resolve should succeed");
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_openai_compat_config_returns_none_for_unknown() {
        let cfg = cfg_from(crate::config::Config::default());
        let resolved =
            resolve_openai_compat_config("unknown-provider", &cfg).expect("resolve should succeed");
        assert!(resolved.is_none());
    }

    #[test]
    fn resolve_openai_compat_config_byok_with_api_key_uses_provider_url() {
        let mut config = crate::config::Config::default();
        config.provider.z_ai = Some(crate::config::ProviderAuth {
            api_key: Some("zai-key".into()),
            api_key_cmd: None,
            base_url: Some("https://custom.zai/v1".into()),
        });
        let cfg = cfg_from(config);

        let resolved = resolve_openai_compat_config("z_ai", &cfg)
            .expect("resolve should succeed")
            .expect("config should resolve");
        assert_eq!(resolved.base_url, "https://custom.zai/v1");
    }

    #[test]
    fn resolve_openai_compat_config_byok_without_auth_falls_back_to_sidecar() {
        let mut config = crate::config::Config::default();
        config.provider.deepseek = None;
        let cfg = cfg_from(config);

        let resolved = resolve_openai_compat_config("deepseek", &cfg)
            .expect("resolve should succeed")
            .expect("config should resolve");
        assert_eq!(resolved.base_url, cfg.cliproxy_base_url);
        assert!(resolved.strip_provider_prefix);
    }

    #[test]
    fn resolve_openai_compat_config_byok_with_invalid_key_errors() {
        let mut config = crate::config::Config::default();
        config.provider.kimi = Some(crate::config::ProviderAuth {
            api_key: Some("".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let cfg = cfg_from(config);

        let err = match resolve_openai_compat_config("kimi", &cfg) {
            Ok(_) => panic!("invalid configured BYOK auth should error"),
            Err(err) => err,
        };
        assert!(
            err.to_string().contains("not configured")
                || err.to_string().contains("empty")
                || err.to_string().contains("API key"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn model_name_for_transport_strips_prefix_for_sidecar() {
        assert_eq!(
            model_name_for_transport("anthropic/claude-sonnet-4.6", true),
            "claude-sonnet-4.6"
        );
    }

    #[test]
    fn model_name_for_transport_keeps_model_for_non_sidecar_base() {
        assert_eq!(
            model_name_for_transport("anthropic/claude-sonnet-4.6", false),
            "anthropic/claude-sonnet-4.6"
        );
    }
}
