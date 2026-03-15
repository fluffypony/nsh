use std::collections::BTreeMap;

use crate::model_defaults;

use super::detect::DetectedKey;

pub(crate) struct ProviderModels {
    pub(crate) main: Vec<String>,
    pub(crate) fast: Vec<String>,
    pub(crate) coding: Vec<String>,
    pub(crate) default_model: String,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ProviderKind {
    Byok,
    Subscription,
    Manual,
}

#[derive(Debug, Clone)]
pub(crate) struct ProviderOption {
    pub(crate) id: String,
    pub(crate) display_name: String,
    pub(crate) kind: ProviderKind,
    pub(crate) detected_key: Option<DetectedKey>,
    pub(crate) requires_cliproxyapi: bool,
    pub(crate) native_base_url: Option<String>,
}

pub(crate) const CLIPROXY_BACKED: &[&str] = &[
    "copilot",
    "kiro",
    "qwen",
    "iflow",
    "claude_sub",
    "codex_sub",
    "gemini_sub",
];

pub(crate) fn build_provider_options(detected_keys: &[DetectedKey]) -> Vec<ProviderOption> {
    let mut by_provider: BTreeMap<String, Vec<&DetectedKey>> = BTreeMap::new();
    for key in detected_keys {
        by_provider
            .entry(key.provider.clone())
            .or_default()
            .push(key);
    }

    let mut options = vec![
        ProviderOption {
            id: "openrouter".into(),
            display_name: "OpenRouter (BYOK)".into(),
            kind: ProviderKind::Byok,
            detected_key: by_provider
                .get("openrouter")
                .and_then(|values| values.first())
                .cloned()
                .cloned(),
            requires_cliproxyapi: false,
            native_base_url: Some("https://openrouter.ai/api/v1".into()),
        },
        ProviderOption {
            id: "anthropic".into(),
            display_name: "Anthropic (BYOK)".into(),
            kind: ProviderKind::Byok,
            detected_key: by_provider
                .get("anthropic")
                .and_then(|values| values.first())
                .cloned()
                .cloned(),
            requires_cliproxyapi: false,
            native_base_url: Some("https://api.anthropic.com".into()),
        },
        ProviderOption {
            id: "openai".into(),
            display_name: "OpenAI (BYOK)".into(),
            kind: ProviderKind::Byok,
            detected_key: by_provider
                .get("openai")
                .and_then(|values| values.first())
                .cloned()
                .cloned(),
            requires_cliproxyapi: false,
            native_base_url: Some("https://api.openai.com/v1".into()),
        },
        ProviderOption {
            id: "gemini".into(),
            display_name: "Gemini (BYOK)".into(),
            kind: ProviderKind::Byok,
            detected_key: by_provider
                .get("gemini")
                .and_then(|values| values.first())
                .cloned()
                .cloned(),
            requires_cliproxyapi: false,
            native_base_url: Some("https://generativelanguage.googleapis.com/v1beta/openai".into()),
        },
        ProviderOption {
            id: "manual".into(),
            display_name: "I'll configure my own".into(),
            kind: ProviderKind::Manual,
            detected_key: None,
            requires_cliproxyapi: false,
            native_base_url: None,
        },
    ];

    for provider_id in [
        "copilot",
        "claude_sub",
        "codex_sub",
        "gemini_sub",
        "kiro",
        "qwen",
        "iflow",
    ] {
        if by_provider.contains_key(provider_id) {
            options.insert(
                0,
                ProviderOption {
                    id: provider_id.into(),
                    display_name: format!("{provider_id} (subscription)"),
                    kind: ProviderKind::Subscription,
                    detected_key: by_provider
                        .get(provider_id)
                        .and_then(|values| values.first())
                        .cloned()
                        .cloned(),
                    requires_cliproxyapi: true,
                    native_base_url: None,
                },
            );
        }
    }

    let oauth = crate::cliproxyapi::detect_existing_oauth_tokens();
    for token in oauth {
        if !options.iter().any(|option| option.id == token.provider) {
            options.insert(
                0,
                ProviderOption {
                    id: token.provider.clone(),
                    display_name: format!("{} (subscription)", token.provider),
                    kind: ProviderKind::Subscription,
                    detected_key: Some(DetectedKey {
                        provider: token.provider,
                        key: "oauth:token".into(),
                        source: token.source,
                    }),
                    requires_cliproxyapi: true,
                    native_base_url: None,
                },
            );
        }
    }

    options
}

pub(crate) fn models_for_provider(provider: &str) -> ProviderModels {
    let defaults = model_defaults::provider_models(provider);
    ProviderModels {
        main: model_defaults::to_vec(defaults.main),
        fast: model_defaults::to_vec(defaults.fast),
        coding: model_defaults::to_vec(defaults.coding),
        default_model: defaults.default_model.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    #[test]
    #[serial]
    fn build_provider_options_includes_defaults_without_detected_keys() {
        let home = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _xdg_config = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let options = build_provider_options(&[]);
        let ids: Vec<&str> = options.iter().map(|option| option.id.as_str()).collect();

        assert!(ids.contains(&"openrouter"));
        assert!(ids.contains(&"anthropic"));
        assert!(ids.contains(&"openai"));
        assert!(ids.contains(&"gemini"));
        assert!(ids.contains(&"manual"));
    }

    #[test]
    #[serial]
    fn build_provider_options_promotes_detected_subscription() {
        let home = tempfile::tempdir().unwrap();
        let _home = EnvVarGuard::set("HOME", home.path());
        let _xdg_config = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let _xdg_data = EnvVarGuard::remove("XDG_DATA_HOME");

        let options = build_provider_options(&[DetectedKey {
            provider: "copilot".into(),
            key: "oauth:github-copilot".into(),
            source: "fixture".into(),
        }]);

        assert_eq!(options[0].id, "copilot");
        assert_eq!(options[0].kind, ProviderKind::Subscription);
        assert!(options[0].requires_cliproxyapi);
    }

    #[test]
    fn models_for_provider_returns_expected_defaults() {
        let models = models_for_provider("openrouter");

        assert!(!models.main.is_empty());
        assert!(!models.fast.is_empty());
        assert!(!models.coding.is_empty());
        assert_eq!(
            models.default_model,
            crate::model_defaults::provider_models("openrouter").default_model
        );
    }
}
