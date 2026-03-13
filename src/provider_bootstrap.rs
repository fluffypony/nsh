pub const DEFAULT_CLIPROXY_BASE_URL: &str = "http://127.0.0.1:8317/v1";

pub fn cliproxy_base_url() -> String {
    crate::cliproxyapi::base_url().unwrap_or_else(|| DEFAULT_CLIPROXY_BASE_URL.to_string())
}

pub fn provider_factory_config(
    config: &crate::config::Config,
) -> crate::provider::ProviderFactoryConfig {
    crate::provider::ProviderFactoryConfig {
        default: config.provider.default.clone(),
        provider: config.provider.clone(),
        cliproxy_base_url: cliproxy_base_url(),
    }
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_CLIPROXY_BASE_URL, cliproxy_base_url, provider_factory_config};
    use crate::config::Config;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    #[test]
    #[serial]
    fn cliproxy_base_url_falls_back_when_no_state_exists() {
        let home = tempfile::tempdir().expect("tempdir");
        let _home_guard = EnvVarGuard::set("HOME", home.path());
        let _xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let _xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");

        assert_eq!(cliproxy_base_url(), DEFAULT_CLIPROXY_BASE_URL);
    }

    #[test]
    fn provider_factory_config_carries_default_and_sidecar_transport() {
        let config = Config::default();
        let factory = provider_factory_config(&config);

        assert_eq!(factory.default, config.provider.default);
        assert!(!factory.cliproxy_base_url.is_empty());
    }
}
