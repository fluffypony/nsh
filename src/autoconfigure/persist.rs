use anyhow::Result;

use super::detect::DetectedKey;
use super::options::{CLIPROXY_BACKED, ProviderKind, ProviderModels, ProviderOption};

pub(crate) fn save_config_routing(
    chosen_provider: &str,
    chosen_key: &str,
    models: &ProviderModels,
    execution_mode: &str,
    _all_keys: &[DetectedKey],
    all_options: &[ProviderOption],
) -> Result<()> {
    let config_path = crate::config::Config::path();
    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };
    let mut doc: toml_edit::DocumentMut = if content.is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        content.parse::<toml_edit::DocumentMut>()?
    };

    ensure_table(&mut doc, "provider");
    doc["provider"]["default"] = toml_edit::value(chosen_provider);
    doc["provider"]["model"] = toml_edit::value(&models.default_model);
    doc["provider"]["timeout_seconds"] = toml_edit::value(60i64);

    ensure_table(&mut doc, "models");
    doc["models"]["main"] = toml_edit::value(to_toml_array(&models.main));
    doc["models"]["fast"] = toml_edit::value(to_toml_array(&models.fast));
    doc["models"]["coding"] = toml_edit::value(to_toml_array(&models.coding));

    ensure_table(&mut doc, "execution");
    doc["execution"]["mode"] = toml_edit::value(execution_mode);

    ensure_table(&mut doc, "provider_routing");
    let via_sidecar = CLIPROXY_BACKED.contains(&chosen_provider);
    doc["provider_routing"]["active"] = toml_edit::value(chosen_provider);
    doc["provider_routing"]["via_cliproxy"] = toml_edit::value(via_sidecar);

    if via_sidecar {
        ensure_table(&mut doc, "cliproxyapi");
        doc["cliproxyapi"]["enabled"] = toml_edit::value(true);
        doc["cliproxyapi"]["auto_start"] = toml_edit::value(true);
        doc["cliproxyapi"]["auto_update"] = toml_edit::value(true);
    }

    if doc["provider"].get(chosen_provider).is_none() {
        doc["provider"][chosen_provider] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if via_sidecar {
        let base_url = crate::provider::openai_compat::cliproxyapi_base_url();
        doc["provider"][chosen_provider]["base_url"] = toml_edit::value(base_url);
        doc["provider"][chosen_provider]["api_key"] = toml_edit::value("nsh-internal");
    } else if !chosen_key.is_empty() {
        doc["provider"][chosen_provider]["api_key"] = toml_edit::value(chosen_key);
        if let Some(option) = all_options.iter().find(|option| option.id == chosen_provider)
            && let Some(url) = &option.native_base_url {
                doc["provider"][chosen_provider]["base_url"] = toml_edit::value(url.as_str());
            }
    }

    let mut configured = vec![chosen_provider.to_string()];
    for option in all_options {
        if option.id == chosen_provider || option.kind == ProviderKind::Manual {
            continue;
        }
        if option.detected_key.is_none() && !option.requires_cliproxyapi {
            continue;
        }
        configured.push(option.id.clone());
        if doc["provider"].get(&option.id).is_none() {
            doc["provider"][&option.id] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if option.requires_cliproxyapi {
            let base_url = crate::provider::openai_compat::cliproxyapi_base_url();
            doc["provider"][&option.id]["base_url"] = toml_edit::value(base_url);
            doc["provider"][&option.id]["api_key"] = toml_edit::value("nsh-internal");
        } else if let Some(key) = &option.detected_key {
            doc["provider"][&option.id]["api_key"] = toml_edit::value(&key.key);
            if let Some(url) = &option.native_base_url {
                doc["provider"][&option.id]["base_url"] = toml_edit::value(url.as_str());
            }
        }
        let models = super::options::models_for_provider(&option.id);
        doc["provider"][&option.id]["model"] = toml_edit::value(&models.default_model);
    }

    let mut configured_array = toml_edit::Array::new();
    for configured_provider in configured {
        configured_array.push(configured_provider.as_str());
    }
    doc["provider_routing"]["configured_providers"] = toml_edit::value(configured_array);

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp_path = config_path.with_extension("tmp");
    std::fs::write(&tmp_path, doc.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    std::fs::rename(&tmp_path, &config_path)?;
    Ok(())
}

pub(crate) fn ensure_table(doc: &mut toml_edit::DocumentMut, key: &str) {
    if doc.get(key).is_none() {
        doc[key] = toml_edit::Item::Table(toml_edit::Table::new());
    }
}

pub(crate) fn to_toml_array(items: &[String]) -> toml_edit::Array {
    let mut array = toml_edit::Array::new();
    for item in items {
        array.push(item.as_str());
    }
    array
}

pub(crate) fn save_config(
    provider: &str,
    api_key: &str,
    models: &ProviderModels,
    execution_mode: &str,
) -> Result<()> {
    let config_path = crate::config::Config::path();

    let content = if config_path.exists() {
        std::fs::read_to_string(&config_path)?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = if content.is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        content.parse::<toml_edit::DocumentMut>()?
    };

    ensure_table(&mut doc, "provider");
    doc["provider"]["default"] = toml_edit::value(provider);
    doc["provider"]["model"] = toml_edit::value(&models.default_model);

    if doc["provider"].get(provider).is_none() {
        doc["provider"][provider] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    doc["provider"][provider]["api_key"] = toml_edit::value(api_key);

    match provider {
        "openrouter" => {
            doc["provider"][provider]["base_url"] =
                toml_edit::value("https://openrouter.ai/api/v1");
        }
        "anthropic" => {
            doc["provider"][provider]["base_url"] = toml_edit::value("https://api.anthropic.com");
        }
        "openai" => {
            doc["provider"][provider]["base_url"] = toml_edit::value("https://api.openai.com/v1");
        }
        "gemini" => {
            doc["provider"][provider]["base_url"] =
                toml_edit::value("https://generativelanguage.googleapis.com/v1beta");
        }
        _ => {}
    }

    ensure_table(&mut doc, "models");
    doc["models"]["main"] = toml_edit::value(to_toml_array(&models.main));
    doc["models"]["fast"] = toml_edit::value(to_toml_array(&models.fast));
    doc["models"]["coding"] = toml_edit::value(to_toml_array(&models.coding));

    ensure_table(&mut doc, "execution");
    doc["execution"]["mode"] = toml_edit::value(execution_mode);

    let should_seed_memory = match doc.get("memory") {
        None => true,
        Some(item) => !item.is_table() && !item.is_table_like(),
    };
    if should_seed_memory {
        doc.remove("memory");
        ensure_table(&mut doc, "memory");
        doc["memory"]["enabled"] = toml_edit::value(true);
        doc["memory"]["fade_after_days"] = toml_edit::value(30i64);
        doc["memory"]["expire_after_days"] = toml_edit::value(90i64);
        doc["memory"]["max_retrieval_per_type"] = toml_edit::value(10i64);
        doc["memory"]["reflection_interval_hours"] = toml_edit::value(24i64);
        doc["memory"]["incognito"] = toml_edit::value(false);
    }

    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let tmp_path = config_path.with_extension("tmp");
    std::fs::write(&tmp_path, doc.to_string())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }

    std::fs::rename(&tmp_path, &config_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    fn temp_home_env() -> (tempfile::TempDir, EnvVarGuard, EnvVarGuard, EnvVarGuard) {
        let home = tempfile::tempdir().unwrap();
        let home_guard = EnvVarGuard::set("HOME", home.path());
        let xdg_config_guard = EnvVarGuard::remove("XDG_CONFIG_HOME");
        let xdg_data_guard = EnvVarGuard::remove("XDG_DATA_HOME");
        (home, home_guard, xdg_config_guard, xdg_data_guard)
    }

    #[test]
    fn ensure_table_creates_missing_table() {
        let mut doc = toml_edit::DocumentMut::new();

        ensure_table(&mut doc, "provider");

        assert!(doc["provider"].is_table());
    }

    #[test]
    fn to_toml_array_preserves_order() {
        let array = to_toml_array(&["a".into(), "b".into(), "c".into()]);

        assert_eq!(array.iter().map(|v| v.as_str().unwrap()).collect::<Vec<_>>(), vec!["a", "b", "c"]);
    }

    #[test]
    #[serial]
    fn save_config_writes_provider_and_models() {
        let (_home, _home_guard, _xdg_config_guard, _xdg_data_guard) = temp_home_env();
        let models = crate::autoconfigure::options::models_for_provider("openrouter");

        save_config("openrouter", "test-key", &models, "normal").unwrap();

        let content = std::fs::read_to_string(crate::config::Config::path()).unwrap();
        assert!(content.contains("default = \"openrouter\""));
        assert!(content.contains("api_key = \"test-key\""));
        assert!(content.contains("mode = \"normal\""));
    }
}
