mod detect;
mod options;
mod persist;

use anyhow::Result;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};

use detect::{DetectedKey, detect_api_keys, mask_key};
use options::{ProviderKind, ProviderOption, build_provider_options, models_for_provider};
use persist::{save_config, save_config_routing};

fn run_interactive_flow(
    options: &[ProviderOption],
    keys: &[DetectedKey],
) -> Result<(ProviderOption, String)> {
    loop {
        eprintln!("Choose your LLM provider:\n");
        for (index, option) in options.iter().enumerate() {
            let status = option
                .detected_key
                .as_ref()
                .map(|key| format!(" ✓ {}", mask_key(&key.key)))
                .unwrap_or_default();
            eprintln!(
                "  \x1b[1m{:>2}\x1b[0m) {}{}",
                index + 1,
                option.display_name,
                status
            );
        }

        let selection = prompt_choice("Select", options.len(), Some(0))?;
        let chosen = options[selection].clone();
        if chosen.kind == ProviderKind::Manual {
            return Ok((chosen, String::new()));
        }

        let provider_keys: Vec<&DetectedKey> =
            keys.iter().filter(|key| key.provider == chosen.id).collect();
        if chosen.kind == ProviderKind::Subscription && provider_keys.is_empty() {
            if !crate::cliproxyapi::is_installed() {
                eprintln!(
                    "\x1b[33mCLIProxyAPI binary not found. Try again shortly or choose another option.\x1b[0m\n"
                );
                continue;
            }
            eprintln!("Starting OAuth login for {}...", chosen.display_name);
            match crate::cliproxyapi::run_oauth_login(&chosen.id) {
                Ok(true) => {
                    let port = crate::cliproxyapi::ensure_running().unwrap_or(8317);
                    let models = models_for_provider(&chosen.id);
                    let test_model = models.fast.first().unwrap_or(&models.default_model).clone();
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    if let Ok(runtime) = runtime {
                        let ok = runtime.block_on(async move {
                            crate::cliproxyapi::test_provider(port, &test_model)
                                .await
                                .unwrap_or(false)
                        });
                        if !ok {
                            eprintln!(
                                "\x1b[33mProvider test failed after login. Choose another option.\x1b[0m\n"
                            );
                            continue;
                        }
                    }
                    return Ok((chosen, "nsh-internal".to_string()));
                }
                _ => {
                    eprintln!("\x1b[33mLogin failed or cancelled. Choose another option.\x1b[0m\n");
                    continue;
                }
            }
        }

        let key = if provider_keys.is_empty() {
            if chosen.kind == ProviderKind::Byok {
                eprint!("Enter your {} API key: ", chosen.display_name);
                io::stderr().flush()?;
                read_line_from_tty()?
            } else {
                "nsh-internal".to_string()
            }
        } else if provider_keys.len() == 1 {
            provider_keys[0].key.clone()
        } else {
            eprintln!("Multiple keys found. Choose one:");
            for (index, key) in provider_keys.iter().enumerate() {
                eprintln!(
                    "  \x1b[1m{}\x1b[0m) {} (from {})",
                    index + 1,
                    mask_key(&key.key),
                    key.source
                );
            }
            let key_choice = prompt_choice("Select key", provider_keys.len(), Some(0))?;
            provider_keys[key_choice].key.clone()
        };
        return Ok((chosen, key));
    }
}

fn run_noninteractive_pick(options: &[ProviderOption]) -> Option<(ProviderOption, String)> {
    for option in options {
        if let Some(key) = &option.detected_key {
            return Some((option.clone(), key.key.clone()));
        }
        if option.requires_cliproxyapi {
            return Some((option.clone(), "nsh-internal".into()));
        }
    }
    None
}

fn legacy_noninteractive_flow(keys: Vec<DetectedKey>) -> Result<()> {
    if keys.is_empty() {
        eprintln!("\x1b[33mNo API keys found.\x1b[0m\n");
        eprintln!(
            "You can set one of these environment variables:\n  export OPENROUTER_API_KEY=...\n  export ANTHROPIC_API_KEY=...\n  export OPENAI_API_KEY=...\n"
        );
        eprintln!("Or edit the config manually: \x1b[1mnsh config edit\x1b[0m");
        return Ok(());
    }

    let mut by_provider: BTreeMap<String, Vec<&DetectedKey>> = BTreeMap::new();
    for key in &keys {
        by_provider.entry(key.provider.clone()).or_default().push(key);
    }

    let (provider, provider_keys) = if by_provider.len() == 1 {
        by_provider.into_iter().next().unwrap()
    } else {
        let providers: Vec<String> = by_provider.keys().cloned().collect();
        eprintln!("Choose a provider:");
        for (index, provider) in providers.iter().enumerate() {
            eprintln!("  \x1b[1m{}\x1b[0m) {}", index + 1, provider);
        }
        let choice = prompt_choice("Select", providers.len(), Some(0))?;
        let provider = providers[choice].clone();
        (provider, by_provider[providers[choice].as_str()].clone())
    };

    let chosen_key = if provider_keys.len() == 1 {
        provider_keys[0].key.clone()
    } else {
        eprintln!("Multiple keys found for {provider}. Choose one:");
        for (index, key) in provider_keys.iter().enumerate() {
            eprintln!(
                "  \x1b[1m{}\x1b[0m) {} (from {})",
                index + 1,
                mask_key(&key.key),
                key.source
            );
        }
        let choice = prompt_choice("Select key", provider_keys.len(), Some(0))?;
        provider_keys[choice].key.clone()
    };

    let models = models_for_provider(&provider);
    save_config(&provider, &chosen_key, &models, "prefill")
}

fn read_line_from_tty() -> Result<String> {
    let mut input = String::new();
    #[cfg(unix)]
    {
        if let Ok(tty) = std::fs::File::open("/dev/tty") {
            let mut reader = io::BufReader::new(tty);
            reader.read_line(&mut input)?;
            return Ok(input.trim().to_string());
        }
    }
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}

fn prompt_choice(prompt: &str, max: usize, default: Option<usize>) -> Result<usize> {
    loop {
        let default_str = default.map_or(String::new(), |default| format!(" [{}]", default + 1));
        eprint!("{prompt}{default_str}: ");
        io::stderr().flush()?;

        let input = read_line_from_tty()?;
        if input.is_empty() {
            if let Some(default) = default {
                return Ok(default);
            }
            continue;
        }

        match input.parse::<usize>() {
            Ok(number) if number >= 1 && number <= max => return Ok(number - 1),
            _ => eprintln!("  Please enter a number between 1 and {max}"),
        }
    }
}

pub fn run_autoconfigure(interactive: bool) -> Result<()> {
    eprintln!("\x1b[1mnsh autoconfigure\x1b[0m");
    eprintln!("Scanning for API keys and subscriptions...\n");

    let keys = detect_api_keys();
    let options = build_provider_options(&keys);

    if interactive {
        let (option, key) = run_interactive_flow(&options, &keys)?;
        eprintln!(
            "How should nsh handle suggested commands?\n  \x1b[1m1\x1b[0m) prefill\n  \x1b[1m2\x1b[0m) confirm\n  \x1b[1m3\x1b[0m) autorun"
        );
        let mode_choice = prompt_choice("Select", 3, Some(0))?;
        let execution_mode = match mode_choice {
            0 => "prefill",
            1 => "confirm",
            2 => "autorun",
            _ => "prefill",
        };
        let models = models_for_provider(&option.id);
        save_config_routing(&option.id, &key, &models, execution_mode, &keys, &options)?;
        eprintln!("\x1b[32m✓ nsh configured successfully!\x1b[0m");
        eprintln!("  Provider: \x1b[1m{}\x1b[0m", option.display_name);
        eprintln!("  Model: \x1b[1m{}\x1b[0m", models.default_model);
        return Ok(());
    }

    match run_noninteractive_pick(&options) {
        Some((option, key)) => {
            let models = models_for_provider(&option.id);
            save_config_routing(&option.id, &key, &models, "prefill", &keys, &options)?;
            eprintln!("\x1b[32m✓ nsh configured successfully!\x1b[0m");
            eprintln!("  Provider: \x1b[1m{}\x1b[0m", option.display_name);
            eprintln!("  Model: \x1b[1m{}\x1b[0m", models.default_model);
            Ok(())
        }
        None => legacy_noninteractive_flow(keys),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autoconfigure::persist::{ensure_table, to_toml_array};

    #[test]
    fn mask_key_long() {
        assert_eq!(mask_key("sk-or-v1-abcdefghijklmnop"), "sk-or-v1...mnop");
    }

    #[test]
    fn mask_key_short() {
        assert_eq!(mask_key("short"), "****");
    }

    #[test]
    fn models_for_known_providers() {
        let models = models_for_provider("openrouter");
        assert!(!models.main.is_empty());
        assert!(!models.fast.is_empty());
        assert!(!models.coding.is_empty());
        assert!(!models.default_model.is_empty());

        let models = models_for_provider("anthropic");
        assert!(models.default_model.contains("claude"));

        let models = models_for_provider("openai");
        assert!(models.default_model.contains("gpt"));

        let models = models_for_provider("gemini");
        assert!(models.default_model.contains("gemini"));
    }

    #[test]
    fn models_for_unknown_provider() {
        let models = models_for_provider("unknown");
        assert!(!models.main.is_empty());
    }

    #[test]
    fn to_toml_array_creates_array() {
        let array = to_toml_array(&["a".into(), "b".into()]);
        assert_eq!(array.len(), 2);
    }

    #[test]
    fn save_config_creates_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".nsh/config.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();

        let models = models_for_provider("openrouter");
        let mut doc = toml_edit::DocumentMut::new();
        ensure_table(&mut doc, "provider");
        doc["provider"]["default"] = toml_edit::value("openrouter");
        doc["provider"]["model"] = toml_edit::value(&models.default_model);
        ensure_table(&mut doc, "models");
        doc["models"]["main"] = toml_edit::value(to_toml_array(&models.main));

        let content = doc.to_string();
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        assert_eq!(
            parsed["provider"]["default"].as_str().unwrap(),
            "openrouter"
        );
    }

    #[test]
    fn save_config_seeds_memory_defaults() {
        let models = models_for_provider("openrouter");
        let mut doc = toml_edit::DocumentMut::new();

        assert!(doc.get("memory").is_none());
        ensure_table(&mut doc, "memory");
        doc["memory"]["enabled"] = toml_edit::value(true);
        doc["memory"]["fade_after_days"] = toml_edit::value(30i64);
        doc["memory"]["expire_after_days"] = toml_edit::value(90i64);
        doc["memory"]["max_retrieval_per_type"] = toml_edit::value(10i64);
        doc["memory"]["reflection_interval_hours"] = toml_edit::value(24i64);
        doc["memory"]["incognito"] = toml_edit::value(false);

        ensure_table(&mut doc, "provider");
        doc["provider"]["default"] = toml_edit::value("openrouter");
        doc["provider"]["model"] = toml_edit::value(&models.default_model);

        let content = doc.to_string();
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        let memory = parsed.get("memory").expect("memory section exists");
        assert_eq!(memory["enabled"].as_bool(), Some(true));
        assert_eq!(memory["fade_after_days"].as_integer(), Some(30));
        assert_eq!(memory["expire_after_days"].as_integer(), Some(90));
        assert_eq!(memory["max_retrieval_per_type"].as_integer(), Some(10));
        assert_eq!(memory["reflection_interval_hours"].as_integer(), Some(24));
        assert_eq!(memory["incognito"].as_bool(), Some(false));
    }

    #[test]
    fn save_config_preserves_existing_memory_section() {
        let existing = r#"
[provider]
default = "openrouter"

[memory]
enabled = false
fade_after_days = 60
"#;
        let mut doc: toml_edit::DocumentMut = existing.parse().unwrap();

        if doc.get("memory").is_none() {
            ensure_table(&mut doc, "memory");
            doc["memory"]["enabled"] = toml_edit::value(true);
            doc["memory"]["fade_after_days"] = toml_edit::value(30i64);
        }

        let content = doc.to_string();
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        let memory = parsed.get("memory").expect("memory section exists");
        assert_eq!(memory["enabled"].as_bool(), Some(false));
        assert_eq!(memory["fade_after_days"].as_integer(), Some(60));
    }

    #[test]
    fn detect_api_keys_returns_vec() {
        let keys = detect_api_keys();
        let _ = keys.len();
    }
}
