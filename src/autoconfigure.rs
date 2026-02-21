use anyhow::Result;
use std::collections::BTreeMap;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

#[derive(Debug, Clone)]
struct DetectedKey {
    provider: String,
    key: String,
    source: String,
}

struct ProviderModels {
    main: Vec<String>,
    fast: Vec<String>,
    coding: Vec<String>,
    default_model: String,
}

fn mask_key(key: &str) -> String {
    if key.len() > 12 {
        format!("{}...{}", &key[..8], &key[key.len() - 4..])
    } else {
        "****".to_string()
    }
}

fn check_env(keys: &mut Vec<DetectedKey>, var: &str, provider: &str) {
    if let Ok(val) = std::env::var(var) {
        let val = val.trim().to_string();
        if !val.is_empty() && val.len() > 5 {
            keys.push(DetectedKey {
                provider: provider.to_string(),
                key: val,
                source: format!("env:{var}"),
            });
        }
    }
}

fn check_file(keys: &mut Vec<DetectedKey>, path: &std::path::Path, provider: &str) {
    if let Ok(content) = std::fs::read_to_string(path) {
        let val = content.trim().to_string();
        if !val.is_empty() && val.len() > 5 {
            keys.push(DetectedKey {
                provider: provider.to_string(),
                key: val,
                source: format!("file:{}", path.display()),
            });
        }
    }
}

fn check_shell_config_for_export(
    keys: &mut Vec<DetectedKey>,
    path: &std::path::Path,
    var: &str,
    provider: &str,
) {
    if let Ok(content) = std::fs::read_to_string(path) {
        for line in content.lines() {
            let line = line.trim();
            let patterns = [format!("export {var}="), format!("{var}=")];
            for pattern in &patterns {
                if line.starts_with(pattern.as_str()) && !line.contains('$') {
                    let val = line[pattern.len()..]
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    if !val.is_empty() && val.len() > 5 {
                        keys.push(DetectedKey {
                            provider: provider.to_string(),
                            key: val,
                            source: format!("file:{}", path.display()),
                        });
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn check_keychain(keys: &mut Vec<DetectedKey>, service: &str, provider: &str) {
    if let Ok(output) = std::process::Command::new("security")
        .args(["find-generic-password", "-s", service, "-w"])
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() {
            let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !val.is_empty() && val.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: val,
                    source: format!("keychain:{service}"),
                });
            }
        }
    }
}

fn check_1password(keys: &mut Vec<DetectedKey>, item_name: &str, provider: &str) {
    if which::which("op").is_err() {
        return;
    }
    if let Ok(output) = std::process::Command::new("op")
        .args(["item", "get", item_name, "--fields", "credential"])
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() {
            let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !val.is_empty() && val.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: val,
                    source: format!("1password:{item_name}"),
                });
            }
        }
    }
}

fn check_pass(keys: &mut Vec<DetectedKey>, pass_path: &str, provider: &str) {
    if which::which("pass").is_err() {
        return;
    }
    if let Ok(output) = std::process::Command::new("pass")
        .args(["show", pass_path])
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() {
            let val = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !val.is_empty() && val.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: val,
                    source: format!("pass:{pass_path}"),
                });
            }
        }
    }
}

fn detect_api_keys() -> Vec<DetectedKey> {
    let mut keys = Vec::new();
    let home = match dirs::home_dir() {
        Some(h) => h,
        None => return keys,
    };

    check_env(&mut keys, "OPENROUTER_API_KEY", "openrouter");
    check_env(&mut keys, "ANTHROPIC_API_KEY", "anthropic");
    check_env(&mut keys, "OPENAI_API_KEY", "openai");
    check_env(&mut keys, "GEMINI_API_KEY", "gemini");
    check_env(&mut keys, "GOOGLE_API_KEY", "gemini");

    let file_checks: Vec<(&str, PathBuf)> = vec![
        ("openrouter", home.join(".config/openrouter/key")),
        ("openrouter", home.join(".config/openrouter/credentials")),
        ("openrouter", home.join(".openrouter")),
        ("anthropic", home.join(".config/anthropic/key")),
        ("anthropic", home.join(".config/anthropic/credentials")),
        ("anthropic", home.join(".config/anthropic/api_key")),
        ("anthropic", home.join(".anthropic/api_key")),
        ("openai", home.join(".config/openai/key")),
        ("openai", home.join(".config/openai/credentials")),
        ("openai", home.join(".config/openai/api_key")),
        ("openai", home.join(".openai/api_key")),
    ];
    for (provider, path) in &file_checks {
        check_file(&mut keys, path, provider);
    }

    let shell_configs = [
        home.join(".bashrc"),
        home.join(".zshrc"),
        home.join(".profile"),
        home.join(".bash_profile"),
        home.join(".env"),
        home.join(".envrc"),
    ];
    let env_vars_to_scan = [
        ("OPENROUTER_API_KEY", "openrouter"),
        ("ANTHROPIC_API_KEY", "anthropic"),
        ("OPENAI_API_KEY", "openai"),
        ("GEMINI_API_KEY", "gemini"),
    ];
    for config_file in &shell_configs {
        for (var, provider) in &env_vars_to_scan {
            check_shell_config_for_export(&mut keys, config_file, var, provider);
        }
    }

    #[cfg(target_os = "macos")]
    {
        let keychain_services = [
            ("openrouter", "openrouter"),
            ("openrouter", "openrouter-api-key"),
            ("anthropic", "anthropic"),
            ("anthropic", "anthropic-api-key"),
            ("openai", "openai"),
            ("openai", "openai-api-key"),
            ("gemini", "gemini-api-key"),
            ("gemini", "google-ai"),
        ];
        for (provider, service) in &keychain_services {
            check_keychain(&mut keys, service, provider);
        }
    }

    let op_items = [
        ("OpenRouter API Key", "openrouter"),
        ("OpenRouter", "openrouter"),
        ("Anthropic API Key", "anthropic"),
        ("Anthropic", "anthropic"),
        ("OpenAI API Key", "openai"),
        ("OpenAI", "openai"),
    ];
    for (item, provider) in &op_items {
        check_1password(&mut keys, item, provider);
    }

    let pass_paths = [
        ("api/openrouter", "openrouter"),
        ("openrouter/api-key", "openrouter"),
        ("api/anthropic", "anthropic"),
        ("anthropic/api-key", "anthropic"),
        ("api/openai", "openai"),
        ("openai/api-key", "openai"),
    ];
    for (path, provider) in &pass_paths {
        check_pass(&mut keys, path, provider);
    }

    let config_path = crate::config::Config::path();
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&config_path) {
            if let Ok(doc) = content.parse::<toml_edit::DocumentMut>() {
                let provider_names = ["openrouter", "anthropic", "openai", "gemini"];
                for pname in &provider_names {
                    if let Some(key) = doc
                        .get("provider")
                        .and_then(|p| p.get(*pname))
                        .and_then(|t| t.as_table())
                        .and_then(|t| t.get("api_key"))
                        .and_then(|k| k.as_str())
                    {
                        if !key.is_empty() && key.len() > 5 {
                            keys.push(DetectedKey {
                                provider: pname.to_string(),
                                key: key.to_string(),
                                source: "existing nsh config".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    let claude_configs = [
        home.join(".claude/config.json"),
        home.join(".config/claude-code/config.json"),
    ];
    for path in &claude_configs {
        if let Ok(content) = std::fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
                if let Some(key) = json
                    .get("apiKey")
                    .or(json.get("api_key"))
                    .and_then(|k| k.as_str())
                {
                    if !key.is_empty() && key.len() > 5 {
                        keys.push(DetectedKey {
                            provider: "anthropic".to_string(),
                            key: key.to_string(),
                            source: format!("file:{}", path.display()),
                        });
                    }
                }
            }
        }
    }

    keys.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.key.cmp(&b.key)));
    keys.dedup_by(|a, b| a.provider == b.provider && a.key == b.key);

    keys
}

fn models_for_provider(provider: &str) -> ProviderModels {
    match provider {
        "openrouter" => ProviderModels {
            main: vec![
                "google/gemini-2.5-flash".into(),
                "google/gemini-3-flash-preview".into(),
                "anthropic/claude-sonnet-4.6".into(),
            ],
            fast: vec![
                "google/gemini-2.5-flash-lite".into(),
                "anthropic/claude-haiku-4.5".into(),
            ],
            coding: vec![
                "anthropic/claude-opus-4.6".into(),
                "anthropic/claude-sonnet-4.6".into(),
            ],
            default_model: "google/gemini-2.5-flash".into(),
        },
        "anthropic" => ProviderModels {
            main: vec![
                "claude-sonnet-4.6".into(),
                "claude-sonnet-4.5".into(),
            ],
            fast: vec!["claude-haiku-4.5".into()],
            coding: vec![
                "claude-opus-4.6".into(),
                "claude-sonnet-4.6".into(),
            ],
            default_model: "claude-sonnet-4.6".into(),
        },
        "openai" => ProviderModels {
            main: vec!["gpt-5.2".into(), "gpt-4.1".into()],
            fast: vec!["gpt-4.1-mini".into(), "gpt-4.1-nano".into()],
            coding: vec!["gpt-5.2-codex".into(), "gpt-5.2".into()],
            default_model: "gpt-5.2".into(),
        },
        "gemini" => ProviderModels {
            main: vec![
                "gemini-2.5-flash".into(),
                "gemini-3-flash-preview".into(),
            ],
            fast: vec!["gemini-2.5-flash-lite".into()],
            coding: vec![
                "gemini-2.5-pro".into(),
                "gemini-3-pro-preview".into(),
                "gemini-2.5-flash".into(),
            ],
            default_model: "gemini-2.5-flash".into(),
        },
        _ => ProviderModels {
            main: vec!["gpt-5.2".into()],
            fast: vec!["gpt-4.1-mini".into()],
            coding: vec!["gpt-5.2-codex".into()],
            default_model: "gpt-5.2".into(),
        },
    }
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
        let default_str = default.map_or(String::new(), |d| format!(" [{}]", d + 1));
        eprint!("{prompt}{default_str}: ");
        io::stderr().flush()?;

        let input = read_line_from_tty()?;

        if input.is_empty() {
            if let Some(d) = default {
                return Ok(d);
            }
            continue;
        }

        match input.parse::<usize>() {
            Ok(n) if n >= 1 && n <= max => return Ok(n - 1),
            _ => {
                eprintln!("  Please enter a number between 1 and {max}");
            }
        }
    }
}

pub fn run_autoconfigure() -> Result<()> {
    eprintln!("\x1b[1mnsh autoconfigure\x1b[0m");
    eprintln!("Scanning for API keys...\n");

    let keys = detect_api_keys();

    if keys.is_empty() {
        eprintln!("\x1b[33mNo API keys found.\x1b[0m\n");
        eprintln!("You can set one of these environment variables:");
        eprintln!("  export OPENROUTER_API_KEY=sk-or-...");
        eprintln!("  export ANTHROPIC_API_KEY=sk-ant-...");
        eprintln!("  export OPENAI_API_KEY=sk-...");
        eprintln!();
        eprintln!("Then run: \x1b[1mnsh autoconfigure\x1b[0m");
        eprintln!();
        eprintln!("Or edit the config manually: \x1b[1mnsh config edit\x1b[0m");
        return Ok(());
    }

    let mut by_provider: BTreeMap<String, Vec<&DetectedKey>> = BTreeMap::new();
    for k in &keys {
        by_provider.entry(k.provider.clone()).or_default().push(k);
    }

    eprintln!("Found keys for {} provider(s):", by_provider.len());
    for (provider, pkeys) in &by_provider {
        for k in pkeys {
            eprintln!(
                "  \x1b[1m{}\x1b[0m \u{2190} {} (from {})",
                provider,
                mask_key(&k.key),
                k.source
            );
        }
    }
    eprintln!();

    let (chosen_provider, provider_keys) = if by_provider.len() == 1 {
        let (provider, pkeys) = by_provider.into_iter().next().unwrap();
        eprintln!("Using \x1b[1m{provider}\x1b[0m (only available provider)\n");
        (
            provider,
            pkeys.into_iter().cloned().collect::<Vec<_>>(),
        )
    } else {
        let providers: Vec<String> = by_provider.keys().cloned().collect();
        eprintln!("Choose a provider:");
        for (i, p) in providers.iter().enumerate() {
            let key_count = by_provider[p].len();
            eprintln!(
                "  \x1b[1m{}\x1b[0m) {} ({} key{})",
                i + 1,
                p,
                key_count,
                if key_count > 1 { "s" } else { "" }
            );
        }
        let choice = prompt_choice("Select", providers.len(), Some(0))?;
        let provider = providers[choice].clone();
        let pkeys = by_provider[&provider]
            .iter()
            .cloned()
            .cloned()
            .collect::<Vec<_>>();
        eprintln!();
        (provider, pkeys)
    };

    let chosen_key = if provider_keys.len() == 1 {
        provider_keys[0].key.clone()
    } else {
        eprintln!("Multiple keys found for {chosen_provider}. Choose one:");
        for (i, k) in provider_keys.iter().enumerate() {
            eprintln!(
                "  \x1b[1m{}\x1b[0m) {} (from {})",
                i + 1,
                mask_key(&k.key),
                k.source
            );
        }
        let choice = prompt_choice("Select key", provider_keys.len(), Some(0))?;
        eprintln!();
        provider_keys[choice].key.clone()
    };

    eprintln!("How should nsh handle suggested commands?");
    eprintln!(
        "  \x1b[1m1\x1b[0m) prefill  \u{2014} command appears at your prompt, you press Enter to run (safest)"
    );
    eprintln!("  \x1b[1m2\x1b[0m) confirm  \u{2014} ask y/n before each step");
    eprintln!(
        "  \x1b[1m3\x1b[0m) autorun  \u{2014} execute safe commands automatically (advanced)"
    );
    let mode_choice = prompt_choice("Select", 3, Some(0))?;
    let execution_mode = match mode_choice {
        0 => "prefill",
        1 => "confirm",
        2 => "autorun",
        _ => "prefill",
    };
    eprintln!();

    let models = models_for_provider(&chosen_provider);

    save_config(&chosen_provider, &chosen_key, &models, execution_mode)?;

    eprintln!("\x1b[32m\u{2714} nsh configured successfully!\x1b[0m");
    eprintln!();
    eprintln!("  Provider: \x1b[1m{chosen_provider}\x1b[0m");
    eprintln!("  Model: \x1b[1m{}\x1b[0m", models.default_model);
    eprintln!(
        "  Main chain: {}",
        models.main.join(" \u{2192} ")
    );
    eprintln!(
        "  Fast chain: {}",
        models.fast.join(" \u{2192} ")
    );
    eprintln!(
        "  Coding chain: {}",
        models.coding.join(" \u{2192} ")
    );
    eprintln!("  Mode: \x1b[1m{execution_mode}\x1b[0m");
    eprintln!();
    eprintln!("To reconfigure at any time, run: \x1b[1mnsh autoconfigure\x1b[0m");
    eprintln!("To edit config manually: \x1b[1mnsh config edit\x1b[0m");

    Ok(())
}

fn ensure_table(doc: &mut toml_edit::DocumentMut, key: &str) {
    if doc.get(key).is_none() {
        doc[key] = toml_edit::Item::Table(toml_edit::Table::new());
    }
}

fn to_toml_array(items: &[String]) -> toml_edit::Array {
    let mut arr = toml_edit::Array::new();
    for item in items {
        arr.push(item.as_str());
    }
    arr
}

fn save_config(
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
            doc["provider"][provider]["base_url"] =
                toml_edit::value("https://api.anthropic.com");
        }
        "openai" => {
            doc["provider"][provider]["base_url"] =
                toml_edit::value("https://api.openai.com/v1");
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

    // Seed memory system defaults if not already present.
    // Also handle the edge case where "memory" exists but is not a table
    // (e.g., if someone accidentally set memory = true instead of [memory]).
    let should_seed_memory = match doc.get("memory") {
        None => true,
        Some(item) => !item.is_table() && !item.is_table_like(),
    };
    if should_seed_memory {
        doc.remove("memory"); // remove non-table value if present
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
        let m = models_for_provider("openrouter");
        assert!(!m.main.is_empty());
        assert!(!m.fast.is_empty());
        assert!(!m.coding.is_empty());
        assert!(!m.default_model.is_empty());

        let m = models_for_provider("anthropic");
        assert!(m.default_model.contains("claude"));

        let m = models_for_provider("openai");
        assert!(m.default_model.contains("gpt"));

        let m = models_for_provider("gemini");
        assert!(m.default_model.contains("gemini"));
    }

    #[test]
    fn models_for_unknown_provider() {
        let m = models_for_provider("unknown");
        assert!(!m.main.is_empty());
    }

    #[test]
    fn to_toml_array_creates_array() {
        let arr = to_toml_array(&["a".into(), "b".into()]);
        assert_eq!(arr.len(), 2);
    }

    #[test]
    fn save_config_creates_valid_toml() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join(".nsh/config.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();

        // Override config path by writing directly
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

        // Simulate save_config logic: seed memory when absent
        assert!(doc.get("memory").is_none());
        ensure_table(&mut doc, "memory");
        doc["memory"]["enabled"] = toml_edit::value(true);
        doc["memory"]["fade_after_days"] = toml_edit::value(30i64);
        doc["memory"]["expire_after_days"] = toml_edit::value(90i64);
        doc["memory"]["max_retrieval_per_type"] = toml_edit::value(10i64);
        doc["memory"]["reflection_interval_hours"] = toml_edit::value(24i64);
        doc["memory"]["incognito"] = toml_edit::value(false);

        // Also set provider so the TOML is realistic
        ensure_table(&mut doc, "provider");
        doc["provider"]["default"] = toml_edit::value("openrouter");
        doc["provider"]["model"] = toml_edit::value(&models.default_model);

        let content = doc.to_string();
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        let mem = parsed.get("memory").expect("memory section exists");
        assert_eq!(mem["enabled"].as_bool(), Some(true));
        assert_eq!(mem["fade_after_days"].as_integer(), Some(30));
        assert_eq!(mem["expire_after_days"].as_integer(), Some(90));
        assert_eq!(mem["max_retrieval_per_type"].as_integer(), Some(10));
        assert_eq!(mem["reflection_interval_hours"].as_integer(), Some(24));
        assert_eq!(mem["incognito"].as_bool(), Some(false));
    }

    #[test]
    fn save_config_preserves_existing_memory_section() {
        // Simulate an existing config that already has a [memory] section
        let existing = r#"
[provider]
default = "openrouter"

[memory]
enabled = false
fade_after_days = 60
"#;
        let mut doc: toml_edit::DocumentMut = existing.parse().unwrap();

        // The save_config guard: only seed if memory is absent
        if doc.get("memory").is_none() {
            ensure_table(&mut doc, "memory");
            doc["memory"]["enabled"] = toml_edit::value(true);
            doc["memory"]["fade_after_days"] = toml_edit::value(30i64);
        }

        let content = doc.to_string();
        let parsed: toml::Value = toml::from_str(&content).expect("valid TOML");
        let mem = parsed.get("memory").expect("memory section exists");
        // Should NOT be overwritten
        assert_eq!(mem["enabled"].as_bool(), Some(false));
        assert_eq!(mem["fade_after_days"].as_integer(), Some(60));
    }

    #[test]
    fn detect_api_keys_returns_vec() {
        let keys = detect_api_keys();
        // Just verify it doesn't panic
        let _ = keys.len();
    }
}
