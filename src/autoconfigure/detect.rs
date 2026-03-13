#[derive(Debug, Clone)]
pub(crate) struct DetectedKey {
    pub(crate) provider: String,
    pub(crate) key: String,
    pub(crate) source: String,
}

pub(crate) fn mask_key(key: &str) -> String {
    if key.len() > 12 {
        format!("{}...{}", &key[..8], &key[key.len() - 4..])
    } else {
        "****".to_string()
    }
}

fn check_env(keys: &mut Vec<DetectedKey>, var: &str, provider: &str) {
    if let Ok(value) = std::env::var(var) {
        let value = value.trim().to_string();
        if !value.is_empty() && value.len() > 5 {
            keys.push(DetectedKey {
                provider: provider.to_string(),
                key: value,
                source: format!("env:{var}"),
            });
        }
    }
}

fn check_file(keys: &mut Vec<DetectedKey>, path: &std::path::Path, provider: &str) {
    if let Ok(content) = std::fs::read_to_string(path) {
        let value = content.trim().to_string();
        if !value.is_empty() && value.len() > 5 {
            keys.push(DetectedKey {
                provider: provider.to_string(),
                key: value,
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
                    let value = line[pattern.len()..]
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_string();
                    if !value.is_empty() && value.len() > 5 {
                        keys.push(DetectedKey {
                            provider: provider.to_string(),
                            key: value,
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
        && output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() && value.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: value,
                    source: format!("keychain:{service}"),
                });
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
        && output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !value.is_empty() && value.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: value,
                    source: format!("1password:{item_name}"),
                });
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
        && output.status.success() {
            let value = String::from_utf8_lossy(&output.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .trim()
                .to_string();
            if !value.is_empty() && value.len() > 5 {
                keys.push(DetectedKey {
                    provider: provider.to_string(),
                    key: value,
                    source: format!("pass:{pass_path}"),
                });
            }
        }
}

pub(crate) fn detect_api_keys() -> Vec<DetectedKey> {
    let mut keys = Vec::new();
    let home = match dirs::home_dir() {
        Some(home) => home,
        None => return keys,
    };

    check_env(&mut keys, "OPENROUTER_API_KEY", "openrouter");
    check_env(&mut keys, "ANTHROPIC_API_KEY", "anthropic");
    check_env(&mut keys, "OPENAI_API_KEY", "openai");
    check_env(&mut keys, "GEMINI_API_KEY", "gemini");
    check_env(&mut keys, "GOOGLE_API_KEY", "gemini");
    check_env(&mut keys, "QWEN_API_KEY", "qwen");
    check_env(&mut keys, "XAI_API_KEY", "z_ai");
    check_env(&mut keys, "MINIMAX_API_KEY", "minimax");
    check_env(&mut keys, "MOONSHOT_API_KEY", "kimi");
    check_env(&mut keys, "DEEPSEEK_API_KEY", "deepseek");

    let file_checks = vec![
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
        ("QWEN_API_KEY", "qwen"),
        ("XAI_API_KEY", "z_ai"),
        ("MINIMAX_API_KEY", "minimax"),
        ("MOONSHOT_API_KEY", "kimi"),
        ("DEEPSEEK_API_KEY", "deepseek"),
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
    if config_path.exists()
        && let Ok(content) = std::fs::read_to_string(&config_path)
            && let Ok(doc) = content.parse::<toml_edit::DocumentMut>() {
                let provider_names = ["openrouter", "anthropic", "openai", "gemini"];
                for provider_name in &provider_names {
                    if let Some(key) = doc
                        .get("provider")
                        .and_then(|provider| provider.get(*provider_name))
                        .and_then(|table| table.as_table())
                        .and_then(|table| table.get("api_key"))
                        .and_then(|key| key.as_str())
                        && !key.is_empty() && key.len() > 5 {
                            keys.push(DetectedKey {
                                provider: provider_name.to_string(),
                                key: key.to_string(),
                                source: "existing nsh config".to_string(),
                            });
                        }
                }
            }

    let copilot_paths = [
        home.join(".config/github-copilot/hosts.json"),
        home.join(".config/github-copilot/apps.json"),
    ];
    for path in &copilot_paths {
        if path.exists() {
            keys.push(DetectedKey {
                provider: "copilot".into(),
                key: "oauth:github-copilot".into(),
                source: format!("{}", path.display()),
            });
            break;
        }
    }

    let claude_paths = [
        home.join(".claude/credentials.json"),
        home.join(".config/claude-code/credentials.json"),
        home.join(".config/claude-code/config.json"),
        home.join(".claude/settings.json"),
    ];
    for path in &claude_paths {
        if path.exists() {
            keys.push(DetectedKey {
                provider: "claude_sub".into(),
                key: "oauth:claude-code".into(),
                source: format!("{}", path.display()),
            });
            break;
        }
    }

    let kiro_token = home.join(".aws/sso/cache/kiro-auth-token.json");
    if kiro_token.exists() {
        keys.push(DetectedKey {
            provider: "kiro".into(),
            key: "oauth:kiro-aws-sso".into(),
            source: format!("{}", kiro_token.display()),
        });
    }

    let codex_auth = home.join(".codex/auth.json");
    if codex_auth.exists() {
        keys.push(DetectedKey {
            provider: "codex_sub".into(),
            key: "oauth:codex".into(),
            source: format!("{}", codex_auth.display()),
        });
    }

    let zai_key = home.join(".config/zai/key");
    if zai_key.exists()
        && let Ok(content) = std::fs::read_to_string(&zai_key) {
            let value = content.trim().to_string();
            if !value.is_empty() && value.len() > 5 {
                keys.push(DetectedKey {
                    provider: "z_ai".into(),
                    key: value,
                    source: format!("{}", zai_key.display()),
                });
            }
        }

    let claude_configs = [
        home.join(".claude/config.json"),
        home.join(".config/claude-code/config.json"),
    ];
    for path in &claude_configs {
        if let Ok(content) = std::fs::read_to_string(path)
            && let Ok(json) = serde_json::from_str::<serde_json::Value>(&content)
                && let Some(key) = json
                    .get("apiKey")
                    .or(json.get("api_key"))
                    .and_then(|key| key.as_str())
                    && !key.is_empty() && key.len() > 5 {
                        keys.push(DetectedKey {
                            provider: "anthropic".to_string(),
                            key: key.to_string(),
                            source: format!("file:{}", path.display()),
                        });
                    }
    }

    keys.sort_by(|a, b| a.provider.cmp(&b.provider).then(a.key.cmp(&b.key)));
    keys.dedup_by(|a, b| a.provider == b.provider && a.key == b.key);
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::EnvVarGuard;
    use serial_test::serial;

    #[test]
    fn mask_key_masks_short_keys() {
        assert_eq!(mask_key("short"), "****");
    }

    #[test]
    fn mask_key_preserves_prefix_and_suffix_for_long_keys() {
        assert_eq!(mask_key("sk-or-v1-abcdefghijklmnop"), "sk-or-v1...mnop");
    }

    #[test]
    #[serial]
    fn check_env_records_trimmed_keys() {
        let _guard = EnvVarGuard::set("OPENROUTER_API_KEY", "  openrouter-secret-key  ");
        let mut keys = Vec::new();

        check_env(&mut keys, "OPENROUTER_API_KEY", "openrouter");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].provider, "openrouter");
        assert_eq!(keys[0].key, "openrouter-secret-key");
        assert_eq!(keys[0].source, "env:OPENROUTER_API_KEY");
    }

    #[test]
    fn check_file_records_trimmed_keys() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("key.txt");
        std::fs::write(&key_path, "  anthropic-secret-key\n").unwrap();
        let mut keys = Vec::new();

        check_file(&mut keys, &key_path, "anthropic");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].provider, "anthropic");
        assert_eq!(keys[0].key, "anthropic-secret-key");
        assert_eq!(keys[0].source, format!("file:{}", key_path.display()));
    }

    #[test]
    fn check_shell_config_for_export_skips_expanded_values() {
        let dir = tempfile::tempdir().unwrap();
        let shell_config = dir.path().join(".env");
        std::fs::write(
            &shell_config,
            "export OPENAI_API_KEY=\"literal-key\"\nOPENAI_API_KEY=$FROM_ENV\n",
        )
        .unwrap();
        let mut keys = Vec::new();

        check_shell_config_for_export(&mut keys, &shell_config, "OPENAI_API_KEY", "openai");

        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].provider, "openai");
        assert_eq!(keys[0].key, "literal-key");
    }
}
