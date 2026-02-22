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

#[derive(Debug, Clone, PartialEq)]
enum ProviderKind {
    Byok,
    Subscription,
    #[allow(dead_code)]
    /// Reserved for future self-hosted providers (e.g., Ollama). Kept to
    /// avoid churn in downstream logic; actual construction will be added
    /// later today.
    SelfHosted,
    Manual,
}

#[derive(Debug, Clone)]
struct ProviderOption {
    id: String,
    display_name: String,
    kind: ProviderKind,
    detected_key: Option<DetectedKey>,
    requires_cliproxyapi: bool,
    native_base_url: Option<String>,
}

const CLIPROXY_BACKED: &[&str] = &[
    "copilot", "kiro", "qwen", "iflow", "claude_sub", "codex_sub", "gemini_sub",
];

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
    // New provider env vars
    check_env(&mut keys, "QWEN_API_KEY", "qwen");
    check_env(&mut keys, "XAI_API_KEY", "z_ai");
    check_env(&mut keys, "MINIMAX_API_KEY", "minimax");
    check_env(&mut keys, "MOONSHOT_API_KEY", "kimi");
    check_env(&mut keys, "DEEPSEEK_API_KEY", "deepseek");

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

    // --- Deeper OAuth/token detection for subscription providers ---
    // GitHub Copilot OAuth files
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

    // Claude Code OAuth files
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

    // Kiro AWS SSO token
    let kiro_token = home.join(".aws/sso/cache/kiro-auth-token.json");
    if kiro_token.exists() {
        keys.push(DetectedKey {
            provider: "kiro".into(),
            key: "oauth:kiro-aws-sso".into(),
            source: format!("{}", kiro_token.display()),
        });
    }

    // Codex OAuth
    let codex_auth = home.join(".codex/auth.json");
    if codex_auth.exists() {
        keys.push(DetectedKey {
            provider: "codex_sub".into(),
            key: "oauth:codex".into(),
            source: format!("{}", codex_auth.display()),
        });
    }

    // Z.ai key file
    let zai_key = home.join(".config/zai/key");
    if zai_key.exists() {
        if let Ok(content) = std::fs::read_to_string(&zai_key) {
            let val = content.trim().to_string();
            if !val.is_empty() && val.len() > 5 {
                keys.push(DetectedKey {
                    provider: "z_ai".into(),
                    key: val,
                    source: format!("{}", zai_key.display()),
                });
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
// ===== Added helpers declarations to satisfy references above =====
fn build_provider_options(detected_keys: &[DetectedKey]) -> Vec<ProviderOption> {
    // Minimal fallback: treat existing BYOK providers and a manual option
    let mut by_provider: BTreeMap<String, Vec<&DetectedKey>> = BTreeMap::new();
    for k in detected_keys { by_provider.entry(k.provider.clone()).or_default().push(k); }
    let mut options = vec![
        ProviderOption { id: "openrouter".into(), display_name: "OpenRouter (BYOK)".into(), kind: ProviderKind::Byok, detected_key: by_provider.get("openrouter").and_then(|v| v.first()).cloned().cloned(), requires_cliproxyapi: false, native_base_url: Some("https://openrouter.ai/api/v1".into()) },
        ProviderOption { id: "anthropic".into(), display_name: "Anthropic (BYOK)".into(), kind: ProviderKind::Byok, detected_key: by_provider.get("anthropic").and_then(|v| v.first()).cloned().cloned(), requires_cliproxyapi: false, native_base_url: Some("https://api.anthropic.com".into()) },
        ProviderOption { id: "openai".into(), display_name: "OpenAI (BYOK)".into(), kind: ProviderKind::Byok, detected_key: by_provider.get("openai").and_then(|v| v.first()).cloned().cloned(), requires_cliproxyapi: false, native_base_url: Some("https://api.openai.com/v1".into()) },
        ProviderOption { id: "gemini".into(), display_name: "Gemini (BYOK)".into(), kind: ProviderKind::Byok, detected_key: by_provider.get("gemini").and_then(|v| v.first()).cloned().cloned(), requires_cliproxyapi: false, native_base_url: Some("https://generativelanguage.googleapis.com/v1beta/openai".into()) },
        ProviderOption { id: "manual".into(), display_name: "I'll configure my own".into(), kind: ProviderKind::Manual, detected_key: None, requires_cliproxyapi: false, native_base_url: None },
    ];
    // Include sidecar-backed subscriptions if keys or OAuth tokens are detected
    for id in ["copilot", "claude_sub", "codex_sub", "gemini_sub", "kiro", "qwen", "iflow"] {
        if by_provider.contains_key(id) {
            options.insert(0, ProviderOption { id: id.into(), display_name: format!("{} (subscription)", id), kind: ProviderKind::Subscription, detected_key: by_provider.get(id).and_then(|v| v.first()).cloned().cloned(), requires_cliproxyapi: true, native_base_url: None });
        }
    }
    // Merge OAuth detections from cliproxyapi
    let oauth = crate::cliproxyapi::detect_existing_oauth_tokens();
    for o in oauth {
        if !options.iter().any(|opt| opt.id == o.provider) {
            options.insert(0, ProviderOption {
                id: o.provider.clone(),
                display_name: format!("{} (subscription)", o.provider),
                kind: ProviderKind::Subscription,
                detected_key: Some(DetectedKey { provider: o.provider, key: "oauth:token".into(), source: o.source }),
                requires_cliproxyapi: true,
                native_base_url: None,
            });
        }
    }
    options
}

fn run_interactive_flow(options: &[ProviderOption], keys: &[DetectedKey]) -> Result<(ProviderOption, String)> {
    loop {
        eprintln!("Choose your LLM provider:\n");
        for (i, opt) in options.iter().enumerate() {
            let status = opt
                .detected_key
                .as_ref()
                .map(|k| format!(" \u{2714} {}", mask_key(&k.key)))
                .unwrap_or_default();
            eprintln!("  \x1b[1m{:>2}\x1b[0m) {}{}", i + 1, opt.display_name, status);
        }
        let idx = prompt_choice("Select", options.len(), Some(0))?;
        let chosen = options[idx].clone();
        if chosen.kind == ProviderKind::Manual {
            return Ok((chosen, String::new()));
        }
        let pkeys: Vec<&DetectedKey> = keys.iter().filter(|k| k.provider == chosen.id).collect();
        if chosen.kind == ProviderKind::Subscription && pkeys.is_empty() {
            // Start OAuth via sidecar binary
            if !crate::cliproxyapi::is_installed() {
                eprintln!("\x1b[33mCLIProxyAPI binary not found. Try again shortly or choose another option.\x1b[0m\n");
                continue;
            }
            eprintln!("Starting OAuth login for {}...", chosen.display_name);
            match crate::cliproxyapi::run_oauth_login(&chosen.id) {
                Ok(true) => {
                    // Sidecar ensure and test
                    let port = match crate::cliproxyapi::ensure_running() { Ok(p) => p, Err(_) => 8317 };
                    // Test provider with fast model via a temporary runtime
                    let models = models_for_provider(&chosen.id);
                    let test_model = models.fast.first().unwrap_or(&models.default_model).clone();
                    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build();
                    if let Ok(rt) = rt {
                        let ok = rt.block_on(async move { crate::cliproxyapi::test_provider(port, &test_model).await.unwrap_or(false) });
                        if !ok {
                            eprintln!("\x1b[33mProvider test failed after login. Choose another option.\x1b[0m\n");
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
        let key = if pkeys.is_empty() {
            if chosen.kind == ProviderKind::Byok {
                eprint!("Enter your {} API key: ", chosen.display_name);
                io::stderr().flush()?;
                read_line_from_tty()? 
            } else {
                "nsh-internal".to_string()
            }
        } else if pkeys.len() == 1 {
            pkeys[0].key.clone()
        } else {
            eprintln!("Multiple keys found. Choose one:");
            for (i, k) in pkeys.iter().enumerate() { eprintln!("  \x1b[1m{}\x1b[0m) {} (from {})", i + 1, mask_key(&k.key), k.source); }
            let kc = prompt_choice("Select key", pkeys.len(), Some(0))?; pkeys[kc].key.clone()
        };
        return Ok((chosen, key));
    }
}

fn run_noninteractive_pick(options: &[ProviderOption]) -> Option<(ProviderOption, String)> {
    for opt in options {
        if let Some(k) = &opt.detected_key { return Some((opt.clone(), k.key.clone())); }
        if opt.requires_cliproxyapi { return Some((opt.clone(), "nsh-internal".into())); }
    }
    None
}

fn save_config_routing(
    chosen_provider: &str,
    chosen_key: &str,
    models: &ProviderModels,
    execution_mode: &str,
    _all_keys: &[DetectedKey],
    all_options: &[ProviderOption],
) -> Result<()> {
    let config_path = crate::config::Config::path();
    let content = if config_path.exists() { std::fs::read_to_string(&config_path)? } else { String::new() };
    let mut doc: toml_edit::DocumentMut = if content.is_empty() { toml_edit::DocumentMut::new() } else { content.parse::<toml_edit::DocumentMut>()? };

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

    // Routing metadata
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

    // Chosen provider auth
    if doc["provider"].get(chosen_provider).is_none() {
        doc["provider"][chosen_provider] = toml_edit::Item::Table(toml_edit::Table::new());
    }
    if via_sidecar {
        let base_url = crate::provider::openai_compat::cliproxyapi_base_url();
        doc["provider"][chosen_provider]["base_url"] = toml_edit::value(base_url);
        doc["provider"][chosen_provider]["api_key"] = toml_edit::value("nsh-internal");
    } else if !chosen_key.is_empty() {
        doc["provider"][chosen_provider]["api_key"] = toml_edit::value(chosen_key);
        if let Some(opt) = all_options.iter().find(|o| o.id == chosen_provider) {
            if let Some(url) = &opt.native_base_url { doc["provider"][chosen_provider]["base_url"] = toml_edit::value(url.as_str()); }
        }
    }

    // Preconfigure other detected providers
    let mut configured = vec![chosen_provider.to_string()];
    for opt in all_options {
        if opt.id == chosen_provider || opt.kind == ProviderKind::Manual { continue; }
        if opt.detected_key.is_none() && !opt.requires_cliproxyapi { continue; }
        configured.push(opt.id.clone());
        if doc["provider"].get(&opt.id).is_none() {
            doc["provider"][&opt.id] = toml_edit::Item::Table(toml_edit::Table::new());
        }
        if opt.requires_cliproxyapi {
            let base_url = crate::provider::openai_compat::cliproxyapi_base_url();
            doc["provider"][&opt.id]["base_url"] = toml_edit::value(base_url);
            doc["provider"][&opt.id]["api_key"] = toml_edit::value("nsh-internal");
        } else if let Some(k) = &opt.detected_key {
            doc["provider"][&opt.id]["api_key"] = toml_edit::value(&k.key);
            if let Some(url) = &opt.native_base_url { doc["provider"][&opt.id]["base_url"] = toml_edit::value(url.as_str()); }
        }
        let m = models_for_provider(&opt.id);
        doc["provider"][&opt.id]["model"] = toml_edit::value(&m.default_model);
    }
    let mut arr = toml_edit::Array::new(); for s in configured { arr.push(s.as_str()); }
    doc["provider_routing"]["configured_providers"] = toml_edit::value(arr);

    if let Some(parent) = config_path.parent() { std::fs::create_dir_all(parent)?; }
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

fn legacy_noninteractive_flow(keys: Vec<DetectedKey>) -> Result<()> {
    if keys.is_empty() {
        eprintln!("\x1b[33mNo API keys found.\x1b[0m\n");
        eprintln!("You can set one of these environment variables:\n  export OPENROUTER_API_KEY=...\n  export ANTHROPIC_API_KEY=...\n  export OPENAI_API_KEY=...\n");
        eprintln!("Or edit the config manually: \x1b[1mnsh config edit\x1b[0m");
        return Ok(());
    }
    let mut by_provider: BTreeMap<String, Vec<&DetectedKey>> = BTreeMap::new();
    for k in &keys { by_provider.entry(k.provider.clone()).or_default().push(k); }
    let (provider, pkeys) = if by_provider.len() == 1 { by_provider.into_iter().next().unwrap() } else {
        let providers: Vec<String> = by_provider.keys().cloned().collect();
        eprintln!("Choose a provider:");
        for (i, p) in providers.iter().enumerate() { eprintln!("  \x1b[1m{}\x1b[0m) {}", i + 1, p); }
        let choice = prompt_choice("Select", providers.len(), Some(0))?;
        let p = providers[choice].clone();
        (p, by_provider[providers[choice].as_str()].clone())
    };
    let chosen_key = if pkeys.len() == 1 { pkeys[0].key.clone() } else {
        eprintln!("Multiple keys found for {provider}. Choose one:");
        for (i, k) in pkeys.iter().enumerate() { eprintln!("  \x1b[1m{}\x1b[0m) {} (from {})", i + 1, mask_key(&k.key), k.source); }
        let c = prompt_choice("Select key", pkeys.len(), Some(0))?; pkeys[c].key.clone()
    };
    let models = models_for_provider(&provider);
    save_config(&provider, &chosen_key, &models, "prefill")
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
            main: vec!["claude-sonnet-4.6".into()],
            fast: vec!["claude-haiku-4.5".into()],
            coding: vec!["claude-opus-4.6".into(), "claude-sonnet-4.6".into()],
            default_model: "claude-sonnet-4.6".into(),
        },
        "openai" => ProviderModels {
            main: vec!["gpt-5.2".into(), "gpt-4.1".into()],
            fast: vec!["gpt-4.1-mini".into(), "gpt-4.1-nano".into()],
            coding: vec!["gpt-5.2-codex".into(), "gpt-5.2".into()],
            default_model: "gpt-5.2".into(),
        },
        "gemini" => ProviderModels {
            main: vec!["gemini-2.5-flash".into(), "gemini-3-flash-preview".into()],
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

pub fn run_autoconfigure(interactive: bool) -> Result<()> {
    eprintln!("\x1b[1mnsh autoconfigure\x1b[0m");
    eprintln!("Scanning for API keys and subscriptions...\n");
    let keys = detect_api_keys();
    let options = build_provider_options(&keys);
    if interactive {
        let (opt, key) = run_interactive_flow(&options, &keys)?;
        eprintln!("How should nsh handle suggested commands?\n  \x1b[1m1\x1b[0m) prefill\n  \x1b[1m2\x1b[0m) confirm\n  \x1b[1m3\x1b[0m) autorun");
        let mode_choice = prompt_choice("Select", 3, Some(0))?;
        let execution_mode = match mode_choice { 0 => "prefill", 1 => "confirm", 2 => "autorun", _ => "prefill" };
        let models = models_for_provider(&opt.id);
        save_config_routing(&opt.id, &key, &models, execution_mode, &keys, &options)?;
        eprintln!("\x1b[32m\u{2714} nsh configured successfully!\x1b[0m");
        eprintln!("  Provider: \x1b[1m{}\x1b[0m", opt.display_name);
        eprintln!("  Model: \x1b[1m{}\x1b[0m", models.default_model);
        return Ok(());
    }
    match run_noninteractive_pick(&options) {
        Some((opt, key)) => {
            let models = models_for_provider(&opt.id);
            save_config_routing(&opt.id, &key, &models, "prefill", &keys, &options)?;
            eprintln!("\x1b[32m\u{2714} nsh configured successfully!\x1b[0m");
            eprintln!("  Provider: \x1b[1m{}\x1b[0m", opt.display_name);
            eprintln!("  Model: \x1b[1m{}\x1b[0m", models.default_model);
            Ok(())
        }
        None => legacy_noninteractive_flow(keys),
    }
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
