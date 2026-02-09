use serde::Deserialize;
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct Config {
    pub provider: ProviderConfig,
    pub context: ContextConfig,
    pub tools: ToolsConfig,
    #[serde(default)]
    pub models: ModelsConfig,
    #[serde(default)]
    pub web_search: WebSearchConfig,
    pub display: DisplayConfig,
    #[serde(default)]
    pub redaction: RedactionConfig,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub db: DbConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            provider: ProviderConfig::default(),
            context: ContextConfig::default(),
            tools: ToolsConfig::default(),
            models: ModelsConfig::default(),
            web_search: WebSearchConfig::default(),
            display: DisplayConfig::default(),
            redaction: RedactionConfig::default(),
            capture: CaptureConfig::default(),
            db: DbConfig::default(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ModelsConfig {
    pub main: Vec<String>,
    pub fast: Vec<String>,
}

impl Default for ModelsConfig {
    fn default() -> Self {
        Self {
            main: vec![
                "google/gemini-2.5-flash".into(),
                "google/gemini-3-flash-preview".into(),
                "anthropic/claude-sonnet-4.5".into(),
            ],
            fast: vec![
                "google/gemini-2.5-flash-lite".into(),
                "anthropic/claude-haiku-4.5".into(),
            ],
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct WebSearchConfig {
    pub provider: String,
    pub model: String,
}

impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            provider: "openrouter".into(),
            model: "perplexity/sonar".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ProviderConfig {
    pub default: String,
    pub model: String,
    pub fallback_model: Option<String>,
    pub web_search_model: String,
    pub openrouter: Option<ProviderAuth>,
    pub anthropic: Option<ProviderAuth>,
    pub openai: Option<ProviderAuth>,
    pub ollama: Option<ProviderAuth>,
    pub gemini: Option<ProviderAuth>,
    pub timeout_seconds: u64,
}

impl Default for ProviderConfig {
    fn default() -> Self {
        Self {
            default: "openrouter".into(),
            model: "google/gemini-2.5-flash".into(),
            fallback_model: Some(
                "anthropic/claude-sonnet-4.5".into(),
            ),
            web_search_model: "perplexity/sonar".into(),
            openrouter: Some(ProviderAuth::default()),
            anthropic: None,
            openai: None,
            ollama: None,
            gemini: None,
            timeout_seconds: 120,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct ProviderAuth {
    pub api_key: Option<String>,
    pub api_key_cmd: Option<String>,
    pub base_url: Option<String>,
}

impl Default for ProviderAuth {
    fn default() -> Self {
        Self {
            api_key: None,
            api_key_cmd: None,
            base_url: None,
        }
    }
}

impl ProviderAuth {
    pub fn resolve_api_key(&self, provider_name: &str) -> anyhow::Result<Zeroizing<String>> {
        if let Some(key) = &self.api_key {
            if !key.is_empty() {
                return Ok(Zeroizing::new(key.clone()));
            }
        }
        if let Some(cmd) = &self.api_key_cmd {
            let output = Command::new("sh").arg("-c").arg(cmd).output()?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!(
                    "api_key_cmd failed (exit {}): {stderr}",
                    output.status.code().unwrap_or(-1)
                );
            }
            let key = String::from_utf8(output.stdout)?.trim().to_string();
            if key.is_empty() {
                anyhow::bail!("api_key_cmd returned empty string");
            }
            return Ok(Zeroizing::new(key));
        }
        let env_var = match provider_name {
            "openrouter" => "OPENROUTER_API_KEY",
            "anthropic" => "ANTHROPIC_API_KEY",
            "openai" => "OPENAI_API_KEY",
            "gemini" => "GEMINI_API_KEY",
            _ => "",
        };
        if !env_var.is_empty() {
            if let Ok(key) = std::env::var(env_var) {
                if !key.is_empty() {
                    return Ok(Zeroizing::new(key));
                }
            }
        }
        anyhow::bail!("No API key for {provider_name} (tried config, api_key_cmd, ${env_var})")
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ContextConfig {
    pub scrollback_lines: usize,
    pub scrollback_pages: usize,
    pub history_summaries: usize,
    pub history_limit: usize,
    pub other_tty_summaries: usize,
    pub max_other_ttys: usize,
    pub project_files_limit: usize,
    pub git_commits: usize,
    pub retention_days: u32,
    pub max_output_storage_bytes: usize,
    pub scrollback_rate_limit_bps: usize,
    pub scrollback_pause_seconds: u64,
    pub include_other_tty: bool,
    pub custom_instructions: Option<String>,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            scrollback_lines: 1000,
            scrollback_pages: 10,
            history_summaries: 100,
            history_limit: 20,
            other_tty_summaries: 10,
            max_other_ttys: 20,
            project_files_limit: 100,
            git_commits: 10,
            retention_days: 1095,
            max_output_storage_bytes: 65536,
            scrollback_rate_limit_bps: 10_485_760,
            scrollback_pause_seconds: 2,
            include_other_tty: false,
            custom_instructions: None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ToolsConfig {
    pub run_command_allowlist: Vec<String>,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            run_command_allowlist: vec![
                "uname".into(),
                "which".into(),
                "cat".into(),
                "head".into(),
                "tail".into(),
                "wc".into(),
                "file".into(),
                "stat".into(),
                "ls".into(),
                "echo".into(),
                "whoami".into(),
                "hostname".into(),
                "date".into(),
                "env".into(),
                "printenv".into(),
                "id".into(),
                "df".into(),
                "free".into(),
                "python3 --version".into(),
                "node --version".into(),
                "git status".into(),
                "git branch".into(),
                "git log".into(),
                "git diff".into(),
                "pip list".into(),
                "cargo --version".into(),
            ],
        }
    }
}

impl ToolsConfig {
    pub fn is_command_allowed(&self, cmd: &str) -> bool {
        let dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\'];
        if cmd.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }
        if self.run_command_allowlist.contains(&"*".to_string()) {
            return true;
        }
        let first_word = cmd.split_whitespace().next().unwrap_or("");
        self.run_command_allowlist.iter().any(|allowed| {
            cmd == allowed
                || cmd.starts_with(&format!("{allowed} "))
                || first_word == allowed
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct DisplayConfig {
    pub chat_color: String,
    pub thinking_indicator: String,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            chat_color: "\x1b[3;36m".into(), // cyan italic
            thinking_indicator:
                "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".into(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub replacement: String,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            patterns: vec![
                r"sk-[a-zA-Z0-9]{20,}".into(),
                r"ghp_[a-zA-Z0-9]{36}".into(),
                r"gho_[a-zA-Z0-9]{36}".into(),
                r"AKIA[A-Z0-9]{16}".into(),
                r"xoxb-[a-zA-Z0-9-]+".into(),
                r"xoxp-[a-zA-Z0-9-]+".into(),
                r"glpat-[a-zA-Z0-9-]+".into(),
                r"ghu_[a-zA-Z0-9]+".into(),
                r"Bearer [a-zA-Z0-9._-]{20,}".into(),
            ],
            replacement: "[REDACTED]".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct CaptureConfig {
    pub mode: String,
    pub alt_screen: String,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            mode: "vt100".into(),
            alt_screen: "drop".into(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub busy_timeout_ms: u64,
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            busy_timeout_ms: 10000,
        }
    }
}

fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        for name in [".nsh.toml", ".nsh/config.toml"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        if dir.join(".git").exists() {
            break;
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

fn deep_merge_toml(base: &mut toml::Value, overlay: &toml::Value) {
    match (base, overlay) {
        (toml::Value::Table(base_table), toml::Value::Table(overlay_table)) => {
            for (key, overlay_val) in overlay_table {
                if let Some(base_val) = base_table.get_mut(key) {
                    deep_merge_toml(base_val, overlay_val);
                } else {
                    base_table.insert(key.clone(), overlay_val.clone());
                }
            }
        }
        (base, overlay) => {
            *base = overlay.clone();
        }
    }
}

fn sanitize_project_config(value: &mut toml::Value) {
    const ALLOWED_SECTIONS: &[&str] = &["context", "display"];

    if let toml::Value::Table(table) = value {
        let disallowed: Vec<String> = table
            .keys()
            .filter(|k| !ALLOWED_SECTIONS.contains(&k.as_str()))
            .cloned()
            .collect();
        if !disallowed.is_empty() {
            eprintln!(
                "nsh: warning: project config contains disallowed sections ({}), ignoring them",
                disallowed.join(", ")
            );
            for key in &disallowed {
                table.remove(key);
            }
        }
    }
}

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = Self::path();
        let mut base_value: toml::Value = if path.exists() {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(&path) {
                    if meta.permissions().mode() & 0o077 != 0 {
                        eprintln!(
                            "nsh: warning: {} is readable by other users. Consider: chmod 600 {}",
                            path.display(),
                            path.display()
                        );
                    }
                }
            }
            let content = std::fs::read_to_string(&path)?;
            toml::from_str(&content)?
        } else {
            tracing::debug!(
                "No config at {}, using defaults",
                path.display()
            );
            toml::Value::Table(toml::map::Map::new())
        };

        // Merge project-level config if found
        if let Some(project_path) = find_project_config() {
            tracing::debug!("Found project config at {}", project_path.display());
            match std::fs::read_to_string(&project_path) {
                Ok(project_content) => {
                    match toml::from_str::<toml::Value>(&project_content) {
                        Ok(mut project_value) => {
                            sanitize_project_config(&mut project_value);
                            deep_merge_toml(&mut base_value, &project_value);
                        }
                        Err(e) => {
                            tracing::warn!("Failed to parse project config {}: {e}", project_path.display());
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to read project config {}: {e}", project_path.display());
                }
            }
        }

        let config: Config = base_value.try_into()?;
        Ok(config)
    }

    pub fn path() -> PathBuf {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".nsh")
            .join("config.toml")
    }

    pub fn nsh_dir() -> PathBuf {
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".nsh")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_values() {
        let config = Config::default();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(
            config.provider.model,
            "google/gemini-2.5-flash"
        );
        assert_eq!(
            config.provider.web_search_model,
            "perplexity/sonar"
        );
        assert_eq!(config.context.history_limit, 20);
        assert_eq!(config.context.retention_days, 1095);
        assert_eq!(config.context.history_summaries, 100);
        assert_eq!(config.context.scrollback_pages, 10);
        assert!(!config.context.include_other_tty);
        assert!(!config.tools.run_command_allowlist.is_empty());
    }

    #[test]
    fn test_config_parse_minimal_toml() {
        let toml_str = r#"
[provider]
default = "openrouter"
"#;
        let config: Config =
            toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(
            config.provider.model,
            "google/gemini-2.5-flash"
        );
    }

    #[test]
    fn test_config_parse_full_toml() {
        let toml_str = r#"
[provider]
default = "anthropic"
model = "claude-3"
web_search_model = "perplexity/sonar-pro"

[provider.openrouter]
api_key = "sk-test"

[context]
history_limit = 50
retention_days = 180

[tools]
run_command_allowlist = ["echo", "ls"]

[display]
chat_color = "red"
"#;
        let config: Config =
            toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "anthropic");
        assert_eq!(config.provider.model, "claude-3");
        assert_eq!(
            config.provider.web_search_model,
            "perplexity/sonar-pro"
        );
        assert_eq!(config.context.history_limit, 50);
        assert_eq!(config.context.retention_days, 180);
        assert_eq!(config.context.history_summaries, 100);
        assert!(!config.context.include_other_tty);
        assert_eq!(
            config.tools.run_command_allowlist,
            vec!["echo", "ls"]
        );
    }

    #[test]
    fn test_config_parse_with_legacy_web_search() {
        let toml_str = r#"
[provider]
default = "openrouter"

[web_search]
provider = "brave"
model = "some-model"
"#;
        let config: Config =
            toml::from_str(toml_str).unwrap();
        assert_eq!(config.web_search.provider, "brave");
        assert_eq!(config.web_search.model, "some-model");
    }

    #[test]
    fn test_is_command_allowed_exact_match() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["git status".into()],
        };
        assert!(tools.is_command_allowed("git status"));
    }

    #[test]
    fn test_is_command_allowed_prefix_match() {
        let tools = ToolsConfig {
            run_command_allowlist: vec![
                "git log".into(),
            ],
        };
        assert!(tools.is_command_allowed("git log --oneline"));
    }

    #[test]
    fn test_is_command_allowed_first_word_match() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into()],
        };
        assert!(tools.is_command_allowed("echo hello world"));
    }

    #[test]
    fn test_is_command_allowed_wildcard() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["*".into()],
        };
        assert!(tools.is_command_allowed("rm -rf /"));
    }

    #[test]
    fn test_is_command_allowed_injection() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["git status".into()],
        };
        assert!(
            !tools.is_command_allowed("git status; rm -rf /"),
            "should reject commands with injection after allowed prefix"
        );
    }

    #[test]
    fn test_deep_merge_toml() {
        let mut base: toml::Value = toml::from_str(r#"
[context]
history_limit = 20
git_commits = 10
"#).unwrap();

        let overlay: toml::Value = toml::from_str(r#"
[context]
history_limit = 50
"#).unwrap();

        deep_merge_toml(&mut base, &overlay);
        let config: Config = base.try_into().unwrap();
        assert_eq!(config.context.history_limit, 50);
        assert_eq!(config.context.git_commits, 10);
    }

    #[test]
    fn test_sanitize_project_config() {
        let mut value: toml::Value = toml::from_str(r#"
[provider]
model = "custom-model"

[provider.openrouter]
api_key = "secret-key"
base_url = "https://custom.url"

[tools]
run_command_allowlist = ["*"]

[context]
git_commits = 5

[display]
chat_color = "red"
"#).unwrap();

        sanitize_project_config(&mut value);
        assert!(value.get("provider").is_none(), "provider section should be stripped");
        assert!(value.get("tools").is_none(), "tools section should be stripped");
        assert!(value.get("context").is_some(), "context section should be kept");
        assert!(value.get("display").is_some(), "display section should be kept");
        let ctx = value.get("context").unwrap().as_table().unwrap();
        assert_eq!(ctx.get("git_commits").unwrap().as_integer(), Some(5));
    }

    #[test]
    fn test_is_command_allowed_rejects_injection_patterns() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into(), "git status".into(), "*".into()],
        };
        // Even with wildcard, dangerous characters should be rejected
        let injection_cases = [
            ("echo hello && rm -rf /", "&&"),
            ("echo hello || rm -rf /", "||"),
            ("echo `whoami`", "backtick"),
            ("echo $(whoami)", "$()"),
            ("echo hello; rm -rf /", "semicolon"),
            ("echo hello\nrm -rf /", "newline"),
            ("git status | cat /etc/passwd", "pipe"),
            ("echo hello > /etc/passwd", "redirect >"),
            ("echo hello < /etc/passwd", "redirect <"),
            ("echo ${PATH}", "variable expansion"),
        ];
        for (cmd, label) in injection_cases {
            assert!(
                !tools.is_command_allowed(cmd),
                "should reject command with {label}: {cmd:?}"
            );
        }
    }
}
