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
    pub web_search: Option<toml::Value>,
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
            web_search: None,
            display: DisplayConfig::default(),
            redaction: RedactionConfig::default(),
            capture: CaptureConfig::default(),
            db: DbConfig::default(),
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
    pub fn resolve_api_key(&self) -> anyhow::Result<Zeroizing<String>> {
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
        anyhow::bail!("No API key configured")
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct ContextConfig {
    pub scrollback_bytes: usize,
    pub scrollback_lines: usize,
    pub history_limit: usize,
    pub token_budget: usize,
    pub retention_days: u32,
    pub max_output_storage_bytes: usize,
    pub scrollback_rate_limit_bps: usize,
    pub scrollback_pause_seconds: u64,
}

impl Default for ContextConfig {
    fn default() -> Self {
        Self {
            scrollback_bytes: 1_048_576, // 1 MB
            scrollback_lines: 1000,
            history_limit: 20,
            token_budget: 8192,
            retention_days: 90,
            max_output_storage_bytes: 32768,
            scrollback_rate_limit_bps: 10_485_760,
            scrollback_pause_seconds: 2,
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
        let dangerous_chars = [';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n'];
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

impl Config {
    pub fn load() -> anyhow::Result<Self> {
        let path = Self::path();
        if path.exists() {
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
            Ok(toml::from_str(&content)?)
        } else {
            tracing::debug!(
                "No config at {}, using defaults",
                path.display()
            );
            Ok(Self::default())
        }
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
        assert_eq!(config.context.retention_days, 90);
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
api_key = "old-key"
"#;
        let config: Config =
            toml::from_str(toml_str).unwrap();
        assert!(config.web_search.is_some());
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
