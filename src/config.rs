use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize, Default)]
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
    #[allow(dead_code)]
    #[serde(default)]
    pub mcp: McpConfig,
    #[allow(dead_code)]
    #[serde(default)]
    pub execution: ExecutionConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExecutionConfig {
    pub mode: String, // "prefill" | "confirm" | "autorun"
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            mode: "prefill".into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
            fallback_model: Some("anthropic/claude-sonnet-4.5".into()),
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

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(default)]
pub struct ProviderAuth {
    pub api_key: Option<String>,
    pub api_key_cmd: Option<String>,
    pub base_url: Option<String>,
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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
        let dangerous_chars = [
            ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\', '\'', '"',
        ];
        if cmd.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }
        if self.run_command_allowlist.contains(&"*".to_string()) {
            return true;
        }
        let argv: Vec<&str> = cmd.split_whitespace().collect();
        if argv.is_empty() {
            return false;
        }
        self.run_command_allowlist.iter().any(|allowed| {
            let parts: Vec<&str> = allowed.split_whitespace().collect();
            if parts.is_empty() {
                return false;
            }
            if parts.len() == 1 {
                argv[0] == parts[0]
            } else {
                argv.len() >= parts.len()
                    && argv[..parts.len()].iter().zip(&parts).all(|(a, b)| a == b)
            }
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DisplayConfig {
    pub chat_color: String,
    pub thinking_indicator: String,
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            chat_color: "\x1b[3;36m".into(), // cyan italic
            thinking_indicator: "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏".into(),
        }
    }
}

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(default)]
pub struct RedactionConfig {
    pub enabled: bool,
    pub patterns: Vec<String>,
    pub replacement: String,
    pub disable_builtin: bool,
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
                r"-----BEGIN[A-Z ]*PRIVATE KEY-----".into(),
                r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}".into(),
                r"sk_live_[a-zA-Z0-9]{24,}".into(),
                r"rk_live_[a-zA-Z0-9]{24,}".into(),
                r"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}".into(),
                r"(?i)(password|passwd|pwd)\s*[=:]\s*\S+".into(),
                r"mongodb(\+srv)?://[^\s]+@".into(),
                r"postgres(ql)?://[^\s]+@".into(),
                r"mysql://[^\s]+@".into(),
                r"sk-ant-[a-zA-Z0-9-]{20,}".into(),
                r"sk-or-v1-[a-zA-Z0-9]{20,}".into(),
                r"npm_[a-zA-Z0-9]{36}".into(),
            ],
            replacement: "[REDACTED]".into(),
            disable_builtin: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct McpConfig {
    #[allow(dead_code)]
    #[serde(default)]
    pub servers: HashMap<String, McpServerConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct McpServerConfig {
    /// Transport type: "stdio" (default) or "http"
    #[serde(default)]
    pub transport: Option<String>,
    /// Command to spawn (required for stdio)
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    /// URL endpoint (required for http)
    #[serde(default)]
    pub url: Option<String>,
    /// Extra HTTP headers (for http transport)
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default = "default_mcp_timeout")]
    pub timeout_seconds: u64,
}

impl McpServerConfig {
    /// Determine effective transport: explicit setting, or inferred from fields.
    pub fn effective_transport(&self) -> String {
        if let Some(ref t) = self.transport {
            return t.clone();
        }
        if self.url.is_some() && self.command.is_none() {
            "http".into()
        } else {
            "stdio".into()
        }
    }
}

fn default_mcp_timeout() -> u64 {
    30
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
            tracing::debug!("No config at {}, using defaults", path.display());
            toml::Value::Table(toml::map::Map::new())
        };

        // Merge project-level config if found
        if let Some(project_path) = find_project_config() {
            tracing::debug!("Found project config at {}", project_path.display());
            match std::fs::read_to_string(&project_path) {
                Ok(project_content) => match toml::from_str::<toml::Value>(&project_content) {
                    Ok(mut project_value) => {
                        sanitize_project_config(&mut project_value);
                        deep_merge_toml(&mut base_value, &project_value);
                    }
                    Err(e) => {
                        tracing::warn!(
                            "Failed to parse project config {}: {e}",
                            project_path.display()
                        );
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        "Failed to read project config {}: {e}",
                        project_path.display()
                    );
                }
            }
        }

        let mut config: Config = base_value.try_into()?;

        if config.web_search.model == WebSearchConfig::default().model
            && config.provider.web_search_model != ProviderConfig::default().web_search_model
        {
            config.web_search.model = config.provider.web_search_model.clone();
        }

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

pub fn build_config_xml(
    config: &Config,
    skills: &[crate::skills::Skill],
    mcp_servers: &[(String, usize)],
) -> String {
    use crate::context::xml_escape;

    let mut x = String::from("<nsh_configuration path=\"~/.nsh/config.toml\">\n");

    // ── Provider ────────────────────────────────────────
    x.push_str("  <section name=\"provider\">\n");
    opt(&mut x, "default", &config.provider.default,
        "Active LLM provider", Some("openrouter,anthropic,openai,ollama,gemini"));
    opt(&mut x, "model", &config.provider.model,
        "Primary model for queries", None);
    opt(&mut x, "fallback_model",
        config.provider.fallback_model.as_deref().unwrap_or("(none)"),
        "Fallback model on 429/5xx errors", None);
    opt(&mut x, "timeout_seconds", &config.provider.timeout_seconds.to_string(),
        "HTTP request timeout in seconds", None);
    x.push_str("    <configured_providers>\n");
    for (name, auth) in [
        ("openrouter", &config.provider.openrouter),
        ("anthropic", &config.provider.anthropic),
        ("openai", &config.provider.openai),
        ("ollama", &config.provider.ollama),
        ("gemini", &config.provider.gemini),
    ] {
        let has_key = auth.as_ref()
            .and_then(|a| a.resolve_api_key(name).ok())
            .is_some();
        x.push_str(&format!(
            "      <provider name=\"{name}\" has_api_key=\"{has_key}\" />\n"
        ));
    }
    x.push_str("    </configured_providers>\n");
    x.push_str("  </section>\n");

    // ── Context ─────────────────────────────────────────
    x.push_str("  <section name=\"context\">\n");
    opt(&mut x, "scrollback_lines", &config.context.scrollback_lines.to_string(),
        "Max terminal scrollback lines captured", None);
    opt(&mut x, "scrollback_pages", &config.context.scrollback_pages.to_string(),
        "Terminal pages included in LLM context", None);
    opt(&mut x, "history_summaries", &config.context.history_summaries.to_string(),
        "Max command history summaries in context", None);
    opt(&mut x, "history_limit", &config.context.history_limit.to_string(),
        "Max conversation history entries per session", None);
    opt(&mut x, "other_tty_summaries", &config.context.other_tty_summaries.to_string(),
        "Command summaries per other TTY session", None);
    opt(&mut x, "max_other_ttys", &config.context.max_other_ttys.to_string(),
        "Max other TTY sessions included", None);
    opt(&mut x, "project_files_limit", &config.context.project_files_limit.to_string(),
        "Max project files listed in context", None);
    opt(&mut x, "git_commits", &config.context.git_commits.to_string(),
        "Recent git commits included in context", None);
    opt(&mut x, "retention_days", &config.context.retention_days.to_string(),
        "Days to retain command history", None);
    opt(&mut x, "max_output_storage_bytes", &config.context.max_output_storage_bytes.to_string(),
        "Max bytes of output stored per command", None);
    opt(&mut x, "include_other_tty", &config.context.include_other_tty.to_string(),
        "Include other TTY sessions in context", None);
    let ci = config.context.custom_instructions.as_deref().unwrap_or("(none)");
    opt(&mut x, "custom_instructions", ci,
        "Custom instructions appended to system prompt", None);
    x.push_str("  </section>\n");

    // ── Models ──────────────────────────────────────────
    x.push_str("  <section name=\"models\">\n");
    x.push_str(&format!(
        "    <option key=\"main\" value=\"{}\" description=\"Model chain for queries (tried in order)\" />\n",
        xml_escape(&config.models.main.join(", "))
    ));
    x.push_str(&format!(
        "    <option key=\"fast\" value=\"{}\" description=\"Model chain for summaries and lightweight tasks\" />\n",
        xml_escape(&config.models.fast.join(", "))
    ));
    x.push_str("  </section>\n");

    // ── Tools ───────────────────────────────────────────
    x.push_str("  <section name=\"tools\">\n");
    x.push_str(&format!(
        "    <option key=\"run_command_allowlist\" value=\"{}\" description=\"Commands the AI can run without user approval\" />\n",
        xml_escape(&config.tools.run_command_allowlist.join(", "))
    ));
    x.push_str("  </section>\n");

    // ── Web Search ──────────────────────────────────────
    x.push_str("  <section name=\"web_search\">\n");
    opt(&mut x, "provider", &config.web_search.provider,
        "Provider for web search queries", None);
    opt(&mut x, "model", &config.web_search.model,
        "Model used for web search", None);
    x.push_str("  </section>\n");

    // ── Display ─────────────────────────────────────────
    x.push_str("  <section name=\"display\">\n");
    opt(&mut x, "chat_color", &config.display.chat_color.replace('\x1b', "\\x1b"),
        "ANSI escape for chat response color", None);
    x.push_str("  </section>\n");

    // ── Redaction ───────────────────────────────────────
    x.push_str("  <section name=\"redaction\">\n");
    opt(&mut x, "enabled", &config.redaction.enabled.to_string(),
        "Auto-redact secrets before sending to LLM", None);
    opt(&mut x, "replacement", &config.redaction.replacement,
        "Replacement text for redacted secrets", None);
    opt(&mut x, "disable_builtin", &config.redaction.disable_builtin.to_string(),
        "Disable built-in secret patterns", None);
    x.push_str(&format!(
        "    <option key=\"patterns\" value=\"({} custom patterns)\" description=\"User-defined regex patterns\" />\n",
        config.redaction.patterns.len()
    ));
    x.push_str("  </section>\n");

    // ── Capture ─────────────────────────────────────────
    x.push_str("  <section name=\"capture\">\n");
    opt(&mut x, "mode", &config.capture.mode,
        "Terminal capture mode", Some("vt100"));
    opt(&mut x, "alt_screen", &config.capture.alt_screen,
        "How to handle alternate screen (TUI apps)", Some("drop,snapshot"));
    x.push_str("  </section>\n");

    // ── Execution ───────────────────────────────────────
    x.push_str("  <section name=\"execution\">\n");
    opt(&mut x, "mode", &config.execution.mode,
        "How suggested commands are delivered", Some("prefill,confirm,autorun"));
    x.push_str("  </section>\n");

    // ── DB ──────────────────────────────────────────────
    x.push_str("  <section name=\"db\">\n");
    opt(&mut x, "busy_timeout_ms", &config.db.busy_timeout_ms.to_string(),
        "SQLite busy timeout in milliseconds", None);
    x.push_str("  </section>\n");

    // ── MCP Servers ─────────────────────────────────────
    x.push_str(&format!(
        "  <mcp_servers count=\"{}\">\n",
        mcp_servers.len()
    ));
    for (name, tool_count) in mcp_servers {
        x.push_str(&format!(
            "    <server name=\"{}\" tools=\"{tool_count}\" />\n",
            xml_escape(name)
        ));
    }
    for (name, srv) in &config.mcp.servers {
        if !mcp_servers.iter().any(|(n, _)| n == name) {
            let transport = srv.effective_transport();
            x.push_str(&format!(
                "    <server name=\"{}\" transport=\"{transport}\" status=\"not_started\" />\n",
                xml_escape(name)
            ));
        }
    }
    x.push_str("  </mcp_servers>\n");

    // ── Skills ──────────────────────────────────────────
    x.push_str(&format!(
        "  <installed_skills count=\"{}\">\n",
        skills.len()
    ));
    for skill in skills {
        let source = if skill.is_project { "project" } else { "global" };
        x.push_str(&format!(
            "    <skill name=\"{}\" description=\"{}\" source=\"{source}\" terminal=\"{}\" />\n",
            xml_escape(&skill.name),
            xml_escape(&skill.description),
            skill.terminal,
        ));
    }
    x.push_str("  </installed_skills>\n");

    x.push_str("</nsh_configuration>");
    x
}

fn opt(x: &mut String, key: &str, value: &str, description: &str, choices: Option<&str>) {
    use crate::context::xml_escape;
    let choices_attr = choices
        .map(|c| format!(" choices=\"{}\"", xml_escape(c)))
        .unwrap_or_default();
    x.push_str(&format!(
        "    <option key=\"{key}\" value=\"{}\" description=\"{}\"{choices_attr} />\n",
        xml_escape(value),
        xml_escape(description),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_values() {
        let config = Config::default();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.provider.model, "google/gemini-2.5-flash");
        assert_eq!(config.provider.web_search_model, "perplexity/sonar");
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
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.provider.model, "google/gemini-2.5-flash");
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
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "anthropic");
        assert_eq!(config.provider.model, "claude-3");
        assert_eq!(config.provider.web_search_model, "perplexity/sonar-pro");
        assert_eq!(config.context.history_limit, 50);
        assert_eq!(config.context.retention_days, 180);
        assert_eq!(config.context.history_summaries, 100);
        assert!(!config.context.include_other_tty);
        assert_eq!(config.tools.run_command_allowlist, vec!["echo", "ls"]);
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
        let config: Config = toml::from_str(toml_str).unwrap();
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
            run_command_allowlist: vec!["git log".into()],
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
        let mut base: toml::Value = toml::from_str(
            r#"
[context]
history_limit = 20
git_commits = 10
"#,
        )
        .unwrap();

        let overlay: toml::Value = toml::from_str(
            r#"
[context]
history_limit = 50
"#,
        )
        .unwrap();

        deep_merge_toml(&mut base, &overlay);
        let config: Config = base.try_into().unwrap();
        assert_eq!(config.context.history_limit, 50);
        assert_eq!(config.context.git_commits, 10);
    }

    #[test]
    fn test_sanitize_project_config() {
        let mut value: toml::Value = toml::from_str(
            r#"
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
"#,
        )
        .unwrap();

        sanitize_project_config(&mut value);
        assert!(
            value.get("provider").is_none(),
            "provider section should be stripped"
        );
        assert!(
            value.get("tools").is_none(),
            "tools section should be stripped"
        );
        assert!(
            value.get("context").is_some(),
            "context section should be kept"
        );
        assert!(
            value.get("display").is_some(),
            "display section should be kept"
        );
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

    #[test]
    fn test_provider_auth_default() {
        let auth = ProviderAuth::default();
        assert!(auth.api_key.is_none());
        assert!(auth.api_key_cmd.is_none());
    }

    #[test]
    fn test_config_from_empty_string() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.provider.model, "google/gemini-2.5-flash");
        assert_eq!(config.context.history_limit, 20);
        assert!(config.redaction.enabled);
    }

    #[test]
    fn test_config_custom_provider() {
        let toml_str = r#"
[provider]
default = "anthropic"
model = "claude-3"
timeout_seconds = 60

[provider.anthropic]
api_key = "sk-test-key"
base_url = "https://custom.api.example.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "anthropic");
        assert_eq!(config.provider.model, "claude-3");
        assert_eq!(config.provider.timeout_seconds, 60);
        let anthropic = config.provider.anthropic.unwrap();
        assert_eq!(anthropic.api_key.as_deref(), Some("sk-test-key"));
        assert_eq!(
            anthropic.base_url.as_deref(),
            Some("https://custom.api.example.com")
        );
    }

    #[test]
    fn test_resolve_api_key_direct() {
        let auth = ProviderAuth {
            api_key: Some("my-direct-key".into()),
            api_key_cmd: None,
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "my-direct-key");
    }

    #[test]
    fn test_resolve_api_key_cmd() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("echo test-key".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "test-key");
    }

    #[test]
    fn test_resolve_api_key_empty_falls_through_to_cmd() {
        let auth = ProviderAuth {
            api_key: Some("".into()),
            api_key_cmd: Some("echo fallback-key".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "fallback-key");
    }

    #[test]
    fn test_resolve_api_key_failing_command() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("false".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
    }

    #[test]
    fn test_is_command_allowed_empty_allowlist() {
        let tools = ToolsConfig {
            run_command_allowlist: vec![],
        };
        assert!(!tools.is_command_allowed("ls"));
        assert!(!tools.is_command_allowed("echo hello"));
        assert!(!tools.is_command_allowed(""));
    }

    #[test]
    fn test_is_command_allowed_default_allowlist() {
        let tools = ToolsConfig::default();
        assert!(tools.is_command_allowed("ls"));
        assert!(tools.is_command_allowed("echo hello"));
        assert!(tools.is_command_allowed("cat /etc/hosts"));
        assert!(tools.is_command_allowed("git status"));
        assert!(tools.is_command_allowed("git log --oneline -5"));
        assert!(tools.is_command_allowed("whoami"));
        assert!(!tools.is_command_allowed("rm -rf /"));
        assert!(!tools.is_command_allowed("curl http://example.com"));
    }

    #[test]
    fn test_nsh_dir_ends_with_nsh() {
        let dir = Config::nsh_dir();
        assert!(dir.ends_with(".nsh"));
    }

    #[test]
    fn test_display_config_default() {
        let dc = DisplayConfig::default();
        assert_eq!(dc.chat_color, "\x1b[3;36m");
        assert_eq!(dc.thinking_indicator, "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏");
    }

    #[test]
    fn test_capture_config_default() {
        let cc = CaptureConfig::default();
        assert_eq!(cc.mode, "vt100");
        assert_eq!(cc.alt_screen, "drop");
    }

    #[test]
    fn test_db_config_default() {
        let db = DbConfig::default();
        assert_eq!(db.busy_timeout_ms, 10000);
    }

    #[test]
    fn test_mcp_config_default() {
        let mcp = McpConfig::default();
        assert!(mcp.servers.is_empty());
    }

    #[test]
    fn test_redaction_config_default() {
        let rc = RedactionConfig::default();
        assert!(rc.enabled);
        assert!(!rc.patterns.is_empty());
        assert_eq!(rc.replacement, "[REDACTED]");
        assert!(!rc.disable_builtin);
    }

    #[test]
    fn test_execution_config_default() {
        let ec = ExecutionConfig::default();
        assert_eq!(ec.mode, "prefill");
    }

    #[test]
    fn test_models_config_default() {
        let mc = ModelsConfig::default();
        assert!(!mc.main.is_empty());
        assert!(!mc.fast.is_empty());
        assert!(mc.main.iter().any(|m| m.contains("gemini")));
        assert!(mc.main.iter().any(|m| m.contains("claude")));
    }

    #[test]
    fn test_web_search_config_default() {
        let ws = WebSearchConfig::default();
        assert_eq!(ws.provider, "openrouter");
        assert_eq!(ws.model, "perplexity/sonar");
    }

    #[test]
    fn test_context_config_default() {
        let ctx = ContextConfig::default();
        assert_eq!(ctx.scrollback_lines, 1000);
        assert_eq!(ctx.scrollback_pages, 10);
        assert_eq!(ctx.history_summaries, 100);
        assert_eq!(ctx.history_limit, 20);
        assert_eq!(ctx.other_tty_summaries, 10);
        assert_eq!(ctx.max_other_ttys, 20);
        assert_eq!(ctx.project_files_limit, 100);
        assert_eq!(ctx.git_commits, 10);
        assert_eq!(ctx.retention_days, 1095);
        assert_eq!(ctx.max_output_storage_bytes, 65536);
        assert_eq!(ctx.scrollback_rate_limit_bps, 10_485_760);
        assert_eq!(ctx.scrollback_pause_seconds, 2);
        assert!(!ctx.include_other_tty);
        assert!(ctx.custom_instructions.is_none());
    }

    #[test]
    fn test_load_or_default_from_file() {
        let config: Config = toml::from_str(
            r#"
[provider]
model = "test-model"
"#,
        )
        .unwrap();
        assert_eq!(config.provider.model, "test-model");
        assert_eq!(config.provider.default, "openrouter");
    }

    #[test]
    fn test_mcp_server_config_with_command() {
        let toml_str = r#"
[mcp.servers.test]
command = "echo"
args = ["hello"]
timeout_seconds = 10
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let servers = &config.mcp.servers;
        assert!(servers.contains_key("test"));
        let server = &servers["test"];
        assert_eq!(server.command.as_deref(), Some("echo"));
        assert_eq!(server.args, vec!["hello"]);
        assert_eq!(server.timeout_seconds, 10);
        assert_eq!(server.effective_transport(), "stdio");
    }

    #[test]
    fn test_mcp_server_config_http_transport() {
        let toml_str = r#"
[mcp.servers.remote]
url = "https://mcp.example.com"

[mcp.servers.remote.headers]
Authorization = "Bearer tok"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let server = &config.mcp.servers["remote"];
        assert_eq!(server.url.as_deref(), Some("https://mcp.example.com"));
        assert_eq!(server.effective_transport(), "http");
        assert_eq!(server.headers.get("Authorization").unwrap(), "Bearer tok");
    }

    #[test]
    fn test_mcp_server_config_explicit_transport() {
        let toml_str = r#"
[mcp.servers.mixed]
transport = "http"
url = "https://example.com"
command = "fallback"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let server = &config.mcp.servers["mixed"];
        assert_eq!(server.effective_transport(), "http");
    }

    #[test]
    fn test_mcp_server_config_env_vars() {
        let toml_str = r#"
[mcp.servers.myserver]
command = "node"
args = ["server.js"]

[mcp.servers.myserver.env]
NODE_ENV = "production"
PORT = "3000"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let server = &config.mcp.servers["myserver"];
        assert_eq!(server.env.get("NODE_ENV").unwrap(), "production");
        assert_eq!(server.env.get("PORT").unwrap(), "3000");
    }

    #[test]
    fn test_mcp_server_config_default_timeout() {
        let toml_str = r#"
[mcp.servers.minimal]
command = "test"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.mcp.servers["minimal"].timeout_seconds, 30);
    }

    #[test]
    fn test_capture_config_parsing() {
        let toml_str = r#"
[capture]
mode = "raw"
alt_screen = "snapshot"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.capture.mode, "raw");
        assert_eq!(config.capture.alt_screen, "snapshot");
    }

    #[test]
    fn test_db_config_parsing() {
        let toml_str = r#"
[db]
busy_timeout_ms = 5000
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.db.busy_timeout_ms, 5000);
    }

    #[test]
    fn test_redaction_config_custom_patterns() {
        let toml_str = r#"
[redaction]
enabled = true
patterns = ["custom_secret_\\w+", "another_pattern"]
replacement = "[HIDDEN]"
disable_builtin = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.redaction.enabled);
        assert_eq!(config.redaction.patterns.len(), 2);
        assert_eq!(config.redaction.patterns[0], r"custom_secret_\w+");
        assert_eq!(config.redaction.replacement, "[HIDDEN]");
        assert!(config.redaction.disable_builtin);
    }

    #[test]
    fn test_redaction_config_disabled() {
        let toml_str = r#"
[redaction]
enabled = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(!config.redaction.enabled);
    }

    #[test]
    fn test_execution_config_autorun() {
        let toml_str = r#"
[execution]
mode = "autorun"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.execution.mode, "autorun");
    }

    #[test]
    fn test_execution_config_confirm() {
        let toml_str = r#"
[execution]
mode = "confirm"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.execution.mode, "confirm");
    }

    #[test]
    fn test_multiple_provider_configs() {
        let toml_str = r#"
[provider]
default = "anthropic"
model = "claude-3"

[provider.openrouter]
api_key = "or-key"
base_url = "https://or.example.com"

[provider.anthropic]
api_key = "ant-key"

[provider.openai]
api_key = "oai-key"
base_url = "https://oai.example.com"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "anthropic");

        let or = config.provider.openrouter.unwrap();
        assert_eq!(or.api_key.as_deref(), Some("or-key"));
        assert_eq!(or.base_url.as_deref(), Some("https://or.example.com"));

        let ant = config.provider.anthropic.unwrap();
        assert_eq!(ant.api_key.as_deref(), Some("ant-key"));
        assert!(ant.base_url.is_none());

        let oai = config.provider.openai.unwrap();
        assert_eq!(oai.api_key.as_deref(), Some("oai-key"));
        assert_eq!(oai.base_url.as_deref(), Some("https://oai.example.com"));

        assert!(config.provider.ollama.is_none());
        assert!(config.provider.gemini.is_none());
    }

    #[test]
    fn test_deep_merge_toml_empty_overlay() {
        let mut base: toml::Value = toml::from_str(
            r#"
[context]
history_limit = 20
git_commits = 10
"#,
        )
        .unwrap();
        let overlay: toml::Value =
            toml::Value::Table(toml::map::Map::new());
        deep_merge_toml(&mut base, &overlay);
        let config: Config = base.try_into().unwrap();
        assert_eq!(config.context.history_limit, 20);
        assert_eq!(config.context.git_commits, 10);
    }

    #[test]
    fn test_deep_merge_toml_new_keys() {
        let mut base: toml::Value = toml::from_str(
            r#"
[context]
history_limit = 20
"#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
[display]
chat_color = "green"
"#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let config: Config = base.try_into().unwrap();
        assert_eq!(config.context.history_limit, 20);
        assert_eq!(config.display.chat_color, "green");
    }

    #[test]
    fn test_deep_merge_toml_recursive_tables() {
        let mut base: toml::Value = toml::from_str(
            r#"
[provider]
default = "openrouter"
model = "original"

[provider.openrouter]
api_key = "base-key"
base_url = "https://base.example.com"
"#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
[provider]
model = "overridden"

[provider.openrouter]
api_key = "overlay-key"
"#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let config: Config = base.try_into().unwrap();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.provider.model, "overridden");
        let or = config.provider.openrouter.unwrap();
        assert_eq!(or.api_key.as_deref(), Some("overlay-key"));
        assert_eq!(or.base_url.as_deref(), Some("https://base.example.com"));
    }

    #[test]
    fn test_deep_merge_toml_scalar_override() {
        let mut base: toml::Value = toml::Value::Integer(10);
        let overlay = toml::Value::Integer(42);
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base, toml::Value::Integer(42));
    }

    #[test]
    fn test_sanitize_project_config_all_disallowed() {
        let mut value: toml::Value = toml::from_str(
            r#"
[provider]
model = "evil"

[tools]
run_command_allowlist = ["*"]

[redaction]
enabled = false

[execution]
mode = "autorun"
"#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        assert!(value.get("provider").is_none());
        assert!(value.get("tools").is_none());
        assert!(value.get("redaction").is_none());
        assert!(value.get("execution").is_none());
        let table = value.as_table().unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_sanitize_project_config_empty() {
        let mut value: toml::Value =
            toml::Value::Table(toml::map::Map::new());
        sanitize_project_config(&mut value);
        let table = value.as_table().unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn test_sanitize_project_config_only_allowed() {
        let mut value: toml::Value = toml::from_str(
            r#"
[context]
git_commits = 5

[display]
chat_color = "red"
"#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        assert!(value.get("context").is_some());
        assert!(value.get("display").is_some());
    }

    #[test]
    fn test_sanitize_project_config_nested_tables() {
        let mut value: toml::Value = toml::from_str(
            r#"
[context]
history_limit = 30
custom_instructions = "be concise"

[provider]
default = "anthropic"

[provider.anthropic]
api_key = "secret"
"#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        assert!(value.get("provider").is_none());
        assert!(value.get("context").is_some());
        let ctx = value.get("context").unwrap().as_table().unwrap();
        assert_eq!(ctx.get("history_limit").unwrap().as_integer(), Some(30));
        assert_eq!(
            ctx.get("custom_instructions").unwrap().as_str(),
            Some("be concise")
        );
    }

    #[test]
    fn test_context_config_custom_instructions() {
        let toml_str = r#"
[context]
custom_instructions = "Always respond in haiku"
include_other_tty = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.context.custom_instructions.as_deref(),
            Some("Always respond in haiku")
        );
        assert!(config.context.include_other_tty);
    }

    #[test]
    fn test_provider_config_with_fallback_model() {
        let toml_str = r#"
[provider]
model = "primary"
fallback_model = "secondary"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.model, "primary");
        assert_eq!(
            config.provider.fallback_model.as_deref(),
            Some("secondary")
        );
    }

    #[test]
    fn test_provider_config_no_fallback() {
        let toml_str = r#"
[provider]
model = "primary"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(
            config.provider.fallback_model.as_deref(),
            Some("anthropic/claude-sonnet-4.5")
        );
    }

    #[test]
    fn test_models_config_custom() {
        let toml_str = r#"
[models]
main = ["model-x", "model-y"]
fast = ["model-z"]
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.models.main, vec!["model-x", "model-y"]);
        assert_eq!(config.models.fast, vec!["model-z"]);
    }

    #[test]
    fn test_multiple_mcp_servers() {
        let toml_str = r#"
[mcp.servers.alpha]
command = "alpha-cmd"
args = ["-v"]

[mcp.servers.beta]
url = "https://beta.example.com"

[mcp.servers.gamma]
transport = "stdio"
command = "gamma-cmd"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.mcp.servers.len(), 3);
        assert_eq!(config.mcp.servers["alpha"].effective_transport(), "stdio");
        assert_eq!(config.mcp.servers["beta"].effective_transport(), "http");
        assert_eq!(config.mcp.servers["gamma"].effective_transport(), "stdio");
    }

    #[test]
    fn test_is_command_allowed_wildcard_blocks_dangerous() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["*".into()],
        };
        assert!(tools.is_command_allowed("anything"));
        assert!(!tools.is_command_allowed("echo; rm"));
        assert!(!tools.is_command_allowed("cmd | pipe"));
    }

    #[test]
    fn test_resolve_api_key_empty_cmd_output() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("echo".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
    }

    #[test]
    fn test_config_parse_all_sections_toml() {
        let toml_str = r#"
[provider]
default = "openai"
model = "gpt-4"
timeout_seconds = 30

[provider.openai]
api_key = "sk-test"

[context]
scrollback_lines = 500
history_limit = 10
git_commits = 5

[tools]
run_command_allowlist = ["ls", "cat"]

[display]
chat_color = "blue"
thinking_indicator = "..."

[redaction]
enabled = false
patterns = ["secret_\\w+"]
replacement = "[HIDDEN]"
disable_builtin = true

[capture]
mode = "raw"
alt_screen = "capture"

[db]
busy_timeout_ms = 5000

[execution]
mode = "autorun"

[models]
main = ["model-a"]
fast = ["model-b"]

[web_search]
provider = "brave"
model = "search-model"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "openai");
        assert_eq!(config.provider.model, "gpt-4");
        assert_eq!(config.provider.timeout_seconds, 30);
        assert_eq!(config.context.scrollback_lines, 500);
        assert_eq!(config.context.history_limit, 10);
        assert_eq!(config.context.git_commits, 5);
        assert_eq!(config.tools.run_command_allowlist, vec!["ls", "cat"]);
        assert_eq!(config.display.chat_color, "blue");
        assert_eq!(config.display.thinking_indicator, "...");
        assert!(!config.redaction.enabled);
        assert!(config.redaction.disable_builtin);
        assert_eq!(config.redaction.replacement, "[HIDDEN]");
        assert_eq!(config.capture.mode, "raw");
        assert_eq!(config.capture.alt_screen, "capture");
        assert_eq!(config.db.busy_timeout_ms, 5000);
        assert_eq!(config.execution.mode, "autorun");
        assert_eq!(config.models.main, vec!["model-a"]);
        assert_eq!(config.models.fast, vec!["model-b"]);
        assert_eq!(config.web_search.provider, "brave");
        assert_eq!(config.web_search.model, "search-model");
    }

    #[test]
    fn test_build_config_xml_basic() {
        let config = Config::default();
        let skills = vec![];
        let mcp_servers = vec![];
        let xml = build_config_xml(&config, &skills, &mcp_servers);
        assert!(xml.contains("<nsh_configuration"));
        assert!(xml.contains("</nsh_configuration>"));
        assert!(xml.contains("provider"));
        assert!(xml.contains("context"));
        assert!(xml.contains("display"));
    }

    #[test]
    fn test_build_config_xml_with_skills() {
        let config = Config::default();
        let skills = vec![crate::skills::Skill {
            name: "test_skill".to_string(),
            description: "A test skill".to_string(),
            command: "echo test".to_string(),
            timeout_seconds: 30,
            parameters: std::collections::HashMap::new(),
            is_project: false,
            terminal: false,
        }];
        let mcp_servers = vec![];
        let xml = build_config_xml(&config, &skills, &mcp_servers);
        assert!(xml.contains("test_skill"));
        assert!(xml.contains("A test skill"));
    }

    #[test]
    fn test_build_config_xml_with_mcp() {
        let config = Config::default();
        let skills = vec![];
        let mcp_servers = vec![("test_server".to_string(), 3)];
        let xml = build_config_xml(&config, &skills, &mcp_servers);
        assert!(xml.contains("test_server"));
        assert!(xml.contains("tools=\"3\""));
    }

    #[test]
    fn test_mcp_effective_transport_default() {
        let cfg = McpServerConfig {
            transport: None,
            command: Some("echo".into()),
            args: vec![],
            env: std::collections::HashMap::new(),
            url: None,
            headers: std::collections::HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "stdio");
    }

    #[test]
    fn test_mcp_effective_transport_explicit_http() {
        let cfg = McpServerConfig {
            transport: Some("http".into()),
            command: None,
            args: vec![],
            env: std::collections::HashMap::new(),
            url: Some("http://localhost:8080".into()),
            headers: std::collections::HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "http");
    }

    #[test]
    fn test_mcp_effective_transport_inferred_http() {
        let cfg = McpServerConfig {
            transport: None,
            command: None,
            args: vec![],
            env: std::collections::HashMap::new(),
            url: Some("http://localhost:8080".into()),
            headers: std::collections::HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "http");
    }

    #[test]
    fn test_opt_without_choices() {
        let mut x = String::new();
        opt(&mut x, "test_key", "test_value", "test description", None);
        assert!(x.contains("test_key"));
        assert!(x.contains("test_value"));
        assert!(x.contains("test description"));
        assert!(!x.contains("choices"));
    }

    #[test]
    fn test_opt_with_choices() {
        let mut x = String::new();
        opt(&mut x, "mode", "prefill", "execution mode", Some("prefill,confirm,autorun"));
        assert!(x.contains("choices="));
        assert!(x.contains("prefill,confirm,autorun"));
    }

    #[test]
    fn test_find_project_config_no_panic() {
        let _ = find_project_config();
    }

    #[test]
    fn test_default_mcp_timeout() {
        assert_eq!(default_mcp_timeout(), 30);
    }
}
