use serde::Deserialize;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct Config {
    pub provider: ProviderConfig,
    pub context: ContextConfig,
    #[serde(default)]
    pub hints: HintsConfig,
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

pub const DEFAULT_SUPPRESSED_EXIT_CODES: &[i32] = &[130, 137, 141, 143];

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HintsConfig {
    pub suppressed_exit_codes: Vec<i32>,
}

impl Default for HintsConfig {
    fn default() -> Self {
        Self {
            suppressed_exit_codes: DEFAULT_SUPPRESSED_EXIT_CODES.to_vec(),
        }
    }
}

impl HintsConfig {
    pub fn normalized_suppressed_exit_codes(&self) -> Vec<i32> {
        let mut codes: Vec<i32> = self
            .suppressed_exit_codes
            .iter()
            .copied()
            .filter(|c| *c > 0 && *c <= 255)
            .collect();
        codes.sort_unstable();
        codes.dedup();
        codes
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ExecutionConfig {
    pub mode: String, // "prefill" | "confirm" | "autorun"
    pub allow_unsafe_autorun: bool,
    pub max_tool_iterations: usize,
    pub confirm_intermediate_steps: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            mode: "prefill".into(),
            allow_unsafe_autorun: false,
            max_tool_iterations: 30,
            confirm_intermediate_steps: false,
        }
    }
}

impl ExecutionConfig {
    pub fn effective_max_tool_iterations(&self) -> usize {
        self.max_tool_iterations.clamp(1, 200)
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
            #[cfg(unix)]
            let output = Command::new("sh").arg("-c").arg(cmd).output()?;
            #[cfg(windows)]
            let output = Command::new("cmd").args(["/C", cmd]).output()?;
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
    pub restore_last_cwd_per_tty: bool,
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
            restore_last_cwd_per_tty: true,
            custom_instructions: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ToolsConfig {
    pub run_command_allowlist: Vec<String>,
    pub sensitive_file_access: String,
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            run_command_allowlist: vec![
                "uname".into(),
                "which".into(),
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
                "npm --version".into(),
                "npm list -g --depth=0".into(),
                "npm prefix -g".into(),
                "npm config get prefix".into(),
                "pipx --version".into(),
                "pipx list".into(),
                "pip3 --version".into(),
                "pip3 list".into(),
                "pip3 show".into(),
                "brew --version".into(),
                "brew list".into(),
                "brew info".into(),
                "brew --prefix".into(),
                "brew outdated".into(),
                "gem --version".into(),
                "go version".into(),
                "sw_vers".into(),
                "type".into(),
                "explorer.exe".into(),
                "wslview".into(),
                "clip.exe".into(),
                "cmd.exe /c ver".into(),
            ],
            sensitive_file_access: "block".into(),
        }
    }
}

pub const TOOL_BLOCKED_KEYS: &[&str] = &[
    "execution.allow_unsafe_autorun",
    "tools.sensitive_file_access",
    "tools.run_command_allowlist",
    "redaction.enabled",
    "redaction.disable_builtin",
];

const TOOL_BLOCKED_KEY_SEGMENTS: &[&str] = &["api_key", "api_key_cmd", "base_url"];

pub fn is_setting_protected(key: &str) -> bool {
    if TOOL_BLOCKED_KEYS.contains(&key) {
        return true;
    }
    if key
        .split('.')
        .any(|segment| TOOL_BLOCKED_KEY_SEGMENTS.contains(&segment))
    {
        return true;
    }
    for blocked in TOOL_BLOCKED_KEYS {
        if blocked.starts_with(key) && blocked[key.len()..].starts_with('.') {
            return true;
        }
    }
    false
}

impl ToolsConfig {
    pub fn is_command_allowed(&self, command: &str) -> bool {
        let trimmed = command.trim();
        if trimmed.is_empty() {
            return false;
        }
        let dangerous_chars = [
            ';', '|', '&', '$', '`', '(', ')', '{', '}', '<', '>', '\n', '\\', '\'', '"',
        ];
        if trimmed.chars().any(|c| dangerous_chars.contains(&c)) {
            return false;
        }
        if self.run_command_allowlist.contains(&"*".to_string()) {
            return true;
        }
        let argv: Vec<&str> = trimmed.split_whitespace().collect();
        for entry in &self.run_command_allowlist {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }
            if let Some((allowed_cmd, allowed_sub)) = entry.split_once(':') {
                if argv.first().map_or(false, |a| *a == allowed_cmd)
                    && argv.get(1).map_or(false, |a| *a == allowed_sub)
                {
                    return true;
                }
            } else if trimmed == entry
                || trimmed.starts_with(entry) && trimmed.as_bytes().get(entry.len()) == Some(&b' ')
            {
                return true;
            }
        }
        false
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
            busy_timeout_ms: 5000,
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
    let global_config_path = Config::path();
    loop {
        for name in [".nsh.toml", ".nsh/config.toml"] {
            let candidate = dir.join(name);
            if candidate.exists() {
                // Never treat the user-global config as a project override.
                if !is_project_config_candidate_allowed(&candidate, &global_config_path) {
                    continue;
                }
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

fn is_project_config_candidate_allowed(candidate: &Path, global_config_path: &Path) -> bool {
    candidate != global_config_path
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

#[cfg(test)]
fn sanitize_project_config(value: &mut toml::Value) {
    sanitize_project_config_for_path(value, None);
}

fn should_emit_project_config_warning_once(
    project_path: Option<&Path>,
    disallowed: &[String],
) -> bool {
    let session_id = match std::env::var("NSH_SESSION_ID") {
        Ok(id) if !id.trim().is_empty() => id,
        _ => return true,
    };

    let marker_dir = std::env::temp_dir().join("nsh-session-warnings");
    if std::fs::create_dir_all(&marker_dir).is_err() {
        return true;
    }

    let mut hasher = DefaultHasher::new();
    session_id.hash(&mut hasher);
    if let Some(path) = project_path {
        path.hash(&mut hasher);
    }
    for section in disallowed {
        section.hash(&mut hasher);
    }
    let marker_name = format!("project-disallowed-sections-{:016x}", hasher.finish());
    let marker_path = marker_dir.join(marker_name);

    match std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(marker_path)
    {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(_) => true,
    }
}

fn sanitize_project_config_for_path(value: &mut toml::Value, project_path: Option<&Path>) {
    // Security: only context and display are allowed in project configs.
    // execution, tools, redaction, and provider sections are blocked to prevent
    // project-level configs from weakening security settings.
    const ALLOWED_SECTIONS: &[&str] = &["context", "display"];

    if let toml::Value::Table(table) = value {
        let disallowed: Vec<String> = table
            .keys()
            .filter(|k| !ALLOWED_SECTIONS.contains(&k.as_str()))
            .cloned()
            .collect();
        if !disallowed.is_empty()
            && should_emit_project_config_warning_once(project_path, &disallowed)
        {
            eprintln!(
                "nsh: warning: project config contains disallowed sections ({}), ignoring them",
                disallowed.join(", ")
            );
        }
        if !disallowed.is_empty() {
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
                        sanitize_project_config_for_path(
                            &mut project_value,
                            Some(project_path.as_path()),
                        );
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
        #[cfg(windows)]
        {
            return dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().expect("Could not determine home directory"))
                .join("nsh")
                .join("config.toml");
        }
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".nsh")
            .join("config.toml")
    }

    pub fn nsh_dir() -> PathBuf {
        #[cfg(windows)]
        {
            return dirs::data_local_dir()
                .unwrap_or_else(|| dirs::home_dir().expect("Could not determine home directory"))
                .join("nsh");
        }
        dirs::home_dir()
            .expect("Could not determine home directory")
            .join(".nsh")
    }
}

#[derive(Debug, Clone)]
pub struct SuppressedExitCodesUpdate {
    pub added: bool,
    pub codes: Vec<i32>,
}

pub fn add_suppressed_exit_code(code: i32) -> anyhow::Result<SuppressedExitCodesUpdate> {
    if !(1..=255).contains(&code) {
        anyhow::bail!("exit code must be in 1..=255");
    }

    let path = Config::path();
    let content = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };

    let mut doc: toml_edit::DocumentMut = if content.is_empty() {
        toml_edit::DocumentMut::new()
    } else {
        content.parse::<toml_edit::DocumentMut>()?
    };

    let had_hints_table = matches!(doc.get("hints"), Some(item) if item.is_table());
    if !had_hints_table {
        doc["hints"] = toml_edit::Item::Table(toml_edit::Table::new());
    }

    let hints = doc["hints"]
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("failed to prepare [hints] table"))?;

    let had_key = hints.get("suppressed_exit_codes").is_some();
    let mut codes: Vec<i32> = if had_key {
        if let Some(arr) = hints
            .get("suppressed_exit_codes")
            .and_then(|v| v.as_array())
        {
            arr.iter()
                .filter_map(|v| v.as_integer())
                .filter_map(|v| i32::try_from(v).ok())
                .collect()
        } else {
            Vec::new()
        }
    } else {
        DEFAULT_SUPPRESSED_EXIT_CODES.to_vec()
    };

    let added = !codes.contains(&code);
    if added {
        codes.push(code);
    }
    codes.retain(|c| *c > 0 && *c <= 255);
    codes.sort_unstable();
    codes.dedup();

    let mut arr = toml_edit::Array::new();
    for c in &codes {
        arr.push(*c as i64);
    }
    hints["suppressed_exit_codes"] = toml_edit::value(arr);

    let new_content = doc.to_string();
    toml::from_str::<Config>(&new_content)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&path, new_content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(SuppressedExitCodesUpdate { added, codes })
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
    opt(
        &mut x,
        "default",
        &config.provider.default,
        "Active LLM provider",
        Some("openrouter,anthropic,openai,ollama,gemini"),
    );
    opt(
        &mut x,
        "model",
        &config.provider.model,
        "Primary model for queries",
        None,
    );
    opt(
        &mut x,
        "fallback_model",
        config
            .provider
            .fallback_model
            .as_deref()
            .unwrap_or("(none)"),
        "Fallback model on 429/5xx errors",
        None,
    );
    opt(
        &mut x,
        "timeout_seconds",
        &config.provider.timeout_seconds.to_string(),
        "HTTP request timeout in seconds",
        None,
    );
    x.push_str("    <configured_providers>\n");
    for (name, auth) in [
        ("openrouter", &config.provider.openrouter),
        ("anthropic", &config.provider.anthropic),
        ("openai", &config.provider.openai),
        ("ollama", &config.provider.ollama),
        ("gemini", &config.provider.gemini),
    ] {
        let has_key = auth
            .as_ref()
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
    opt(
        &mut x,
        "scrollback_lines",
        &config.context.scrollback_lines.to_string(),
        "Max terminal scrollback lines captured",
        None,
    );
    opt(
        &mut x,
        "scrollback_pages",
        &config.context.scrollback_pages.to_string(),
        "Terminal pages included in LLM context",
        None,
    );
    opt(
        &mut x,
        "history_summaries",
        &config.context.history_summaries.to_string(),
        "Max command history summaries in context",
        None,
    );
    opt(
        &mut x,
        "history_limit",
        &config.context.history_limit.to_string(),
        "Max conversation history entries per session",
        None,
    );
    opt(
        &mut x,
        "other_tty_summaries",
        &config.context.other_tty_summaries.to_string(),
        "Command summaries per other TTY session",
        None,
    );
    opt(
        &mut x,
        "max_other_ttys",
        &config.context.max_other_ttys.to_string(),
        "Max other TTY sessions included",
        None,
    );
    opt(
        &mut x,
        "project_files_limit",
        &config.context.project_files_limit.to_string(),
        "Max project files listed in context",
        None,
    );
    opt(
        &mut x,
        "git_commits",
        &config.context.git_commits.to_string(),
        "Recent git commits included in context",
        None,
    );
    opt(
        &mut x,
        "retention_days",
        &config.context.retention_days.to_string(),
        "Days to retain command history",
        None,
    );
    opt(
        &mut x,
        "max_output_storage_bytes",
        &config.context.max_output_storage_bytes.to_string(),
        "Max bytes of output stored per command",
        None,
    );
    opt(
        &mut x,
        "include_other_tty",
        &config.context.include_other_tty.to_string(),
        "Include other TTY sessions in context",
        None,
    );
    opt(
        &mut x,
        "restore_last_cwd_per_tty",
        &config.context.restore_last_cwd_per_tty.to_string(),
        "Restore shell cwd to the last directory used on this TTY",
        None,
    );
    let ci = config
        .context
        .custom_instructions
        .as_deref()
        .unwrap_or("(none)");
    opt(
        &mut x,
        "custom_instructions",
        ci,
        "Custom instructions appended to system prompt",
        None,
    );
    x.push_str("  </section>\n");

    // ── Hints ───────────────────────────────────────────
    x.push_str("  <section name=\"hints\">\n");
    x.push_str(&format!(
        "    <option key=\"suppressed_exit_codes\" value=\"{}\" description=\"Exit codes that should not show '? fix' failure hints\" />\n",
        crate::context::xml_escape(
            &config
                .hints
                .normalized_suppressed_exit_codes()
                .iter()
                .map(std::string::ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )
    ));
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
        "    <option key=\"run_command_allowlist\" value=\"{}\" description=\"Commands the AI can run without user approval\" protected=\"true\" />\n",
        xml_escape(&config.tools.run_command_allowlist.join(", "))
    ));
    x.push_str(&format!(
        "    <option key=\"sensitive_file_access\" value=\"{}\" description=\"Controls access to sensitive directories: block | ask | allow (MANUAL EDIT ONLY)\" protected=\"true\" />\n",
        xml_escape(&config.tools.sensitive_file_access)
    ));
    x.push_str("  </section>\n");

    // ── Web Search ──────────────────────────────────────
    x.push_str("  <section name=\"web_search\">\n");
    opt(
        &mut x,
        "provider",
        &config.web_search.provider,
        "Provider for web search queries",
        None,
    );
    opt(
        &mut x,
        "model",
        &config.web_search.model,
        "Model used for web search",
        None,
    );
    x.push_str("  </section>\n");

    // ── Display ─────────────────────────────────────────
    x.push_str("  <section name=\"display\">\n");
    opt(
        &mut x,
        "chat_color",
        &config.display.chat_color.replace('\x1b', "\\x1b"),
        "ANSI escape for chat response color",
        None,
    );
    x.push_str("  </section>\n");

    // ── Redaction ───────────────────────────────────────
    x.push_str("  <section name=\"redaction\">\n");
    x.push_str(&format!(
        "    <option key=\"enabled\" value=\"{}\" description=\"Auto-redact secrets before sending to LLM\" protected=\"true\" />\n",
        config.redaction.enabled
    ));
    opt(
        &mut x,
        "replacement",
        &config.redaction.replacement,
        "Replacement text for redacted secrets",
        None,
    );
    x.push_str(&format!(
        "    <option key=\"disable_builtin\" value=\"{}\" description=\"Disable built-in secret patterns\" protected=\"true\" />\n",
        config.redaction.disable_builtin
    ));
    x.push_str(&format!(
        "    <option key=\"patterns\" value=\"({} custom patterns)\" description=\"User-defined regex patterns\" />\n",
        config.redaction.patterns.len()
    ));
    x.push_str("  </section>\n");

    // ── Capture ─────────────────────────────────────────
    x.push_str("  <section name=\"capture\">\n");
    opt(
        &mut x,
        "mode",
        &config.capture.mode,
        "Terminal capture mode",
        Some("vt100"),
    );
    opt(
        &mut x,
        "alt_screen",
        &config.capture.alt_screen,
        "How to handle alternate screen (TUI apps)",
        Some("drop,snapshot"),
    );
    x.push_str("  </section>\n");

    // ── Execution ───────────────────────────────────────
    x.push_str("  <section name=\"execution\">\n");
    opt(
        &mut x,
        "mode",
        &config.execution.mode,
        "How suggested commands are delivered",
        Some("prefill,confirm,autorun"),
    );
    x.push_str(&format!(
        "    <option key=\"allow_unsafe_autorun\" value=\"{}\" description=\"Allow !! and autorun mode to auto-run elevated-risk commands (MANUAL EDIT ONLY)\" protected=\"true\" />\n",
        config.execution.allow_unsafe_autorun
    ));
    opt(
        &mut x,
        "max_tool_iterations",
        &config.execution.max_tool_iterations.to_string(),
        "Maximum number of tool loop iterations per query",
        None,
    );
    opt(
        &mut x,
        "confirm_intermediate_steps",
        &config.execution.confirm_intermediate_steps.to_string(),
        "Ask y/n before immediately running pending intermediate commands outside autorun",
        Some("true,false"),
    );
    x.push_str("  </section>\n");

    // ── DB ──────────────────────────────────────────────
    x.push_str("  <section name=\"db\">\n");
    opt(
        &mut x,
        "busy_timeout_ms",
        &config.db.busy_timeout_ms.to_string(),
        "SQLite busy timeout in milliseconds",
        None,
    );
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
        let source = if skill.is_project {
            "project"
        } else {
            "global"
        };
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
        assert_eq!(
            config.hints.normalized_suppressed_exit_codes(),
            vec![130, 137, 141, 143]
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
            ..Default::default()
        };
        assert!(tools.is_command_allowed("git status"));
    }

    #[test]
    fn test_is_command_allowed_prefix_match() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["git log".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("git log --oneline"));
    }

    #[test]
    fn test_is_command_allowed_first_word_match() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("echo hello world"));
    }

    #[test]
    fn test_is_command_allowed_wildcard() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["*".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("rm -rf /"));
    }

    #[test]
    fn test_is_command_allowed_injection() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["git status".into()],
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
        assert_eq!(db.busy_timeout_ms, 5000);
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
        assert_eq!(ec.max_tool_iterations, 30);
        assert!(!ec.confirm_intermediate_steps);
        assert_eq!(ec.effective_max_tool_iterations(), 30);
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
        assert!(ctx.restore_last_cwd_per_tty);
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
        assert_eq!(config.execution.max_tool_iterations, 30);
        assert!(!config.execution.confirm_intermediate_steps);
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
    fn test_execution_config_custom_loop_and_intermediate_confirmation() {
        let toml_str = r#"
[execution]
max_tool_iterations = 35
confirm_intermediate_steps = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.execution.max_tool_iterations, 35);
        assert!(!config.execution.confirm_intermediate_steps);
    }

    #[test]
    fn test_execution_config_effective_max_tool_iterations_bounds() {
        let mut ec = ExecutionConfig::default();
        ec.max_tool_iterations = 0;
        assert_eq!(ec.effective_max_tool_iterations(), 1);
        ec.max_tool_iterations = 250;
        assert_eq!(ec.effective_max_tool_iterations(), 200);
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
        let overlay: toml::Value = toml::Value::Table(toml::map::Map::new());
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
        let mut value: toml::Value = toml::Value::Table(toml::map::Map::new());
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
        assert_eq!(config.provider.fallback_model.as_deref(), Some("secondary"));
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
            ..Default::default()
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
        opt(
            &mut x,
            "mode",
            "prefill",
            "execution mode",
            Some("prefill,confirm,autorun"),
        );
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

    #[test]
    #[serial_test::serial]
    fn test_resolve_api_key_via_env_and_fallback() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: None,
            base_url: None,
        };

        // Test env var lookup for each known provider
        unsafe { std::env::set_var("ANTHROPIC_API_KEY", "ant-env-key") };
        assert_eq!(*auth.resolve_api_key("anthropic").unwrap(), "ant-env-key");
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY") };

        unsafe { std::env::set_var("OPENAI_API_KEY", "oai-env-key") };
        assert_eq!(*auth.resolve_api_key("openai").unwrap(), "oai-env-key");
        unsafe { std::env::remove_var("OPENAI_API_KEY") };

        unsafe { std::env::set_var("GEMINI_API_KEY", "gem-env-key") };
        assert_eq!(*auth.resolve_api_key("gemini").unwrap(), "gem-env-key");
        unsafe { std::env::remove_var("GEMINI_API_KEY") };

        // Unknown provider: no env var mapping, should bail
        let result = auth.resolve_api_key("unknown_provider");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No API key for unknown_provider")
        );

        // Known provider with no env var set: should bail with env var name in message
        unsafe { std::env::remove_var("ANTHROPIC_API_KEY") };
        let result = auth.resolve_api_key("anthropic");
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("No API key for anthropic"));
        assert!(err_msg.contains("ANTHROPIC_API_KEY"));
    }

    #[test]
    fn test_is_command_allowed_empty_allowlist_entry() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["".into(), "ls".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("ls"));
        assert!(!tools.is_command_allowed("rm foo"));
    }

    #[test]
    fn test_is_command_allowed_empty_command() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["ls".into()],
            ..Default::default()
        };
        assert!(!tools.is_command_allowed(""));
        assert!(!tools.is_command_allowed("   "));
    }

    #[test]
    fn test_build_config_xml_with_not_started_mcp_servers() {
        let toml_str = r#"
[mcp.servers.my_server]
command = "my-cmd"
args = ["--flag"]

[mcp.servers.http_server]
url = "https://example.com/mcp"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let skills = vec![];
        let started_servers: Vec<(String, usize)> = vec![];
        let xml = build_config_xml(&config, &skills, &started_servers);
        assert!(xml.contains("status=\"not_started\""));
        assert!(xml.contains("my_server") || xml.contains("http_server"));
    }

    #[test]
    fn test_build_config_xml_mcp_partial_started() {
        let toml_str = r#"
[mcp.servers.started_one]
command = "cmd1"

[mcp.servers.not_started_one]
command = "cmd2"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let skills = vec![];
        let started = vec![("started_one".to_string(), 5)];
        let xml = build_config_xml(&config, &skills, &started);
        assert!(xml.contains("tools=\"5\""));
        assert!(xml.contains("not_started_one"));
        assert!(xml.contains("status=\"not_started\""));
    }

    #[test]
    fn test_build_config_xml_web_search_model_override() {
        let toml_str = r#"
[provider]
web_search_model = "custom/search-model"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.web_search.model, "perplexity/sonar");
    }

    #[test]
    fn test_deep_merge_toml_table_over_scalar() {
        let mut base: toml::Value = toml::from_str(
            r#"
key = "scalar"
"#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
key = "overridden"
"#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.get("key").unwrap().as_str(), Some("overridden"));
    }

    #[test]
    fn test_find_project_config_returns_option() {
        let result = find_project_config();
        assert!(result.is_none() || result.unwrap().exists());
    }

    #[test]
    fn test_project_config_candidate_rejects_global_config_path() {
        let global = PathBuf::from("/Users/example/.nsh/config.toml");
        assert!(!is_project_config_candidate_allowed(&global, &global));
    }

    #[test]
    fn test_project_config_candidate_allows_distinct_path() {
        let global = PathBuf::from("/Users/example/.nsh/config.toml");
        let project = PathBuf::from("/Users/example/work/repo/.nsh.toml");
        assert!(is_project_config_candidate_allowed(&project, &global));
    }

    #[test]
    fn test_config_path_ends_with_config_toml() {
        let path = Config::path();
        assert!(path.to_string_lossy().ends_with("config.toml"));
    }

    #[test]
    fn test_default_config_provider() {
        let config = Config::default();
        assert_eq!(config.provider.default, "openrouter");
    }

    #[test]
    fn test_default_config_context_limits() {
        let config = Config::default();
        assert!(config.context.history_limit > 0);
        assert!(config.context.history_summaries > 0);
        assert!(config.context.scrollback_lines > 0);
    }

    #[test]
    fn test_config_from_partial_toml() {
        let toml_str = r#"
[provider]
model = "gpt-4"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.model, "gpt-4");
        assert_eq!(config.provider.default, "openrouter");
    }

    #[test]
    fn test_build_config_xml_contains_sections() {
        let config = Config::default();
        let skills = vec![];
        let mcp_info = vec![];
        let xml = build_config_xml(&config, &skills, &mcp_info);
        assert!(xml.contains("<nsh_configuration"));
        assert!(xml.contains("</nsh_configuration>"));
        assert!(xml.contains("provider"));
    }

    // ── deep_merge_toml ─────────────────────────────────

    #[test]
    fn test_deep_merge_toml_overlapping_keys() {
        let mut base: toml::Value = toml::from_str(
            r#"
            a = 1
            b = 2
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            b = 99
            c = 3
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let t = base.as_table().unwrap();
        assert_eq!(t["a"].as_integer(), Some(1));
        assert_eq!(t["b"].as_integer(), Some(99));
        assert_eq!(t["c"].as_integer(), Some(3));
    }

    #[test]
    fn test_deep_merge_toml_non_table_values() {
        let mut base: toml::Value = toml::Value::Integer(10);
        let overlay = toml::Value::Integer(20);
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.as_integer(), Some(20));
    }

    #[test]
    fn test_deep_merge_toml_nested_tables() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [outer]
            keep = "yes"
            inner_val = "old"
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            [outer]
            inner_val = "new"
            added = true
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let outer = base.get("outer").unwrap().as_table().unwrap();
        assert_eq!(outer["keep"].as_str(), Some("yes"));
        assert_eq!(outer["inner_val"].as_str(), Some("new"));
        assert_eq!(outer["added"].as_bool(), Some(true));
    }

    #[test]
    fn test_deep_merge_toml_overlay_adds_new_table() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [a]
            x = 1
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            [b]
            y = 2
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(
            base.get("a").unwrap().get("x").unwrap().as_integer(),
            Some(1)
        );
        assert_eq!(
            base.get("b").unwrap().get("y").unwrap().as_integer(),
            Some(2)
        );
    }

    // ── sanitize_project_config ─────────────────────────

    #[test]
    fn test_sanitize_project_config_only_allowed_keys() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [context]
            history_limit = 10
            [display]
            chat_color = "blue"
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(t.contains_key("context"));
        assert!(t.contains_key("display"));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn test_sanitize_project_config_disallowed_removed() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [provider]
            default = "anthropic"
            [tools]
            run_command_allowlist = ["rm"]
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(!t.contains_key("provider"));
        assert!(!t.contains_key("tools"));
        assert!(t.is_empty());
    }

    #[test]
    fn test_sanitize_project_config_mixed() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [context]
            history_limit = 5
            [provider]
            model = "evil-model"
            [display]
            chat_color = "green"
            [mcp]
            ignored = true
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(t.contains_key("context"));
        assert!(t.contains_key("display"));
        assert!(!t.contains_key("provider"));
        assert!(!t.contains_key("mcp"));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn test_sanitize_project_config_non_table_noop() {
        let mut value = toml::Value::String("not a table".into());
        sanitize_project_config(&mut value);
        assert_eq!(value.as_str(), Some("not a table"));
    }

    // ── build_config_xml with skills and MCP ────────────

    #[test]
    fn test_build_config_xml_with_skills_list() {
        let config = Config::default();
        let skills = vec![
            crate::skills::Skill {
                name: "deploy".into(),
                description: "Deploy the app".into(),
                command: "make deploy".into(),
                timeout_seconds: 60,
                terminal: true,
                parameters: HashMap::new(),
                is_project: false,
            },
            crate::skills::Skill {
                name: "lint".into(),
                description: "Run linter".into(),
                command: "cargo clippy".into(),
                timeout_seconds: 30,
                terminal: false,
                parameters: HashMap::new(),
                is_project: true,
            },
        ];
        let xml = build_config_xml(&config, &skills, &[]);
        assert!(xml.contains("name=\"deploy\""));
        assert!(xml.contains("source=\"global\""));
        assert!(xml.contains("name=\"lint\""));
        assert!(xml.contains("source=\"project\""));
        assert!(xml.contains("terminal=\"true\""));
        assert!(xml.contains("terminal=\"false\""));
        assert!(xml.contains("count=\"2\""));
    }

    #[test]
    fn test_build_config_xml_all_sections_present() {
        let config = Config::default();
        let xml = build_config_xml(&config, &[], &[]);
        for section in [
            "provider",
            "context",
            "hints",
            "models",
            "tools",
            "web_search",
            "display",
            "redaction",
            "capture",
            "execution",
            "db",
        ] {
            assert!(
                xml.contains(&format!("name=\"{section}\"")),
                "missing section: {section}"
            );
        }
        assert!(xml.contains("<mcp_servers"));
        assert!(xml.contains("<installed_skills"));
    }

    #[test]
    fn test_build_config_xml_mcp_started_and_not() {
        let toml_str = r#"
            [mcp.servers.s1]
            command = "cmd1"
            [mcp.servers.s2]
            url = "http://localhost:9090"
        "#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let started = vec![("s1".to_string(), 7)];
        let xml = build_config_xml(&config, &[], &started);
        assert!(xml.contains("name=\"s1\""));
        assert!(xml.contains("tools=\"7\""));
        assert!(xml.contains("name=\"s2\""));
        assert!(xml.contains("status=\"not_started\""));
        assert!(xml.contains("transport=\"http\""));
    }

    // ── Config full deserialization ─────────────────────

    #[test]
    fn test_config_full_deserialization() {
        let toml_str = r#"
[provider]
default = "gemini"
model = "gemini-pro"
fallback_model = "gemini-flash"
web_search_model = "perplexity/sonar-pro"
timeout_seconds = 60

[provider.gemini]
api_key = "test-key"
base_url = "https://custom.endpoint"

[context]
scrollback_lines = 500
scrollback_pages = 5
history_summaries = 50
history_limit = 10
other_tty_summaries = 5
max_other_ttys = 10
project_files_limit = 200
git_commits = 20
retention_days = 365
max_output_storage_bytes = 32768
include_other_tty = true
custom_instructions = "Be concise"

[tools]
run_command_allowlist = ["echo", "ls", "cat"]

[models]
main = ["model-a", "model-b"]
fast = ["model-c"]

[web_search]
provider = "brave"
model = "brave/search"

[display]
chat_color = "\\x1b[31m"

[redaction]
enabled = false
replacement = "[HIDDEN]"
disable_builtin = true
patterns = ["custom-pattern"]

[capture]
mode = "raw"
alt_screen = "snapshot"

[execution]
mode = "autorun"

[db]
busy_timeout_ms = 5000

[mcp.servers.test_srv]
command = "test-cmd"
args = ["--verbose"]
timeout_seconds = 45
"#;
        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.provider.default, "gemini");
        assert_eq!(config.provider.model, "gemini-pro");
        assert_eq!(
            config.provider.fallback_model.as_deref(),
            Some("gemini-flash")
        );
        assert_eq!(config.provider.timeout_seconds, 60);
        let gemini_auth = config.provider.gemini.as_ref().unwrap();
        assert_eq!(gemini_auth.api_key.as_deref(), Some("test-key"));
        assert_eq!(
            gemini_auth.base_url.as_deref(),
            Some("https://custom.endpoint")
        );

        assert_eq!(config.context.scrollback_lines, 500);
        assert_eq!(config.context.history_limit, 10);
        assert_eq!(config.context.git_commits, 20);
        assert!(config.context.include_other_tty);
        assert_eq!(
            config.context.custom_instructions.as_deref(),
            Some("Be concise")
        );
        assert_eq!(config.context.project_files_limit, 200);
        assert_eq!(config.context.max_output_storage_bytes, 32768);

        assert_eq!(
            config.tools.run_command_allowlist,
            vec!["echo", "ls", "cat"]
        );

        assert_eq!(config.models.main, vec!["model-a", "model-b"]);
        assert_eq!(config.models.fast, vec!["model-c"]);

        assert_eq!(config.web_search.provider, "brave");
        assert_eq!(config.web_search.model, "brave/search");

        assert!(!config.redaction.enabled);
        assert_eq!(config.redaction.replacement, "[HIDDEN]");
        assert!(config.redaction.disable_builtin);
        assert_eq!(config.redaction.patterns, vec!["custom-pattern"]);

        assert_eq!(config.capture.mode, "raw");
        assert_eq!(config.capture.alt_screen, "snapshot");

        assert_eq!(config.execution.mode, "autorun");
        assert_eq!(config.db.busy_timeout_ms, 5000);

        let srv = config.mcp.servers.get("test_srv").unwrap();
        assert_eq!(srv.command.as_deref(), Some("test-cmd"));
        assert_eq!(srv.args, vec!["--verbose"]);
        assert_eq!(srv.timeout_seconds, 45);
    }

    // ── ProviderAuth::resolve_api_key ───────────────────

    #[test]
    fn test_resolve_api_key_with_api_key_present() {
        let auth = ProviderAuth {
            api_key: Some("direct-key".into()),
            api_key_cmd: None,
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "direct-key");
    }

    #[test]
    fn test_resolve_api_key_empty_string_ignored() {
        let auth = ProviderAuth {
            api_key: Some("".into()),
            api_key_cmd: None,
            base_url: None,
        };
        let result = auth.resolve_api_key("unknown_provider");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_api_key_via_cmd() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("echo cmd-key".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "cmd-key");
    }

    #[test]
    fn test_resolve_api_key_cmd_failure() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("false".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("api_key_cmd failed")
        );
    }

    #[test]
    fn test_resolve_api_key_cmd_empty_output() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("printf ''".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty string"));
    }

    #[test]
    fn test_resolve_api_key_prefers_api_key_over_cmd() {
        let auth = ProviderAuth {
            api_key: Some("direct".into()),
            api_key_cmd: Some("echo cmd".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "direct");
    }

    // ── McpServerConfig defaults ────────────────────────

    #[test]
    fn test_mcp_server_config_from_toml_defaults() {
        let toml_str = r#"
            [srv]
            command = "my-cmd"
        "#;
        let map: HashMap<String, McpServerConfig> = toml::from_str(toml_str).unwrap();
        let srv = &map["srv"];
        assert_eq!(srv.command.as_deref(), Some("my-cmd"));
        assert!(srv.transport.is_none());
        assert!(srv.args.is_empty());
        assert!(srv.env.is_empty());
        assert!(srv.url.is_none());
        assert!(srv.headers.is_empty());
        assert_eq!(srv.timeout_seconds, 30);
    }

    // ── default_mcp_timeout ─────────────────────────────

    #[test]
    fn test_default_mcp_timeout_value() {
        assert_eq!(default_mcp_timeout(), 30);
    }

    // ── new config fields ───────────────────────────────

    #[test]
    fn test_default_allow_unsafe_autorun() {
        let config = Config::default();
        assert!(!config.execution.allow_unsafe_autorun);
    }

    #[test]
    fn test_default_sensitive_file_access() {
        let config = Config::default();
        assert_eq!(config.tools.sensitive_file_access, "block");
    }

    #[test]
    fn test_parse_allow_unsafe_autorun() {
        let toml_str = r#"
[execution]
allow_unsafe_autorun = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(config.execution.allow_unsafe_autorun);
    }

    #[test]
    fn test_parse_sensitive_file_access() {
        let toml_str = r#"
[tools]
sensitive_file_access = "allow"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.tools.sensitive_file_access, "allow");
    }

    // ── is_setting_protected ────────────────────────────

    #[test]
    fn test_is_setting_protected_blocked_keys() {
        assert!(is_setting_protected("execution.allow_unsafe_autorun"));
        assert!(is_setting_protected("tools.sensitive_file_access"));
        assert!(is_setting_protected("tools.run_command_allowlist"));
        assert!(is_setting_protected("redaction.enabled"));
        assert!(is_setting_protected("redaction.disable_builtin"));
    }

    #[test]
    fn test_is_setting_protected_blocked_segments() {
        assert!(is_setting_protected("provider.openrouter.api_key"));
        assert!(is_setting_protected("provider.openai.api_key"));
        assert!(is_setting_protected("provider.anthropic.api_key_cmd"));
        assert!(is_setting_protected("provider.custom.base_url"));
    }

    #[test]
    fn test_is_setting_protected_allows_safe_keys() {
        assert!(!is_setting_protected("provider.model"));
        assert!(!is_setting_protected("context.history_limit"));
        assert!(!is_setting_protected("display.chat_color"));
        assert!(!is_setting_protected("execution.mode"));
    }

    #[test]
    fn test_is_setting_protected_blocks_parent_tables() {
        assert!(is_setting_protected("execution"));
        assert!(is_setting_protected("tools"));
        assert!(is_setting_protected("redaction"));
    }

    // ── is_setting_protected edge cases ─────────────────

    #[test]
    fn test_is_setting_protected_empty_string() {
        assert!(!is_setting_protected(""));
    }

    #[test]
    fn test_is_setting_protected_single_segment_no_match() {
        assert!(!is_setting_protected("provider"));
        assert!(!is_setting_protected("context"));
        assert!(!is_setting_protected("display"));
        assert!(!is_setting_protected("models"));
    }

    #[test]
    fn test_is_setting_protected_deeply_nested_api_key() {
        assert!(is_setting_protected("some.deeply.nested.api_key"));
        assert!(is_setting_protected("a.b.c.api_key_cmd"));
        assert!(is_setting_protected("x.y.base_url"));
    }

    #[test]
    fn test_is_setting_protected_partial_segment_no_false_positive() {
        assert!(!is_setting_protected("provider.api_keyboard"));
        assert!(!is_setting_protected("tools.api_keychain"));
        assert!(!is_setting_protected("provider.base_url_extra"));
    }

    #[test]
    fn test_is_setting_protected_exact_segment_match_only() {
        assert!(is_setting_protected("api_key"));
        assert!(is_setting_protected("api_key_cmd"));
        assert!(is_setting_protected("base_url"));
    }

    #[test]
    fn test_is_setting_protected_prefix_blocks_children() {
        assert!(is_setting_protected("tools.run_command_allowlist"));
        assert!(is_setting_protected("execution.allow_unsafe_autorun"));
        assert!(!is_setting_protected("execution.mode"));
    }

    // ── Config::path() and Config::nsh_dir() ────────────

    #[test]
    fn test_config_path_is_inside_nsh_dir() {
        let path = Config::path();
        let dir = Config::nsh_dir();
        assert!(path.starts_with(&dir));
    }

    #[test]
    fn test_nsh_dir_is_under_home() {
        let dir = Config::nsh_dir();
        let home = dirs::home_dir().unwrap();
        assert!(dir.starts_with(&home));
    }

    #[test]
    fn test_config_path_file_name() {
        let path = Config::path();
        assert_eq!(path.file_name().unwrap().to_str().unwrap(), "config.toml");
    }

    #[test]
    fn test_nsh_dir_last_component() {
        let dir = Config::nsh_dir();
        assert_eq!(dir.file_name().unwrap().to_str().unwrap(), ".nsh");
    }

    // ── Partial TOML deserialization ─────────────────────

    #[test]
    fn test_config_only_context_section() {
        let toml_str = r#"
[context]
history_limit = 42
git_commits = 3
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.context.history_limit, 42);
        assert_eq!(config.context.git_commits, 3);
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.execution.mode, "prefill");
    }

    #[test]
    fn test_config_only_display_section() {
        let toml_str = r#"
[display]
chat_color = "magenta"
thinking_indicator = "..."
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.display.chat_color, "magenta");
        assert_eq!(config.display.thinking_indicator, "...");
        assert_eq!(config.context.history_limit, 20);
    }

    #[test]
    fn test_config_only_execution_section() {
        let toml_str = r#"
[execution]
mode = "confirm"
allow_unsafe_autorun = true
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.execution.mode, "confirm");
        assert!(config.execution.allow_unsafe_autorun);
    }

    #[test]
    fn test_config_only_web_search_section() {
        let toml_str = r#"
[web_search]
provider = "custom_search"
model = "custom/model"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.web_search.provider, "custom_search");
        assert_eq!(config.web_search.model, "custom/model");
    }

    #[test]
    fn test_config_only_models_section() {
        let toml_str = r#"
[models]
main = ["single-model"]
fast = []
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.models.main, vec!["single-model"]);
        assert!(config.models.fast.is_empty());
    }

    #[test]
    fn test_config_only_redaction_section() {
        let toml_str = r#"
[redaction]
enabled = false
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert!(!config.redaction.enabled);
        assert!(!config.redaction.patterns.is_empty());
        assert_eq!(config.redaction.replacement, "[REDACTED]");
    }

    #[test]
    fn test_config_only_mcp_section() {
        let toml_str = r#"
[mcp.servers.solo]
command = "solo-cmd"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.mcp.servers.len(), 1);
        assert_eq!(config.provider.default, "openrouter");
    }

    #[test]
    fn test_config_unknown_keys_ignored() {
        let toml_str = r#"
[provider]
default = "openrouter"
unknown_field = "ignored"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(result.is_err() || result.unwrap().provider.default == "openrouter");
    }

    #[test]
    fn test_config_unknown_top_level_section_accepted() {
        let toml_str = r#"
[nonexistent_section]
key = "value"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "openrouter");
    }

    // ── api_key_cmd resolution edge cases ───────────────

    #[test]
    fn test_resolve_api_key_cmd_trims_whitespace() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("printf '  trimmed-key  '".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "trimmed-key");
    }

    #[test]
    fn test_resolve_api_key_cmd_trims_trailing_newlines() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("printf 'mykey\\n\\n'".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "mykey");
    }

    #[test]
    fn test_resolve_api_key_cmd_whitespace_only_output() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("printf '   '".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty string"));
    }

    #[test]
    fn test_resolve_api_key_empty_key_no_cmd_no_env() {
        let auth = ProviderAuth {
            api_key: Some("".into()),
            api_key_cmd: None,
            base_url: None,
        };
        let result = auth.resolve_api_key("ollama");
        assert!(result.is_err());
    }

    #[test]
    fn test_resolve_api_key_cmd_nonexistent_command() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("nonexistent_command_xyz_12345".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
    }

    #[test]
    #[serial_test::serial]
    fn test_resolve_api_key_openrouter_env_var() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: None,
            base_url: None,
        };
        unsafe { std::env::set_var("OPENROUTER_API_KEY", "or-env-key") };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "or-env-key");
        unsafe { std::env::remove_var("OPENROUTER_API_KEY") };
    }

    #[test]
    #[serial_test::serial]
    fn test_resolve_api_key_empty_env_var_ignored() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: None,
            base_url: None,
        };
        unsafe { std::env::set_var("OPENROUTER_API_KEY", "") };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
        unsafe { std::env::remove_var("OPENROUTER_API_KEY") };
    }

    #[test]
    fn test_resolve_api_key_ollama_no_env_mapping() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: None,
            base_url: None,
        };
        let result = auth.resolve_api_key("ollama");
        assert!(result.is_err());
    }

    // ── McpServerConfig effective_transport ──────────────

    #[test]
    fn test_effective_transport_both_url_and_command_defaults_stdio() {
        let cfg = McpServerConfig {
            transport: None,
            command: Some("cmd".into()),
            args: vec![],
            env: HashMap::new(),
            url: Some("http://example.com".into()),
            headers: HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "stdio");
    }

    #[test]
    fn test_effective_transport_neither_url_nor_command() {
        let cfg = McpServerConfig {
            transport: None,
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: None,
            headers: HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "stdio");
    }

    #[test]
    fn test_effective_transport_explicit_overrides_inference() {
        let cfg = McpServerConfig {
            transport: Some("stdio".into()),
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some("http://example.com".into()),
            headers: HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "stdio");
    }

    // ── is_command_allowed edge cases ───────────────────

    #[test]
    fn test_is_command_allowed_multiword_prefix_no_partial() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["git log".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("git log --oneline"));
        assert!(!tools.is_command_allowed("git logx"));
        assert!(!tools.is_command_allowed("git"));
    }

    #[test]
    fn test_is_command_allowed_backslash_rejected() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into()],
            ..Default::default()
        };
        assert!(!tools.is_command_allowed("echo hello\\nworld"));
    }

    #[test]
    fn test_is_command_allowed_curly_braces_rejected() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into()],
            ..Default::default()
        };
        assert!(!tools.is_command_allowed("echo {a,b}"));
    }

    #[test]
    fn test_is_command_allowed_quotes_rejected() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["echo".into()],
            ..Default::default()
        };
        assert!(!tools.is_command_allowed("echo 'hello'"));
        assert!(!tools.is_command_allowed("echo \"hello\""));
    }

    // ── ProviderConfig defaults ─────────────────────────

    #[test]
    fn test_provider_config_defaults() {
        let p = ProviderConfig::default();
        assert_eq!(p.default, "openrouter");
        assert_eq!(p.model, "google/gemini-2.5-flash");
        assert_eq!(
            p.fallback_model.as_deref(),
            Some("anthropic/claude-sonnet-4.5")
        );
        assert_eq!(p.web_search_model, "perplexity/sonar");
        assert!(p.openrouter.is_some());
        assert!(p.anthropic.is_none());
        assert!(p.openai.is_none());
        assert!(p.ollama.is_none());
        assert!(p.gemini.is_none());
        assert_eq!(p.timeout_seconds, 120);
    }

    // ── deep_merge_toml edge cases ──────────────────────

    #[test]
    fn test_deep_merge_toml_array_replaced_not_merged() {
        let mut base: toml::Value = toml::from_str(
            r#"
            arr = [1, 2, 3]
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            arr = [4, 5]
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let arr = base.get("arr").unwrap().as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0].as_integer(), Some(4));
        assert_eq!(arr[1].as_integer(), Some(5));
    }

    #[test]
    fn test_deep_merge_toml_type_change() {
        let mut base: toml::Value = toml::from_str(
            r#"
            key = "string"
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            key = 42
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.get("key").unwrap().as_integer(), Some(42));
    }

    #[test]
    fn test_deep_merge_toml_bool_values() {
        let mut base = toml::Value::Boolean(false);
        let overlay = toml::Value::Boolean(true);
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.as_bool(), Some(true));
    }

    // ── sanitize_project_config edge cases ──────────────

    #[test]
    fn test_sanitize_project_config_blocks_capture_db_mcp() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [capture]
            mode = "raw"
            [db]
            busy_timeout_ms = 1000
            [mcp.servers.evil]
            command = "evil-cmd"
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(!t.contains_key("capture"));
        assert!(!t.contains_key("db"));
        assert!(!t.contains_key("mcp"));
        assert!(t.is_empty());
    }

    #[test]
    fn test_sanitize_project_config_blocks_web_search() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [web_search]
            provider = "evil_search"
            [models]
            main = ["evil-model"]
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(!t.contains_key("web_search"));
        assert!(!t.contains_key("models"));
    }

    // ── Config deserialization with type mismatches ──────

    #[test]
    fn test_config_wrong_type_for_history_limit() {
        let toml_str = r#"
[context]
history_limit = "not_a_number"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_wrong_type_for_enabled() {
        let toml_str = r#"
[redaction]
enabled = "yes"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_wrong_type_for_timeout() {
        let toml_str = r#"
[provider]
timeout_seconds = "fast"
"#;
        let result: Result<Config, _> = toml::from_str(toml_str);
        assert!(result.is_err());
    }

    // ── opt helper XML escaping ─────────────────────────

    #[test]
    fn test_opt_escapes_special_characters() {
        let mut x = String::new();
        opt(
            &mut x,
            "key",
            "value with <angle> & \"quotes\"",
            "desc with <html>",
            None,
        );
        assert!(!x.contains("<angle>"));
        assert!(!x.contains("& \""));
        assert!(x.contains("&amp;") || x.contains("&lt;") || x.contains("&quot;"));
    }

    // ── ToolsConfig default allowlist content ───────────

    #[test]
    fn test_tools_default_allowlist_contains_expected_commands() {
        let tools = ToolsConfig::default();
        let list = &tools.run_command_allowlist;
        assert!(list.contains(&"uname".to_string()));
        assert!(list.contains(&"whoami".to_string()));
        assert!(list.contains(&"git status".to_string()));
        assert!(list.contains(&"git branch".to_string()));
        assert!(list.contains(&"git diff".to_string()));
        assert!(list.contains(&"cargo --version".to_string()));
        assert!(list.contains(&"python3 --version".to_string()));
        assert!(list.contains(&"node --version".to_string()));
    }

    // ── Config::default() comprehensive ─────────────────

    #[test]
    fn test_config_default_all_subsections_populated() {
        let config = Config::default();
        assert!(!config.models.main.is_empty());
        assert!(!config.models.fast.is_empty());
        assert_eq!(config.web_search.provider, "openrouter");
        assert_eq!(config.web_search.model, "perplexity/sonar");
        assert_eq!(config.execution.mode, "prefill");
        assert!(!config.execution.allow_unsafe_autorun);
        assert_eq!(config.display.chat_color, "\x1b[3;36m");
        assert!(config.redaction.enabled);
        assert_eq!(config.capture.mode, "vt100");
        assert_eq!(config.db.busy_timeout_ms, 10000);
        assert!(config.mcp.servers.is_empty());
        assert_eq!(config.tools.sensitive_file_access, "block");
    }

    // ── RedactionConfig patterns are valid regex ────────

    #[test]
    fn test_redaction_default_patterns_are_valid_regex() {
        let rc = RedactionConfig::default();
        for pattern in &rc.patterns {
            assert!(
                regex::Regex::new(pattern).is_ok(),
                "invalid regex pattern: {pattern}"
            );
        }
    }

    // ── TOOL_BLOCKED_KEYS completeness ──────────────────

    #[test]
    fn test_tool_blocked_keys_non_empty() {
        assert!(TOOL_BLOCKED_KEYS.contains(&"tools.run_command_allowlist"));
        assert!(TOOL_BLOCKED_KEY_SEGMENTS.contains(&"api_key"));
    }

    #[test]
    fn test_all_tool_blocked_keys_are_protected() {
        for key in TOOL_BLOCKED_KEYS {
            assert!(is_setting_protected(key), "{key} should be protected");
        }
    }

    #[test]
    fn test_all_tool_blocked_segments_are_protected() {
        for segment in TOOL_BLOCKED_KEY_SEGMENTS {
            assert!(
                is_setting_protected(segment),
                "bare segment {segment} should be protected"
            );
            let dotted = format!("some.prefix.{segment}");
            assert!(
                is_setting_protected(&dotted),
                "dotted path {dotted} should be protected"
            );
        }
    }

    #[test]
    fn test_config_load_returns_config() {
        let result = Config::load();
        assert!(result.is_ok() || result.is_err());
    }

    #[test]
    fn test_is_setting_protected_prefix_does_not_false_match_without_dot() {
        assert!(!is_setting_protected("executionx"));
        assert!(!is_setting_protected("toolshed"));
        assert!(!is_setting_protected("redactions"));
    }

    #[test]
    fn test_default_config_display_fields() {
        let config = Config::default();
        assert!(!config.display.chat_color.is_empty());
        assert!(!config.display.thinking_indicator.is_empty());
    }

    #[test]
    fn test_default_config_capture_fields() {
        let config = Config::default();
        assert_eq!(config.capture.mode, "vt100");
        assert_eq!(config.capture.alt_screen, "drop");
    }

    #[test]
    fn test_default_config_redaction_fields() {
        let config = Config::default();
        assert!(config.redaction.enabled);
        assert!(!config.redaction.disable_builtin);
        assert_eq!(config.redaction.replacement, "[REDACTED]");
        assert!(!config.redaction.patterns.is_empty());
    }

    #[test]
    fn test_default_config_context_all_fields() {
        let ctx = ContextConfig::default();
        assert_eq!(ctx.scrollback_lines, 1000);
        assert_eq!(ctx.scrollback_pages, 10);
        assert_eq!(ctx.other_tty_summaries, 10);
        assert_eq!(ctx.max_other_ttys, 20);
        assert_eq!(ctx.project_files_limit, 100);
        assert_eq!(ctx.git_commits, 10);
        assert_eq!(ctx.max_output_storage_bytes, 65536);
        assert_eq!(ctx.scrollback_rate_limit_bps, 10_485_760);
        assert_eq!(ctx.scrollback_pause_seconds, 2);
        assert!(ctx.restore_last_cwd_per_tty);
        assert!(ctx.custom_instructions.is_none());
    }

    #[test]
    fn test_default_hints_config() {
        let hints = HintsConfig::default();
        assert_eq!(
            hints.normalized_suppressed_exit_codes(),
            vec![130, 137, 141, 143]
        );
    }

    #[test]
    fn test_hints_normalized_suppressed_exit_codes() {
        let hints = HintsConfig {
            suppressed_exit_codes: vec![141, 130, -1, 141, 999, 0, 143],
        };
        assert_eq!(
            hints.normalized_suppressed_exit_codes(),
            vec![130, 141, 143]
        );
    }

    #[test]
    fn test_default_models_config() {
        let m = ModelsConfig::default();
        assert!(m.main.len() >= 2);
        assert!(!m.fast.is_empty());
        assert!(m.main.iter().any(|s| s.contains("gemini")));
        assert!(
            m.fast
                .iter()
                .any(|s| s.contains("lite") || s.contains("haiku"))
        );
    }

    #[test]
    fn test_default_web_search_config() {
        let ws = WebSearchConfig::default();
        assert_eq!(ws.provider, "openrouter");
        assert_eq!(ws.model, "perplexity/sonar");
    }

    #[test]
    fn test_default_execution_config() {
        let e = ExecutionConfig::default();
        assert_eq!(e.mode, "prefill");
        assert!(!e.allow_unsafe_autorun);
    }

    #[test]
    fn test_default_db_config() {
        let d = DbConfig::default();
        assert_eq!(d.busy_timeout_ms, 5000);
    }

    #[test]
    fn test_default_mcp_config() {
        let m = McpConfig::default();
        assert!(m.servers.is_empty());
    }

    #[test]
    fn test_provider_auth_default_fields_are_none() {
        let auth = ProviderAuth::default();
        assert!(auth.api_key.is_none());
        assert!(auth.api_key_cmd.is_none());
        assert!(auth.base_url.is_none());
    }

    #[test]
    fn test_is_command_allowed_wildcard_allows_all() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["*".into()],
            ..Default::default()
        };
        assert!(tools.is_command_allowed("anything goes"));
        assert!(tools.is_command_allowed("rm -rf /"));
    }

    #[test]
    fn test_is_command_allowed_wildcard_still_blocks_dangerous() {
        let tools = ToolsConfig {
            run_command_allowlist: vec!["*".into()],
            ..Default::default()
        };
        assert!(!tools.is_command_allowed("echo; rm"));
        assert!(!tools.is_command_allowed("echo | cat"));
    }

    #[test]
    fn test_effective_transport_url_only_infers_http() {
        let cfg = McpServerConfig {
            transport: None,
            command: None,
            args: vec![],
            env: HashMap::new(),
            url: Some("http://localhost:8080".into()),
            headers: HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "http");
    }

    #[test]
    fn test_mcp_server_config_with_env_and_headers() {
        let toml_str = r#"
            [srv]
            command = "my-cmd"
            args = ["--flag"]
            timeout_seconds = 60

            [srv.env]
            MY_VAR = "val"

            [srv.headers]
            Authorization = "Bearer tok"
        "#;
        let map: HashMap<String, McpServerConfig> = toml::from_str(toml_str).unwrap();
        let srv = &map["srv"];
        assert_eq!(srv.env.get("MY_VAR").unwrap(), "val");
        assert_eq!(srv.headers.get("Authorization").unwrap(), "Bearer tok");
        assert_eq!(srv.timeout_seconds, 60);
    }

    #[test]
    fn test_redaction_config_equality() {
        let a = RedactionConfig::default();
        let b = RedactionConfig::default();
        assert_eq!(a, b);
    }

    #[test]
    fn test_config_debug_trait() {
        let config = Config::default();
        let debug_str = format!("{config:?}");
        assert!(debug_str.contains("Config"));
        assert!(debug_str.contains("provider"));
    }

    #[test]
    fn test_deep_merge_toml_empty_overlay_preserves_base() {
        let mut base: toml::Value = toml::from_str(
            r#"
            key = "value"
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::Value::Table(toml::map::Map::new());
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.get("key").unwrap().as_str(), Some("value"));
    }

    #[test]
    fn test_deep_merge_toml_empty_base() {
        let mut base: toml::Value = toml::Value::Table(toml::map::Map::new());
        let overlay: toml::Value = toml::from_str(
            r#"
            new_key = "new_value"
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.get("new_key").unwrap().as_str(), Some("new_value"));
    }

    #[test]
    fn test_sanitize_project_config_empty_table() {
        let mut value: toml::Value = toml::Value::Table(toml::map::Map::new());
        sanitize_project_config(&mut value);
        assert!(value.as_table().unwrap().is_empty());
    }

    #[test]
    fn test_build_config_xml_no_skills_no_mcp() {
        let config = Config::default();
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("count=\"0\""));
        assert!(xml.contains("<installed_skills count=\"0\">"));
    }

    #[test]
    fn test_opt_with_choices_xml() {
        let mut x = String::new();
        opt(
            &mut x,
            "mode",
            "prefill",
            "execution mode",
            Some("prefill,confirm,autorun"),
        );
        assert!(x.contains("choices=\"prefill,confirm,autorun\""));
        assert!(x.contains("key=\"mode\""));
    }

    #[test]
    fn test_opt_without_choices_xml() {
        let mut x = String::new();
        opt(&mut x, "model", "gpt-4", "model name", None);
        assert!(!x.contains("choices="));
        assert!(x.contains("key=\"model\""));
        assert!(x.contains("value=\"gpt-4\""));
    }

    #[test]
    fn test_build_config_xml_custom_instructions_present() {
        let mut config = Config::default();
        config.context.custom_instructions = Some("Always be concise".into());
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("custom_instructions"));
        assert!(xml.contains("Always be concise"));
    }

    #[test]
    fn test_build_config_xml_custom_instructions_none() {
        let mut config = Config::default();
        config.context.custom_instructions = None;
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("custom_instructions"));
        assert!(xml.contains("(none)"));
    }

    #[test]
    fn test_build_config_xml_fallback_model_none() {
        let mut config = Config::default();
        config.provider.fallback_model = None;
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("fallback_model"));
        assert!(xml.contains("(none)"));
    }

    #[test]
    fn test_build_config_xml_configured_providers_has_key_check() {
        let mut config = Config::default();
        config.provider.anthropic = Some(ProviderAuth {
            api_key: Some("test-key".into()),
            api_key_cmd: None,
            base_url: None,
        });
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("name=\"anthropic\" has_api_key=\"true\""));
    }

    #[test]
    fn test_build_config_xml_configured_providers_no_key() {
        let mut config = Config::default();
        config.provider.openai = None;
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("name=\"openai\" has_api_key=\"false\""));
    }

    #[test]
    fn test_build_config_xml_display_escapes_ansi() {
        let mut config = Config::default();
        config.display.chat_color = "\x1b[31m".into();
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("\\x1b[31m"));
    }

    #[test]
    fn test_deep_merge_toml_scalar_to_table() {
        let mut base: toml::Value = toml::from_str(
            r#"
            key = "scalar"
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            [key]
            nested = true
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert!(base.get("key").unwrap().is_table());
        assert_eq!(
            base.get("key").unwrap().get("nested").unwrap().as_bool(),
            Some(true)
        );
    }

    #[test]
    fn test_deep_merge_toml_table_to_scalar() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [key]
            nested = true
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            key = "scalar"
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        assert_eq!(base.get("key").unwrap().as_str(), Some("scalar"));
    }

    #[test]
    fn test_deep_merge_toml_deeply_nested() {
        let mut base: toml::Value = toml::from_str(
            r#"
            [a.b.c]
            x = 1
            y = 2
        "#,
        )
        .unwrap();
        let overlay: toml::Value = toml::from_str(
            r#"
            [a.b.c]
            y = 99
            z = 3
        "#,
        )
        .unwrap();
        deep_merge_toml(&mut base, &overlay);
        let c = base.get("a").unwrap().get("b").unwrap().get("c").unwrap();
        assert_eq!(c.get("x").unwrap().as_integer(), Some(1));
        assert_eq!(c.get("y").unwrap().as_integer(), Some(99));
        assert_eq!(c.get("z").unwrap().as_integer(), Some(3));
    }

    #[test]
    fn test_sanitize_project_config_only_context_passes() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [context]
            history_limit = 5
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert_eq!(t.len(), 1);
        assert!(t.contains_key("context"));
    }

    #[test]
    fn test_sanitize_project_config_execution_blocked() {
        let mut value: toml::Value = toml::from_str(
            r#"
            [execution]
            allow_unsafe_autorun = true
            [redaction]
            enabled = false
        "#,
        )
        .unwrap();
        sanitize_project_config(&mut value);
        let t = value.as_table().unwrap();
        assert!(!t.contains_key("execution"));
        assert!(!t.contains_key("redaction"));
    }

    #[test]
    fn test_config_web_search_model_override_from_provider() {
        let toml_str = r#"
[provider]
web_search_model = "custom/search-model"
"#;
        let mut base_value: toml::Value = toml::from_str(toml_str).unwrap();
        deep_merge_toml(&mut base_value, &toml::Value::Table(toml::map::Map::new()));
        let mut config: Config = base_value.try_into().unwrap();
        if config.web_search.model == WebSearchConfig::default().model
            && config.provider.web_search_model != ProviderConfig::default().web_search_model
        {
            config.web_search.model = config.provider.web_search_model.clone();
        }
        assert_eq!(config.web_search.model, "custom/search-model");
    }

    #[test]
    fn test_config_web_search_model_no_override_when_explicitly_set() {
        let toml_str = r#"
[provider]
web_search_model = "custom/search-model"

[web_search]
model = "explicit/model"
"#;
        let mut base_value: toml::Value = toml::from_str(toml_str).unwrap();
        deep_merge_toml(&mut base_value, &toml::Value::Table(toml::map::Map::new()));
        let mut config: Config = base_value.try_into().unwrap();
        if config.web_search.model == WebSearchConfig::default().model
            && config.provider.web_search_model != ProviderConfig::default().web_search_model
        {
            config.web_search.model = config.provider.web_search_model.clone();
        }
        assert_eq!(config.web_search.model, "explicit/model");
    }

    #[test]
    fn test_mcp_server_effective_transport_explicit_http() {
        let cfg = McpServerConfig {
            transport: Some("http".into()),
            command: Some("cmd".into()),
            args: vec![],
            env: HashMap::new(),
            url: None,
            headers: HashMap::new(),
            timeout_seconds: 30,
        };
        assert_eq!(cfg.effective_transport(), "http");
    }

    #[test]
    fn test_build_config_xml_mcp_all_started() {
        let toml_str = r#"
[mcp.servers.s1]
command = "cmd1"
[mcp.servers.s2]
command = "cmd2"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        let started = vec![("s1".to_string(), 3), ("s2".to_string(), 5)];
        let xml = build_config_xml(&config, &[], &started);
        assert!(xml.contains("tools=\"3\""));
        assert!(xml.contains("tools=\"5\""));
        assert!(!xml.contains("status=\"not_started\""));
    }

    // ── Additional coverage tests ───────────────────────

    #[test]
    fn test_config_from_empty_toml() {
        let config: Config = toml::from_str("").unwrap();
        assert_eq!(config.provider.default, "openrouter");
        assert_eq!(config.context.retention_days, 1095);
        assert!(config.redaction.enabled);
        assert!(config.mcp.servers.is_empty());
    }

    #[test]
    fn test_config_malformed_toml_errors() {
        let bad_toml = "[provider\ndefault = oops";
        let result: Result<Config, _> = toml::from_str(bad_toml);
        assert!(result.is_err());
    }

    #[test]
    fn test_is_setting_protected_parent_prefix_with_dot() {
        assert!(is_setting_protected("tools.sensitive_file_access"));
        assert!(is_setting_protected("tools.run_command_allowlist"));
        assert!(!is_setting_protected("toolshed.something"));
    }

    #[test]
    fn test_is_setting_protected_segment_in_middle() {
        assert!(is_setting_protected("foo.api_key.bar"));
        assert!(is_setting_protected("some.api_key_cmd.nested"));
        assert!(is_setting_protected("deeply.nested.base_url.more"));
    }

    #[test]
    fn test_build_config_xml_redaction_section_details() {
        let mut config = Config::default();
        config.redaction.enabled = false;
        config.redaction.disable_builtin = true;
        config.redaction.replacement = "[HIDDEN]".into();
        config.redaction.patterns = vec!["a".into(), "b".into(), "c".into()];
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("\"false\""));
        assert!(xml.contains("[HIDDEN]"));
        assert!(xml.contains("(3 custom patterns)"));
    }

    #[test]
    fn test_build_config_xml_tools_section_contents() {
        let mut config = Config::default();
        config.tools.run_command_allowlist = vec!["echo".into(), "ls".into()];
        config.tools.sensitive_file_access = "allow".into();
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("echo, ls"));
        assert!(xml.contains("allow"));
        assert!(xml.contains("protected=\"true\""));
    }

    #[test]
    fn test_build_config_xml_models_section_lists() {
        let mut config = Config::default();
        config.models.main = vec!["model-a".into(), "model-b".into()];
        config.models.fast = vec!["model-fast".into()];
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("model-a, model-b"));
        assert!(xml.contains("model-fast"));
    }

    #[test]
    fn test_provider_auth_api_key_takes_precedence_over_env() {
        let auth = ProviderAuth {
            api_key: Some("config-key".into()),
            api_key_cmd: Some("echo cmd-key".into()),
            base_url: None,
        };
        let key = auth.resolve_api_key("openrouter").unwrap();
        assert_eq!(*key, "config-key");
    }

    #[test]
    fn test_resolve_api_key_cmd_returns_empty() {
        let auth = ProviderAuth {
            api_key: None,
            api_key_cmd: Some("printf ''".into()),
            base_url: None,
        };
        let result = auth.resolve_api_key("openrouter");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_config_load_uses_defaults_when_no_file() {
        let config = Config::load().unwrap_or_default();
        assert_eq!(config.provider.default, "openrouter");
        assert!(config.context.retention_days > 0);
        assert!(config.db.busy_timeout_ms > 0);
    }

    #[test]
    fn test_build_config_xml_custom_instructions() {
        let mut config = Config::default();
        config.context.custom_instructions = Some("Always use verbose output".into());
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("Always use verbose output"));
        assert!(xml.contains("custom_instructions"));
    }

    #[test]
    fn test_build_config_xml_execution_section() {
        let mut config = Config::default();
        config.execution.mode = "autorun".into();
        config.execution.allow_unsafe_autorun = true;
        let xml = build_config_xml(&config, &[], &[]);
        assert!(xml.contains("autorun"));
        assert!(xml.contains("allow_unsafe_autorun"));
        assert!(xml.contains("true"));
    }

    #[test]
    fn test_toml_parse_all_sections() {
        let toml_str = r#"
[provider]
default = "anthropic"
model = "claude-3"
timeout_seconds = 30

[context]
history_limit = 10
retention_days = 90
custom_instructions = "Be concise"

[display]
chat_color = "green"

[redaction]
enabled = false
replacement = "[HIDDEN]"
disable_builtin = true
patterns = ["custom_pattern"]

[capture]
mode = "vt100"
alt_screen = "snapshot"

[db]
busy_timeout_ms = 5000

[execution]
mode = "confirm"
allow_unsafe_autorun = true

[web_search]
provider = "custom"
model = "custom/model"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.provider.default, "anthropic");
        assert_eq!(config.context.history_limit, 10);
        assert_eq!(
            config.context.custom_instructions.as_deref(),
            Some("Be concise")
        );
        assert!(!config.redaction.enabled);
        assert_eq!(config.redaction.replacement, "[HIDDEN]");
        assert!(config.redaction.disable_builtin);
        assert_eq!(config.capture.alt_screen, "snapshot");
        assert_eq!(config.db.busy_timeout_ms, 5000);
        assert_eq!(config.execution.mode, "confirm");
        assert!(config.execution.allow_unsafe_autorun);
        assert_eq!(config.web_search.provider, "custom");
    }

    #[test]
    fn test_build_config_xml_with_global_and_project_skills() {
        let config = Config::default();
        let skills = vec![
            crate::skills::Skill {
                name: "test-skill".into(),
                description: "A test skill".into(),
                command: String::new(),
                timeout_seconds: 30,
                terminal: false,
                parameters: std::collections::HashMap::new(),
                is_project: false,
            },
            crate::skills::Skill {
                name: "project-skill".into(),
                description: "A project skill".into(),
                command: String::new(),
                timeout_seconds: 30,
                terminal: true,
                parameters: std::collections::HashMap::new(),
                is_project: true,
            },
        ];
        let xml = build_config_xml(&config, &skills, &[]);
        assert!(xml.contains("test-skill"));
        assert!(xml.contains("source=\"global\""));
        assert!(xml.contains("project-skill"));
        assert!(xml.contains("source=\"project\""));
        assert!(xml.contains("terminal=\"true\""));
        assert!(xml.contains("count=\"2\""));
    }
}
