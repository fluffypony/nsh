/// Shared model defaults used by config defaults and autoconfigure.
///
/// Keep provider model choices centralized here so updates stay consistent
/// across all entry points.
pub struct ProviderModelDefaults {
    pub default_model: &'static str,
    pub main: &'static [&'static str],
    pub fast: &'static [&'static str],
    pub coding: &'static [&'static str],
}

pub const DEFAULT_PROVIDER: &str = "openrouter";
pub const DEFAULT_FALLBACK_MODEL: &str = "anthropic/claude-sonnet-4.6";
pub const DEFAULT_WEB_SEARCH_PROVIDER: &str = "openrouter";
pub const DEFAULT_WEB_SEARCH_MODEL: &str = "perplexity/sonar";

pub const GEMINI_25_PRO_OPENROUTER: &str = "google/gemini-2.5-pro";
pub const GEMINI_3_PRO_OPENROUTER: &str = "google/gemini-3-pro";

const OPENROUTER_MAIN: &[&str] = &[
    "google/gemini-3.1-flash-lite-preview",
    "google/gemini-3-flash-preview",
    "anthropic/claude-sonnet-4.6",
];
const OPENROUTER_FAST: &[&str] = &["google/gemini-3.1-flash-lite-preview", "anthropic/claude-haiku-4.5"];
const OPENROUTER_CODING: &[&str] = &["anthropic/claude-opus-4.6", "anthropic/claude-sonnet-4.6"];

const ANTHROPIC_MAIN: &[&str] = &["claude-sonnet-4.6"];
const ANTHROPIC_FAST: &[&str] = &["claude-haiku-4.5"];
const ANTHROPIC_CODING: &[&str] = &["claude-opus-4.6", "claude-sonnet-4.6"];

const OPENAI_MAIN: &[&str] = &["gpt-5.2", "gpt-5.1"];
const OPENAI_FAST: &[&str] = &["gpt-5.1-codex-mini"];
const OPENAI_CODING: &[&str] = &["gpt-5.2-codex", "gpt-5.1-codex"];

const GEMINI_MAIN: &[&str] = &["gemini-3.1-flash-lite-preview", "gemini-3-flash-preview"];
const GEMINI_FAST: &[&str] = &["gemini-3.1-flash-lite-preview"];
const GEMINI_CODING: &[&str] = &[
    "gemini-3.1-pro-preview",
    "gemini-3-pro-preview",
    "gemini-2.5-flash",
];

const OPENROUTER_DEFAULTS: ProviderModelDefaults = ProviderModelDefaults {
    default_model: "google/gemini-3.1-flash-lite-preview",
    main: OPENROUTER_MAIN,
    fast: OPENROUTER_FAST,
    coding: OPENROUTER_CODING,
};

const ANTHROPIC_DEFAULTS: ProviderModelDefaults = ProviderModelDefaults {
    default_model: "claude-sonnet-4.6",
    main: ANTHROPIC_MAIN,
    fast: ANTHROPIC_FAST,
    coding: ANTHROPIC_CODING,
};

const OPENAI_DEFAULTS: ProviderModelDefaults = ProviderModelDefaults {
    default_model: "gpt-5.2",
    main: OPENAI_MAIN,
    fast: OPENAI_FAST,
    coding: OPENAI_CODING,
};

const GEMINI_DEFAULTS: ProviderModelDefaults = ProviderModelDefaults {
    default_model: "gemini-3.1-flash-lite-preview",
    main: GEMINI_MAIN,
    fast: GEMINI_FAST,
    coding: GEMINI_CODING,
};

pub fn provider_models(provider: &str) -> ProviderModelDefaults {
    match provider {
        "openrouter" => OPENROUTER_DEFAULTS,
        "anthropic" => ANTHROPIC_DEFAULTS,
        "openai" => OPENAI_DEFAULTS,
        "gemini" => GEMINI_DEFAULTS,
        _ => OPENAI_DEFAULTS,
    }
}

pub fn to_vec(models: &[&str]) -> Vec<String> {
    models.iter().map(|m| (*m).to_string()).collect()
}
