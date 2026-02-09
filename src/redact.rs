use std::sync::LazyLock;

use crate::config::RedactionConfig;

static COMPILED_DEFAULTS: LazyLock<Vec<regex::Regex>> = LazyLock::new(|| {
    RedactionConfig::default()
        .patterns
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect()
});

pub fn redact_secrets(text: &str, config: &RedactionConfig) -> String {
    if !config.enabled {
        return text.to_string();
    }

    let regexes: Vec<regex::Regex>;
    let patterns = if config.patterns == RedactionConfig::default().patterns {
        &*COMPILED_DEFAULTS
    } else {
        regexes = config
            .patterns
            .iter()
            .filter_map(|p| regex::Regex::new(p).ok())
            .collect();
        &regexes
    };

    let mut result = text.to_string();
    for re in patterns {
        result = re.replace_all(&result, config.replacement.as_str()).to_string();
    }
    result
}
