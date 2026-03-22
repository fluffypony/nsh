use serde_json::json;

/// Apply provider-specific "thinking" knobs into an OpenAI-compatible request body.
pub fn apply_thinking_mode(body: &mut serde_json::Value, model: &str, think: bool) {
    if !think {
        if model.starts_with("google/gemini-3") {
            body["reasoning"] = json!({"effort": "low"});
        }
        return;
    }
    if model.starts_with("google/gemini-3") {
        body["reasoning"] = json!({"effort": "high"});
    } else if model.contains("claude") && model.contains("sonnet") {
        body["reasoning"] = json!({"enabled": true, "budget_tokens": 32768});
    }
}

/// Select the effective model name to use when "thinking" mode is enabled.
pub fn thinking_model_name(model: &str, think: bool) -> String {
    if think
        && (model.starts_with("google/gemini-2.5") || model.starts_with("google/gemini-3"))
        && !model.ends_with(":thinking")
    {
        format!("{model}:thinking")
    } else {
        model.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_thinking_mode_gemini3_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", false);
        assert_eq!(body["reasoning"]["effort"], "low");
    }

    #[test]
    fn apply_thinking_mode_gemini3_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", true);
        assert_eq!(body["reasoning"]["effort"], "high");
    }

    #[test]
    fn apply_thinking_mode_claude_sonnet_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["reasoning"]["budget_tokens"], 32768);
    }

    #[test]
    fn thinking_model_name_gemini_25_think() {
        let result = thinking_model_name("google/gemini-2.5-pro", true);
        assert_eq!(result, "google/gemini-2.5-pro:thinking");
    }

    #[test]
    fn thinking_model_name_non_google_no_change() {
        assert_eq!(thinking_model_name("claude-3-opus", true), "claude-3-opus");
        assert_eq!(thinking_model_name("gpt-4o", false), "gpt-4o");
    }
}
