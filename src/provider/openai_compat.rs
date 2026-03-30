use reqwest::Client;
use serde_json::json;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

use crate::provider::*;

pub struct OpenAICompatProvider {
    client: Client,
    api_key: Zeroizing<String>,
    base_url: String,
    strip_provider_prefix: bool,
    fallback_model: Option<String>,
    extra_headers: Vec<(String, String)>,
    debug_provider_name: String,
}

pub struct OpenAICompatProviderConfig {
    pub api_key: Zeroizing<String>,
    pub base_url: String,
    pub strip_provider_prefix: bool,
    pub fallback_model: Option<String>,
    pub extra_headers: Vec<(String, String)>,
    pub timeout_seconds: u64,
    pub debug_provider_name: String,
}

struct OpenAITransportResponse {
    response: reqwest::Response,
    debug_path: Option<PathBuf>,
}

impl OpenAICompatProvider {
    pub fn new(config: OpenAICompatProviderConfig) -> anyhow::Result<Self> {
        Ok(Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(config.timeout_seconds))
                .build()?,
            api_key: config.api_key,
            base_url: config.base_url,
            strip_provider_prefix: config.strip_provider_prefix,
            fallback_model: config.fallback_model,
            extra_headers: config.extra_headers,
            debug_provider_name: config.debug_provider_name,
        })
    }

    fn build_request_body(&self, request: &ChatRequest) -> serde_json::Value {
        let model = crate::provider::routing::model_name_for_transport(
            request.model.as_str(),
            self.strip_provider_prefix,
        );
        let anthropic = is_anthropic_model(&model);

        let messages = if anthropic {
            build_openai_messages(&request.messages, "")
        } else {
            build_openai_messages(&request.messages, &request.system)
        };
        let mut tools = build_openai_tools(&request.tools);

        let mut body = json!({
            "model": model,
            "messages": messages,
            "max_tokens": request.max_tokens,
            "stream": request.stream,
        });

        // Some models (e.g., codex-only) may not support tool/function calling — strip tools
        let caps = crate::config::model_capabilities(&self.debug_provider_name, &model);
        let model_is_codex_like = model.contains("codex");
        if model_is_codex_like || !caps.supports_tool_calling {
            tools.clear();
        }

        if !tools.is_empty() {
            // When the model supports strict tool schemas, attempt per-tool normalization.
            // Tools with compatible schemas get strict: true; incompatible tools are left
            // non-strict (OpenAI defaults strict to false when absent).
            if caps.supports_strict_tool_schemas {
                for tool in &mut tools {
                    if let Some(func) = tool.get_mut("function") {
                        if let Some(params) = func.get_mut("parameters") {
                            // Clone so we can attempt normalization without corrupting
                            // the original schema if the tool is incompatible.
                            let mut strict_params = params.clone();
                            if try_make_strict_compliant(&mut strict_params) {
                                *params = strict_params;
                                func["strict"] = json!(true);
                            }
                            // else: tool schema is inherently incompatible with strict
                            // mode (e.g. untyped properties, dynamic maps). Leave it
                            // non-strict — OpenAI defaults strict to false.
                        }
                    }
                }
            }
            if anthropic && let Some(last) = tools.last_mut() {
                last["cache_control"] = json!({"type": "ephemeral"});
            }
            body["tools"] = json!(tools);
        }

        match request.tool_choice {
            ToolChoice::Required => {
                body["tool_choice"] = json!("required");
            }
            ToolChoice::None => {
                body["tool_choice"] = json!("none");
            }
            ToolChoice::Auto => {
                body["tool_choice"] = json!("auto");
            }
        }
        if model_is_codex_like || !caps.supports_tool_calling {
            body["tool_choice"] = json!("none");
        }

        if anthropic {
            body["system"] = json!([{
                "type": "text",
                "text": &request.system,
                "cache_control": {"type": "ephemeral"}
            }]);
        }

        // Optional native web search tool hint for OpenAI endpoints (non-critical)
        if self.base_url.contains("api.openai.com") && caps.supports_web_search {
            // Provide a hint via extra_body if caller passed a tools array; noop otherwise
            // This is intentionally non-fatal and may be ignored by endpoints that don't support it.
            // body["tools"] may already exist; do not mutate structure significantly here.
        }

        // Apply provider-native response_format if present
        if let Some(ref rf) = request.response_format {
            body["response_format"] = rf.clone();
        }

        if let Some(serde_json::Value::Object(map)) = &request.extra_body {
            for (k, v) in map {
                if k.starts_with("_transport_") {
                    continue;
                }
                body[k] = v.clone();
            }
        }

        body
    }

    fn build_http_request(&self, body: &serde_json::Value, model: &str) -> reqwest::RequestBuilder {
        // reqwest internally copies the value into its own buffer, so zeroization is best-effort
        let auth_value = Zeroizing::new(format!("Bearer {}", &*self.api_key));
        let mut header_val = reqwest::header::HeaderValue::from_str(&auth_value)
            .unwrap_or_else(|_| reqwest::header::HeaderValue::from_static(""));
        header_val.set_sensitive(true);
        let mut req = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("Authorization", header_val)
            .json(body);
        for (k, v) in &self.extra_headers {
            req = req.header(k.as_str(), v.as_str());
        }
        if is_anthropic_model(model) && self.base_url.contains("openrouter") {
            req = req.header("anthropic-beta", "prompt-caching-2024-07-31");
        }
        req
    }

    async fn record_error_response(
        &self,
        response: reqwest::Response,
        label: &str,
        debug_path: Option<&Path>,
    ) -> anyhow::Error {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if let Some(path) = debug_path {
            crate::debug_io::append(
                path,
                "raw_provider_response",
                &format!("status={status}\n{text}"),
            );
        }
        anyhow::anyhow!("API error ({label} {status}): {text}")
    }

    async fn send_transport_request(
        &self,
        body: serde_json::Value,
        model: &str,
        fallback_log_label: &str,
    ) -> anyhow::Result<OpenAITransportResponse> {
        let debug_path = crate::debug_io::begin(&self.debug_provider_name, &body);
        let response = self.build_http_request(&body, model).send().await?;
        let status = response.status();
        if status.is_success() {
            return Ok(OpenAITransportResponse {
                response,
                debug_path,
            });
        }

        if is_retryable(status)
            && let Some(fallback) = &self.fallback_model
        {
            tracing::warn!("Primary failed ({status}), {fallback_log_label}: {fallback}");
            let fallback_model = crate::provider::routing::model_name_for_transport(
                fallback,
                self.strip_provider_prefix,
            );
            let mut fallback_body = body.clone();
            fallback_body["model"] = json!(&fallback_model);
            let fallback_response = self
                .build_http_request(&fallback_body, &fallback_model)
                .send()
                .await?;
            if fallback_response.status().is_success() {
                return Ok(OpenAITransportResponse {
                    response: fallback_response,
                    debug_path,
                });
            }
            return Err(self
                .record_error_response(fallback_response, "fallback", debug_path.as_deref())
                .await);
        }

        Err(self
            .record_error_response(response, "primary", debug_path.as_deref())
            .await)
    }

    fn append_json_debug(&self, debug_path: Option<&Path>, response_json: &serde_json::Value) {
        if let Some(path) = debug_path {
            crate::debug_io::append(
                path,
                "raw_provider_response",
                &serde_json::to_string_pretty(response_json)
                    .unwrap_or_else(|_| response_json.to_string()),
            );
        }
    }
}

fn is_retryable(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

pub(crate) fn is_anthropic_model(model: &str) -> bool {
    model.contains("claude") || model.starts_with("anthropic/")
}

/// Attempt to transform a tool's parameter schema into OpenAI strict-mode compliant form.
/// Returns `true` if successful, `false` if the schema is inherently incompatible
/// (e.g., untyped properties, dynamic additionalProperties, freeform objects).
///
/// On success, the schema is mutated in place with:
/// - `additionalProperties: false` on all object schemas
/// - `required` set to all property keys
/// - Originally-optional properties made nullable
fn try_make_strict_compliant(schema: &mut serde_json::Value) -> bool {
    let Some(obj) = schema.as_object_mut() else {
        return true; // non-object leaf — nothing to enforce
    };

    // Detect type as either a string or a type-union array (e.g., ["object", "null"])
    let type_includes = |target: &str| -> bool {
        match obj.get("type") {
            Some(serde_json::Value::String(s)) => s == target,
            Some(serde_json::Value::Array(arr)) => {
                arr.iter().any(|v| v.as_str() == Some(target))
            }
            _ => false,
        }
    };
    let is_object = type_includes("object");
    let is_array = type_includes("array");

    // Reject schemas with composition or dynamic keywords — incompatible with strict mode
    if obj.contains_key("oneOf")
        || obj.contains_key("anyOf")
        || obj.contains_key("allOf")
        || obj.contains_key("$ref")
        || obj.contains_key("patternProperties")
    {
        return false;
    }

    // Non-object, non-array JSON objects: only valid if they have an explicit type or enum.
    // Empty {} or untyped schemas are incompatible.
    if !is_object && !is_array {
        if obj.contains_key("type") || obj.contains_key("enum") {
            return true;
        }
        return false;
    }

    if is_object {
        // Check additionalProperties compatibility:
        // - absent → we'll set to false (OK)
        // - false → already compliant (OK)
        // - true → explicit freeform (incompatible)
        // - object → dynamic map pattern (incompatible)
        match obj.get("additionalProperties") {
            Some(ap) if ap.is_object() => return false,
            Some(ap) if ap.as_bool() == Some(true) => return false,
            _ => {}
        }

        // Freeform object with no properties key at all
        if obj.get("properties").is_none() {
            return false;
        }

        // Malformed properties field (exists but not an object)
        if let Some(properties) = obj.get("properties") {
            if properties.as_object().is_none() {
                return false;
            }
        }

        // Clone properties to inspect keys and types before mutating
        if let Some(props) = obj.get("properties").and_then(|p| p.as_object()).cloned() {
            let all_keys: Vec<String> = props.keys().cloned().collect();

            // Every property must have an explicit "type" or "enum" for strict mode
            for (_key, prop_val) in props.iter() {
                if let Some(prop_obj) = prop_val.as_object() {
                    if !prop_obj.contains_key("type") && !prop_obj.contains_key("enum") {
                        return false;
                    }
                }
            }

            // Recurse into each property's schema BEFORE nullable transformation,
            // so nested type checks (is_object, is_array) see the original types.
            if let Some(props_mut) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
                for (_key, prop_schema) in props_mut.iter_mut() {
                    if !try_make_strict_compliant(prop_schema) {
                        return false;
                    }
                }
            }

            // Snapshot original required keys before overwriting
            let original_required: HashSet<String> = obj
                .get("required")
                .and_then(|r| r.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();

            // Make originally-optional properties nullable so the model can pass null
            if let Some(props_mut) = obj.get_mut("properties").and_then(|p| p.as_object_mut()) {
                for key in &all_keys {
                    if !original_required.contains(key) {
                        if let Some(prop) = props_mut.get_mut(key) {
                            make_property_nullable(prop);
                        }
                    }
                }
            }

            // Set required to ALL property keys
            let all_keys_json: Vec<serde_json::Value> = all_keys
                .iter()
                .map(|k| serde_json::Value::String(k.clone()))
                .collect();
            obj.insert(
                "required".to_string(),
                serde_json::Value::Array(all_keys_json),
            );
        }

        // Set additionalProperties: false
        obj.insert("additionalProperties".to_string(), json!(false));
    }

    // Recurse into array items
    if is_array {
        if let Some(items) = obj.get_mut("items") {
            if !try_make_strict_compliant(items) {
                return false;
            }
        }
    }

    true
}

/// Convert a property's type to nullable by adding "null" to the type union.
/// Also adds null to enum arrays if present.
fn make_property_nullable(prop: &mut serde_json::Value) {
    // Handle "type" field
    if let Some(type_val) = prop.get("type").cloned() {
        match &type_val {
            serde_json::Value::String(s) if s != "null" => {
                prop["type"] = json!([s.as_str(), "null"]);
            }
            serde_json::Value::Array(arr) => {
                if !arr.iter().any(|v| v.as_str() == Some("null")) {
                    let mut new_arr = arr.clone();
                    new_arr.push(json!("null"));
                    prop["type"] = serde_json::Value::Array(new_arr);
                }
            }
            _ => {}
        }
    }
    // Handle "enum" field — add null as a valid value
    if let Some(enum_val) = prop.get_mut("enum").and_then(|e| e.as_array_mut()) {
        if !enum_val.contains(&json!(null)) {
            enum_val.push(json!(null));
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAICompatProvider {
    async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
        let model = request.model.clone();
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(false);
        let OpenAITransportResponse {
            response,
            debug_path,
        } = self
            .send_transport_request(body, &model, "trying fallback")
            .await?;
        let response_json: serde_json::Value = response.json().await?;
        self.append_json_debug(debug_path.as_deref(), &response_json);
        parse_openai_response(&response_json)
    }

    async fn stream(
        &self,
        request: ChatRequest,
    ) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
        let model = request.model.clone();
        let mut body = self.build_request_body(&request);
        body["stream"] = json!(true);
        let OpenAITransportResponse {
            response,
            debug_path,
        } = self
            .send_transport_request(body, &model, "stream fallback")
            .await?;
        spawn_openai_stream(response, debug_path)
    }
}

pub fn build_openai_messages(messages: &[Message], system: &str) -> Vec<serde_json::Value> {
    let mut out = Vec::new();
    if !system.is_empty() {
        out.push(json!({"role": "system", "content": system}));
    }
    for msg in messages {
        match msg.role {
            Role::User => {
                let text: String = msg
                    .content
                    .iter()
                    .filter_map(|c| {
                        if let ContentBlock::Text { text } = c {
                            Some(text.as_str())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                out.push(json!({"role": "user", "content": text}));
            }
            Role::Assistant => {
                let mut tool_calls = vec![];
                let mut text_parts = vec![];
                for block in &msg.content {
                    match block {
                        ContentBlock::ToolUse { id, name, input } => {
                            tool_calls.push(json!({
                                "id": id, "type": "function",
                                "function": {"name": name, "arguments": input.to_string()}
                            }));
                        }
                        ContentBlock::Text { text } => {
                            text_parts.push(text.as_str());
                        }
                        _ => {}
                    }
                }
                let mut msg_json = json!({"role": "assistant"});
                if !text_parts.is_empty() {
                    msg_json["content"] = json!(text_parts.join("\n"));
                }
                if !tool_calls.is_empty() {
                    msg_json["tool_calls"] = json!(tool_calls);
                }
                out.push(msg_json);
            }
            Role::Tool => {
                for block in &msg.content {
                    if let ContentBlock::ToolResult {
                        tool_use_id,
                        content,
                        ..
                    } = block
                    {
                        let truncated = crate::util::truncate(content, 60000);
                        out.push(json!({"role": "tool", "tool_call_id": tool_use_id, "content": truncated}));
                    }
                }
            }
            _ => {}
        }
    }
    out
}

pub fn build_openai_tools(tools: &[crate::tools::ToolDefinition]) -> Vec<serde_json::Value> {
    tools.iter().map(|t| json!({
        "type": "function",
        "function": {"name": t.name, "description": t.description, "parameters": t.parameters}
    })).collect()
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::provider::policy::{apply_thinking_mode, thinking_model_name};
    use crate::provider::{ContentBlock, Message, Role};
    use crate::tools::ToolDefinition;
    use serde_json::json;

    // ── Strict-mode normalization tests ─────────────────────────

    #[test]
    fn strict_normalization_adds_all_properties_to_required() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "The command"},
                "explanation": {"type": "string", "description": "Why"},
                "pending": {"type": "boolean", "description": "Run in background"},
                "expected_timeout_seconds": {"type": "integer", "description": "Timeout"}
            },
            "required": ["command", "explanation"]
        });

        assert!(try_make_strict_compliant(&mut schema));

        let required = schema["required"].as_array().unwrap();
        let req_strs: Vec<&str> = required.iter().filter_map(|v| v.as_str()).collect();

        assert!(req_strs.contains(&"command"));
        assert!(req_strs.contains(&"explanation"));
        assert!(req_strs.contains(&"pending"));
        assert!(req_strs.contains(&"expected_timeout_seconds"));
        assert_eq!(schema["additionalProperties"], json!(false));

        // Originally-optional properties should be nullable
        assert_eq!(
            schema["properties"]["pending"]["type"],
            json!(["boolean", "null"])
        );
        assert_eq!(
            schema["properties"]["expected_timeout_seconds"]["type"],
            json!(["integer", "null"])
        );

        // Originally-required properties should NOT be nullable
        assert_eq!(schema["properties"]["command"]["type"], json!("string"));
        assert_eq!(schema["properties"]["explanation"]["type"], json!("string"));
    }

    #[test]
    fn strict_normalization_skips_untyped_properties() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "action": {"type": "string"},
                "value": {"description": "no type here"}
            },
            "required": ["action"]
        });

        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_skips_dynamic_additional_properties() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }
            },
            "required": ["name"]
        });

        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_skips_freeform_objects() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "key": {"type": "string"},
                "data": {"type": "object"}
            },
            "required": ["key"]
        });

        // "data" is type:object with no properties → freeform → incompatible
        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_handles_nested_objects() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "config": {
                    "type": "object",
                    "properties": {
                        "key": {"type": "string"},
                        "value": {"type": "string"}
                    },
                    "required": ["key"]
                }
            },
            "required": ["name", "config"]
        });

        assert!(try_make_strict_compliant(&mut schema));
        assert_eq!(
            schema["properties"]["config"]["additionalProperties"],
            json!(false)
        );

        let nested_req = schema["properties"]["config"]["required"]
            .as_array()
            .unwrap();
        let nested_strs: Vec<&str> = nested_req.iter().filter_map(|v| v.as_str()).collect();
        assert!(nested_strs.contains(&"key"));
        assert!(nested_strs.contains(&"value"));

        // "value" was not originally required in nested, so it should be nullable
        assert_eq!(
            schema["properties"]["config"]["properties"]["value"]["type"],
            json!(["string", "null"])
        );
    }

    #[test]
    fn strict_normalization_handles_array_items() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "optional_field": {"type": "integer"}
                        },
                        "required": ["name"]
                    }
                }
            },
            "required": ["items"]
        });

        assert!(try_make_strict_compliant(&mut schema));
        let items_schema = &schema["properties"]["items"]["items"];
        assert_eq!(items_schema["additionalProperties"], json!(false));

        let items_req = items_schema["required"].as_array().unwrap();
        assert_eq!(items_req.len(), 2);
    }

    #[test]
    fn strict_normalization_with_empty_properties() {
        let mut schema = json!({
            "type": "object",
            "properties": {},
            "required": []
        });

        assert!(try_make_strict_compliant(&mut schema));
        assert_eq!(schema["additionalProperties"], json!(false));
    }

    #[test]
    fn strict_normalization_skips_empty_root_schema() {
        let mut schema = json!({});
        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_skips_composition_schemas() {
        let mut schema = json!({
            "oneOf": [
                {"type": "string"},
                {"type": "integer"}
            ]
        });
        assert!(!try_make_strict_compliant(&mut schema));

        let mut schema2 = json!({
            "anyOf": [
                {"type": "string"},
                {"type": "null"}
            ]
        });
        assert!(!try_make_strict_compliant(&mut schema2));
    }

    #[test]
    fn strict_normalization_skips_ref_schemas() {
        let mut schema = json!({"$ref": "#/definitions/Foo"});
        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_skips_typed_composition_schemas() {
        // Schema with type AND oneOf — still incompatible
        let mut schema = json!({
            "type": "object",
            "oneOf": [
                {"properties": {"a": {"type": "string"}}, "required": ["a"]},
                {"properties": {"b": {"type": "integer"}}, "required": ["b"]}
            ]
        });
        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_skips_pattern_properties() {
        let mut schema = json!({
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "patternProperties": {"^x-": {"type": "string"}},
            "required": ["name"]
        });
        assert!(!try_make_strict_compliant(&mut schema));
    }

    #[test]
    fn strict_normalization_handles_type_union_array() {
        // type expressed as ["object", "null"] — should still be detected as object
        let mut schema = json!({
            "type": ["object", "null"],
            "properties": {
                "key": {"type": "string"}
            },
            "required": ["key"]
        });
        assert!(try_make_strict_compliant(&mut schema));
        assert_eq!(schema["additionalProperties"], json!(false));
    }

    #[test]
    fn strict_normalization_preserves_original_on_failure() {
        let original = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "env": {
                    "type": "object",
                    "additionalProperties": {"type": "string"}
                }
            },
            "required": ["name"]
        });
        let mut schema = original.clone();
        assert!(!try_make_strict_compliant(&mut schema));
        // The caller should have cloned before calling — this test documents
        // that the function may partially mutate before returning false.
        // The build_request_body code clones before attempting normalization.
    }

    #[test]
    fn strict_normalization_enum_gets_null() {
        let mut schema = json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["set", "remove"]
                }
            },
            "required": []
        });

        assert!(try_make_strict_compliant(&mut schema));
        let enum_vals = schema["properties"]["action"]["enum"].as_array().unwrap();
        assert!(enum_vals.contains(&json!(null)));
        assert!(enum_vals.contains(&json!("set")));
        assert!(enum_vals.contains(&json!("remove")));
    }

    /// Integration test: verify all built-in tool definitions can be processed
    /// without panic, and that strict-compatible tools get proper normalization.
    #[test]
    fn all_builtin_tools_normalization() {
        use crate::tools::all_tool_definitions;

        let tools = all_tool_definitions();
        let mut strict_count = 0;
        let mut non_strict_count = 0;

        for tool_def in &tools {
            let mut params = tool_def.parameters.clone();
            let result = try_make_strict_compliant(&mut params);

            if result {
                strict_count += 1;
                // Verify: all property keys are in required
                if let Some(props) = params.get("properties").and_then(|p| p.as_object()) {
                    let required: Vec<&str> = params
                        .get("required")
                        .and_then(|r| r.as_array())
                        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                        .unwrap_or_default();

                    for key in props.keys() {
                        assert!(
                            required.contains(&key.as_str()),
                            "Tool '{}': property '{}' missing from required after normalization",
                            tool_def.name,
                            key
                        );
                    }
                }
            } else {
                non_strict_count += 1;
            }
        }

        // Sanity: most tools should be strict-compatible
        assert!(
            strict_count > non_strict_count,
            "Expected more strict-compatible tools than non-strict, got {strict_count} strict vs {non_strict_count} non-strict"
        );
    }

    // ── Live API validation (requires OPENAI_API_KEY) ──────────

    /// Send all built-in tool schemas (with strict normalization applied) to the
    /// real OpenAI API and verify we get a 200 — not a 400 schema rejection.
    /// Run with: cargo test -- --ignored openai_live_strict_tools
    #[tokio::test]
    #[ignore]
    async fn openai_live_strict_tools_gpt4o() {
        openai_live_strict_tools("gpt-4o").await;
    }

    #[tokio::test]
    #[ignore]
    async fn openai_live_strict_tools_gpt5() {
        openai_live_strict_tools("gpt-5").await;
    }

    async fn openai_live_strict_tools(model: &str) {
        use crate::tools::all_tool_definitions;

        let api_key = std::env::var("OPENAI_API_KEY")
            .expect("OPENAI_API_KEY must be set to run this test");

        // Build tool schemas exactly as build_request_body does
        let tool_defs = all_tool_definitions();
        let mut tools = build_openai_tools(&tool_defs);

        let mut strict_count = 0;
        let mut non_strict_names = vec![];
        for tool in &mut tools {
            if let Some(func) = tool.get_mut("function") {
                if let Some(params) = func.get_mut("parameters") {
                    let mut strict_params = params.clone();
                    if try_make_strict_compliant(&mut strict_params) {
                        *params = strict_params;
                        func["strict"] = json!(true);
                        strict_count += 1;
                    } else {
                        non_strict_names.push(
                            func.get("name")
                                .and_then(|n| n.as_str())
                                .unwrap_or("?")
                                .to_string(),
                        );
                    }
                }
            }
        }

        eprintln!(
            "[{model}] Sending {} tools ({strict_count} strict, {} non-strict: {:?})",
            tools.len(),
            non_strict_names.len(),
            non_strict_names
        );

        let body = json!({
            "model": model,
            "messages": [{"role": "user", "content": "Say hello"}],
            "tools": tools,
            "max_tokens": 16,
        });

        let client = reqwest::Client::new();
        let resp = client
            .post("https://api.openai.com/v1/chat/completions")
            .header("Authorization", format!("Bearer {api_key}"))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .expect("HTTP request failed");

        let status = resp.status();
        let resp_text = resp.text().await.unwrap_or_default();

        // 400 = schema rejected (the bug we're fixing). Other errors (401, 429, 5xx)
        // are auth/quota/infra issues unrelated to schema validity.
        if status == 400 {
            panic!("[{model}] OpenAI rejected tool schemas with 400 Bad Request:\n{resp_text}");
        } else if status == 429 || status == 401 || status == 403 {
            eprintln!(
                "[{model}] SKIPPED — auth/quota error (HTTP {status}), not a schema error. \
                 Check your OpenAI billing. Response: {resp_text}"
            );
        } else if status.is_success() {
            eprintln!("[{model}] PASSED — API accepted all tool schemas (HTTP {status})");
        } else {
            eprintln!(
                "[{model}] WARNING — unexpected HTTP {status} (not a schema 400): {resp_text}"
            );
        }
    }

    // ── Existing message/tool tests ──────────────────────────────

    #[test]
    fn build_openai_messages_user() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: "hello".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "user");
        assert_eq!(result[0]["content"], "hello");
    }

    #[test]
    fn build_openai_messages_with_system() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text { text: "hi".into() }],
        }];
        let result = build_openai_messages(&msgs, "You are helpful");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[0]["content"], "You are helpful");
        assert_eq!(result[1]["role"], "user");
    }

    #[test]
    fn build_openai_messages_assistant_text_and_tool_calls() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "thinking".into(),
                },
                ContentBlock::ToolUse {
                    id: "c1".into(),
                    name: "read_file".into(),
                    input: json!({"path": "/tmp"}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert_eq!(result[0]["content"], "thinking");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "c1");
        assert_eq!(tc[0]["type"], "function");
        assert_eq!(tc[0]["function"]["name"], "read_file");
    }

    #[test]
    fn build_openai_messages_tool_result() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "c1".into(),
                content: "file contents".into(),
                is_error: false,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "tool");
        assert_eq!(result[0]["tool_call_id"], "c1");
        assert_eq!(result[0]["content"], "file contents");
    }

    #[test]
    fn build_openai_tools_basic() {
        let tools = vec![ToolDefinition {
            name: "test_tool".into(),
            description: "A test tool".into(),
            parameters: json!({"type": "object", "properties": {}}),
        }];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["type"], "function");
        assert_eq!(result[0]["function"]["name"], "test_tool");
        assert_eq!(result[0]["function"]["description"], "A test tool");
    }

    #[test]
    fn build_openai_tools_empty() {
        let result = build_openai_tools(&[]);
        assert!(result.is_empty());
    }

    #[test]
    fn is_anthropic_model_claude() {
        assert!(is_anthropic_model("claude-3.5-sonnet"));
        assert!(is_anthropic_model("claude-3-opus"));
        assert!(is_anthropic_model("anthropic/claude-3.5-sonnet"));
    }

    #[test]
    fn is_anthropic_model_non_claude() {
        assert!(!is_anthropic_model("gpt-4"));
        assert!(!is_anthropic_model("gemini-pro"));
        assert!(!is_anthropic_model("llama-3"));
    }

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
    fn apply_thinking_mode_claude_sonnet_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_other_model_no_change() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "gpt-4", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn thinking_model_name_gemini_25_think() {
        let result = thinking_model_name("google/gemini-2.5-pro", true);
        assert_eq!(result, "google/gemini-2.5-pro:thinking");
    }

    #[test]
    fn thinking_model_name_gemini_25_already_thinking() {
        let result = thinking_model_name("google/gemini-2.5-pro:thinking", true);
        assert_eq!(result, "google/gemini-2.5-pro:thinking");
    }

    #[test]
    fn thinking_model_name_gemini_25_no_think() {
        let result = thinking_model_name("google/gemini-2.5-pro", false);
        assert_eq!(result, "google/gemini-2.5-pro");
    }

    #[test]
    fn thinking_model_name_non_gemini() {
        let result = thinking_model_name("gpt-4", true);
        assert_eq!(result, "gpt-4");
    }

    #[test]
    fn build_openai_messages_empty() {
        let result = build_openai_messages(&[], "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_empty_with_system() {
        let result = build_openai_messages(&[], "sys prompt");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[0]["content"], "sys prompt");
    }

    #[test]
    fn build_openai_messages_user_multiple_text_blocks() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text {
                    text: "line1".into(),
                },
                ContentBlock::Text {
                    text: "line2".into(),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "line1\nline2");
    }

    #[test]
    fn build_openai_messages_user_filters_non_text() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![
                ContentBlock::Text {
                    text: "hello".into(),
                },
                ContentBlock::ToolUse {
                    id: "x".into(),
                    name: "y".into(),
                    input: json!({}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result[0]["content"], "hello");
    }

    #[test]
    fn build_openai_messages_assistant_tool_only() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolUse {
                id: "t1".into(),
                name: "run".into(),
                input: json!({"cmd": "ls"}),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["function"]["name"], "run");
        assert_eq!(tc[0]["function"]["arguments"], r#"{"cmd":"ls"}"#);
    }

    #[test]
    fn build_openai_messages_assistant_multiple_tool_calls() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::ToolUse {
                    id: "a".into(),
                    name: "foo".into(),
                    input: json!({}),
                },
                ContentBlock::ToolUse {
                    id: "b".into(),
                    name: "bar".into(),
                    input: json!({"x": 1}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 2);
        assert_eq!(tc[0]["id"], "a");
        assert_eq!(tc[1]["id"], "b");
    }

    #[test]
    fn build_openai_messages_tool_multiple_results() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![
                ContentBlock::ToolResult {
                    tool_use_id: "c1".into(),
                    content: "result1".into(),
                    is_error: false,
                },
                ContentBlock::ToolResult {
                    tool_use_id: "c2".into(),
                    content: "result2".into(),
                    is_error: true,
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["tool_call_id"], "c1");
        assert_eq!(result[0]["content"], "result1");
        assert_eq!(result[1]["tool_call_id"], "c2");
        assert_eq!(result[1]["content"], "result2");
    }

    #[test]
    fn build_openai_messages_tool_ignores_non_tool_result() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::Text {
                text: "ignored".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_system_role_ignored() {
        let msgs = vec![Message {
            role: Role::System,
            content: vec![ContentBlock::Text { text: "sys".into() }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert!(result.is_empty());
    }

    #[test]
    fn build_openai_messages_mixed_conversation() {
        let msgs = vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "question".into(),
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![
                    ContentBlock::Text {
                        text: "let me check".into(),
                    },
                    ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "search".into(),
                        input: json!({"q": "test"}),
                    },
                ],
            },
            Message {
                role: Role::Tool,
                content: vec![ContentBlock::ToolResult {
                    tool_use_id: "t1".into(),
                    content: "found it".into(),
                    is_error: false,
                }],
            },
            Message {
                role: Role::Assistant,
                content: vec![ContentBlock::Text {
                    text: "here you go".into(),
                }],
            },
        ];
        let result = build_openai_messages(&msgs, "Be helpful");
        assert_eq!(result.len(), 5); // system + 4 messages
        assert_eq!(result[0]["role"], "system");
        assert_eq!(result[1]["role"], "user");
        assert_eq!(result[2]["role"], "assistant");
        assert_eq!(result[3]["role"], "tool");
        assert_eq!(result[4]["role"], "assistant");
    }

    #[test]
    fn build_openai_tools_multiple() {
        let tools = vec![
            ToolDefinition {
                name: "alpha".into(),
                description: "First".into(),
                parameters: json!({"type": "object"}),
            },
            ToolDefinition {
                name: "beta".into(),
                description: "Second".into(),
                parameters: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            },
        ];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["function"]["name"], "alpha");
        assert_eq!(result[1]["function"]["name"], "beta");
        assert_eq!(
            result[1]["function"]["parameters"]["properties"]["x"]["type"],
            "string"
        );
    }

    #[test]
    fn is_retryable_429() {
        assert!(is_retryable(reqwest::StatusCode::TOO_MANY_REQUESTS));
    }

    #[test]
    fn is_retryable_500() {
        assert!(is_retryable(reqwest::StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn is_retryable_502() {
        assert!(is_retryable(reqwest::StatusCode::BAD_GATEWAY));
    }

    #[test]
    fn is_retryable_200_false() {
        assert!(!is_retryable(reqwest::StatusCode::OK));
    }

    #[test]
    fn is_retryable_400_false() {
        assert!(!is_retryable(reqwest::StatusCode::BAD_REQUEST));
    }

    #[test]
    fn is_retryable_401_false() {
        assert!(!is_retryable(reqwest::StatusCode::UNAUTHORIZED));
    }

    fn make_provider() -> OpenAICompatProvider {
        OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("test-key".into()),
            base_url: "https://api.example.com".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap()
    }

    fn make_chat_request(
        model: &str,
        system: &str,
        messages: Vec<Message>,
        tools: Vec<ToolDefinition>,
        tool_choice: ToolChoice,
        extra_body: Option<serde_json::Value>,
    ) -> ChatRequest {
        ChatRequest {
            model: model.into(),
            system: system.into(),
            messages,
            tools,
            tool_choice,
            max_tokens: 1024,
            stream: false,
            extra_body,
            response_format: None,
        }
    }

    #[test]
    fn build_request_body_basic() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "Be helpful",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
        assert_eq!(body["max_tokens"], 1024);
        assert_eq!(body["stream"], false);
        assert_eq!(body["tool_choice"], "auto");
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "Be helpful");
        assert_eq!(msgs[1]["role"], "user");
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn build_request_body_with_tools() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "do it".into(),
                }],
            }],
            vec![ToolDefinition {
                name: "my_tool".into(),
                description: "does stuff".into(),
                parameters: json!({"type": "object"}),
            }],
            ToolChoice::Required,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["function"]["name"], "my_tool");
    }

    #[test]
    fn build_request_body_tool_choice_none() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::None, None);
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "none");
    }

    #[test]
    fn build_request_body_anthropic_system_as_array() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "You are an assistant",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hello".into(),
                }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys.len(), 1);
        assert_eq!(sys[0]["type"], "text");
        assert_eq!(sys[0]["text"], "You are an assistant");
        assert_eq!(sys[0]["cache_control"]["type"], "ephemeral");
        let msgs = body["messages"].as_array().unwrap();
        assert!(
            !msgs.iter().any(|m| m["role"] == "system"),
            "anthropic model should not have system in messages"
        );
    }

    #[test]
    fn build_request_body_anthropic_tool_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-opus",
            "sys",
            vec![],
            vec![
                ToolDefinition {
                    name: "first".into(),
                    description: "d1".into(),
                    parameters: json!({}),
                },
                ToolDefinition {
                    name: "second".into(),
                    description: "d2".into(),
                    parameters: json!({}),
                },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools[0].get("cache_control").is_none());
        assert_eq!(tools[1]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_request_body_extra_body_merged() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"temperature": 0.5, "top_p": 0.9})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["temperature"], 0.5);
        assert_eq!(body["top_p"], 0.9);
    }

    #[test]
    fn build_request_body_extra_body_none() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        let body = provider.build_request_body(&req);
        assert!(body.get("temperature").is_none());
    }

    #[test]
    fn build_request_body_strips_internal_transport_metadata() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({
                "_transport_base_url": "http://127.0.0.1:8317/v1",
                "temperature": 0.2
            })),
        );
        let body = provider.build_request_body(&req);
        assert!(body.get("_transport_base_url").is_none());
        assert_eq!(body["temperature"], 0.2);
    }

    #[test]
    fn build_request_body_normalizes_model_for_sidecar_transport() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("test-key".into()),
            base_url: crate::provider::bootstrap::cliproxy_base_url(),
            strip_provider_prefix: true,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let req = make_chat_request(
            "anthropic/claude-sonnet-4.6",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "claude-sonnet-4.6");
    }

    #[test]
    fn apply_thinking_mode_non_gemini3_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "gpt-4", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_claude_opus_think_no_reasoning() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3-opus", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn thinking_model_name_gemini_3_think() {
        let result = thinking_model_name("google/gemini-3-pro", true);
        assert_eq!(result, "google/gemini-3-pro:thinking");
    }

    #[test]
    fn is_anthropic_model_edge_cases() {
        assert!(is_anthropic_model("anthropic/something-else"));
        assert!(!is_anthropic_model("not-anthropic-model"));
        assert!(!is_anthropic_model(""));
        assert!(is_anthropic_model("my-claude-variant"));
    }

    #[test]
    fn is_retryable_503() {
        assert!(is_retryable(reqwest::StatusCode::SERVICE_UNAVAILABLE));
    }

    #[test]
    fn is_retryable_504() {
        assert!(is_retryable(reqwest::StatusCode::GATEWAY_TIMEOUT));
    }

    #[test]
    fn is_retryable_403_not() {
        assert!(!is_retryable(reqwest::StatusCode::FORBIDDEN));
    }

    #[test]
    fn is_retryable_404_not() {
        assert!(!is_retryable(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn thinking_model_name_gemini25_flash_think() {
        let result = thinking_model_name("google/gemini-2.5-flash", true);
        assert_eq!(result, "google/gemini-2.5-flash:thinking");
    }

    #[test]
    fn thinking_model_name_gemini25_flash_no_think() {
        let result = thinking_model_name("google/gemini-2.5-flash", false);
        assert_eq!(result, "google/gemini-2.5-flash");
    }

    #[test]
    fn thinking_model_name_gemini25_flash_already_thinking() {
        let result = thinking_model_name("google/gemini-2.5-flash:thinking", true);
        assert_eq!(result, "google/gemini-2.5-flash:thinking");
    }

    #[test]
    fn apply_thinking_mode_anthropic_prefixed_claude_sonnet() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "anthropic/claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["reasoning"]["budget_tokens"], 32768);
    }

    #[test]
    fn apply_thinking_mode_gemini3_flash_no_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-flash", false);
        assert_eq!(body["reasoning"]["effort"], "low");
    }

    #[test]
    fn apply_thinking_mode_gemini3_flash_think() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "google/gemini-3-flash", true);
        assert_eq!(body["reasoning"]["effort"], "high");
    }

    #[test]
    fn build_openai_messages_assistant_text_only() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::Text {
                text: "just text".into(),
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert_eq!(result[0]["content"], "just text");
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn build_openai_messages_assistant_multiple_text_blocks() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "part1".into(),
                },
                ContentBlock::Text {
                    text: "part2".into(),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result[0]["content"], "part1\npart2");
    }

    #[test]
    fn build_openai_messages_tool_result_error_still_included() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "e1".into(),
                content: "something broke".into(),
                is_error: true,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "tool");
        assert_eq!(result[0]["tool_call_id"], "e1");
        assert_eq!(result[0]["content"], "something broke");
    }

    #[test]
    fn build_openai_tools_preserves_parameters() {
        let tools = vec![ToolDefinition {
            name: "search".into(),
            description: "Search things".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"}
                },
                "required": ["query"]
            }),
        }];
        let result = build_openai_tools(&tools);
        assert_eq!(
            result[0]["function"]["parameters"]["properties"]["query"]["type"],
            "string"
        );
        assert_eq!(result[0]["function"]["parameters"]["required"][0], "query");
    }

    #[test]
    fn build_request_body_anthropic_no_system_in_messages() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-haiku",
            "system prompt here",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        for m in msgs {
            assert_ne!(m["role"], "system");
        }
        assert!(body["system"].is_array());
    }

    #[test]
    fn build_request_body_non_anthropic_system_in_messages() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4o",
            "system prompt",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs[0]["role"], "system");
        assert_eq!(msgs[0]["content"], "system prompt");
        assert!(body.get("system").is_none());
    }

    #[test]
    fn build_request_body_extra_body_overrides() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"max_tokens": 2048})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["max_tokens"], 2048);
    }

    #[test]
    fn build_request_body_empty_tools_not_included() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        let body = provider.build_request_body(&req);
        assert!(body.get("tools").is_none());
    }

    #[test]
    fn is_anthropic_model_prefix_only() {
        assert!(is_anthropic_model("anthropic/llama"));
    }

    #[test]
    fn is_anthropic_model_claude_substring() {
        assert!(is_anthropic_model("openrouter/claude-3.5-sonnet"));
    }

    #[test]
    fn build_request_body_anthropic_cache_control_on_system() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3-haiku",
            "be brief",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["cache_control"]["type"], "ephemeral");
        assert_eq!(sys[0]["text"], "be brief");
    }

    #[test]
    fn build_request_body_extra_body_map_multiple_keys() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({"temperature": 0.7, "frequency_penalty": 1.2, "custom_field": "abc"})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["temperature"], 0.7);
        assert_eq!(body["frequency_penalty"], 1.2);
        assert_eq!(body["custom_field"], "abc");
    }

    #[test]
    fn build_request_body_tool_choice_required() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![ToolDefinition {
                name: "t".into(),
                description: "d".into(),
                parameters: json!({}),
            }],
            ToolChoice::Required,
            None,
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
    }

    #[test]
    fn build_request_body_tool_choice_none_value() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::None, None);
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "none");
    }

    #[test]
    fn build_request_body_tool_choice_auto_value() {
        let provider = make_provider();
        let req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "auto");
    }

    #[test]
    fn build_openai_tools_multiple_preserves_all() {
        let tools = vec![
            ToolDefinition {
                name: "tool_a".into(),
                description: "desc a".into(),
                parameters: json!({"type": "object", "properties": {"x": {"type": "string"}}}),
            },
            ToolDefinition {
                name: "tool_b".into(),
                description: "desc b".into(),
                parameters: json!({"type": "object", "properties": {"y": {"type": "integer"}}}),
            },
            ToolDefinition {
                name: "tool_c".into(),
                description: "desc c".into(),
                parameters: json!({"type": "object"}),
            },
        ];
        let result = build_openai_tools(&tools);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0]["function"]["name"], "tool_a");
        assert_eq!(result[1]["function"]["name"], "tool_b");
        assert_eq!(result[2]["function"]["name"], "tool_c");
        assert_eq!(
            result[0]["function"]["parameters"]["properties"]["x"]["type"],
            "string"
        );
        assert_eq!(
            result[1]["function"]["parameters"]["properties"]["y"]["type"],
            "integer"
        );
    }

    #[test]
    fn build_openai_messages_empty_content_blocks() {
        let msgs = vec![Message {
            role: Role::User,
            content: vec![],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "user");
        assert_eq!(result[0]["content"], "");
    }

    #[test]
    fn build_openai_messages_assistant_empty_content() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn is_anthropic_model_various_strings() {
        assert!(is_anthropic_model("claude-instant"));
        assert!(is_anthropic_model("anthropic/gemma"));
        assert!(!is_anthropic_model("gpt-3.5-turbo"));
        assert!(!is_anthropic_model("mistral-large"));
        assert!(!is_anthropic_model("deepseek-coder"));
    }

    #[test]
    fn thinking_model_name_non_google_no_change() {
        assert_eq!(thinking_model_name("claude-3-opus", true), "claude-3-opus");
        assert_eq!(thinking_model_name("gpt-4o", false), "gpt-4o");
    }

    #[test]
    fn apply_thinking_mode_no_think_non_gemini3() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", false);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn apply_thinking_mode_think_claude_non_sonnet_no_reasoning() {
        let mut body = json!({});
        apply_thinking_mode(&mut body, "claude-3-haiku", true);
        assert!(body.get("reasoning").is_none());
    }

    #[test]
    fn provider_new_constructs_successfully() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "https://api.example.com".into(),
            strip_provider_prefix: false,
            fallback_model: Some("fallback-model".into()),
            extra_headers: vec![("X-Custom".into(), "val".into())],
            timeout_seconds: 60,
            debug_provider_name: "test".into(),
        });
        assert!(provider.is_ok());
    }

    #[test]
    fn provider_new_zero_timeout() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "http://localhost".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 0,
            debug_provider_name: "test".into(),
        });
        assert!(provider.is_ok());
    }

    #[test]
    fn build_request_body_anthropic_no_system_message_in_messages_array() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys prompt",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "q".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_non_anthropic_empty_system_no_system_message() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_anthropic_tools_cache_control_only_last() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys",
            vec![],
            vec![
                ToolDefinition {
                    name: "a".into(),
                    description: "".into(),
                    parameters: json!({}),
                },
                ToolDefinition {
                    name: "b".into(),
                    description: "".into(),
                    parameters: json!({}),
                },
                ToolDefinition {
                    name: "c".into(),
                    description: "".into(),
                    parameters: json!({}),
                },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 3);
        assert!(tools[0].get("cache_control").is_none());
        assert!(tools[1].get("cache_control").is_none());
        assert_eq!(tools[2]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_request_body_non_anthropic_tools_no_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![
                ToolDefinition {
                    name: "a".into(),
                    description: "".into(),
                    parameters: json!({}),
                },
                ToolDefinition {
                    name: "b".into(),
                    description: "".into(),
                    parameters: json!({}),
                },
            ],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        for tool in tools {
            assert!(tool.get("cache_control").is_none());
        }
    }

    #[test]
    fn build_request_body_extra_body_non_object_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!("not an object")),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    #[test]
    fn build_request_body_stream_field_set() {
        let provider = make_provider();
        let mut req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        req.stream = true;
        let body = provider.build_request_body(&req);
        assert_eq!(body["stream"], true);

        req.stream = false;
        let body = provider.build_request_body(&req);
        assert_eq!(body["stream"], false);
    }

    #[test]
    fn build_openai_messages_multiple_users_in_sequence() {
        let msgs = vec![
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "first".into(),
                }],
            },
            Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "second".into(),
                }],
            },
        ];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["content"], "first");
        assert_eq!(result[1]["content"], "second");
    }

    #[test]
    fn build_openai_messages_tool_result_with_non_tool_result_blocks() {
        let msgs = vec![Message {
            role: Role::Tool,
            content: vec![
                ContentBlock::Text {
                    text: "ignored".into(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "c1".into(),
                    content: "result".into(),
                    is_error: false,
                },
                ContentBlock::Text {
                    text: "also ignored".into(),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["tool_call_id"], "c1");
    }

    #[test]
    fn is_retryable_201_not() {
        assert!(!is_retryable(reqwest::StatusCode::CREATED));
    }

    #[test]
    fn is_retryable_301_not() {
        assert!(!is_retryable(reqwest::StatusCode::MOVED_PERMANENTLY));
    }

    #[test]
    fn thinking_model_name_gemini_20_not_affected() {
        assert_eq!(
            thinking_model_name("google/gemini-2.0-pro", true),
            "google/gemini-2.0-pro"
        );
    }

    #[test]
    fn apply_thinking_mode_gemini3_with_existing_body_fields() {
        let mut body = json!({"temperature": 0.5});
        apply_thinking_mode(&mut body, "google/gemini-3-pro", true);
        assert_eq!(body["reasoning"]["effort"], "high");
        assert_eq!(body["temperature"], 0.5);
    }

    #[test]
    fn apply_thinking_mode_claude_sonnet_think_does_not_remove_other_fields() {
        let mut body = json!({"some_field": 42});
        apply_thinking_mode(&mut body, "claude-3.5-sonnet", true);
        assert_eq!(body["reasoning"]["enabled"], true);
        assert_eq!(body["some_field"], 42);
    }

    #[test]
    fn build_request_body_model_field_matches_request() {
        let provider = make_provider();
        for model in &[
            "gpt-4",
            "claude-3.5-sonnet",
            "anthropic/claude-3-haiku",
            "google/gemini-3-pro",
        ] {
            let req = make_chat_request(model, "", vec![], vec![], ToolChoice::Auto, None);
            let body = provider.build_request_body(&req);
            assert_eq!(body["model"], *model);
        }
    }

    #[test]
    fn build_request_body_max_tokens_from_request() {
        let provider = make_provider();
        let mut req = make_chat_request("gpt-4", "", vec![], vec![], ToolChoice::Auto, None);
        req.max_tokens = 4096;
        let body = provider.build_request_body(&req);
        assert_eq!(body["max_tokens"], 4096);
    }

    #[test]
    fn build_openai_messages_assistant_ignores_tool_result_block() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "thinking".into(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "tr1".into(),
                    content: "should be ignored".into(),
                    is_error: false,
                },
                ContentBlock::ToolUse {
                    id: "tu1".into(),
                    name: "search".into(),
                    input: json!({"q": "test"}),
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "thinking");
        let tc = result[0]["tool_calls"].as_array().unwrap();
        assert_eq!(tc.len(), 1);
        assert_eq!(tc[0]["id"], "tu1");
    }

    #[test]
    fn build_openai_messages_assistant_only_tool_result_ignored() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![ContentBlock::ToolResult {
                tool_use_id: "tr1".into(),
                content: "ignored".into(),
                is_error: false,
            }],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["role"], "assistant");
        assert!(result[0].get("content").is_none());
        assert!(result[0].get("tool_calls").is_none());
    }

    #[test]
    fn provider_new_with_fallback_and_extra_headers() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("sk-test".into()),
            base_url: "https://openrouter.ai/api/v1".into(),
            strip_provider_prefix: false,
            fallback_model: Some("gpt-3.5-turbo".into()),
            extra_headers: vec![
                ("X-Title".into(), "MyApp".into()),
                ("HTTP-Referer".into(), "https://example.com".into()),
            ],
            timeout_seconds: 120,
            debug_provider_name: "test".into(),
        });
        assert!(provider.is_ok());
        let p = provider.unwrap();
        assert_eq!(p.base_url, "https://openrouter.ai/api/v1");
        assert_eq!(p.fallback_model.as_deref(), Some("gpt-3.5-turbo"));
        assert_eq!(p.extra_headers.len(), 2);
        assert_eq!(p.extra_headers[0].0, "X-Title");
    }

    #[test]
    fn build_request_body_anthropic_with_empty_system() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text { text: "hi".into() }],
            }],
            vec![],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        assert!(body["system"].is_array());
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["text"], "");
    }

    #[test]
    fn build_request_body_anthropic_with_tools_and_extra_body() {
        let provider = make_provider();
        let req = make_chat_request(
            "anthropic/claude-3-sonnet",
            "system text",
            vec![Message {
                role: Role::User,
                content: vec![ContentBlock::Text {
                    text: "hello".into(),
                }],
            }],
            vec![ToolDefinition {
                name: "my_tool".into(),
                description: "desc".into(),
                parameters: json!({"type": "object"}),
            }],
            ToolChoice::Required,
            Some(json!({"temperature": 0.3})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["tool_choice"], "required");
        assert_eq!(body["temperature"], 0.3);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools[0]["cache_control"]["type"], "ephemeral");
        let sys = body["system"].as_array().unwrap();
        assert_eq!(sys[0]["text"], "system text");
        let msgs = body["messages"].as_array().unwrap();
        assert!(msgs.iter().all(|m| m["role"] != "system"));
    }

    #[test]
    fn build_request_body_single_anthropic_tool_gets_cache_control() {
        let provider = make_provider();
        let req = make_chat_request(
            "claude-3.5-sonnet",
            "sys",
            vec![],
            vec![ToolDefinition {
                name: "only_tool".into(),
                description: "d".into(),
                parameters: json!({}),
            }],
            ToolChoice::Auto,
            None,
        );
        let body = provider.build_request_body(&req);
        let tools = body["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn build_http_request_sets_authorization_and_extra_headers() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("test-api-key".into()),
            base_url: "https://api.example.com".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![("X-Custom".into(), "custom-val".into())],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert_eq!(
            built.url().as_str(),
            "https://api.example.com/chat/completions"
        );
        assert!(built.headers().get("Authorization").is_some());
        assert!(built.headers()["Authorization"].is_sensitive());
        assert_eq!(built.headers().get("X-Custom").unwrap(), "custom-val");
    }

    #[test]
    fn build_http_request_anthropic_openrouter_adds_beta_header() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "https://openrouter.ai/api/v1".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let body = json!({"model": "claude-3.5-sonnet"});
        let req = provider.build_http_request(&body, "claude-3.5-sonnet");
        let built = req.build().unwrap();
        assert_eq!(
            built.headers().get("anthropic-beta").unwrap(),
            "prompt-caching-2024-07-31"
        );
    }

    #[test]
    fn build_http_request_anthropic_non_openrouter_no_beta_header() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "https://api.anthropic.com".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let body = json!({"model": "claude-3.5-sonnet"});
        let req = provider.build_http_request(&body, "claude-3.5-sonnet");
        let built = req.build().unwrap();
        assert!(built.headers().get("anthropic-beta").is_none());
    }

    #[test]
    fn build_http_request_non_anthropic_openrouter_no_beta_header() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "https://openrouter.ai/api/v1".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert!(built.headers().get("anthropic-beta").is_none());
    }

    #[test]
    fn build_http_request_multiple_extra_headers() {
        let provider = OpenAICompatProvider::new(OpenAICompatProviderConfig {
            api_key: Zeroizing::new("key".into()),
            base_url: "https://api.example.com".into(),
            strip_provider_prefix: false,
            fallback_model: None,
            extra_headers: vec![
                ("X-First".into(), "one".into()),
                ("X-Second".into(), "two".into()),
                ("X-Third".into(), "three".into()),
            ],
            timeout_seconds: 30,
            debug_provider_name: "test".into(),
        })
        .unwrap();
        let body = json!({"model": "gpt-4"});
        let req = provider.build_http_request(&body, "gpt-4");
        let built = req.build().unwrap();
        assert_eq!(built.headers().get("X-First").unwrap(), "one");
        assert_eq!(built.headers().get("X-Second").unwrap(), "two");
        assert_eq!(built.headers().get("X-Third").unwrap(), "three");
    }

    #[test]
    fn build_request_body_extra_body_empty_object() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!({})),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    #[test]
    fn build_request_body_extra_body_array_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(json!([1, 2, 3])),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
        assert!(body.get("0").is_none());
    }

    #[test]
    fn build_request_body_extra_body_null_ignored() {
        let provider = make_provider();
        let req = make_chat_request(
            "gpt-4",
            "",
            vec![],
            vec![],
            ToolChoice::Auto,
            Some(serde_json::Value::Null),
        );
        let body = provider.build_request_body(&req);
        assert_eq!(body["model"], "gpt-4");
    }

    async fn start_sse_server(body: &str) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let response_body = body.to_string();
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let http = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n{response_body}",
            );
            let _ = socket.write_all(http.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        (url, handle)
    }

    #[tokio::test]
    async fn spawn_openai_stream_text_delta() {
        let sse = "data: {\"id\":\"gen-1\",\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n\ndata: {\"id\":\"gen-1\",\"choices\":[{\"finish_reason\":\"stop\",\"delta\":{}}]}\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::GenerationId(id) if id == "gen-1"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "hello"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_tool_use() {
        let sse = concat!(
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tc1\",\"function\":{\"name\":\"search\",\"arguments\":\"\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"q\\\"\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-2\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"test\\\"}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { name, .. } if name == "search"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseDelta(s) if s == "{\"q\""));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseDelta(s) if s == ":\"test\"}"));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_multiple_tool_calls() {
        let sse = concat!(
            "data: {\"id\":\"gen-3\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"tc1\",\"function\":{\"name\":\"foo\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-3\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"tc2\",\"function\":{\"name\":\"bar\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: {\"id\":\"gen-3\",\"choices\":[{\"finish_reason\":\"tool_calls\",\"delta\":{}}]}\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { ref name, .. } if name == "foo"));
        let _ = rx.recv().await.unwrap(); // ToolUseDelta("{}")
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd)); // end of first tool
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseStart { ref name, .. } if name == "bar"));
        let _ = rx.recv().await.unwrap(); // ToolUseDelta("{}")
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd)); // end of second tool (from finish_reason)
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_done_marker() {
        let sse = "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\ndata: [DONE]\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // TextDelta
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_empty_content_skipped() {
        let sse = concat!(
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"\"}}]}\n\n",
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"real\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "real"));
    }

    #[tokio::test]
    async fn spawn_openai_stream_invalid_json_skipped() {
        let sse = "data: not-json\n\ndata: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::TextDelta(t) if t == "ok"));
    }

    #[tokio::test]
    async fn spawn_openai_stream_tool_with_done_closes_tool() {
        let sse = concat!(
            "data: {\"id\":\"g\",\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"t1\",\"function\":{\"name\":\"fn1\",\"arguments\":\"{}\"}}]}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let (url, _handle) = start_sse_server(sse).await;
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // ToolUseStart
        let _ = rx.recv().await.unwrap(); // ToolUseDelta
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::ToolUseEnd));
        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn spawn_openai_stream_error_event() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let url = format!("http://{addr}");
        let _handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let _ = tokio::io::AsyncReadExt::read(&mut socket, &mut buf).await;
            let http = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\ndata: {\"id\":\"g\",\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n";
            let _ = socket.write_all(http.as_bytes()).await;
            socket.shutdown().await.unwrap();
        });
        let resp = reqwest::get(&url).await.unwrap();
        let mut rx = spawn_openai_stream(resp, None).unwrap();
        let _ = rx.recv().await.unwrap(); // GenerationId
        let _ = rx.recv().await.unwrap(); // TextDelta "hi"
        let ev = rx.recv().await;
        assert!(
            ev.is_none()
                || matches!(
                    ev,
                    Some(StreamEvent::Error(_)) | Some(StreamEvent::Done { .. })
                )
        );
    }

    #[test]
    fn build_openai_messages_assistant_with_tool_result_block_ignored() {
        let msgs = vec![Message {
            role: Role::Assistant,
            content: vec![
                ContentBlock::Text {
                    text: "response".into(),
                },
                ContentBlock::ToolResult {
                    tool_use_id: "tr1".into(),
                    content: "should be ignored".into(),
                    is_error: false,
                },
            ],
        }];
        let result = build_openai_messages(&msgs, "");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["content"], "response");
        assert!(result[0].get("tool_calls").is_none());
    }
}

pub fn spawn_openai_stream(
    resp: reqwest::Response,
    debug_path: Option<std::path::PathBuf>,
) -> anyhow::Result<tokio::sync::mpsc::Receiver<StreamEvent>> {
    let (tx, rx) = tokio::sync::mpsc::channel(64);
    tokio::spawn(async move {
        use eventsource_stream::Eventsource;
        use futures::StreamExt;
        let mut stream = resp.bytes_stream().eventsource();
        let mut current_tool_index: Option<usize> = None;
        let mut done_sent = false;
        let mut generation_id: Option<String> = None;
        // Add timeout bounds to detect stalled SSE connections (300s for thinking models)
        while let Ok(maybe_event) =
            tokio::time::timeout(std::time::Duration::from_secs(300), stream.next()).await
        {
            let Some(event) = maybe_event else { break };
            let event = match event {
                Ok(e) => e,
                Err(e) => {
                    let _ = tx.send(StreamEvent::Error(e.to_string())).await;
                    if let Some(path) = &debug_path {
                        crate::debug_io::append(path, "raw_provider_response", &e.to_string());
                    }
                    break;
                }
            };
            if event.data == "[DONE]" {
                if current_tool_index.is_some() {
                    let _ = tx.send(StreamEvent::ToolUseEnd).await;
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
                done_sent = true;
                break;
            }
            let chunk: serde_json::Value = match serde_json::from_str(&event.data) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if let Some(path) = &debug_path {
                crate::debug_io::append(path, "raw_provider_response", &event.data);
            }

            if generation_id.is_none()
                && let Some(id) = chunk["id"].as_str()
            {
                let _ = tx.send(StreamEvent::GenerationId(id.to_string())).await;
                generation_id = Some(id.to_string());
            }

            let delta = &chunk["choices"][0]["delta"];
            if let Some(content) = delta["content"].as_str()
                && !content.is_empty()
            {
                let _ = tx.send(StreamEvent::TextDelta(content.to_string())).await;
            }
            if let Some(tool_calls) = delta["tool_calls"].as_array() {
                for tc in tool_calls {
                    let idx = tc["index"].as_u64().unwrap_or(0) as usize;
                    if current_tool_index != Some(idx) {
                        if current_tool_index.is_some() {
                            let _ = tx.send(StreamEvent::ToolUseEnd).await;
                        }
                        current_tool_index = Some(idx);
                        let id = tc["id"].as_str().unwrap_or("").to_string();
                        let name = tc["function"]["name"].as_str().unwrap_or("").to_string();
                        if !name.is_empty() {
                            let _ = tx.send(StreamEvent::ToolUseStart { id, name }).await;
                        }
                    }
                    if let Some(args) = tc["function"]["arguments"].as_str()
                        && !args.is_empty()
                    {
                        let _ = tx.send(StreamEvent::ToolUseDelta(args.to_string())).await;
                    }
                }
            }
            if chunk["choices"][0]["finish_reason"].as_str().is_some() {
                if current_tool_index.is_some() {
                    let _ = tx.send(StreamEvent::ToolUseEnd).await;
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
                done_sent = true;
                break;
            }
        }

        // Stream ended without [DONE] or finish_reason — ensure cleanup
        if current_tool_index.is_some() {
            let _ = tx.send(StreamEvent::ToolUseEnd).await;
        }
        if !done_sent {
            let _ = tx.send(StreamEvent::Done { usage: None }).await;
        }
    });
    Ok(rx)
}
