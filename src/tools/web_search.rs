use crate::config::Config;
use crate::provider::{self, ChatRequest, ContentBlock, Message, Role, ToolChoice};
use crate::tools::{ToolInvocationContext, ToolInvocationResult};
use serde_json::json;

/// Async because it makes an outgoing HTTP request to the web search provider API.
pub async fn invoke(
    input: &serde_json::Value,
    ctx: &ToolInvocationContext<'_>,
) -> anyhow::Result<ToolInvocationResult> {
    let query = input["query"].as_str().unwrap_or("");
    Ok(ToolInvocationResult::from_result(
        execute(query, ctx.config).await,
    ))
}

async fn execute(query: &str, config: &Config) -> anyhow::Result<String> {
    execute_with_provider_factory(query, config, provider::create_provider).await
}

fn build_request(query: &str, config: &Config) -> anyhow::Result<ChatRequest> {
    let ws_provider_name = &config.web_search.provider;
    let ws_model = &config.web_search.model;
    let model_caps = crate::config::model_capabilities(ws_provider_name, ws_model);
    if !model_caps.supports_web_search {
        if ws_provider_name == "ollama" {
            anyhow::bail!(
                "Web search not available with provider ollama. \
                 Configure [web_search] provider to use openrouter or another search-capable provider."
            );
        }
        anyhow::bail!(
            "Web search requires a search-capable provider/model. \
             Configure [web_search] to use a supported combination instead of {}/{}.",
            ws_provider_name,
            ws_model
        );
    }

    Ok(ChatRequest {
        model: ws_model.clone(),
        system:
            "Provide a concise factual answer with sources. If web retrieval is available, use it and cite URLs."
                .into(),
        messages: vec![Message {
            role: Role::User,
            content: vec![ContentBlock::Text {
                text: query.to_string(),
            }],
        }],
        tools: vec![],
        tool_choice: ToolChoice::None,
        max_tokens: 1024,
        stream: false,
        extra_body: Some(json!({ "web_search_options": {} })),
    })
}

fn response_text(response: &Message) -> String {
    response
        .content
        .iter()
        .filter_map(|b| {
            if let ContentBlock::Text { text } = b {
                Some(text.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

async fn execute_request(
    request: ChatRequest,
    provider: &provider::ActiveProvider,
) -> anyhow::Result<String> {
    let response = provider.complete(request).await?;
    let text = response_text(&response);

    if text.is_empty() {
        Ok("No results returned.".into())
    } else {
        Ok(text)
    }
}

async fn execute_with_provider_builder<F>(
    query: &str,
    config: &Config,
    build_provider: F,
) -> anyhow::Result<String>
where
    F: FnOnce() -> anyhow::Result<provider::ActiveProvider>,
{
    let request = build_request(query, config)?;
    let provider = build_provider()?;
    execute_request(request, &provider).await
}

async fn execute_with_active_provider(
    query: &str,
    config: &Config,
    provider: &provider::ActiveProvider,
) -> anyhow::Result<String> {
    let request = build_request(query, config)?;
    execute_request(request, provider).await
}

async fn execute_with_provider_factory<F>(
    query: &str,
    config: &Config,
    provider_factory: F,
) -> anyhow::Result<String>
where
    F: Fn(&str, &provider::ProviderFactoryConfig) -> anyhow::Result<Box<dyn provider::LlmProvider>>,
{
    let ws_provider_name = &config.web_search.provider;
    let provider_cfg = crate::provider::bootstrap::provider_factory_config(config);
    execute_with_provider_builder(query, config, || {
        provider::ActiveProvider::from_factory(ws_provider_name, &provider_cfg, provider_factory)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct StubProvider {
        message: Message,
        captured_request: Option<Arc<Mutex<Option<ChatRequest>>>>,
    }

    #[async_trait::async_trait]
    impl provider::LlmProvider for StubProvider {
        async fn complete(&self, request: ChatRequest) -> anyhow::Result<Message> {
            if let Some(captured) = &self.captured_request {
                *captured.lock().expect("lock captured request") = Some(request);
            }
            Ok(self.message.clone())
        }

        async fn stream(
            &self,
            _request: ChatRequest,
        ) -> anyhow::Result<tokio::sync::mpsc::Receiver<provider::StreamEvent>> {
            anyhow::bail!("stream not used in web_search tool")
        }
    }

    #[tokio::test]
    async fn execute_returns_provider_specific_ollama_message() {
        let mut config = Config::default();
        config.web_search.provider = "ollama".into();

        let err = execute_with_provider_factory("latest rust release", &config, |_name, _cfg| {
            anyhow::bail!("factory failed")
        })
        .await
        .expect_err("expected error");

        assert!(
            err.to_string()
                .contains("Web search not available with provider ollama"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn execute_joins_text_blocks_and_sets_request_fields() {
        let mut config = Config::default();
        config.web_search.provider = "openai".into();
        config.web_search.model = "gpt-5.2".into();
        let captured_request: Arc<Mutex<Option<ChatRequest>>> = Arc::new(Mutex::new(None));
        let captured_request_for_provider = Arc::clone(&captured_request);
        let provider = provider::ActiveProvider::new(
            Box::new(StubProvider {
                captured_request: Some(Arc::clone(&captured_request_for_provider)),
                message: Message {
                    role: Role::Assistant,
                    content: vec![
                        ContentBlock::Text {
                            text: "line 1".into(),
                        },
                        ContentBlock::ToolUse {
                            id: "ignored".into(),
                            name: "tool".into(),
                            input: serde_json::json!({}),
                        },
                        ContentBlock::Text {
                            text: "line 2".into(),
                        },
                    ],
                },
            }),
            None,
        );

        let output = execute_with_active_provider("find docs", &config, &provider)
            .await
            .expect("execute should succeed");

        assert_eq!(output, "line 1\nline 2");
        let request = captured_request
            .lock()
            .expect("lock captured request")
            .clone()
            .expect("request should be captured");
        assert_eq!(request.model, config.web_search.model);
        assert!(matches!(request.tool_choice, ToolChoice::None));
        assert!(!request.stream);
        assert_eq!(request.max_tokens, 1024);
        assert!(
            request
                .extra_body
                .as_ref()
                .and_then(|extra| extra.get("web_search_options"))
                .is_some()
        );
        assert_eq!(request.messages.len(), 1);
        assert!(matches!(request.messages[0].role, Role::User));
        assert!(matches!(
            request.messages[0].content.as_slice(),
            [ContentBlock::Text { text }] if text == "find docs"
        ));
    }

    #[tokio::test]
    async fn execute_sets_web_search_options_for_supported_models() {
        let mut config = Config::default();
        config.web_search.provider = "openai".into();
        config.web_search.model = "gpt-5.2".into();
        let captured_request: Arc<Mutex<Option<ChatRequest>>> = Arc::new(Mutex::new(None));
        let captured_request_for_provider = Arc::clone(&captured_request);
        let provider = provider::ActiveProvider::new(
            Box::new(StubProvider {
                captured_request: Some(Arc::clone(&captured_request_for_provider)),
                message: Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "result".into(),
                    }],
                },
            }),
            None,
        );

        let _ = execute_with_active_provider("latest rust release", &config, &provider)
            .await
            .expect("execute should succeed");

        let request = captured_request
            .lock()
            .expect("lock captured request")
            .clone()
            .expect("request should be captured");
        assert_eq!(
            request.extra_body,
            Some(json!({ "web_search_options": {} }))
        );
    }

    #[tokio::test]
    async fn execute_returns_default_when_provider_returns_no_text() {
        let mut config = Config::default();
        config.web_search.provider = "openai".into();
        config.web_search.model = "gpt-5.2".into();
        let provider = provider::ActiveProvider::new(
            Box::new(StubProvider {
                captured_request: None,
                message: Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "id".into(),
                        name: "noop".into(),
                        input: serde_json::json!({}),
                    }],
                },
            }),
            None,
        );
        let output = execute_with_active_provider("find docs", &config, &provider)
            .await
            .expect("execute should succeed");

        assert_eq!(output, "No results returned.");
    }

    #[tokio::test]
    async fn execute_propagates_non_ollama_factory_errors() {
        let mut config = Config::default();
        config.web_search.provider = "openai".into();
        config.web_search.model = "gpt-5.2".into();

        let err = execute_with_provider_builder("find docs", &config, || {
            anyhow::bail!("provider init failed")
        })
        .await
        .expect_err("expected error");

        assert!(err.to_string().contains("provider init failed"));
    }

    #[tokio::test]
    async fn execute_rejects_non_search_capable_provider_model() {
        let config = Config::default();

        let err = execute_with_provider_factory("find docs", &config, |_name, _cfg| {
            anyhow::bail!("provider factory should not be called")
        })
        .await
        .expect_err("expected unsupported capability error");

        assert!(
            err.to_string()
                .contains("Web search requires a search-capable provider/model"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn invoke_wraps_unsupported_config_as_failure_outcome() {
        let config = Config::default();
        let ctx = ToolInvocationContext::standalone(&config, false);
        let outcome = invoke(&serde_json::json!({"query": "find docs"}), &ctx)
            .await
            .expect("invoke should succeed");

        let (content, is_error) = outcome.into_outcome_or_failure("web_search").into_parts();
        assert!(is_error);
        assert!(content.contains("search-capable provider/model"));
    }
}
