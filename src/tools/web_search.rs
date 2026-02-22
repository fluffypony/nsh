use crate::config::Config;
use crate::provider::{self, ChatRequest, ContentBlock, Message, Role, ToolChoice};

pub async fn execute(query: &str, config: &Config) -> anyhow::Result<String> {
    execute_with_provider_factory(query, config, provider::create_provider).await
}

async fn execute_with_provider_factory<F>(
    query: &str,
    config: &Config,
    provider_factory: F,
) -> anyhow::Result<String>
where
    F: Fn(&str, &Config) -> anyhow::Result<Box<dyn provider::LlmProvider>>,
{
    let ws_provider_name = &config.web_search.provider;
    let ws_model = &config.web_search.model;

    let provider = match provider_factory(ws_provider_name, config) {
        Ok(p) => p,
        Err(e) => {
            if ws_provider_name == "ollama" {
                anyhow::bail!(
                    "Web search not available with provider ollama. \
                     Configure [web_search] provider to use openrouter or another search-capable provider."
                );
            }
            return Err(e);
        }
    };

    let request = ChatRequest {
        model: ws_model.clone(),
        system: "Provide a concise factual answer with sources. Be brief.".into(),
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
        extra_body: None,
    };

    let response = provider.complete(request).await?;

    let text = response
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
        .join("\n");

    if text.is_empty() {
        Ok("No results returned.".into())
    } else {
        Ok(text)
    }
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
        let config = Config::default();
        let captured_request: Arc<Mutex<Option<ChatRequest>>> = Arc::new(Mutex::new(None));
        let captured_request_for_provider = Arc::clone(&captured_request);

        let output = execute_with_provider_factory("find docs", &config, |provider_name, _cfg| {
            assert_eq!(provider_name, "openrouter");
            Ok(Box::new(StubProvider {
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
            }))
        })
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
        assert_eq!(request.messages.len(), 1);
        assert!(matches!(request.messages[0].role, Role::User));
        assert!(matches!(
            request.messages[0].content.as_slice(),
            [ContentBlock::Text { text }] if text == "find docs"
        ));
    }

    #[tokio::test]
    async fn execute_returns_default_when_provider_returns_no_text() {
        let config = Config::default();
        let output = execute_with_provider_factory("find docs", &config, |_name, _cfg| {
            Ok(Box::new(StubProvider {
                captured_request: None,
                message: Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "id".into(),
                        name: "noop".into(),
                        input: serde_json::json!({}),
                    }],
                },
            }))
        })
        .await
        .expect("execute should succeed");

        assert_eq!(output, "No results returned.");
    }

    #[tokio::test]
    async fn execute_propagates_non_ollama_factory_errors() {
        let mut config = Config::default();
        config.web_search.provider = "openrouter".into();

        let err = execute_with_provider_factory("find docs", &config, |_name, _cfg| {
            anyhow::bail!("provider init failed")
        })
        .await
        .expect_err("expected error");

        assert!(err.to_string().contains("provider init failed"));
    }
}
