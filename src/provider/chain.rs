use std::time::Duration;
use tokio::sync::mpsc;

use crate::provider::{ChatRequest, ContentBlock, LlmProvider, StreamEvent};

pub fn is_retryable_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("429")
        || msg.contains("Too Many Requests")
        || msg.contains("500")
        || msg.contains("502")
        || msg.contains("503")
        || msg.contains("504")
        || msg.contains("Internal Server Error")
        || msg.contains("Bad Gateway")
        || msg.contains("Service Unavailable")
        || msg.contains("Gateway Timeout")
        || msg.contains("timeout")
        || msg.contains("timed out")
}

#[allow(dead_code)]
pub async fn call_with_chain(
    provider: &dyn LlmProvider,
    request: ChatRequest,
    chain: &[String],
) -> anyhow::Result<(mpsc::Receiver<StreamEvent>, String)> {
    for (i, model) in chain.iter().enumerate() {
        let mut req = request.clone();
        req.model = model.clone();
        for attempt in 0..2 {
            match provider.stream(req.clone()).await {
                Ok(rx) => return Ok((rx, model.clone())),
                Err(e) if is_retryable_error(&e) && attempt == 0 => {
                    tracing::warn!("Model {model} attempt {attempt}: {e}, retrying...");
                    tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
                    continue;
                }
                Err(e) if i < chain.len() - 1 => {
                    tracing::warn!(
                        "Model {model} failed: {e}, falling back to {}",
                        chain[i + 1]
                    );
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    anyhow::bail!("All models in chain exhausted")
}

pub async fn stream_with_complete_fallback(
    provider: &dyn LlmProvider,
    request: ChatRequest,
) -> anyhow::Result<mpsc::Receiver<StreamEvent>> {
    match provider.stream(request.clone()).await {
        Ok(rx) => Ok(rx),
        Err(e) => {
            tracing::warn!("Streaming failed, falling back to non-streaming: {e}");
            let response = provider.complete(request).await?;
            let (tx, rx) = mpsc::channel(8);
            tokio::spawn(async move {
                for block in &response.content {
                    match block {
                        ContentBlock::Text { text } => {
                            let _ = tx.send(StreamEvent::TextDelta(text.clone())).await;
                        }
                        ContentBlock::ToolUse { id, name, input } => {
                            let _ = tx
                                .send(StreamEvent::ToolUseStart {
                                    id: id.clone(),
                                    name: name.clone(),
                                })
                                .await;
                            let _ = tx.send(StreamEvent::ToolUseDelta(input.to_string())).await;
                            let _ = tx.send(StreamEvent::ToolUseEnd).await;
                        }
                        _ => {}
                    }
                }
                let _ = tx.send(StreamEvent::Done { usage: None }).await;
            });
            Ok(rx)
        }
    }
}

#[allow(dead_code)]
pub async fn call_chain_with_fallback(
    provider: &dyn LlmProvider,
    request: ChatRequest,
    chain: &[String],
) -> anyhow::Result<(mpsc::Receiver<StreamEvent>, String)> {
    call_chain_with_fallback_think(provider, request, chain, false).await
}

pub async fn call_chain_with_fallback_think(
    provider: &dyn LlmProvider,
    request: ChatRequest,
    chain: &[String],
    think: bool,
) -> anyhow::Result<(mpsc::Receiver<StreamEvent>, String)> {
    for (i, model) in chain.iter().enumerate() {
        let mut req = request.clone();
        req.model = super::openai_compat::thinking_model_name(model, think);
        let mut extra = req.extra_body.take().unwrap_or(serde_json::json!({}));
        super::openai_compat::apply_thinking_mode(&mut extra, model, think);
        if extra.as_object().is_some_and(|m| !m.is_empty()) {
            req.extra_body = Some(extra);
        }
        for attempt in 0..2 {
            match stream_with_complete_fallback(provider, req.clone()).await {
                Ok(rx) => return Ok((rx, model.clone())),
                Err(e) if is_retryable_error(&e) && attempt == 0 => {
                    tracing::warn!("Model {model} attempt {attempt}: {e}, retrying...");
                    tokio::time::sleep(Duration::from_millis(500 * (attempt as u64 + 1))).await;
                    continue;
                }
                Err(e) if i < chain.len() - 1 => {
                    tracing::warn!(
                        "Model {model} failed: {e}, falling back to {}",
                        chain[i + 1]
                    );
                    break;
                }
                Err(e) => return Err(e),
            }
        }
    }
    anyhow::bail!("All models in chain exhausted")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ChatRequest, ContentBlock, LlmProvider, Message, Role, StreamEvent, ToolChoice};
    use std::sync::Arc;

    struct MockProvider {
        complete_result: Arc<dyn Fn() -> anyhow::Result<Message> + Send + Sync>,
        stream_result: Arc<dyn Fn() -> anyhow::Result<mpsc::Receiver<StreamEvent>> + Send + Sync>,
    }

    #[async_trait::async_trait]
    impl LlmProvider for MockProvider {
        async fn complete(&self, _request: ChatRequest) -> anyhow::Result<Message> {
            (self.complete_result)()
        }
        async fn stream(
            &self,
            _request: ChatRequest,
        ) -> anyhow::Result<mpsc::Receiver<StreamEvent>> {
            (self.stream_result)()
        }
    }

    fn dummy_request() -> ChatRequest {
        ChatRequest {
            model: "test".into(),
            system: "test".into(),
            messages: vec![],
            tools: vec![],
            tool_choice: ToolChoice::Auto,
            max_tokens: 100,
            stream: true,
            extra_body: None,
        }
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_stream_ok() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!("complete should not be called")),
            stream_result: Arc::new(|| {
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    let _ = tx.send(StreamEvent::TextDelta("hello".into())).await;
                    let _ = tx.send(StreamEvent::Done { usage: None }).await;
                });
                Ok(rx)
            }),
        };
        let mut rx = stream_with_complete_fallback(&provider, dummy_request())
            .await
            .unwrap();
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "hello"));
        let done = rx.recv().await.unwrap();
        assert!(matches!(done, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_falls_back() {
        let provider = MockProvider {
            complete_result: Arc::new(|| {
                Ok(Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::Text {
                        text: "fallback".into(),
                    }],
                })
            }),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("stream not supported"))),
        };
        let mut rx = stream_with_complete_fallback(&provider, dummy_request())
            .await
            .unwrap();
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "fallback"));
        let done = rx.recv().await.unwrap();
        assert!(matches!(done, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn call_chain_with_fallback_think_first_succeeds() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!("complete should not be called")),
            stream_result: Arc::new(|| {
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    let _ = tx.send(StreamEvent::TextDelta("ok".into())).await;
                    let _ = tx.send(StreamEvent::Done { usage: None }).await;
                });
                Ok(rx)
            }),
        };
        let chain = vec!["model-a".to_string(), "model-b".to_string()];
        let (mut rx, model) = call_chain_with_fallback_think(&provider, dummy_request(), &chain, false)
            .await
            .unwrap();
        assert_eq!(model, "model-a");
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "ok"));
    }

    #[tokio::test]
    async fn call_chain_with_fallback_think_falls_back_to_second() {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let provider = MockProvider {
            complete_result: Arc::new(|| Err(anyhow::anyhow!("complete also fails"))),
            stream_result: Arc::new(move || {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 1 {
                    Err(anyhow::anyhow!("model not available"))
                } else {
                    let (tx, rx) = mpsc::channel(8);
                    tokio::spawn(async move {
                        let _ = tx.send(StreamEvent::TextDelta("from-b".into())).await;
                        let _ = tx.send(StreamEvent::Done { usage: None }).await;
                    });
                    Ok(rx)
                }
            }),
        };
        let chain = vec!["model-a".to_string(), "model-b".to_string()];
        let (mut rx, model) = call_chain_with_fallback_think(&provider, dummy_request(), &chain, false)
            .await
            .unwrap();
        assert_eq!(model, "model-b");
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "from-b"));
    }

    #[test]
    fn retryable_429() {
        let e = anyhow::anyhow!("HTTP 429 Too Many Requests");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_500() {
        let e = anyhow::anyhow!("500 Internal Server Error");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_502() {
        let e = anyhow::anyhow!("502 Bad Gateway");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_503() {
        let e = anyhow::anyhow!("503 Service Unavailable");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_504() {
        let e = anyhow::anyhow!("504 Gateway Timeout");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_timeout() {
        let e = anyhow::anyhow!("connection timed out");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_timeout_keyword() {
        let e = anyhow::anyhow!("request timeout reached");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn not_retryable_400() {
        let e = anyhow::anyhow!("400 Bad Request: invalid model");
        assert!(!is_retryable_error(&e));
    }

    #[test]
    fn not_retryable_401() {
        let e = anyhow::anyhow!("401 Unauthorized");
        assert!(!is_retryable_error(&e));
    }

    #[test]
    fn not_retryable_403() {
        let e = anyhow::anyhow!("403 Forbidden");
        assert!(!is_retryable_error(&e));
    }

    #[test]
    fn not_retryable_404() {
        let e = anyhow::anyhow!("404 Not Found");
        assert!(!is_retryable_error(&e));
    }

    #[test]
    fn not_retryable_generic() {
        let e = anyhow::anyhow!("something went wrong");
        assert!(!is_retryable_error(&e));
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_tool_use_content() {
        let provider = MockProvider {
            complete_result: Arc::new(|| {
                Ok(Message {
                    role: Role::Assistant,
                    content: vec![ContentBlock::ToolUse {
                        id: "t1".into(),
                        name: "search".into(),
                        input: serde_json::json!({"q": "test"}),
                    }],
                })
            }),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("stream fail"))),
        };
        let mut rx = stream_with_complete_fallback(&provider, dummy_request())
            .await
            .unwrap();
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::ToolUseStart { name, .. } if name == "search"));
        let delta = rx.recv().await.unwrap();
        assert!(matches!(delta, StreamEvent::ToolUseDelta(_)));
        let end = rx.recv().await.unwrap();
        assert!(matches!(end, StreamEvent::ToolUseEnd));
        let done = rx.recv().await.unwrap();
        assert!(matches!(done, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_both_fail() {
        let provider = MockProvider {
            complete_result: Arc::new(|| Err(anyhow::anyhow!("complete also fails"))),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("stream fails"))),
        };
        let result = stream_with_complete_fallback(&provider, dummy_request()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_chain_with_fallback_think_all_fail() {
        let provider = MockProvider {
            complete_result: Arc::new(|| Err(anyhow::anyhow!("nope"))),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("also nope"))),
        };
        let chain = vec!["model-a".to_string()];
        let result = call_chain_with_fallback_think(&provider, dummy_request(), &chain, false).await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("also nope") || err_msg.contains("nope"));
    }

    #[tokio::test]
    async fn call_chain_with_fallback_think_empty_chain() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(|| unreachable!()),
        };
        let chain: Vec<String> = vec![];
        let result = call_chain_with_fallback_think(&provider, dummy_request(), &chain, false).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exhausted"));
    }

    #[tokio::test]
    async fn call_chain_with_fallback_think_retries_on_retryable() {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let provider = MockProvider {
            complete_result: Arc::new(|| Err(anyhow::anyhow!("503 Service Unavailable"))),
            stream_result: Arc::new(move || {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Err(anyhow::anyhow!("503 Service Unavailable"))
                } else {
                    let (tx, rx) = mpsc::channel(8);
                    tokio::spawn(async move {
                        let _ = tx.send(StreamEvent::TextDelta("ok".into())).await;
                        let _ = tx.send(StreamEvent::Done { usage: None }).await;
                    });
                    Ok(rx)
                }
            }),
        };
        let chain = vec!["model-a".to_string()];
        let (mut rx, model) = call_chain_with_fallback_think(&provider, dummy_request(), &chain, false)
            .await
            .unwrap();
        assert_eq!(model, "model-a");
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "ok"));
    }

    #[test]
    fn retryable_internal_server_error() {
        let e = anyhow::anyhow!("Internal Server Error");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_bad_gateway() {
        let e = anyhow::anyhow!("Bad Gateway");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_service_unavailable() {
        let e = anyhow::anyhow!("Service Unavailable");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_gateway_timeout() {
        let e = anyhow::anyhow!("Gateway Timeout");
        assert!(is_retryable_error(&e));
    }

    #[test]
    fn retryable_too_many_requests_phrase() {
        let e = anyhow::anyhow!("Too Many Requests");
        assert!(is_retryable_error(&e));
    }

    #[tokio::test]
    async fn call_with_chain_first_model_succeeds() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(|| {
                let (tx, rx) = mpsc::channel(8);
                tokio::spawn(async move {
                    let _ = tx.send(StreamEvent::TextDelta("ok".into())).await;
                    let _ = tx.send(StreamEvent::Done { usage: None }).await;
                });
                Ok(rx)
            }),
        };
        let chain = vec!["model-a".to_string(), "model-b".to_string()];
        let (mut rx, model) = call_with_chain(&provider, dummy_request(), &chain)
            .await
            .unwrap();
        assert_eq!(model, "model-a");
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "ok"));
    }

    #[tokio::test]
    async fn call_with_chain_falls_back_on_failure() {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(move || {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n < 1 {
                    Err(anyhow::anyhow!("model not available"))
                } else {
                    let (tx, rx) = mpsc::channel(8);
                    tokio::spawn(async move {
                        let _ = tx.send(StreamEvent::TextDelta("from-b".into())).await;
                        let _ = tx.send(StreamEvent::Done { usage: None }).await;
                    });
                    Ok(rx)
                }
            }),
        };
        let chain = vec!["model-a".to_string(), "model-b".to_string()];
        let (mut rx, model) = call_with_chain(&provider, dummy_request(), &chain)
            .await
            .unwrap();
        assert_eq!(model, "model-b");
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "from-b"));
    }

    #[tokio::test]
    async fn call_with_chain_empty_chain() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(|| unreachable!()),
        };
        let chain: Vec<String> = vec![];
        let result = call_with_chain(&provider, dummy_request(), &chain).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exhausted"));
    }

    #[tokio::test]
    async fn call_with_chain_all_fail() {
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("nope"))),
        };
        let chain = vec!["a".to_string()];
        let result = call_with_chain(&provider, dummy_request(), &chain).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn call_with_chain_retries_on_retryable_then_succeeds() {
        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cc = call_count.clone();
        let provider = MockProvider {
            complete_result: Arc::new(|| unreachable!()),
            stream_result: Arc::new(move || {
                let n = cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                if n == 0 {
                    Err(anyhow::anyhow!("429 Too Many Requests"))
                } else {
                    let (tx, rx) = mpsc::channel(8);
                    tokio::spawn(async move {
                        let _ = tx.send(StreamEvent::TextDelta("ok".into())).await;
                        let _ = tx.send(StreamEvent::Done { usage: None }).await;
                    });
                    Ok(rx)
                }
            }),
        };
        let chain = vec!["model-a".to_string()];
        let (_, model) = call_with_chain(&provider, dummy_request(), &chain)
            .await
            .unwrap();
        assert_eq!(model, "model-a");
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_mixed_content() {
        let provider = MockProvider {
            complete_result: Arc::new(|| {
                Ok(Message {
                    role: Role::Assistant,
                    content: vec![
                        ContentBlock::Text { text: "thinking".into() },
                        ContentBlock::ToolUse {
                            id: "t1".into(),
                            name: "search".into(),
                            input: serde_json::json!({"q": "test"}),
                        },
                    ],
                })
            }),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("stream fail"))),
        };
        let mut rx = stream_with_complete_fallback(&provider, dummy_request())
            .await
            .unwrap();
        let first = rx.recv().await.unwrap();
        assert!(matches!(first, StreamEvent::TextDelta(t) if t == "thinking"));
        let tool_start = rx.recv().await.unwrap();
        assert!(matches!(tool_start, StreamEvent::ToolUseStart { name, .. } if name == "search"));
        let tool_delta = rx.recv().await.unwrap();
        assert!(matches!(tool_delta, StreamEvent::ToolUseDelta(_)));
        let tool_end = rx.recv().await.unwrap();
        assert!(matches!(tool_end, StreamEvent::ToolUseEnd));
        let done = rx.recv().await.unwrap();
        assert!(matches!(done, StreamEvent::Done { .. }));
    }

    #[tokio::test]
    async fn stream_with_complete_fallback_empty_content() {
        let provider = MockProvider {
            complete_result: Arc::new(|| {
                Ok(Message {
                    role: Role::Assistant,
                    content: vec![],
                })
            }),
            stream_result: Arc::new(|| Err(anyhow::anyhow!("no stream"))),
        };
        let mut rx = stream_with_complete_fallback(&provider, dummy_request())
            .await
            .unwrap();
        let done = rx.recv().await.unwrap();
        assert!(matches!(done, StreamEvent::Done { .. }));
    }
}
