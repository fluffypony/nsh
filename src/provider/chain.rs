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
