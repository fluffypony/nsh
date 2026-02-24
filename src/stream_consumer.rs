use crate::provider::{ContentBlock, Message, Role, StreamEvent, Usage};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;

pub enum DisplayEvent {
    TextChunk(String),
    ToolStarted { name: String },
    ToolFinished { name: String },
    Done,
}

pub async fn consume_stream(
    rx: &mut mpsc::Receiver<StreamEvent>,
    cancelled: &Arc<AtomicBool>,
    on_event: &mut dyn FnMut(DisplayEvent),
) -> anyhow::Result<(Message, Option<Usage>)> {
    let mut content_blocks = Vec::new();
    let mut current_text = String::new();
    let mut current_tool_name = String::new();
    let mut current_tool_id = String::new();
    let mut current_tool_input = String::new();
    let mut is_streaming_text = false;
    let mut usage = None;

    loop {
        let event = tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Some(e) => e,
                    None => break,
                }
            }
            _ = check_cancelled(cancelled) => {
                if is_streaming_text {
                    on_event(DisplayEvent::Done);
                }
                anyhow::bail!("interrupted");
            }
        };

        match event {
            StreamEvent::TextDelta(text) => {
                if !is_streaming_text {
                    is_streaming_text = true;
                }
                on_event(DisplayEvent::TextChunk(text.clone()));
                current_text.push_str(&text);
            }

            StreamEvent::ToolUseStart { id, name } => {
                on_event(DisplayEvent::ToolStarted { name: name.clone() });
                current_tool_id = id;
                current_tool_name = name;
                current_tool_input.clear();
            }

            StreamEvent::ToolUseDelta(json_chunk) => {
                current_tool_input.push_str(&json_chunk);
            }

            StreamEvent::ToolUseEnd => {
                let input = serde_json::from_str::<serde_json::Value>(&current_tool_input)
                    .ok()
                    .or_else(|| {
                        tracing::warn!(
                            "Failed to parse tool input JSON ({} bytes), attempting extraction",
                            current_tool_input.len()
                        );
                        crate::json_extract::extract_json(&current_tool_input)
                    })
                    .unwrap_or_else(|| {
                        tracing::warn!("All tool input parse attempts failed, using empty object");
                        serde_json::json!({})
                    });
                content_blocks.push(ContentBlock::ToolUse {
                    id: current_tool_id.clone(),
                    name: current_tool_name.clone(),
                    input,
                });
                on_event(DisplayEvent::ToolFinished {
                    name: current_tool_name.clone(),
                });
                current_tool_input.clear();
            }

            StreamEvent::GenerationId(_) => {}

            StreamEvent::Done { usage: u } => {
                usage = u;
                break;
            }

            StreamEvent::Error(e) => {
                on_event(DisplayEvent::Done);
                anyhow::bail!("Stream error: {e}");
            }
        }
    }

    on_event(DisplayEvent::Done);

    if !current_tool_name.is_empty() && current_tool_input.is_empty() {
        // Tool started but input never arrived: inject empty object to avoid parser confusion
        content_blocks.push(ContentBlock::ToolUse {
            id: current_tool_id.clone(),
            name: current_tool_name.clone(),
            input: serde_json::json!({}),
        });
    }

    if !current_text.is_empty() {
        content_blocks.insert(0, ContentBlock::Text { text: current_text });
    }

    Ok((
        Message {
            role: Role::Assistant,
            content: content_blocks,
        },
        usage,
    ))
}

async fn check_cancelled(cancelled: &Arc<AtomicBool>) {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{StreamEvent, Usage};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    fn not_cancelled() -> Arc<AtomicBool> {
        Arc::new(AtomicBool::new(false))
    }

    #[tokio::test]
    async fn test_consume_stream_text_only() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::TextDelta("hello ".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::TextDelta("world".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let (msg, usage) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert!(matches!(msg.role, crate::provider::Role::Assistant));
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            crate::provider::ContentBlock::Text { text } => assert_eq!(text, "hello world"),
            _ => panic!("expected Text block"),
        }
        assert!(usage.is_none());
    }

    #[tokio::test]
    async fn test_consume_stream_tool_use() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
            name: "run_command".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"cmd":"ls"}"#.into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let (msg, _) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { id, name, input } => {
                assert_eq!(id, "t1");
                assert_eq!(name, "run_command");
                assert_eq!(input, &serde_json::json!({"cmd": "ls"}));
            }
            _ => panic!("expected ToolUse block"),
        }
    }

    #[tokio::test]
    async fn test_consume_stream_text_and_tool() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::TextDelta("thinking...".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseStart {
            id: "t2".into(),
            name: "chat".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"response":"hi"}"#.into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let (msg, _) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert_eq!(msg.content.len(), 2);
        assert!(
            matches!(&msg.content[0], crate::provider::ContentBlock::Text { text } if text == "thinking...")
        );
        assert!(
            matches!(&msg.content[1], crate::provider::ContentBlock::ToolUse { name, .. } if name == "chat")
        );
    }

    #[tokio::test]
    async fn test_consume_stream_with_usage() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::TextDelta("ok".into())).await.unwrap();
        tx.send(StreamEvent::Done {
            usage: Some(Usage {
                input_tokens: 100,
                output_tokens: 50,
            }),
        })
        .await
        .unwrap();
        drop(tx);

        let (_, usage) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        let u = usage.unwrap();
        assert_eq!(u.input_tokens, 100);
        assert_eq!(u.output_tokens, 50);
    }

    #[tokio::test]
    async fn test_consume_stream_error() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::Error("connection lost".into()))
            .await
            .unwrap();
        drop(tx);

        let result = consume_stream(&mut rx, &cancel, &mut |_| {}).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("connection lost"));
    }

    #[tokio::test]
    async fn test_consume_stream_cancelled() {
        let (_tx, mut rx) = mpsc::channel::<StreamEvent>(16);
        let cancel = Arc::new(AtomicBool::new(true));

        let result = consume_stream(&mut rx, &cancel, &mut |_| {}).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("interrupted"));
    }

    #[tokio::test]
    async fn test_consume_stream_generation_id_ignored() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::GenerationId("gen-123".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::TextDelta("hi".into())).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let (msg, _) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert_eq!(msg.content.len(), 1);
    }

    #[tokio::test]
    async fn test_consume_stream_empty() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();
        drop(tx);

        let (msg, usage) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert!(msg.content.is_empty());
        assert!(usage.is_none());
    }

    #[tokio::test]
    async fn test_consume_stream_tool_with_invalid_json_fallback() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::ToolUseStart {
            id: "t3".into(),
            name: "test".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta("not valid json{{{".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let (msg, _) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { input, .. } => {
                assert_eq!(input, &serde_json::json!({}));
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[tokio::test]
    async fn test_consume_stream_unflushed_tool_at_end() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();

        tx.send(StreamEvent::ToolUseStart {
            id: "t4".into(),
            name: "cmd".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"x":1}"#.into()))
            .await
            .unwrap();
        // No ToolUseEnd — channel just closes
        drop(tx);

        let (msg, _) = consume_stream(&mut rx, &cancel, &mut |_| {}).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            crate::provider::ContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "cmd");
                assert_eq!(input, &serde_json::json!({"x": 1}));
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[tokio::test]
    async fn test_consume_stream_display_events() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancel = not_cancelled();
        let mut event_names = vec![];

        tx.send(StreamEvent::TextDelta("hi".into())).await.unwrap();
        tx.send(StreamEvent::ToolUseStart {
            id: "t5".into(),
            name: "search".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta("{}".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        consume_stream(&mut rx, &cancel, &mut |e| match e {
            DisplayEvent::TextChunk(_) => event_names.push("text"),
            DisplayEvent::ToolStarted { .. } => event_names.push("tool_start"),
            DisplayEvent::ToolFinished { .. } => event_names.push("tool_end"),
            DisplayEvent::Done => event_names.push("done"),
        })
        .await
        .unwrap();

        assert!(event_names.contains(&"text"));
        assert!(event_names.contains(&"tool_start"));
        assert!(event_names.contains(&"tool_end"));
        assert!(event_names.contains(&"done"));
    }

    #[tokio::test]
    async fn test_consume_stream_cancelled_while_streaming_text() {
        let (tx, mut rx) = mpsc::channel::<StreamEvent>(16);
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel2 = cancel.clone();
        let mut got_done = false;

        tx.send(StreamEvent::TextDelta("partial".into()))
            .await
            .unwrap();

        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            cancel2.store(true, Ordering::SeqCst);
        });

        let result = consume_stream(&mut rx, &cancel, &mut |e| {
            if matches!(e, DisplayEvent::Done) {
                got_done = true;
            }
        })
        .await;

        handle.await.unwrap();
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("interrupted"));
        assert!(
            got_done,
            "should emit Done when cancelled while streaming text"
        );
    }
}
