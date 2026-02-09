use crate::provider::{ContentBlock, Message, Role, StreamEvent, Usage};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
                    .or_else(|| crate::json_extract::extract_json(&current_tool_input))
                    .unwrap_or_else(|| serde_json::json!({}));
                content_blocks.push(ContentBlock::ToolUse {
                    id: current_tool_id.clone(),
                    name: current_tool_name.clone(),
                    input,
                });
                on_event(DisplayEvent::ToolFinished { name: current_tool_name.clone() });
                current_tool_input.clear();
            }

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

    if !current_tool_name.is_empty() && !current_tool_input.is_empty() {
        let input = serde_json::from_str::<serde_json::Value>(&current_tool_input)
            .ok()
            .or_else(|| crate::json_extract::extract_json(&current_tool_input))
            .unwrap_or_else(|| serde_json::json!({}));
        content_blocks.push(ContentBlock::ToolUse {
            id: current_tool_id.clone(),
            name: current_tool_name.clone(),
            input,
        });
    }

    if !current_text.is_empty() {
        content_blocks.insert(
            0,
            ContentBlock::Text {
                text: current_text,
            },
        );
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
