use crate::provider::{ContentBlock, Message, Role, StreamEvent};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);
static SPINNER_HANDLE: Mutex<Option<std::thread::JoinHandle<()>>> =
    Mutex::new(None);

pub fn show_spinner() {
    SPINNER_ACTIVE.store(true, Ordering::SeqCst);
    let handle = std::thread::spawn(move || {
        let frames = [
            "\u{280b}", "\u{2819}", "\u{2839}", "\u{2838}",
            "\u{283c}", "\u{2834}", "\u{2826}", "\u{2827}",
            "\u{2807}", "\u{280f}",
        ];
        let mut i = 0;
        while SPINNER_ACTIVE.load(Ordering::SeqCst) {
            eprint!(
                "\r\x1b[2m{} thinking...\x1b[0m",
                frames[i % frames.len()]
            );
            io::stderr().flush().ok();
            i += 1;
            std::thread::sleep(std::time::Duration::from_millis(
                80,
            ));
        }
    });
    if let Ok(mut guard) = SPINNER_HANDLE.lock() {
        *guard = Some(handle);
    }
}

pub fn hide_spinner() {
    SPINNER_ACTIVE.store(false, Ordering::SeqCst);
    if let Ok(mut guard) = SPINNER_HANDLE.lock() {
        if let Some(handle) = guard.take() {
            let _ = handle.join();
        }
    }
    eprint!("\r\x1b[K");
    io::stderr().flush().ok();
}

/// Consume a streaming response, display chat text in real-time,
/// and accumulate the full Message for the conversation.
pub async fn consume_stream(
    rx: &mut mpsc::Receiver<StreamEvent>,
    cancelled: &Arc<AtomicBool>,
) -> anyhow::Result<Message> {
    let mut content_blocks = Vec::new();
    let mut current_text = String::new();
    let mut current_tool_name = String::new();
    let mut current_tool_id = String::new();
    let mut current_tool_input = String::new();
    let mut is_streaming_text = false;

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
                    eprint!("\x1b[0m");
                }
                eprintln!("\nnsh: interrupted");
                std::process::exit(130);
            }
        };

        match event {
            StreamEvent::TextDelta(text) => {
                if !is_streaming_text {
                    is_streaming_text = true;
                    eprint!("\x1b[3;36m"); // cyan italic
                }
                eprint!("{text}");
                io::stderr().flush().ok();
                current_text.push_str(&text);
            }

            StreamEvent::ToolUseStart { id, name } => {
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
                current_tool_input.clear();
            }

            StreamEvent::Done { .. } => break,

            StreamEvent::Error(e) => {
                if is_streaming_text {
                    eprintln!("\x1b[0m");
                }
                anyhow::bail!("Stream error: {e}");
            }
        }
    }

    if is_streaming_text {
        eprintln!("\x1b[0m"); // reset color + newline
    }

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

    Ok(Message {
        role: Role::Assistant,
        content: content_blocks,
    })
}

async fn check_cancelled(cancelled: &Arc<AtomicBool>) {
    loop {
        if cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
