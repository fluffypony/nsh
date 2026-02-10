use crate::provider::{ContentBlock, Message, Role, StreamEvent};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc;

static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);
static SPINNER_HANDLE: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);

static CHAT_COLOR: OnceLock<String> = OnceLock::new();
static SPINNER_FRAMES: OnceLock<Vec<String>> = OnceLock::new();

pub fn configure_display(config: &crate::config::DisplayConfig) {
    let _ = CHAT_COLOR.set(config.chat_color.clone());
    let frames: Vec<String> = config
        .thinking_indicator
        .chars()
        .map(|c| c.to_string())
        .collect();
    if !frames.is_empty() {
        let _ = SPINNER_FRAMES.set(frames);
    }
}

fn chat_color() -> &'static str {
    CHAT_COLOR.get().map(|s| s.as_str()).unwrap_or("\x1b[3;36m")
}

fn spinner_frames() -> &'static [String] {
    static DEFAULT: OnceLock<Vec<String>> = OnceLock::new();
    SPINNER_FRAMES.get().unwrap_or_else(|| {
        DEFAULT.get_or_init(|| {
            vec!["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
                .into_iter()
                .map(String::from)
                .collect()
        })
    })
}

#[allow(dead_code)]
pub fn show_spinner() {
    SPINNER_ACTIVE.store(true, Ordering::SeqCst);
    let handle = std::thread::spawn(move || {
        let frames = spinner_frames();
        let mut i = 0;
        while SPINNER_ACTIVE.load(Ordering::SeqCst) {
            eprint!("\r\x1b[2m{} thinking...\x1b[0m", frames[i % frames.len()]);
            io::stderr().flush().ok();
            i += 1;
            std::thread::sleep(std::time::Duration::from_millis(80));
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

pub struct SpinnerGuard {
    did_start: bool,
}

impl SpinnerGuard {
    pub fn new() -> Self {
        let was_inactive = SPINNER_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok();
        if was_inactive {
            let handle = std::thread::spawn(move || {
                let frames = spinner_frames();
                let mut i = 0;
                while SPINNER_ACTIVE.load(Ordering::SeqCst) {
                    eprint!("\r\x1b[2m{} thinking...\x1b[0m", frames[i % frames.len()]);
                    std::io::Write::flush(&mut std::io::stderr()).ok();
                    i += 1;
                    std::thread::sleep(std::time::Duration::from_millis(80));
                }
            });
            if let Ok(mut guard) = SPINNER_HANDLE.lock() {
                *guard = Some(handle);
            }
            Self { did_start: true }
        } else {
            Self { did_start: false }
        }
    }
}

impl Drop for SpinnerGuard {
    fn drop(&mut self) {
        if self.did_start {
            hide_spinner();
        }
    }
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
                    eprint!("{}", chat_color());
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

            StreamEvent::GenerationId(_) => {}

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
        content_blocks.insert(0, ContentBlock::Text { text: current_text });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    #[test]
    fn test_configure_display() {
        let config = crate::config::DisplayConfig::default();
        configure_display(&config);
    }

    #[test]
    fn test_chat_color_default() {
        let color = chat_color();
        assert!(!color.is_empty());
    }

    #[test]
    fn test_spinner_frames_default() {
        let frames = spinner_frames();
        assert!(!frames.is_empty());
    }

    #[test]
    fn test_hide_spinner_noop_when_not_active() {
        hide_spinner();
    }

    #[test]
    fn test_spinner_guard_noop() {
    }

    #[tokio::test]
    async fn test_consume_stream_text() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::TextDelta("hello ".to_string())).await.unwrap();
        tx.send(StreamEvent::TextDelta("world".to_string())).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        if let ContentBlock::Text { text } = &msg.content[0] {
            assert_eq!(text, "hello world");
        } else {
            panic!("expected text content");
        }
    }

    #[tokio::test]
    async fn test_consume_stream_tool_use() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
            name: "command".into(),
        }).await.unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"command":"ls"}"#.into())).await.unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        if let ContentBlock::ToolUse { name, input, .. } = &msg.content[0] {
            assert_eq!(name, "command");
            assert_eq!(input["command"].as_str(), Some("ls"));
        } else {
            panic!("expected tool use");
        }
    }

    #[tokio::test]
    async fn test_consume_stream_error() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::Error("test error".into())).await.unwrap();
        drop(tx);

        let result = consume_stream(&mut rx, &cancelled).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_consume_stream_generation_id_ignored() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::GenerationId("gen-123".into())).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert!(msg.content.is_empty());
    }

    #[tokio::test]
    async fn test_consume_stream_text_and_tool() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::TextDelta("thinking...".into())).await.unwrap();
        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
            name: "chat".into(),
        }).await.unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"response":"hi"}"#.into())).await.unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 2);
    }

    #[tokio::test]
    async fn test_consume_stream_channel_closed() {
        let (tx, mut rx) = mpsc::channel::<StreamEvent>(8);
        let cancelled = Arc::new(AtomicBool::new(false));
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert!(msg.content.is_empty());
    }
}
