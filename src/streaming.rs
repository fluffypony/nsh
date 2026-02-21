use crate::provider::{Message, StreamEvent};
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc;

static SPINNER_ACTIVE: AtomicBool = AtomicBool::new(false);
static SPINNER_HANDLE: Mutex<Option<std::thread::JoinHandle<()>>> = Mutex::new(None);
static JSON_OUTPUT: AtomicBool = AtomicBool::new(false);
static LAST_STREAM_HAD_TEXT: AtomicBool = AtomicBool::new(false);

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

pub fn set_json_output(enabled: bool) {
    JSON_OUTPUT.store(enabled, Ordering::SeqCst);
}

pub fn json_output_enabled() -> bool {
    JSON_OUTPUT.load(Ordering::SeqCst)
}

pub fn last_stream_had_text() -> bool {
    LAST_STREAM_HAD_TEXT.load(Ordering::SeqCst)
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

impl Default for SpinnerGuard {
    fn default() -> Self {
        Self::new()
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
    LAST_STREAM_HAD_TEXT.store(false, Ordering::SeqCst);
    let mut is_streaming = false;
    let mut json_display = if JSON_OUTPUT.load(Ordering::SeqCst) {
        Some(crate::json_display::JsonDisplay::new())
    } else {
        None
    };
    let color = chat_color().to_string();
    let (msg, _usage) = crate::stream_consumer::consume_stream(rx, cancelled, &mut |event| {
        if let Some(display) = json_display.as_mut() {
            display.handle_event(event);
            return;
        }
        match event {
            crate::stream_consumer::DisplayEvent::TextChunk(text) => {
                LAST_STREAM_HAD_TEXT.store(true, Ordering::SeqCst);
                if !is_streaming {
                    is_streaming = true;
                    eprint!("{color}");
                }
                eprint!("{text}");
                io::stderr().flush().ok();
            }
            crate::stream_consumer::DisplayEvent::Done => {
                if is_streaming {
                    eprintln!("\x1b[0m");
                    io::stderr().flush().ok();
                    is_streaming = false;
                }
            }
            _ => {}
        }
    })
    .await?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::{ContentBlock, StreamEvent};
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
    fn test_spinner_guard_noop() {}

    #[tokio::test]
    async fn test_consume_stream_text() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::TextDelta("hello ".to_string()))
            .await
            .unwrap();
        tx.send(StreamEvent::TextDelta("world".to_string()))
            .await
            .unwrap();
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
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"command":"ls"}"#.into()))
            .await
            .unwrap();
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

        tx.send(StreamEvent::Error("test error".into()))
            .await
            .unwrap();
        drop(tx);

        let result = consume_stream(&mut rx, &cancelled).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_consume_stream_generation_id_ignored() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::GenerationId("gen-123".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert!(msg.content.is_empty());
    }

    #[tokio::test]
    async fn test_consume_stream_text_and_tool() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::TextDelta("thinking...".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
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

    #[test]
    fn test_spinner_guard_creates_and_drops() {
        SPINNER_ACTIVE.store(false, Ordering::SeqCst);
        {
            let guard = SpinnerGuard::new();
            assert!(guard.did_start);
            assert!(SPINNER_ACTIVE.load(Ordering::SeqCst));
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(!SPINNER_ACTIVE.load(Ordering::SeqCst));
    }

    #[serial_test::serial]
    #[test]
    fn test_spinner_guard_second_is_noop() {
        SPINNER_ACTIVE.store(false, Ordering::SeqCst);
        let guard1 = SpinnerGuard::new();
        assert!(guard1.did_start);
        let guard2 = SpinnerGuard::new();
        assert!(!guard2.did_start);
        drop(guard2);
        assert!(SPINNER_ACTIVE.load(Ordering::SeqCst));
        drop(guard1);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    #[test]
    fn test_spinner_frames_returns_defaults() {
        let frames = spinner_frames();
        assert!(frames.len() >= 10);
        assert_eq!(frames[0], "⠋");
    }

    #[test]
    fn test_show_and_hide_spinner() {
        show_spinner();
        std::thread::sleep(std::time::Duration::from_millis(100));
        hide_spinner();
    }

    #[tokio::test]
    async fn test_consume_stream_unflushed_tool_at_end() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
            name: "cmd".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"x":1}"#.into()))
            .await
            .unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        match &msg.content[0] {
            ContentBlock::ToolUse { name, input, .. } => {
                assert_eq!(name, "cmd");
                assert_eq!(input, &serde_json::json!({"x": 1}));
            }
            _ => panic!("expected ToolUse"),
        }
    }

    #[tokio::test]
    async fn test_consume_stream_tool_with_invalid_json() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::ToolUseStart {
            id: "t2".into(),
            name: "test".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta("not json{{".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        if let ContentBlock::ToolUse { input, .. } = &msg.content[0] {
            assert_eq!(input, &serde_json::json!({}));
        }
    }

    #[tokio::test]
    async fn test_consume_stream_multiple_tools() {
        let (tx, mut rx) = mpsc::channel(16);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::ToolUseStart {
            id: "t1".into(),
            name: "search".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"q":"test"}"#.into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::ToolUseStart {
            id: "t2".into(),
            name: "read".into(),
        })
        .await
        .unwrap();
        tx.send(StreamEvent::ToolUseDelta(r#"{"path":"/"}"#.into()))
            .await
            .unwrap();
        tx.send(StreamEvent::ToolUseEnd).await.unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 2);
    }

    #[tokio::test]
    async fn test_consume_stream_text_then_done_covers_display() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::TextDelta("chunk1".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::TextDelta("chunk2".into()))
            .await
            .unwrap();
        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert_eq!(msg.content.len(), 1);
        if let ContentBlock::Text { text } = &msg.content[0] {
            assert_eq!(text, "chunk1chunk2");
        } else {
            panic!("expected text");
        }
    }

    #[tokio::test]
    async fn test_consume_stream_done_without_text() {
        let (tx, mut rx) = mpsc::channel(8);
        let cancelled = Arc::new(AtomicBool::new(false));

        tx.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx);

        let msg = consume_stream(&mut rx, &cancelled).await.unwrap();
        assert!(msg.content.is_empty());
    }

    #[test]
    fn test_chat_color_returns_nonempty() {
        let c = chat_color();
        assert!(!c.is_empty());
    }

    #[test]
    fn test_configure_display_custom_values() {
        let config = crate::config::DisplayConfig {
            chat_color: "\x1b[1;32m".into(),
            thinking_indicator: "/-\\|".into(),
        };
        configure_display(&config);
    }

    #[test]
    fn test_show_spinner_then_immediate_hide() {
        SPINNER_ACTIVE.store(false, Ordering::SeqCst);
        show_spinner();
        assert!(SPINNER_ACTIVE.load(Ordering::SeqCst));
        hide_spinner();
        assert!(!SPINNER_ACTIVE.load(Ordering::SeqCst));
    }

    #[test]
    fn test_spinner_guard_already_active_returns_did_start_false() {
        SPINNER_ACTIVE.store(true, Ordering::SeqCst);
        let guard = SpinnerGuard::new();
        assert!(!guard.did_start);
        drop(guard);
        assert!(SPINNER_ACTIVE.load(Ordering::SeqCst));
        SPINNER_ACTIVE.store(false, Ordering::SeqCst);
        if let Ok(mut h) = SPINNER_HANDLE.lock() {
            if let Some(handle) = h.take() {
                let _ = handle.join();
            }
        }
    }
}
