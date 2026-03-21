use crate::provider::{Message, StreamEvent};
use crate::tui::theme;
use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn default_spinner_frames() -> Vec<String> {
    vec!["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷", "⣾", "⣽"]
        .into_iter()
        .map(String::from)
        .collect()
}

#[derive(Clone)]
pub struct StreamDisplay {
    chat_color: String,
    spinner_frames: Arc<Vec<String>>,
    json_output: bool,
    spinner_active: Arc<AtomicBool>,
    spinner_handle: Arc<Mutex<Option<std::thread::JoinHandle<()>>>>,
    last_stream_had_text: Arc<AtomicBool>,
}

impl StreamDisplay {
    pub fn new(config: &crate::config::DisplayConfig, json_output: bool) -> Self {
        let spinner_frames = config
            .thinking_indicator
            .chars()
            .map(|c| c.to_string())
            .collect::<Vec<_>>();
        Self {
            chat_color: config.chat_color.clone(),
            spinner_frames: Arc::new(if spinner_frames.is_empty() {
                default_spinner_frames()
            } else {
                spinner_frames
            }),
            json_output,
            spinner_active: Arc::new(AtomicBool::new(false)),
            spinner_handle: Arc::new(Mutex::new(None)),
            last_stream_had_text: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn json_output_enabled(&self) -> bool {
        self.json_output
    }

    #[cfg(test)]
    pub fn last_stream_had_text(&self) -> bool {
        self.last_stream_had_text.load(Ordering::SeqCst)
    }

    pub fn spinner_guard(&self) -> StreamSpinnerGuard {
        StreamSpinnerGuard::new(self.clone())
    }

    fn start_spinner(&self) -> bool {
        if self.json_output
            || self
                .spinner_active
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_err()
        {
            return false;
        }

        let spinner_active = Arc::clone(&self.spinner_active);
        let spinner_frames = Arc::clone(&self.spinner_frames);
        let handle = std::thread::spawn(move || {
            let mut i = 0;
            while spinner_active.load(Ordering::SeqCst) {
                eprint!(
                    "\r  {}{} {}thinking…{}\x1b[K",
                    crate::tui::theme::current_theme().spinner,
                    spinner_frames[i % spinner_frames.len()],
                    crate::tui::theme::current_theme().dim,
                    crate::tui::theme::current_theme().reset
                );
                io::stderr().flush().ok();
                i += 1;
                std::thread::sleep(std::time::Duration::from_millis(80));
            }
        });

        if let Ok(mut guard) = self.spinner_handle.lock() {
            *guard = Some(handle);
        }
        true
    }

    fn stop_spinner(&self) {
        self.spinner_active.store(false, Ordering::SeqCst);
        if let Ok(mut guard) = self.spinner_handle.lock()
            && let Some(handle) = guard.take()
        {
            let _ = handle.join();
        }
        eprint!("\r\x1b[K");
        io::stderr().flush().ok();
    }

    pub async fn consume_stream(
        &self,
        rx: &mut mpsc::Receiver<StreamEvent>,
        cancelled: &Arc<AtomicBool>,
    ) -> anyhow::Result<Message> {
        self.stop_spinner();
        self.last_stream_had_text.store(false, Ordering::SeqCst);
        let mut is_streaming = false;
        let mut json_display = self.json_output.then_some(crate::json_display::JsonDisplay);
        let color = self.chat_color.clone();
        let last_stream_had_text = Arc::clone(&self.last_stream_had_text);
        let (msg, _usage) = crate::stream_consumer::consume_stream(rx, cancelled, &mut |event| {
            if let crate::stream_consumer::DisplayEvent::TextChunk(_) = event {
                last_stream_had_text.store(true, Ordering::SeqCst);
            }
            if let Some(display) = json_display.as_mut() {
                display.handle_event(event);
                return;
            }
            match event {
                crate::stream_consumer::DisplayEvent::TextChunk(text) => {
                    if !is_streaming {
                        is_streaming = true;
                        eprint!("{color}");
                    }
                    eprint!("{text}");
                    io::stderr().flush().ok();
                }
                crate::stream_consumer::DisplayEvent::Done => {
                    if is_streaming {
                        eprintln!("{}", theme::current_theme().reset);
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
}

impl Default for StreamDisplay {
    fn default() -> Self {
        Self::new(&crate::config::DisplayConfig::default(), false)
    }
}

pub struct StreamSpinnerGuard {
    display: StreamDisplay,
    did_start: bool,
}

impl StreamSpinnerGuard {
    fn new(display: StreamDisplay) -> Self {
        let did_start = display.start_spinner();
        Self { display, did_start }
    }
}

impl Drop for StreamSpinnerGuard {
    fn drop(&mut self) {
        if self.did_start {
            self.display.stop_spinner();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::StreamEvent;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn stream_display_instances_track_text_independently() {
        let config = crate::config::DisplayConfig::default();
        let display_with_text = StreamDisplay::new(&config, true);
        let display_without_text = StreamDisplay::new(&config, true);
        let cancelled = Arc::new(AtomicBool::new(false));

        let (tx1, mut rx1) = mpsc::channel(8);
        tx1.send(StreamEvent::TextDelta("hello".into()))
            .await
            .unwrap();
        tx1.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx1);
        display_with_text
            .consume_stream(&mut rx1, &cancelled)
            .await
            .unwrap();

        let (tx2, mut rx2) = mpsc::channel(8);
        tx2.send(StreamEvent::Done { usage: None }).await.unwrap();
        drop(tx2);
        display_without_text
            .consume_stream(&mut rx2, &cancelled)
            .await
            .unwrap();

        assert!(display_with_text.last_stream_had_text());
        assert!(!display_without_text.last_stream_had_text());
    }
}
