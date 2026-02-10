use crate::config::DisplayConfig;
use crate::stream_consumer::DisplayEvent;
use std::io::{self, Write};

#[allow(dead_code)]
pub struct TerminalDisplay {
    is_streaming_text: bool,
    chat_color: String,
}

#[allow(dead_code)]
impl TerminalDisplay {
    pub fn new(config: &DisplayConfig) -> Self {
        Self {
            is_streaming_text: false,
            chat_color: config.chat_color.clone(),
        }
    }

    pub fn handle_event(&mut self, event: DisplayEvent) {
        match event {
            DisplayEvent::TextChunk(text) => {
                if !self.is_streaming_text {
                    self.is_streaming_text = true;
                    eprint!("{}", self.chat_color);
                }
                eprint!("{text}");
                io::stderr().flush().ok();
            }
            DisplayEvent::ToolStarted { .. } => {}
            DisplayEvent::ToolFinished { .. } => {}
            DisplayEvent::Done => {
                if self.is_streaming_text {
                    eprintln!("\x1b[0m");
                    self.is_streaming_text = false;
                }
            }
        }
    }
}
