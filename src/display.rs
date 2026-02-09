use crate::stream_consumer::DisplayEvent;
use std::io::{self, Write};

pub struct TerminalDisplay {
    is_streaming_text: bool,
}

impl TerminalDisplay {
    pub fn new() -> Self {
        Self {
            is_streaming_text: false,
        }
    }

    pub fn handle_event(&mut self, event: DisplayEvent) {
        match event {
            DisplayEvent::TextChunk(text) => {
                if !self.is_streaming_text {
                    self.is_streaming_text = true;
                    eprint!("\x1b[3;36m");
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
