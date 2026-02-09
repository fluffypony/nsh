use crate::stream_consumer::DisplayEvent;
use std::io::{self, Write};

pub struct JsonDisplay;

impl JsonDisplay {
    pub fn new() -> Self {
        Self
    }

    pub fn handle_event(&mut self, event: DisplayEvent) {
        let json = match event {
            DisplayEvent::TextChunk(text) => {
                serde_json::json!({"type": "text", "content": text})
            }
            DisplayEvent::ToolStarted { name } => {
                serde_json::json!({"type": "tool_start", "name": name})
            }
            DisplayEvent::ToolFinished { name } => {
                serde_json::json!({"type": "tool_end", "name": name})
            }
            DisplayEvent::Done => {
                serde_json::json!({"type": "done"})
            }
        };
        let mut stderr = io::stderr().lock();
        let _ = serde_json::to_writer(&mut stderr, &json);
        let _ = writeln!(stderr);
    }
}
