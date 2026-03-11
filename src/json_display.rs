use crate::stream_consumer::DisplayEvent;
use std::io::{self, Write};

pub struct JsonDisplay;

impl JsonDisplay {
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

impl Default for JsonDisplay {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_display_handles_all_events() {
        let mut d = JsonDisplay;
        d.handle_event(DisplayEvent::TextChunk("hi".into()));
        d.handle_event(DisplayEvent::ToolStarted {
            name: "test_tool".into(),
        });
        d.handle_event(DisplayEvent::ToolFinished {
            name: "test_tool".into(),
        });
        d.handle_event(DisplayEvent::Done);
    }
}
