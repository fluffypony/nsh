use crate::config::DisplayConfig;
use crate::stream_consumer::DisplayEvent;
use std::io::{self, Write};

pub struct TerminalDisplay {
    is_streaming_text: bool,
    chat_color: String,
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_display() -> TerminalDisplay {
        TerminalDisplay::new(&DisplayConfig::default())
    }

    #[test]
    fn test_handle_event_done_when_not_streaming() {
        let mut display = test_display();
        display.handle_event(DisplayEvent::Done);
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_text_sets_streaming() {
        let mut display = test_display();
        display.handle_event(DisplayEvent::TextChunk("hello".into()));
        assert!(display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_done_resets_streaming() {
        let mut display = test_display();
        display.handle_event(DisplayEvent::TextChunk("hello".into()));
        assert!(display.is_streaming_text);
        display.handle_event(DisplayEvent::Done);
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_tool_started() {
        let mut display = test_display();
        display.handle_event(DisplayEvent::ToolStarted {
            name: "test_tool".into(),
        });
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_tool_finished() {
        let mut display = test_display();
        display.handle_event(DisplayEvent::ToolFinished {
            name: "test_tool".into(),
        });
        assert!(!display.is_streaming_text);
    }
}
