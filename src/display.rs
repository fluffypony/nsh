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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DisplayConfig;

    #[test]
    fn test_new_display() {
        let config = DisplayConfig::default();
        let display = TerminalDisplay::new(&config);
        assert!(!display.is_streaming_text);
        assert_eq!(display.chat_color, config.chat_color);
    }

    #[test]
    fn test_handle_event_done_when_not_streaming() {
        let config = DisplayConfig::default();
        let mut display = TerminalDisplay::new(&config);
        display.handle_event(DisplayEvent::Done);
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_text_sets_streaming() {
        let config = DisplayConfig::default();
        let mut display = TerminalDisplay::new(&config);
        display.handle_event(DisplayEvent::TextChunk("hello".into()));
        assert!(display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_done_resets_streaming() {
        let config = DisplayConfig::default();
        let mut display = TerminalDisplay::new(&config);
        display.handle_event(DisplayEvent::TextChunk("hello".into()));
        assert!(display.is_streaming_text);
        display.handle_event(DisplayEvent::Done);
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_tool_started() {
        let config = DisplayConfig::default();
        let mut display = TerminalDisplay::new(&config);
        display.handle_event(DisplayEvent::ToolStarted { name: "test_tool".into() });
        assert!(!display.is_streaming_text);
    }

    #[test]
    fn test_handle_event_tool_finished() {
        let config = DisplayConfig::default();
        let mut display = TerminalDisplay::new(&config);
        display.handle_event(DisplayEvent::ToolFinished { name: "test_tool".into() });
        assert!(!display.is_streaming_text);
    }
}
