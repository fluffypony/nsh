pub mod classifier;
pub mod consolidator;
pub mod extractor;
pub mod output_truncator;
pub mod router;

use std::time::{Duration, Instant};

use crate::memory::types::ShellEvent;

pub struct IngestionBuffer {
    events: Vec<ShellEvent>,
    last_flush: Instant,
    max_buffer_size: usize,
    max_buffer_age: Duration,
}

impl IngestionBuffer {
    pub fn new(max_buffer_size: usize, max_buffer_age_secs: u64) -> Self {
        Self {
            events: Vec::new(),
            last_flush: Instant::now(),
            max_buffer_size,
            max_buffer_age: Duration::from_secs(max_buffer_age_secs),
        }
    }

    pub fn push(&mut self, event: ShellEvent) -> bool {
        self.events.push(event);
        self.should_flush()
    }

    pub fn should_flush(&self) -> bool {
        self.events.len() >= self.max_buffer_size
            || self.last_flush.elapsed() >= self.max_buffer_age
    }

    pub fn flush(&mut self) -> Vec<ShellEvent> {
        self.last_flush = Instant::now();
        std::mem::take(&mut self.events)
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
}

pub fn can_fast_path(event: &ShellEvent) -> bool {
    use crate::memory::types::ShellEventType;
    match event.event_type {
        ShellEventType::SessionStart | ShellEventType::SessionEnd | ShellEventType::ProjectSwitch => true,
        ShellEventType::CommandExecution => {
            if let Some(ref cmd) = event.command {
                classifier::is_low_signal(cmd) || event.exit_code == Some(0) && event.output.as_ref().map_or(true, |o| o.len() < 200)
            } else {
                true
            }
        }
        _ => false,
    }
}

pub fn fast_path_episodic(event: &ShellEvent) -> crate::memory::types::EpisodicEventCreate {
    use crate::memory::types::{EpisodicEventCreate, EventType, Actor, ShellEventType};

    let (event_type, actor, summary) = match event.event_type {
        ShellEventType::SessionStart => (
            EventType::SessionStart,
            Actor::System,
            "Session started".to_string(),
        ),
        ShellEventType::SessionEnd => (
            EventType::SessionEnd,
            Actor::System,
            "Session ended".to_string(),
        ),
        ShellEventType::CommandExecution => {
            let cmd = event.command.as_deref().unwrap_or("(unknown)");
            let exit = event.exit_code.unwrap_or(0);
            let et = if exit != 0 {
                EventType::CommandError
            } else {
                EventType::CommandExecution
            };
            (et, Actor::User, format!("Ran `{cmd}` (exit {exit})"))
        }
        ShellEventType::FileEdit => (
            EventType::FileEdit,
            Actor::User,
            format!("Edited {}", event.file_path.as_deref().unwrap_or("file")),
        ),
        ShellEventType::UserInstruction => (
            EventType::UserInstruction,
            Actor::User,
            event.instruction.clone().unwrap_or_else(|| "User instruction".into()),
        ),
        ShellEventType::AssistantAction => (
            EventType::AssistantAction,
            Actor::Assistant,
            event.instruction.clone().unwrap_or_else(|| "Assistant action".into()),
        ),
        ShellEventType::ProjectSwitch => {
            let dir = event.working_dir.as_deref().unwrap_or("unknown");
            (
                EventType::ProjectSwitch,
                Actor::System,
                format!("Switched to project at {dir}"),
            )
        }
    };

    let keywords = generate_fast_path_keywords(event);

    EpisodicEventCreate {
        event_type,
        actor,
        summary,
        details: None,
        command: event.command.clone(),
        exit_code: event.exit_code,
        working_dir: event.working_dir.clone(),
        project_context: event
            .git_context
            .as_ref()
            .and_then(|g| g.repo_root.clone()),
        search_keywords: keywords,
    }
}

fn generate_fast_path_keywords(event: &ShellEvent) -> String {
    let mut keywords = Vec::new();
    if let Some(ref cmd) = event.command {
        let first_word = cmd.split_whitespace().next().unwrap_or("");
        keywords.push(first_word.to_string());
        for word in cmd.split_whitespace().skip(1).take(5) {
            if word.len() > 2 && !word.starts_with('-') {
                keywords.push(word.to_string());
            }
        }
    }
    if let Some(ref cwd) = event.working_dir {
        if let Some(dir) = std::path::Path::new(cwd)
            .file_name()
            .and_then(|n| n.to_str())
        {
            if !dir.is_empty() {
                keywords.push(dir.to_string());
            }
        }
    }
    keywords.dedup();
    keywords.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::types::{ShellEvent, ShellEventType};

    fn make_event(cmd: &str, exit_code: i32) -> ShellEvent {
        ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some(cmd.to_string()),
            output: None,
            exit_code: Some(exit_code),
            working_dir: Some("/home/user".into()),
            session_id: None,
            timestamp: chrono::Utc::now().to_rfc3339(),
            git_context: None,
            instruction: None,
            file_path: None,
        }
    }

    #[test]
    fn buffer_push_and_flush() {
        let mut buf = IngestionBuffer::new(3, 60);
        assert!(!buf.push(make_event("ls", 0)));
        assert!(!buf.push(make_event("pwd", 0)));
        assert!(buf.push(make_event("cd foo", 0)));

        let events = buf.flush();
        assert_eq!(events.len(), 3);
        assert!(buf.is_empty());
    }

    #[test]
    fn can_fast_path_simple_commands() {
        let event = make_event("ls", 0);
        assert!(can_fast_path(&event));
    }

    #[test]
    fn fast_path_episodic_creates_event() {
        let event = make_event("cargo build", 0);
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.summary, "Ran `cargo build` (exit 0)");
        assert!(ep.search_keywords.contains("cargo"));
    }

    #[test]
    fn fast_path_keywords_unix_path() {
        let mut event = make_event("git status", 0);
        event.working_dir = Some("/home/user/project".into());
        let kw = generate_fast_path_keywords(&event);
        assert!(kw.contains("project"));
    }

    #[test]
    fn fast_path_keywords_windows_path() {
        let mut event = make_event("dir", 0);
        event.working_dir = Some("C:\\Users\\alice\\project".into());
        let kw = generate_fast_path_keywords(&event);
        assert!(kw.contains("project"), "keywords were: {kw}");
    }
}
