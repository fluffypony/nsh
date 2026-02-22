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

    #[cfg(test)]
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
        ShellEventType::SessionStart
        | ShellEventType::SessionEnd
        | ShellEventType::ProjectSwitch => true,
        ShellEventType::CommandExecution => {
            if let Some(ref cmd) = event.command {
                classifier::is_low_signal(cmd)
                    || event.exit_code == Some(0)
                        && event.output.as_ref().is_none_or(|o| o.len() < 200)
            } else {
                true
            }
        }
        _ => false,
    }
}

pub fn fast_path_episodic(event: &ShellEvent) -> crate::memory::types::EpisodicEventCreate {
    use crate::memory::types::{Actor, EpisodicEventCreate, EventType, ShellEventType};

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
            event
                .instruction
                .clone()
                .unwrap_or_else(|| "User instruction".into()),
        ),
        ShellEventType::AssistantAction => (
            EventType::AssistantAction,
            Actor::Assistant,
            event
                .instruction
                .clone()
                .unwrap_or_else(|| "Assistant action".into()),
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
        project_context: event.git_context.as_ref().and_then(|g| g.repo_root.clone()),
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
        let trimmed = cwd.trim_end_matches(['/', '\\']);
        if let Some(dir) = std::path::Path::new(trimmed)
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

    #[test]
    fn fast_path_keywords_trailing_separator() {
        let mut event = make_event("ls", 0);
        event.working_dir = Some("/home/user/project/".into());
        let kw = generate_fast_path_keywords(&event);
        assert!(kw.contains("project"), "keywords were: {kw}");
    }

    #[test]
    fn can_fast_path_session_events() {
        let session_start = ShellEvent {
            event_type: ShellEventType::SessionStart,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        assert!(can_fast_path(&session_start));

        let session_end = ShellEvent {
            event_type: ShellEventType::SessionEnd,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        assert!(can_fast_path(&session_end));
    }

    #[test]
    fn can_fast_path_project_switch() {
        let event = ShellEvent {
            event_type: ShellEventType::ProjectSwitch,
            command: None,
            output: None,
            exit_code: None,
            working_dir: Some("/home/user/new-project".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        assert!(can_fast_path(&event));
    }

    #[test]
    fn can_fast_path_simple_success_short_output() {
        let event = ShellEvent {
            event_type: ShellEventType::CommandExecution,
            command: Some("echo hello".into()),
            output: Some("hello".into()),
            exit_code: Some(0),
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        assert!(can_fast_path(&event));
    }

    #[test]
    fn cannot_fast_path_user_instruction() {
        let event = ShellEvent {
            event_type: ShellEventType::UserInstruction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("how do I build this".into()),
            file_path: None,
        };
        assert!(!can_fast_path(&event));
    }

    #[test]
    fn cannot_fast_path_assistant_action() {
        let event = ShellEvent {
            event_type: ShellEventType::AssistantAction,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: Some("suggested fix".into()),
            file_path: None,
        };
        assert!(!can_fast_path(&event));
    }

    #[test]
    fn fast_path_episodic_session_start() {
        let event = ShellEvent {
            event_type: ShellEventType::SessionStart,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.summary, "Session started");
        assert_eq!(ep.event_type, crate::memory::types::EventType::SessionStart);
        assert_eq!(ep.actor, crate::memory::types::Actor::System);
    }

    #[test]
    fn fast_path_episodic_session_end() {
        let event = ShellEvent {
            event_type: ShellEventType::SessionEnd,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.summary, "Session ended");
    }

    #[test]
    fn fast_path_episodic_error_command() {
        let event = make_event("cargo test", 1);
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.event_type, crate::memory::types::EventType::CommandError);
        assert!(ep.summary.contains("exit 1"));
    }

    #[test]
    fn fast_path_episodic_project_switch() {
        let event = ShellEvent {
            event_type: ShellEventType::ProjectSwitch,
            command: None,
            output: None,
            exit_code: None,
            working_dir: Some("/home/user/new-project".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let ep = fast_path_episodic(&event);
        assert!(ep.summary.contains("new-project"));
        assert_eq!(
            ep.event_type,
            crate::memory::types::EventType::ProjectSwitch
        );
    }

    #[test]
    fn fast_path_episodic_file_edit() {
        let event = ShellEvent {
            event_type: ShellEventType::FileEdit,
            command: None,
            output: None,
            exit_code: None,
            working_dir: None,
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: Some("src/main.rs".into()),
        };
        let ep = fast_path_episodic(&event);
        assert!(ep.summary.contains("src/main.rs"));
    }

    #[test]
    fn fast_path_episodic_preserves_working_dir() {
        let event = make_event("ls", 0);
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.working_dir.as_deref(), Some("/home/user"));
    }

    #[test]
    fn fast_path_episodic_with_git_context() {
        let mut event = make_event("git status", 0);
        event.git_context = Some(crate::memory::types::GitContext {
            branch: Some("main".into()),
            repo_root: Some("/home/user/project".into()),
        });
        let ep = fast_path_episodic(&event);
        assert_eq!(ep.project_context.as_deref(), Some("/home/user/project"));
    }

    #[test]
    fn fast_path_keywords_skip_flags() {
        let event = make_event("cargo build --release --target x86_64", 0);
        let kw = generate_fast_path_keywords(&event);
        // Flags starting with - should be skipped
        assert!(!kw.contains("--release"));
        assert!(!kw.contains("--target"));
    }

    #[test]
    fn fast_path_keywords_skip_short_args() {
        let event = make_event("ls -l -a", 0);
        let kw = generate_fast_path_keywords(&event);
        // Short args like "-l" should be skipped (starts with -)
        assert!(kw.contains("ls"));
    }

    #[test]
    fn buffer_flush_resets_timer() {
        let mut buf = IngestionBuffer::new(10, 60);
        buf.push(make_event("ls", 0));
        let events = buf.flush();
        assert_eq!(events.len(), 1);
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
    }

    #[test]
    fn fast_path_keywords_no_command() {
        let event = ShellEvent {
            event_type: ShellEventType::SessionStart,
            command: None,
            output: None,
            exit_code: None,
            working_dir: Some("/home/user".into()),
            session_id: None,
            timestamp: String::new(),
            git_context: None,
            instruction: None,
            file_path: None,
        };
        let kw = generate_fast_path_keywords(&event);
        assert!(
            kw.contains("user"),
            "should still extract from working_dir: {kw}"
        );
    }

    #[test]
    fn fast_path_keywords_root_path() {
        let mut event = make_event("ls", 0);
        event.working_dir = Some("/".into());
        let kw = generate_fast_path_keywords(&event);
        // Root path should not crash
        assert!(kw.contains("ls"));
    }
}
