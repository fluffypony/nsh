const INPUT_POLL_SLICE: std::time::Duration = std::time::Duration::from_millis(200);

enum TimedInputStep {
    Pending,
    Event(crossterm::event::Event),
    Expired,
    Error,
}

trait TimedInputSource {
    fn next_step(&mut self, max_wait: std::time::Duration) -> TimedInputStep;
}

struct CrosstermTimedInput {
    deadline: std::time::Instant,
}

impl CrosstermTimedInput {
    fn new(timeout_secs: u64) -> Self {
        Self {
            deadline: std::time::Instant::now()
                + std::time::Duration::from_secs(timeout_secs.max(1)),
        }
    }
}

impl TimedInputSource for CrosstermTimedInput {
    fn next_step(&mut self, max_wait: std::time::Duration) -> TimedInputStep {
        use crossterm::event;

        let now = std::time::Instant::now();
        if now >= self.deadline {
            return TimedInputStep::Expired;
        }

        let wait = self.deadline.saturating_duration_since(now).min(max_wait);
        let polled = match event::poll(wait) {
            Ok(polled) => polled,
            Err(_) => return TimedInputStep::Error,
        };
        if !polled {
            return if std::time::Instant::now() >= self.deadline {
                TimedInputStep::Expired
            } else {
                TimedInputStep::Pending
            };
        }

        match event::read() {
            Ok(event) => TimedInputStep::Event(event),
            Err(_) => TimedInputStep::Error,
        }
    }
}

enum UserInputProgress {
    Continue,
    Submit(Option<String>),
}

fn is_confirmation_accepted(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn is_yes_confirmation_accepted(line: &str) -> bool {
    line.trim().eq_ignore_ascii_case("yes")
}

fn is_default_yes_confirmation_accepted(line: &str) -> bool {
    !matches!(line.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

fn print_confirmation_prompt(prompt: &str) -> std::io::Result<()> {
    use std::io::Write;

    eprint!("{prompt}");
    std::io::stderr().flush()
}

fn read_line_from_reader<R: std::io::BufRead>(reader: &mut R) -> std::io::Result<String> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    Ok(line)
}

pub(crate) fn read_terminal_line() -> std::io::Result<String> {
    use std::io::IsTerminal;

    read_terminal_line_with(std::io::stdin().is_terminal(), || {
        std::fs::File::open("/dev/tty")
    })
}

pub(crate) fn read_terminal_line_with<F>(
    stdin_is_terminal: bool,
    tty_opener: F,
) -> std::io::Result<String>
where
    F: FnOnce() -> std::io::Result<std::fs::File>,
{
    if stdin_is_terminal {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line)
    } else {
        let tty = tty_opener()?;
        let mut reader = std::io::BufReader::new(tty);
        read_line_from_reader(&mut reader)
    }
}

fn read_tty_line() -> std::io::Result<String> {
    let tty = std::fs::File::open("/dev/tty")?;
    let mut reader = std::io::BufReader::new(tty);
    read_line_from_reader(&mut reader)
}

pub fn read_tty_confirmation() -> bool {
    read_terminal_line()
        .map(|line| is_confirmation_accepted(&line))
        .unwrap_or(false)
}

pub fn prompt_tty_confirmation(prompt: &str) -> std::io::Result<bool> {
    print_confirmation_prompt(prompt)?;
    Ok(read_tty_confirmation())
}

/// Strict confirmation that only accepts "yes".
/// Used for dangerous actions requiring explicit typed acknowledgement.
pub fn read_tty_yes_confirmation() -> bool {
    read_terminal_line()
        .map(|line| is_yes_confirmation_accepted(&line))
        .unwrap_or(false)
}

/// Like read_tty_confirmation but defaults to "No" when a read error occurs.
/// Useful for potentially dangerous defaults where we should not auto-approve.
pub fn read_tty_confirmation_default_yes() -> bool {
    read_terminal_line()
        .map(|line| is_default_yes_confirmation_accepted(&line))
        .unwrap_or(false)
}

/// Read confirmation from /dev/tty directly, avoiding stdin conflicts
/// with child processes that inherit stdin. Returns true if user presses
/// Enter or 'y'; false on 'n'/'no' or read failure.
pub fn read_tty_confirmation_safe() -> bool {
    read_tty_line()
        .map(|line| is_default_yes_confirmation_accepted(&line))
        .unwrap_or(false)
}

fn handle_user_input_event(line: &mut String, event: crossterm::event::Event) -> UserInputProgress {
    use crossterm::event::{Event, KeyCode, KeyEventKind};

    match event {
        Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
            KeyCode::Enter => {
                let trimmed = line.trim().to_string();
                UserInputProgress::Submit((!trimmed.is_empty()).then_some(trimmed))
            }
            KeyCode::Char(c) => {
                line.push(c);
                UserInputProgress::Continue
            }
            KeyCode::Backspace => {
                line.pop();
                UserInputProgress::Continue
            }
            _ => UserInputProgress::Continue,
        },
        _ => UserInputProgress::Continue,
    }
}

fn read_user_input_with_timeout_from(source: &mut impl TimedInputSource) -> Option<String> {
    let mut line = String::new();

    loop {
        match source.next_step(INPUT_POLL_SLICE) {
            TimedInputStep::Pending => {}
            TimedInputStep::Expired | TimedInputStep::Error => return None,
            TimedInputStep::Event(event) => match handle_user_input_event(&mut line, event) {
                UserInputProgress::Continue => {}
                UserInputProgress::Submit(result) => return result,
            },
        }
    }
}

/// Read a single line of user input with a timeout (in seconds).
/// Returns Some(trimmed_line) if input received and non-empty; otherwise None.
pub fn read_user_input_with_timeout(timeout_secs: u64) -> Option<String> {
    let mut source = CrosstermTimedInput::new(timeout_secs);
    read_user_input_with_timeout_from(&mut source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use std::collections::VecDeque;

    struct FakeTimedInput {
        steps: VecDeque<TimedInputStep>,
    }

    impl FakeTimedInput {
        fn new(steps: Vec<TimedInputStep>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    impl TimedInputSource for FakeTimedInput {
        fn next_step(&mut self, _max_wait: std::time::Duration) -> TimedInputStep {
            self.steps.pop_front().unwrap_or(TimedInputStep::Expired)
        }
    }

    fn key(code: KeyCode) -> Event {
        Event::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    #[test]
    fn confirmation_accepts_short_and_long_yes() {
        assert!(is_confirmation_accepted("y"));
        assert!(is_confirmation_accepted(" YES "));
        assert!(!is_confirmation_accepted("no"));
    }

    #[test]
    fn strict_yes_confirmation_only_accepts_yes() {
        assert!(is_yes_confirmation_accepted("yes"));
        assert!(!is_yes_confirmation_accepted("y"));
        assert!(!is_yes_confirmation_accepted("no"));
    }

    #[test]
    fn default_yes_confirmation_only_rejects_no_values() {
        assert!(is_default_yes_confirmation_accepted(""));
        assert!(is_default_yes_confirmation_accepted("y"));
        assert!(!is_default_yes_confirmation_accepted("n"));
        assert!(!is_default_yes_confirmation_accepted("NO"));
    }

    #[test]
    fn read_user_input_with_timeout_collects_chars_and_backspace() {
        let mut input = FakeTimedInput::new(vec![
            TimedInputStep::Event(key(KeyCode::Char('h'))),
            TimedInputStep::Event(key(KeyCode::Char('i'))),
            TimedInputStep::Event(key(KeyCode::Backspace)),
            TimedInputStep::Event(key(KeyCode::Char('o'))),
            TimedInputStep::Event(key(KeyCode::Enter)),
        ]);

        assert_eq!(
            read_user_input_with_timeout_from(&mut input).as_deref(),
            Some("ho")
        );
    }

    #[test]
    fn read_user_input_with_timeout_ignores_non_press_and_resize_events() {
        let mut input = FakeTimedInput::new(vec![
            TimedInputStep::Event(Event::Resize(80, 24)),
            TimedInputStep::Event(Event::Key(KeyEvent {
                code: KeyCode::Char('x'),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Release,
                state: KeyEventState::NONE,
            })),
            TimedInputStep::Event(key(KeyCode::Char('y'))),
            TimedInputStep::Event(key(KeyCode::Enter)),
        ]);

        assert_eq!(
            read_user_input_with_timeout_from(&mut input).as_deref(),
            Some("y")
        );
    }

    #[test]
    fn read_user_input_with_timeout_returns_none_for_empty_submit() {
        let mut input =
            FakeTimedInput::new(vec![TimedInputStep::Event(key(KeyCode::Enter))]);

        assert_eq!(read_user_input_with_timeout_from(&mut input), None);
    }

    #[test]
    fn read_user_input_with_timeout_returns_none_when_time_expires() {
        let mut input = FakeTimedInput::new(vec![TimedInputStep::Pending, TimedInputStep::Expired]);

        assert_eq!(read_user_input_with_timeout_from(&mut input), None);
    }
}
