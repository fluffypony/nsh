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

pub fn prompt_tty_yes_confirmation(prompt: &str) -> std::io::Result<bool> {
    print_confirmation_prompt(prompt)?;
    Ok(read_tty_yes_confirmation())
}

/// Like read_tty_confirmation but defaults to "No" when a read error occurs.
/// Useful for potentially dangerous defaults where we should not auto-approve.
pub fn read_tty_confirmation_default_yes() -> bool {
    read_terminal_line()
        .map(|line| is_default_yes_confirmation_accepted(&line))
        .unwrap_or(false)
}

pub fn prompt_tty_confirmation_default_yes(prompt: &str) -> std::io::Result<bool> {
    print_confirmation_prompt(prompt)?;
    Ok(read_tty_confirmation_default_yes())
}

/// Read confirmation from /dev/tty directly, avoiding stdin conflicts
/// with child processes that inherit stdin. Returns true if user presses
/// Enter or 'y'; false on 'n'/'no' or read failure.
pub fn read_tty_confirmation_safe() -> bool {
    read_tty_line()
        .map(|line| is_default_yes_confirmation_accepted(&line))
        .unwrap_or(false)
}

pub fn prompt_tty_confirmation_safe(prompt: &str) -> std::io::Result<bool> {
    print_confirmation_prompt(prompt)?;
    Ok(read_tty_confirmation_safe())
}

/// Read a single line of user input with a timeout (in seconds).
/// Returns Some(trimmed_line) if input received and non-empty; otherwise None.
pub fn read_user_input_with_timeout(timeout_secs: u64) -> Option<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind};

    let timeout = std::time::Duration::from_secs(timeout_secs.max(1));
    let start = std::time::Instant::now();
    let mut line = String::new();

    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());
        let wait = remaining.min(std::time::Duration::from_millis(200));
        let polled = match event::poll(wait) {
            Ok(v) => v,
            Err(_) => return None,
        };
        if !polled {
            continue;
        }

        match event::read() {
            Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Enter => {
                    let trimmed = line.trim().to_string();
                    return if trimmed.is_empty() {
                        None
                    } else {
                        Some(trimmed)
                    };
                }
                KeyCode::Char(c) => line.push(c),
                KeyCode::Backspace => {
                    line.pop();
                }
                _ => {}
            },
            Ok(_) => {}
            Err(_) => return None,
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::{
        is_confirmation_accepted, is_default_yes_confirmation_accepted,
        is_yes_confirmation_accepted,
    };

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
}
