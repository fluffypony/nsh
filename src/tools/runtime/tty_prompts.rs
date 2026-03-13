fn is_confirmation_accepted(line: &str) -> bool {
    matches!(line.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

fn is_yes_confirmation_accepted(line: &str) -> bool {
    line.trim().eq_ignore_ascii_case("yes")
}

fn is_default_yes_confirmation_accepted(line: &str) -> bool {
    !matches!(line.trim().to_ascii_lowercase().as_str(), "n" | "no")
}

pub fn read_tty_confirmation() -> bool {
    use std::io::{BufRead, IsTerminal};

    let line = if std::io::stdin().is_terminal() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            line
        } else {
            return false;
        }
    } else {
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let mut reader = std::io::BufReader::new(tty);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    line
                } else {
                    return false;
                }
            }
            Err(_) => return false,
        }
    };
    is_confirmation_accepted(&line)
}

/// Strict confirmation that only accepts "yes".
/// Used for dangerous actions requiring explicit typed acknowledgement.
pub fn read_tty_yes_confirmation() -> bool {
    use std::io::{BufRead, IsTerminal};

    let line = if std::io::stdin().is_terminal() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            line
        } else {
            return false;
        }
    } else {
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let mut reader = std::io::BufReader::new(tty);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    line
                } else {
                    return false;
                }
            }
            Err(_) => return false,
        }
    };
    is_yes_confirmation_accepted(&line)
}

/// Like read_tty_confirmation but defaults to "No" when a read error occurs.
/// Useful for potentially dangerous defaults where we should not auto-approve.
pub fn read_tty_confirmation_default_yes() -> bool {
    use std::io::{BufRead, IsTerminal};

    let line = if std::io::stdin().is_terminal() {
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_ok() {
            line
        } else {
            return false; // default to No on read error
        }
    } else {
        match std::fs::File::open("/dev/tty") {
            Ok(tty) => {
                let mut reader = std::io::BufReader::new(tty);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    line
                } else {
                    return false; // default to No on read error
                }
            }
            Err(_) => return false,
        }
    };
    is_default_yes_confirmation_accepted(&line)
}

/// Read confirmation from /dev/tty directly, avoiding stdin conflicts
/// with child processes that inherit stdin. Returns true if user presses
/// Enter or 'y'; false on 'n'/'no' or read failure.
pub fn read_tty_confirmation_safe() -> bool {
    match std::fs::File::open("/dev/tty") {
        Ok(tty) => {
            use std::io::BufRead;

            let mut reader = std::io::BufReader::new(tty);
            let mut line = String::new();
            if reader.read_line(&mut line).is_ok() {
                is_default_yes_confirmation_accepted(&line)
            } else {
                false
            }
        }
        Err(_) => false,
    }
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
