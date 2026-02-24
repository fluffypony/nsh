use std::io::{self, BufRead, Write, IsTerminal};

pub fn execute(
    question: &str,
    options: Option<&[String]>,
    autorun_timeout: Option<u64>,
    default_response: Option<&str>,
) -> anyhow::Result<String> {
    use crate::tui::{self, BoxStyle, ContentLine};

    // Build content lines for the TUI box
    let mut content = Vec::new();
    content.push(ContentLine { text: question.to_string(), dim: false });
    if let Some(opts) = options {
        content.push(ContentLine { text: String::new(), dim: true });
        for (i, opt) in opts.iter().enumerate() {
            content.push(ContentLine { text: format!("{}) {}", i + 1, opt), dim: true });
        }
    }
    if let (Some(timeout), Some(default)) = (autorun_timeout, default_response) {
        content.push(ContentLine { text: String::new(), dim: true });
        content.push(ContentLine {
            text: format!("(auto-answer in {}s: {})", timeout, default),
            dim: true,
        });
    }
    tui::render_box("Question", &content, BoxStyle::Question);

    let th = crate::tui::theme::current_theme();
    eprint!("  {}❯{} ", th.accent, th.reset);
    io::stderr().flush()?;

    if let Some(timeout_secs) = autorun_timeout {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = read_user_input_inner(
                std::io::stdin().is_terminal(),
                || std::fs::File::open("/dev/tty"),
            );
            let _ = tx.send(result);
        });

        match rx.recv_timeout(std::time::Duration::from_secs(timeout_secs)) {
            Ok(Ok(input)) if !input.is_empty() => Ok(resolve_option_selection(input, options)),
            _ => {
                let response = default_response
                    .map(|s| s.to_string())
                    .or_else(|| options.and_then(|o| o.first().cloned()))
                    .unwrap_or_else(|| "Proceeding with best judgment".into());
                eprintln!("\x1b[2m  (timed out, auto-selecting: {})\x1b[0m", response);
                Ok(resolve_option_selection(response, options))
            }
        }
    } else {
        let input = read_user_input()?;
        Ok(resolve_option_selection(input, options))
    }
}

fn read_user_input() -> anyhow::Result<String> {
    use std::io::IsTerminal;
    read_user_input_inner(std::io::stdin().is_terminal(), || {
        std::fs::File::open("/dev/tty")
    })
}

fn read_user_input_inner<F>(stdin_is_terminal: bool, tty_opener: F) -> anyhow::Result<String>
where
    F: FnOnce() -> io::Result<std::fs::File>,
{
    if stdin_is_terminal {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        return Ok(input.trim().to_string());
    }

    // stdin is piped — try /dev/tty for interactive input
    match tty_opener() {
        Ok(tty) => {
            let mut reader = io::BufReader::new(tty);
            let mut input = String::new();
            reader.read_line(&mut input)?;
            Ok(input.trim().to_string())
        }
        Err(_) => anyhow::bail!("Cannot read user input: stdin is piped and /dev/tty is unavailable. Provide a default_response in autorun mode."),
    }
}

fn resolve_option_selection(input: String, options: Option<&[String]>) -> String {
    if let Some(opts) = options {
        if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= opts.len() {
                return opts[num - 1].clone();
            }
        }
    }
    input
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_option_selection_uses_numeric_choice() {
        let options = vec!["alpha".to_string(), "beta".to_string(), "gamma".to_string()];
        let out = resolve_option_selection("2".to_string(), Some(&options));
        assert_eq!(out, "beta");
    }

    #[test]
    fn resolve_option_selection_preserves_non_numeric_input() {
        let options = vec!["alpha".to_string(), "beta".to_string()];
        let out = resolve_option_selection("custom value".to_string(), Some(&options));
        assert_eq!(out, "custom value");
    }

    #[test]
    fn resolve_option_selection_ignores_out_of_range_numbers() {
        let options = vec!["alpha".to_string(), "beta".to_string()];
        let out = resolve_option_selection("9".to_string(), Some(&options));
        assert_eq!(out, "9");
    }

    #[test]
    fn read_user_input_inner_returns_fallback_when_tty_unavailable() {
        let err = read_user_input_inner(false, || {
            Err(io::Error::new(io::ErrorKind::NotFound, "no tty"))
        })
        .unwrap_err();
        assert!(err.to_string().contains("Cannot read user input: stdin is piped"));
    }

    #[test]
    fn read_user_input_inner_reads_from_tty_when_piped() {
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        std::fs::write(tmp.path(), "picked option\n").expect("write temp input");
        let path = tmp.path().to_path_buf();

        let out = read_user_input_inner(false, move || std::fs::File::open(path))
            .expect("read from fake tty");
        assert_eq!(out, "picked option");
    }
}
