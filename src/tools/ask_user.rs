use std::io::{self, BufRead, Write};

pub fn execute(question: &str, options: Option<&[String]>) -> anyhow::Result<String> {
    let color = "\x1b[1;33m"; // bold yellow
    let reset = "\x1b[0m";

    eprint!("{color}nsh needs input:{reset} {question}");

    if let Some(opts) = options {
        eprintln!();
        for (i, opt) in opts.iter().enumerate() {
            eprintln!("  {}) {}", i + 1, opt);
        }
        eprint!("> ");
    } else {
        eprint!("\n> ");
    }

    io::stderr().flush()?;

    let input = read_user_input()?;
    Ok(resolve_option_selection(input, options))
}

fn read_user_input() -> anyhow::Result<String> {
    use std::io::IsTerminal;
    read_user_input_inner(std::io::stdin().is_terminal(), || std::fs::File::open("/dev/tty"))
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
        Err(_) => Ok("Cannot ask user — stdin is piped. Proceeding with best guess.".into()),
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
        let out = read_user_input_inner(false, || {
            Err(io::Error::new(io::ErrorKind::NotFound, "no tty"))
        })
        .expect("fallback should be returned");
        assert_eq!(out, "Cannot ask user — stdin is piped. Proceeding with best guess.");
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
