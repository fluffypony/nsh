use std::io::{self, BufRead, Write};

pub fn execute(question: &str, options: Option<&[String]>) -> anyhow::Result<String> {
    let color = "\x1b[1;33m"; // bold yellow
    let reset = "\x1b[0m";

    eprint!("{color}nsh asks:{reset} {question}");

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

    // If options were given and user typed a number, resolve it
    if let Some(opts) = options {
        if let Ok(num) = input.parse::<usize>() {
            if num >= 1 && num <= opts.len() {
                return Ok(opts[num - 1].clone());
            }
        }
    }

    Ok(input)
}

fn read_user_input() -> anyhow::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        return Ok(input.trim().to_string());
    }

    // stdin is piped — try /dev/tty for interactive input
    match std::fs::File::open("/dev/tty") {
        Ok(tty) => {
            let mut reader = io::BufReader::new(tty);
            let mut input = String::new();
            reader.read_line(&mut input)?;
            Ok(input.trim().to_string())
        }
        Err(_) => Ok("Cannot ask user — stdin is piped. Proceeding with best guess.".into()),
    }
}
