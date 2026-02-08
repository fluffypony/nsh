use std::io::{self, Write};

pub fn execute(
    question: &str,
    options: Option<&[String]>,
) -> anyhow::Result<String> {
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

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_string();

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
