use std::process::Command;

pub fn execute(
    cmd: &str,
    section: Option<u8>,
) -> anyhow::Result<String> {
    let mut args = vec![];
    if let Some(s) = section {
        args.push(s.to_string());
    }
    args.push(cmd.to_string());

    let output = Command::new("man")
        .args(&args)
        .env("MANPAGER", "cat")
        .env("COLUMNS", "80")
        .output()?;

    if !output.status.success() {
        return Ok(format!("No man page found for '{cmd}'"));
    }

    let text = String::from_utf8_lossy(&output.stdout);
    Ok(crate::util::truncate(&text, 4000))
}
