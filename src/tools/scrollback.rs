/// Fetch recent terminal scrollback. Reads from the file written by
/// the PTY pump process.
pub fn execute(max_lines: usize) -> anyhow::Result<String> {
    let session_id = std::env::var("NSH_SESSION_ID")
        .unwrap_or_else(|_| "default".into());
    let scrollback_path = crate::config::Config::nsh_dir()
        .join(format!("scrollback_{session_id}"));

    if !scrollback_path.exists() {
        return Ok(
            "[No scrollback available — PTY wrap mode may not be active]"
                .into(),
        );
    }

    let raw = std::fs::read(&scrollback_path)?;
    let stripped = crate::ansi::strip(&raw);
    let lines: Vec<&str> = stripped.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].join("\n"))
}
