use crate::config::Config;

pub fn execute(max_lines: usize, config: &Config) -> anyhow::Result<String> {
    let session_id =
        std::env::var("NSH_SESSION_ID").unwrap_or_else(|_| "default".into());
    let nsh_dir = Config::nsh_dir();

    let socket_path = nsh_dir.join(format!("scrollback_{session_id}.sock"));
    let file_path = nsh_dir.join(format!("scrollback_{session_id}"));

    let raw_text = if socket_path.exists() {
        match read_from_socket(&socket_path) {
            Ok(text) => text,
            Err(_) => read_from_file(&file_path)?,
        }
    } else {
        read_from_file(&file_path)?
    };

    let cleaned = crate::ansi::strip(raw_text.as_bytes());
    let redacted = crate::redact::redact_secrets(&cleaned, &config.redaction);

    let lines: Vec<&str> = redacted.lines().collect();
    let start = lines.len().saturating_sub(max_lines);
    Ok(lines[start..].join("\n"))
}

fn read_from_socket(path: &std::path::Path) -> anyhow::Result<String> {
    use std::io::Read;
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut data = String::new();
    stream.read_to_string(&mut data)?;
    Ok(data)
}

fn read_from_file(path: &std::path::Path) -> anyhow::Result<String> {
    if !path.exists() {
        return Ok(
            "[No scrollback available — PTY wrap mode may not be active]".into(),
        );
    }
    let raw = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&raw).to_string())
}
