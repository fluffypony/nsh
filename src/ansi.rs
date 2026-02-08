/// Strip ANSI escape sequences from terminal output.
pub fn strip(input: &[u8]) -> String {
    let stripped = strip_ansi_escapes::strip(input);
    String::from_utf8_lossy(&stripped).to_string()
}
