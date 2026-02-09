pub fn strip(input: &[u8]) -> String {
    let stripped = strip_ansi_escapes::strip(input);
    let text = String::from_utf8_lossy(&stripped).to_string();
    normalize(&text)
}

pub fn strip_and_normalize(input: &[u8]) -> String {
    let trimmed = trim_utf8_leading(input);
    let stripped = strip_ansi_escapes::strip(trimmed);
    let text = String::from_utf8_lossy(&stripped).to_string();
    normalize(&text)
}

fn normalize(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "")
        .replace("\x1b[200~", "")
        .replace("\x1b[201~", "")
        .replace("\x1b[?2004h", "")
        .replace("\x1b[?2004l", "")
}

fn trim_utf8_leading(input: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < input.len() && (input[start] & 0xC0) == 0x80 {
        start += 1;
    }
    &input[start..]
}
