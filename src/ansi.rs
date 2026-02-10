pub fn strip(input: &[u8]) -> String {
    let stripped = strip_ansi_escapes::strip(input);
    let text = String::from_utf8_lossy(&stripped).to_string();
    normalize(&text)
}

#[allow(dead_code)]
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

#[allow(dead_code)]
fn trim_utf8_leading(input: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < input.len() && (input[start] & 0xC0) == 0x80 {
        start += 1;
    }
    &input[start..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_plain_text() {
        assert_eq!(strip(b"hello world"), "hello world");
    }

    #[test]
    fn test_strip_ansi_color_codes() {
        assert_eq!(strip(b"\x1b[31mred\x1b[0m"), "red");
    }

    #[test]
    fn test_strip_crlf_normalized_to_lf() {
        assert_eq!(strip(b"line1\r\nline2\r\n"), "line1\nline2\n");
    }

    #[test]
    fn test_strip_bracketed_paste_mode() {
        let input = b"\x1b[200~pasted\x1b[201~";
        assert_eq!(strip(input), "pasted");

        let input2 = b"\x1b[?2004htext\x1b[?2004l";
        assert_eq!(strip(input2), "text");
    }

    #[test]
    fn test_strip_and_normalize_leading_continuation_bytes() {
        let input: Vec<u8> = vec![0x80, 0xBF, b'h', b'i'];
        assert_eq!(strip_and_normalize(&input), "hi");
    }

    #[test]
    fn test_strip_and_normalize_regular_input() {
        assert_eq!(strip_and_normalize(b"hello"), "hello");
    }

    #[test]
    fn test_trim_utf8_leading_with_continuation_bytes() {
        let input: &[u8] = &[0x80, 0xBF, 0x80, b'A', b'B'];
        assert_eq!(trim_utf8_leading(input), b"AB");
    }

    #[test]
    fn test_trim_utf8_leading_clean_input() {
        let input: &[u8] = b"clean";
        assert_eq!(trim_utf8_leading(input), b"clean");
    }
}
