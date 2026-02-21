const LOW_SIGNAL_COMMANDS: &[&str] = &[
    "ls", "ll", "la", "cd", "pwd", "clear", "exit", "history",
    "echo", "true", "false", ":", "test", "whoami", "date",
];

pub fn is_low_signal(command: &str) -> bool {
    let first_word = command.split_whitespace().next().unwrap_or("");
    let base = first_word.rsplit('/').next().unwrap_or(first_word);
    LOW_SIGNAL_COMMANDS.contains(&base)
}

pub fn is_rapid_repeat(command: &str, last_command: Option<&str>, last_timestamp: Option<i64>, now: i64) -> bool {
    if let (Some(last_cmd), Some(last_ts)) = (last_command, last_timestamp) {
        if last_cmd == command && (now - last_ts) < 5 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_signal_detection() {
        assert!(is_low_signal("ls"));
        assert!(is_low_signal("ls -la"));
        assert!(is_low_signal("cd /tmp"));
        assert!(is_low_signal("pwd"));
        assert!(!is_low_signal("cargo build"));
        assert!(!is_low_signal("git push"));
    }

    #[test]
    fn rapid_repeat_detection() {
        assert!(is_rapid_repeat("ls", Some("ls"), Some(100), 103));
        assert!(!is_rapid_repeat("ls", Some("ls"), Some(100), 106));
        assert!(!is_rapid_repeat("ls", Some("pwd"), Some(100), 102));
        assert!(!is_rapid_repeat("ls", None, None, 100));
    }
}
