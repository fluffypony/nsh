const LOW_SIGNAL_COMMANDS: &[&str] = &[
    "ls", "ll", "la", "cd", "pwd", "clear", "exit", "history",
    "echo", "true", "false", ":", "test", "whoami", "date",
];

pub fn is_low_signal(command: &str) -> bool {
    let first_word = command.split_whitespace().next().unwrap_or("");
    let base = first_word.rsplit('/').next().unwrap_or(first_word);
    LOW_SIGNAL_COMMANDS.contains(&base)
}

#[cfg(test)]
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

    #[test]
    fn low_signal_with_arguments() {
        assert!(is_low_signal("ls -la /tmp"));
        assert!(is_low_signal("cd ~/projects"));
        assert!(is_low_signal("echo hello world"));
        assert!(is_low_signal("clear"));
        assert!(is_low_signal("exit"));
        assert!(is_low_signal("history | grep foo"));
        assert!(is_low_signal("pwd"));
        assert!(is_low_signal("date"));
        assert!(is_low_signal("whoami"));
    }

    #[test]
    fn not_low_signal_commands() {
        assert!(!is_low_signal("cargo build --release"));
        assert!(!is_low_signal("git push origin main"));
        assert!(!is_low_signal("docker run -it ubuntu"));
        assert!(!is_low_signal("npm install express"));
        assert!(!is_low_signal("ssh user@host"));
        assert!(!is_low_signal("kubectl get pods"));
        assert!(!is_low_signal("terraform plan"));
    }

    #[test]
    fn low_signal_full_path() {
        assert!(is_low_signal("/bin/ls"));
        assert!(is_low_signal("/usr/bin/pwd"));
        assert!(!is_low_signal("/usr/bin/cargo build"));
    }

    #[test]
    fn rapid_repeat_at_boundary() {
        // Exactly 5 seconds: should be rapid (< 5 is the check)
        assert!(!is_rapid_repeat("ls", Some("ls"), Some(100), 105));
        // 4 seconds: should be rapid
        assert!(is_rapid_repeat("ls", Some("ls"), Some(100), 104));
    }

    #[test]
    fn rapid_repeat_different_commands() {
        assert!(!is_rapid_repeat("git status", Some("git push"), Some(100), 101));
    }

    #[test]
    fn low_signal_empty_command() {
        assert!(!is_low_signal(""));
    }

    #[test]
    fn is_low_signal_special_builtins() {
        assert!(is_low_signal("true"));
        assert!(is_low_signal("false"));
        assert!(is_low_signal(":"));
        assert!(is_low_signal("test -f file.txt"));
    }
}
