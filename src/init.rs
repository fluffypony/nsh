pub fn generate_init_script(shell: &str) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let template = match shell {
        "zsh" => include_str!("../shell/nsh.zsh"),
        "bash" => include_str!("../shell/nsh.bash"),
        "fish" => include_str!("../shell/nsh.fish"),
        other => {
            return format!(
                "# nsh: unsupported shell '{other}'. Supported: zsh, bash, fish\n\
                 echo 'nsh: unsupported shell' >&2"
            );
        }
    };
    template.replace("__SESSION_ID__", &session_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nested_shell_guard_zsh() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("if [[ -n \"${NSH_SESSION_ID:-}\" ]]"),
            "Zsh init script should contain NSH_SESSION_ID early-exit guard"
        );
        // The guard should appear before the session ID export
        let guard_pos = script.find("if [[ -n \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        let export_pos = script.find("export NSH_SESSION_ID=").unwrap();
        assert!(
            guard_pos < export_pos,
            "Nested shell guard should come before session ID export"
        );
    }

    #[test]
    fn test_nested_shell_guard_bash() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("if [[ -n \"${NSH_SESSION_ID:-}\" ]]"),
            "Bash init script should contain NSH_SESSION_ID early-exit guard"
        );
        let guard_pos = script.find("if [[ -n \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        let export_pos = script.find("export NSH_SESSION_ID=").unwrap();
        assert!(
            guard_pos < export_pos,
            "Nested shell guard should come before session ID export"
        );
    }

    #[test]
    fn test_session_id_placeholder_replaced_fish() {
        let script = generate_init_script("fish");
        assert!(!script.contains("__SESSION_ID__"));
        assert!(script.contains("NSH_SESSION_ID"));
    }

    #[test]
    fn test_session_id_placeholder_replaced() {
        let script = generate_init_script("zsh");
        assert!(
            !script.contains("__SESSION_ID__"),
            "Session ID placeholder should be replaced with a UUID"
        );
        assert!(script.contains("NSH_SESSION_ID="));
    }
}
