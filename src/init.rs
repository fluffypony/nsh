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

    #[test]
    fn test_zsh_prefers_original_tty_when_wrapped() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("export NSH_TTY=\"${NSH_ORIG_TTY:-$(tty)}\""),
            "zsh init should preserve original tty identity under nsh wrap"
        );
    }

    #[test]
    fn test_bash_prefers_original_tty_when_wrapped() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("export NSH_TTY=\"${NSH_ORIG_TTY:-$(tty)}\""),
            "bash init should preserve original tty identity under nsh wrap"
        );
    }

    #[test]
    fn test_fish_prefers_original_tty_when_wrapped() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("if set -q NSH_ORIG_TTY"),
            "fish init should preserve original tty identity under nsh wrap"
        );
    }

    #[test]
    fn test_zsh_installs_accept_line_wrapper() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__nsh_install_accept_line_widget"),
            "zsh init should install an accept-line wrapper for natural-language queries"
        );
        assert!(
            script.contains("zle -N accept-line __nsh_accept_line"),
            "zsh init should register a custom accept-line widget"
        );
    }

    #[test]
    fn test_zsh_accept_line_wrapper_handles_question_prefixes() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("'? '*)"),
            "zsh accept-line wrapper should handle '? ' prompts"
        );
        assert!(
            script.contains("'?? '*)"),
            "zsh accept-line wrapper should handle '?? ' prompts"
        );
        assert!(
            script.contains("'?! '*)"),
            "zsh accept-line wrapper should handle '?! ' prompts"
        );
    }

    #[test]
    fn test_zsh_accept_line_wrapper_has_recursion_guard() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("if [[ \"$orig_widget\" == \"user:__nsh_accept_line\" ]]"),
            "zsh accept-line wrapper should detect recursive widget chaining"
        );
        assert!(
            script.contains("zle .accept-line"),
            "zsh accept-line wrapper should fall back to builtin accept-line on recursion"
        );
    }

    #[test]
    fn test_zsh_accept_line_install_heals_corrupt_orig_widget() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains(
                "if [[ \"${widgets[__nsh_accept_line_orig]:-}\" == \"user:__nsh_accept_line\" ]]"
            ),
            "zsh init should repair corrupted __nsh_accept_line_orig bindings"
        );
        assert!(
            script.contains("zle -N __nsh_accept_line_orig .accept-line"),
            "zsh init should restore builtin accept-line as the orig widget when needed"
        );
    }

    #[test]
    fn test_zsh_cleanup_uses_command_rm() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("command rm -f \"$cmd_file\""),
            "zsh init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_bash_cleanup_uses_command_rm() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("command rm -f \"$cmd_file\""),
            "bash init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_fish_cleanup_uses_command_rm() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("command rm -f $cmd_file"),
            "fish init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_zsh_pending_file_io_uses_command() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("local cmd=\"$(command cat \"$cmd_file\")\""),
            "zsh init should bypass cat aliases when reading pending command files"
        );
        assert!(
            script.contains("command touch \"$HOME/.nsh/redact_active_${NSH_SESSION_ID}\""),
            "zsh init should bypass touch aliases when toggling redact markers"
        );
    }

    #[test]
    fn test_bash_pending_file_io_uses_command() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("cmd=\"$(command cat \"$cmd_file\")\""),
            "bash init should bypass cat aliases when reading pending command files"
        );
        assert!(
            script.contains("command touch \"$HOME/.nsh/redact_active_${NSH_SESSION_ID}\""),
            "bash init should bypass touch aliases when toggling redact markers"
        );
    }

    #[test]
    fn test_fish_pending_file_io_uses_command() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("set -l cmd (command cat $cmd_file)"),
            "fish init should bypass cat aliases when reading pending command files"
        );
        assert!(
            script.contains("command touch \"$HOME/.nsh/redact_active_$NSH_SESSION_ID\""),
            "fish init should bypass touch aliases when toggling redact markers"
        );
    }

    #[test]
    fn test_zsh_query_wrappers_clear_stale_pending_state() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__nsh_clear_pending_command"),
            "zsh init should define pending command cleanup helper"
        );
        assert!(
            script.contains("alias '?'='noglob nsh_query'"),
            "zsh init should route ? queries through wrapper functions"
        );
    }

    #[test]
    fn test_bash_query_wrappers_clear_stale_pending_state() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("__nsh_clear_pending_command"),
            "bash init should define pending command cleanup helper"
        );
        assert!(
            script.contains("nsh_query()") && script.contains("__nsh_clear_pending_command"),
            "bash init should clear stale pending command files before new queries"
        );
    }

    #[test]
    fn test_fish_query_wrappers_clear_stale_pending_state() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("function __nsh_clear_pending_command"),
            "fish init should define pending command cleanup helper"
        );
        assert!(
            script.contains("abbr -a '?' -- 'nsh_query'"),
            "fish init should route ? queries through wrapper functions"
        );
    }

    #[test]
    fn test_zsh_restores_last_cwd_from_tty() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("command nsh session last-cwd --tty \"$NSH_TTY\""),
            "zsh init should query last cwd for current tty"
        );
        assert!(
            script.contains("builtin cd -- \"$restore_cwd\""),
            "zsh init should restore last cwd when available"
        );
    }

    #[test]
    fn test_bash_restores_last_cwd_from_tty() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("command nsh session last-cwd --tty \"$NSH_TTY\""),
            "bash init should query last cwd for current tty"
        );
        assert!(
            script.contains("builtin cd -- \"$restore_cwd\""),
            "bash init should restore last cwd when available"
        );
    }

    #[test]
    fn test_fish_restores_last_cwd_from_tty() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("command nsh session last-cwd --tty \"$NSH_TTY\""),
            "fish init should query last cwd for current tty"
        );
        assert!(
            script.contains("builtin cd -- \"$restore_cwd\""),
            "fish init should restore last cwd when available"
        );
    }

    #[test]
    fn test_zsh_emits_iterm2_current_dir() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "zsh init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("CurrentDir"),
            "zsh init should emit iTerm2 CurrentDir escape"
        );
    }

    #[test]
    fn test_bash_emits_iterm2_current_dir() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "bash init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("CurrentDir"),
            "bash init should emit iTerm2 CurrentDir escape"
        );
    }

    #[test]
    fn test_fish_emits_iterm2_current_dir() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "fish init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("CurrentDir"),
            "fish init should emit iTerm2 CurrentDir escape"
        );
    }
}
