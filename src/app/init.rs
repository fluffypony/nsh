pub fn generate_init_script(shell: &str) -> String {
    let session_id = uuid::Uuid::new_v4().to_string();
    let template = match shell {
        "zsh" => include_str!("../../shell/nsh.zsh"),
        "bash" => include_str!("../../shell/nsh.bash"),
        "fish" => include_str!("../../shell/nsh.fish"),
        "powershell" | "pwsh" => include_str!("../../shell/nsh.ps1"),
        "cmd" => "@echo off\r\nDOSKEY ?=nsh query -- $*\r\n",
        other => {
            return format!(
                "# nsh: unsupported shell '{other}'. Supported: zsh, bash, fish, powershell, pwsh, cmd\n\
                 echo 'nsh: unsupported shell' >&2"
            );
        }
    };
    template
        .replace("__SESSION_ID__", &session_id)
        .replace("__NSH_VERSION__", env!("CARGO_PKG_VERSION"))
        .replace("__HOOK_HASH__", env!("NSH_HOOK_HASH"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_init_guard_zsh() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("exec nsh wrap"),
            "Zsh init script should auto-wrap when not already wrapped"
        );
        // Session init is conditional (only when NSH_SESSION_ID is not set)
        assert!(
            script.contains("if [[ -z \"${NSH_SESSION_ID:-}\" ]]"),
            "Zsh init script should have conditional session init block"
        );
        // Function definitions should appear BEFORE the session init block
        let func_pos = script.find("__nsh_preexec()").unwrap();
        let init_pos = script.find("if [[ -z \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        assert!(
            func_pos < init_pos,
            "Hook functions should be defined before session init block"
        );
        // Exports should appear before session init (unconditional)
        let export_hash_pos = script.find("export NSH_HOOK_HASH=").unwrap();
        assert!(
            export_hash_pos < init_pos,
            "Hook hash export should be unconditional (before session init)"
        );
    }

    #[test]
    fn test_session_init_guard_bash() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("exec nsh wrap"),
            "Bash init script should auto-wrap when not already wrapped"
        );
        // Session init is conditional (only when NSH_SESSION_ID is not set)
        assert!(
            script.contains("if [[ -z \"${NSH_SESSION_ID:-}\" ]]"),
            "Bash init script should have conditional session init block"
        );
        // Function definitions should appear BEFORE the session init block
        let func_pos = script.find("__nsh_prompt_command()").unwrap();
        let init_pos = script.find("if [[ -z \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        assert!(
            func_pos < init_pos,
            "Hook functions should be defined before session init block"
        );
    }

    #[test]
    fn test_session_id_placeholder_replaced_fish() {
        let script = generate_init_script("fish");
        assert!(!script.contains("__SESSION_ID__"));
        assert!(script.contains("NSH_SESSION_ID"));
    }

    #[test]
    fn test_session_id_placeholder_replaced_powershell() {
        let script = generate_init_script("powershell");
        assert!(!script.contains("__SESSION_ID__"));
        assert!(script.contains("NSH_SESSION_ID"));
        assert!(
            script.contains("& nsh wrap"),
            "PowerShell init script should auto-wrap on non-Windows"
        );
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
    fn test_fish_auto_wrap() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("exec nsh wrap"),
            "fish init script should auto-wrap when not already wrapped"
        );
    }

    #[test]
    fn test_zsh_wrap_sets_wrap_session_id() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("export NSH_WRAP_SESSION_ID="),
            "zsh init should export NSH_WRAP_SESSION_ID before wrap"
        );
        assert!(
            script.contains("export NSH_SESSION_ID=\"${NSH_WRAP_SESSION_ID:-"),
            "zsh init should derive NSH_SESSION_ID from NSH_WRAP_SESSION_ID when present"
        );
    }

    #[test]
    fn test_bash_wrap_sets_wrap_session_id() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("export NSH_WRAP_SESSION_ID="),
            "bash init should export NSH_WRAP_SESSION_ID before wrap"
        );
        assert!(
            script.contains("export NSH_SESSION_ID=\"${NSH_WRAP_SESSION_ID:-"),
            "bash init should derive NSH_SESSION_ID from NSH_WRAP_SESSION_ID when present"
        );
    }

    #[test]
    fn test_fish_wrap_sets_wrap_session_id() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("set -gx NSH_WRAP_SESSION_ID"),
            "fish init should export NSH_WRAP_SESSION_ID before wrap"
        );
        assert!(
            script.contains("if set -q NSH_WRAP_SESSION_ID"),
            "fish init should derive NSH_SESSION_ID from NSH_WRAP_SESSION_ID when present"
        );
    }

    #[test]
    fn test_powershell_wrap_sets_wrap_session_id() {
        let script = generate_init_script("powershell");
        assert!(
            script.contains("$env:NSH_WRAP_SESSION_ID"),
            "PowerShell init should set NSH_WRAP_SESSION_ID before wrap"
        );
        assert!(
            script.contains("$env:NSH_SESSION_ID = if ($env:NSH_WRAP_SESSION_ID)"),
            "PowerShell init should derive NSH_SESSION_ID from NSH_WRAP_SESSION_ID when present"
        );
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
    fn test_zsh_accept_line_has_reentrance_guard() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__nsh_accept_line_active"),
            "zsh accept-line wrapper should have a reentrance guard variable"
        );
        // The guard should check for the variable early and fall back to builtin
        let guard_pos = script.find("__nsh_accept_line_active").unwrap();
        let func_pos = script.find("__nsh_accept_line()").unwrap();
        assert!(
            guard_pos > func_pos,
            "reentrance guard should be inside the accept-line wrapper function"
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
            script.contains("command rm -f \"$payload_file\""),
            "zsh init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_bash_cleanup_uses_command_rm() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("command rm -f \"$payload_file\""),
            "bash init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_fish_cleanup_uses_command_rm() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("command rm -f $payload_file"),
            "fish init should bypass rm aliases when clearing pending command files"
        );
    }

    #[test]
    fn test_zsh_pending_file_io_uses_command() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("command cat \"$payload_file\""),
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
            script.contains("command cat \"$payload_file\""),
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
            script.contains("command cat $payload_file"),
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
    fn test_zsh_emits_iterm2_cwd() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "zsh init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("file://"),
            "zsh init should emit standard OSC 7 file:// CWD escape"
        );
    }

    #[test]
    fn test_bash_emits_iterm2_cwd() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "bash init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("file://"),
            "bash init should emit standard OSC 7 file:// CWD escape"
        );
    }

    #[test]
    fn test_fish_emits_iterm2_cwd() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("__nsh_emit_iterm2_cwd"),
            "fish init should include iTerm2 cwd emitter"
        );
        assert!(
            script.contains("file://"),
            "fish init should emit standard OSC 7 file:// CWD escape"
        );
    }

    #[test]
    fn test_zsh_post_init_integrity_check() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("typeset -f"),
            "zsh init should verify hook functions exist after init"
        );
        assert!(
            script.contains("shell integration broken"),
            "zsh init should warn if hook functions are missing"
        );
    }

    #[test]
    fn test_bash_post_init_integrity_check() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("declare -F"),
            "bash init should verify hook functions exist after init"
        );
        assert!(
            script.contains("shell integration broken"),
            "bash init should warn if hook functions are missing"
        );
    }

    #[test]
    fn test_fish_post_init_integrity_check() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("functions -q"),
            "fish init should verify hook functions exist after init"
        );
        assert!(
            script.contains("shell integration broken"),
            "fish init should warn if hook functions are missing"
        );
    }

    #[test]
    fn test_zsh_session_owner_pid_guard() {
        let script = generate_init_script("zsh");
        assert!(
            script.contains("__NSH_SESSION_OWNER_PID"),
            "zsh init should track session owner PID to prevent subshell cleanup"
        );
    }

    #[test]
    fn test_bash_session_owner_pid_guard() {
        let script = generate_init_script("bash");
        assert!(
            script.contains("__NSH_SESSION_OWNER_PID"),
            "bash init should track session owner PID to prevent subshell cleanup"
        );
    }

    #[test]
    fn test_fish_session_owner_pid_guard() {
        let script = generate_init_script("fish");
        assert!(
            script.contains("__NSH_SESSION_OWNER_PID"),
            "fish init should track session owner PID to prevent subshell cleanup"
        );
    }

    #[test]
    fn test_ps1_session_owner_pid_guard() {
        let script = generate_init_script("powershell");
        assert!(
            script.contains("__NSH_SESSION_OWNER_PID"),
            "powershell init should track session owner PID to prevent subshell cleanup"
        );
    }

    #[test]
    fn test_zsh_unconditional_exports() {
        let script = generate_init_script("zsh");
        // NSH_HOOK_HASH and NSH_HOOKS_VERSION should be set unconditionally
        // (outside the session init block)
        let export_pos = script.find("export NSH_HOOK_HASH=").unwrap();
        let init_pos = script.find("if [[ -z \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        assert!(
            export_pos < init_pos,
            "NSH_HOOK_HASH should be exported unconditionally before session init"
        );
    }

    #[test]
    fn test_bash_unconditional_exports() {
        let script = generate_init_script("bash");
        let export_pos = script.find("export NSH_HOOK_HASH=").unwrap();
        let init_pos = script.find("if [[ -z \"${NSH_SESSION_ID:-}\" ]]").unwrap();
        assert!(
            export_pos < init_pos,
            "NSH_HOOK_HASH should be exported unconditionally before session init"
        );
    }

    #[test]
    fn test_fish_unconditional_exports() {
        let script = generate_init_script("fish");
        let export_pos = script.find("set -gx NSH_HOOK_HASH").unwrap();
        // Use the session init comment marker to find the right block
        // (not the `if not set -q NSH_SESSION_ID` in __nsh_clear_pending_command)
        let init_pos = script.find("# \u{2500}\u{2500} Session init").unwrap();
        assert!(
            export_pos < init_pos,
            "NSH_HOOK_HASH should be exported unconditionally before session init"
        );
    }
}
