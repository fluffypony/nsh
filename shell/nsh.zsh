# nsh — Natural Shell integration for zsh
# Eval this: eval "$(nsh init zsh)"

# ── Session management ──────────────────────────────────
export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="$(tty)"

# ── Aliases for ? and ?? ────────────────────────────────
alias '?'='noglob nsh query --'
alias '??'='noglob nsh query --'

# ── preexec: fires BEFORE each command executes ─────────
__nsh_preexec() {
    export __NSH_CMD="$1"
    export __NSH_CMD_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    export __NSH_CWD="$PWD"
}

# ── precmd: fires AFTER each command completes ──────────
__nsh_precmd() {
    local exit_code=$?
    # Skip if no command was recorded
    [[ -z "${__NSH_CMD:-}" ]] && return

    # Record command asynchronously
    nsh record \
        --session "$NSH_SESSION_ID" \
        --command "$__NSH_CMD" \
        --cwd "$__NSH_CWD" \
        --exit-code "$exit_code" \
        --started-at "$__NSH_CMD_START" &!

    unset __NSH_CMD __NSH_CMD_START __NSH_CWD
}

# ── Check for pending commands from nsh query ───────────
__nsh_check_pending() {
    local cmd_file="$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}"
    if [[ -f "$cmd_file" ]]; then
        local cmd="$(cat "$cmd_file")"
        rm -f "$cmd_file"
        if [[ -n "$cmd" ]]; then
            # print -z pushes text onto the editing buffer
            print -z "$cmd"
        fi
    fi
}

# Install hooks
autoload -Uz add-zsh-hook
add-zsh-hook preexec __nsh_preexec
add-zsh-hook precmd __nsh_precmd
add-zsh-hook precmd __nsh_check_pending

# ── Cleanup on exit ─────────────────────────────────────
__nsh_cleanup() {
    nsh session end --session "$NSH_SESSION_ID" 2>/dev/null
}
trap __nsh_cleanup EXIT
