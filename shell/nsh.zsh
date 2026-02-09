# nsh — Natural Shell integration for zsh
# Eval this: eval "$(nsh init zsh)"

# ── Nested shell guard ──────────────────────────────────
if [[ -n "${NSH_SESSION_ID:-}" ]]; then
    # Already inside nsh — only reinstall hooks, skip session init
    alias '?'='noglob nsh query --'
    alias '??'='noglob nsh query --'
    autoload -Uz add-zsh-hook
    add-zsh-hook preexec __nsh_preexec
    add-zsh-hook precmd __nsh_precmd
    add-zsh-hook precmd __nsh_check_pending
    return 0
fi

# ── Session management ──────────────────────────────────
export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="$(tty)"

# Start session asynchronously
nsh session start --session "$NSH_SESSION_ID" --tty "$(tty)" --shell "zsh" --pid "$$" >/dev/null 2>&1 &!

# ── Aliases for ? and ?? ────────────────────────────────
alias '?'='noglob nsh query --'
alias '??'='noglob nsh query --'

# ── State variables ─────────────────────────────────────
__NSH_LAST_RECORDED_CMD=""
__NSH_LAST_RECORDED_START=""

# ── preexec: fires BEFORE each command executes ─────────
__nsh_preexec() {
    export __NSH_CMD="$1"
    export __NSH_CMD_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    export __NSH_CWD="$PWD"

    # Redact-next-command mechanism
    local redact_next="$HOME/.nsh/redact_next_${NSH_SESSION_ID}"
    if [[ -f "$redact_next" ]]; then
        rm -f "$redact_next"
        touch "$HOME/.nsh/redact_active_${NSH_SESSION_ID}"
    fi
}

# ── precmd: fires AFTER each command completes ──────────
__nsh_precmd() {
    local exit_code=$?

    # Hook self-healing: recover if hooks were overwritten
    if (( ! ${precmd_functions[(I)__nsh_precmd]} )); then
        add-zsh-hook precmd __nsh_precmd
    fi

    # Capture and clear state immediately
    local cmd="$__NSH_CMD"
    local start="$__NSH_CMD_START"
    local cwd="$__NSH_CWD"
    __NSH_CMD=""
    __NSH_CMD_START=""
    __NSH_CWD=""

    # Remove redact_active flag
    rm -f "$HOME/.nsh/redact_active_${NSH_SESSION_ID}" 2>/dev/null

    # Skip if no command was recorded
    [[ -z "${cmd:-}" ]] && return

    # Deduplication guard
    if [[ "$cmd" == "$__NSH_LAST_RECORDED_CMD" && "$start" == "$__NSH_LAST_RECORDED_START" ]]; then
        return
    fi
    __NSH_LAST_RECORDED_CMD="$cmd"
    __NSH_LAST_RECORDED_START="$start"

    # Record command asynchronously
    nsh record \
        --session "$NSH_SESSION_ID" \
        --command "$cmd" \
        --cwd "$cwd" \
        --exit-code "$exit_code" \
        --started-at "$start" \
        --tty "$(tty)" \
        --pid "$$" \
        --shell "zsh" >/dev/null 2>&1 &!
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
