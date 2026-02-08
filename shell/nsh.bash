# nsh — Natural Shell integration for bash
# Eval this: eval "$(nsh init bash)"

export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="$(tty)"

# ── Aliases ─────────────────────────────────────────────
alias '?'='nsh query --'
alias '??'='nsh query --'

# ── bash-preexec equivalent (inline) ────────────────────
__nsh_cmd=""
__nsh_cmd_start=""

__nsh_debug_trap() {
    if [[ -z "$__nsh_cmd" && -n "$BASH_COMMAND" ]]; then
        [[ "$BASH_COMMAND" == __nsh_* ]] && return
        __nsh_cmd="$(HISTTIMEFORMAT='' history 1 | sed 's/^ *[0-9]* *//')"
        __nsh_cmd_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    fi
}

__nsh_prompt_command() {
    local exit_code=$?
    if [[ -n "$__nsh_cmd" ]]; then
        nsh record \
            --session "$NSH_SESSION_ID" \
            --command "$__nsh_cmd" \
            --cwd "$PWD" \
            --exit-code "$exit_code" \
            --started-at "$__nsh_cmd_start" &
        disown 2>/dev/null
        __nsh_cmd=""
        __nsh_cmd_start=""
    fi
}

# ── Check for pending commands from nsh query ───────────
__nsh_check_pending() {
    local cmd_file="$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}"
    if [[ -f "$cmd_file" ]]; then
        local cmd="$(cat "$cmd_file")"
        rm -f "$cmd_file"
        if [[ -n "$cmd" ]]; then
            READLINE_LINE="$cmd"
            READLINE_POINT=${#cmd}
        fi
    fi
}

trap '__nsh_debug_trap' DEBUG
PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"

__nsh_cleanup() {
    nsh session end --session "$NSH_SESSION_ID" 2>/dev/null
}
trap '__nsh_cleanup' EXIT
