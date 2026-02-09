# nsh — Natural Shell integration for bash
# Eval this: eval "$(nsh init bash)"

# ── Nested shell guard ──────────────────────────────────
if [[ -n "${NSH_SESSION_ID:-}" ]]; then
    alias '?'='nsh query --'
    alias '??'='nsh query --'
    # reinstall hooks only
    trap '__nsh_debug_trap' DEBUG
    PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"
    return 0
fi

export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="$(tty)"

# Start session asynchronously
nsh session start --session "$NSH_SESSION_ID" --tty "$(tty)" --shell "bash" --pid "$$" >/dev/null 2>&1 &
disown 2>/dev/null

# ── Aliases ─────────────────────────────────────────────
alias '?'='nsh query --'
alias '??'='nsh query --'

# ── State variables ─────────────────────────────────────
__nsh_cmd=""
__nsh_cmd_start=""
__nsh_last_recorded_cmd=""
__nsh_last_recorded_start=""

__nsh_debug_trap() {
    if [[ -z "$__nsh_cmd" && -n "$BASH_COMMAND" ]]; then
        [[ "$BASH_COMMAND" == __nsh_* ]] && return
        local hist_control="$HISTCONTROL"
        HISTCONTROL=""
        __nsh_cmd="$(HISTTIMEFORMAT='' history 1 | sed 's/^ *[0-9]* *//')"
        HISTCONTROL="$hist_control"
        __nsh_cmd_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    fi

    # Redact-next-command mechanism
    local redact_next="$HOME/.nsh/redact_next_${NSH_SESSION_ID}"
    if [[ -f "$redact_next" ]]; then
        rm -f "$redact_next"
        touch "$HOME/.nsh/redact_active_${NSH_SESSION_ID}"
    fi
}

# ── Hook self-healing ───────────────────────────────────
__nsh_ensure_hooks() {
    case ";${PROMPT_COMMAND:-};" in
        *";__nsh_prompt_command;"*) ;;
        *) PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
}

__nsh_prompt_command() {
    local exit_code=$?

    __nsh_ensure_hooks

    # Capture and clear state immediately
    local cmd="$__nsh_cmd"
    local start="$__nsh_cmd_start"
    __nsh_cmd=""
    __nsh_cmd_start=""

    # Remove redact_active flag
    rm -f "$HOME/.nsh/redact_active_${NSH_SESSION_ID}" 2>/dev/null

    if [[ -n "$cmd" ]]; then
        # Deduplication guard
        if [[ "$cmd" == "$__nsh_last_recorded_cmd" && "$start" == "$__nsh_last_recorded_start" ]]; then
            return
        fi
        __nsh_last_recorded_cmd="$cmd"
        __nsh_last_recorded_start="$start"

        nsh record \
            --session "$NSH_SESSION_ID" \
            --command "$cmd" \
            --cwd "$PWD" \
            --exit-code "$exit_code" \
            --started-at "$start" \
            --tty "$(tty)" \
            --pid "$$" \
            --shell "bash" >/dev/null 2>&1 &
        disown 2>/dev/null
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
