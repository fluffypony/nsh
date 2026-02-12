# nsh — Natural Shell integration for bash
# Eval this: eval "$(nsh init bash)"

__nsh_clear_pending_command() {
    [[ -z "${NSH_SESSION_ID:-}" ]] && return 0
    command rm -f \
        "$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}" \
        "$HOME/.nsh/pending_flag_${NSH_SESSION_ID}" 2>/dev/null
    __nsh_pending_cmd=""
}

# ── Nested shell guard ──────────────────────────────────
if [[ -n "${NSH_SESSION_ID:-}" ]]; then
    nsh_query() { history -s -- "? $*"; __nsh_clear_pending_command; command nsh query -- "$@"; }
    nsh_query_think() { history -s -- "?? $*"; __nsh_clear_pending_command; command nsh query --think -- "$@"; }
    nsh_query_private() { history -s -- "?! $*"; __nsh_clear_pending_command; command nsh query --private -- "$@"; }
    alias '?'='nsh_query'
    alias '??'='nsh_query_think'
    alias '?!'='nsh_query_private'
    # Only reinstall hooks if not already present
    case ";${PROMPT_COMMAND:-};" in
        *";__nsh_prompt_command;"*) ;;
        *) PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
    trap '__nsh_debug_trap' DEBUG
    return 0
fi

export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="${NSH_ORIG_TTY:-$(tty)}"
export NSH_HISTFILE="${HISTFILE:-$HOME/.bash_history}"

# Start session asynchronously
nsh session start --session "$NSH_SESSION_ID" --tty "$NSH_TTY" --shell "bash" --pid "$$" >/dev/null 2>&1 &
disown 2>/dev/null

# ── Aliases ─────────────────────────────────────────────
nsh_query() { history -s -- "? $*"; __nsh_clear_pending_command; command nsh query -- "$@"; }
nsh_query_think() { history -s -- "?? $*"; __nsh_clear_pending_command; command nsh query --think -- "$@"; }
nsh_query_private() { history -s -- "?! $*"; __nsh_clear_pending_command; command nsh query --private -- "$@"; }
alias '?'='nsh_query'
alias '??'='nsh_query_think'
alias '?!'='nsh_query_private'

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
        __nsh_cmd_start_epoch=$(date +%s)

        # Mark scrollback position for per-command output capture
        nsh daemon-send capture-mark --session "$NSH_SESSION_ID" 2>/dev/null
    fi

    # Redact-next-command mechanism
    local redact_next="$HOME/.nsh/redact_next_${NSH_SESSION_ID}"
    if [[ -f "$redact_next" ]]; then
        command rm -f "$redact_next"
        command touch "$HOME/.nsh/redact_active_${NSH_SESSION_ID}"
    fi
}

# ── Hook self-healing ───────────────────────────────────
__nsh_ensure_hooks() {
    case ";${PROMPT_COMMAND:-};" in
        *";__nsh_prompt_command;"*) ;;
        *) PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
    esac
    trap '__nsh_debug_trap' DEBUG 2>/dev/null
}

__nsh_prompt_command() {
    local exit_code=$?

    __nsh_ensure_hooks

    # Capture and clear state immediately
    local cmd="$__nsh_cmd"
    local start="$__nsh_cmd_start"
    __nsh_cmd=""
    __nsh_cmd_start=""

    local duration_ms=0
    if [[ -n "${__nsh_cmd_start_epoch:-}" ]]; then
        duration_ms=$(( ($(date +%s) - ${__nsh_cmd_start_epoch}) * 1000 ))
        __nsh_cmd_start_epoch=""
    fi

    # Remove redact_active flag
    command rm -f "$HOME/.nsh/redact_active_${NSH_SESSION_ID}" 2>/dev/null

    if [[ -n "$cmd" ]]; then
        # Deduplication guard
        if [[ "$cmd" == "$__nsh_last_recorded_cmd" && "$start" == "$__nsh_last_recorded_start" ]]; then
            return
        fi
        __nsh_last_recorded_cmd="$cmd"
        __nsh_last_recorded_start="$start"

        # Hint after failure
        if [[ $exit_code -ne 0 ]]; then
            if [[ $exit_code -eq 130 || $exit_code -eq 143 || $exit_code -eq 137 ]]; then
                :
            else
                case "$cmd" in
                    grep*|test*|"["*|diff*|cmp*|nsh*|ssh*|scp*|sftp*|rsync*|mosh*|ping*|curl*|wget*|ftp*|telnet*|nc*|exit*|logout*|fg*|bg*) ;;
                    *)
                        printf '\x1b[2m  nsh: command failed (exit %d) — type ? fix to diagnose\x1b[0m\n' "$exit_code" >&2
                        ;;
                esac
            fi
        fi

        nsh daemon-send record \
            --session "$NSH_SESSION_ID" \
            --command "$cmd" \
            --cwd "$PWD" \
            --exit-code "$exit_code" \
            --started-at "$start" \
            --duration-ms "$duration_ms" \
            --tty "$NSH_TTY" \
            --pid "$$" \
            --shell "bash" >/dev/null 2>&1 &
        disown 2>/dev/null
    fi

    # Heartbeat for cross-TTY detection (~60s)
    local now
    now=$(date +%s)
    if (( now - ${__nsh_last_heartbeat:-0} > 60 )); then
        __nsh_last_heartbeat=$now
        nsh daemon-send heartbeat --session "$NSH_SESSION_ID" >/dev/null 2>&1 &
        disown 2>/dev/null
    fi

    # Auto-continue pending multi-step task
    local pending_flag="$HOME/.nsh/pending_flag_${NSH_SESSION_ID}"
    if [[ -f "$pending_flag" ]]; then
        if [[ -n "${__nsh_pending_cmd:-}" && "$cmd" == "$__nsh_pending_cmd" ]]; then
            command rm -f "$pending_flag"
            __nsh_pending_cmd=""
            nsh query -- "__NSH_CONTINUE__" >/dev/null 2>&1 &
            disown 2>/dev/null
        fi
    fi
}

# ── Check for pending commands from nsh query ───────────
__nsh_check_pending() {
    local cmd_file="$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}"
    if [[ -f "$cmd_file" ]]; then
        local cmd
        cmd="$(command cat "$cmd_file")"
        command rm -f "$cmd_file"
        if [[ -n "$cmd" ]]; then
            __nsh_pending_cmd="$cmd"
            # Method 1: READLINE_LINE (bash 5.1+)
            READLINE_LINE="$cmd"
            READLINE_POINT=${#cmd}
            # Method 2: Fallback — push to history so user presses Up
            history -s -- "$cmd"
        fi
    fi
}

trap '__nsh_debug_trap' DEBUG
PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"

__nsh_cleanup() {
    nsh session end --session "$NSH_SESSION_ID" 2>/dev/null
}
trap '__nsh_cleanup' EXIT
