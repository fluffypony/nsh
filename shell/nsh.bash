# nsh — Natural Shell integration for bash
# Eval this: eval "$(nsh init bash)"

# Auto-wrap once so init and daemon share the same session identity.
if [[ -z "${NSH_PTY_ACTIVE:-}" && -z "${NSH_NO_WRAP:-}" ]] && [[ $- == *i* ]] && [[ -t 0 && -t 1 ]]; then
    export NSH_WRAP_SESSION_ID="${NSH_WRAP_SESSION_ID:-__SESSION_ID__}"
    exec nsh wrap
    return 0
fi

__nsh_clear_pending_command() {
    [[ -z "${NSH_SESSION_ID:-}" ]] && return 0
    command rm -f \
        "$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}" \
        "$HOME/.nsh/pending_flag_${NSH_SESSION_ID}" \
        "$HOME/.nsh/pending_autorun_${NSH_SESSION_ID}" 2>/dev/null
    __nsh_pending_cmd=""
}

__nsh_load_suppressed_exit_codes() {
    local codes
    if codes="$(command nsh session suppressed-exit-codes 2>/dev/null)"; then
        export NSH_HINT_SUPPRESSED_EXIT_CODES="$codes"
    else
        export NSH_HINT_SUPPRESSED_EXIT_CODES="130 137 141 143"
    fi
}

__nsh_is_suppressed_exit_code() {
    local code="$1"
    local c
    for c in $NSH_HINT_SUPPRESSED_EXIT_CODES; do
        [[ "$c" == "$code" ]] && return 0
    done
    return 1
}

__nsh_query_ignore_exit_code() {
    local code=""
    if [[ "${1:-}" == "ignore" ]]; then
        if [[ "${2:-}" =~ ^[0-9]+$ ]]; then
            code="$2"
        else
            code="${NSH_LAST_FAILED_EXIT_CODE:-}"
        fi
    else
        return 1
    fi

    if [[ -z "$code" || "$code" == "0" ]]; then
        printf '\x1b[2m  nsh: no recent failed exit code to ignore\x1b[0m\n' >&2
        return 0
    fi

    if command nsh session ignore-exit-code --code "$code" >/dev/null 2>&1; then
        __nsh_load_suppressed_exit_codes
        printf '\x1b[2m  nsh: suppressed exit code %s for failure hints\x1b[0m\n' "$code" >&2
    else
        printf '\x1b[2m  nsh: failed to update suppressed exit codes\x1b[0m\n' >&2
    fi
    return 0
}

__nsh_emit_iterm2_cwd() {
    [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]] || return 0
    local path="$PWD"
    path="${path//%/%25}"
    path="${path// /%20}"
    path="${path//#/%23}"
    path="${path//\?/%3F}"
    path="${path//;/%3B}"
    local host="${HOSTNAME:-localhost}"
    printf '\033]7;file://%s%s\007' "$host" "$path"
    printf '\033]1337;CurrentDir=%s\007' "$PWD"
}

# ── Nested shell guard ──────────────────────────────────
if [[ -n "${NSH_SESSION_ID:-}" ]]; then
    __nsh_load_suppressed_exit_codes
    nsh_query() { history -s -- "? $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query -- "$@"; }
    nsh_query_think() { history -s -- "?? $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query --think -- "$@"; }
    nsh_query_private() { history -s -- "?! $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query --private -- "$@"; }
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

# Detect WSL for any WSL-specific adjustments
if [[ -f /proc/version ]] && grep -qi microsoft /proc/version 2>/dev/null; then
    export NSH_IS_WSL=1
fi

export NSH_SESSION_ID="${NSH_WRAP_SESSION_ID:-__SESSION_ID__}"
export NSH_TTY="${NSH_ORIG_TTY:-$(tty)}"
export NSH_HISTFILE="${HISTFILE:-$HOME/.bash_history}"
export NSH_HOOK_HASH="__HOOK_HASH__"
export NSH_HOOKS_VERSION="__NSH_VERSION__"
__nsh_load_suppressed_exit_codes

__nsh_restore_last_cwd() {
    local restore_cwd
    restore_cwd="$(command nsh session last-cwd --tty "$NSH_TTY" 2>/dev/null)" || return 0
    if [[ -n "$restore_cwd" && -d "$restore_cwd" && "$PWD" != "$restore_cwd" ]]; then
        builtin cd -- "$restore_cwd" 2>/dev/null || true
    fi
}
__nsh_restore_last_cwd

# Start session asynchronously
nsh session start --session "$NSH_SESSION_ID" --tty "$NSH_TTY" --shell "bash" --pid "$$" >/dev/null 2>&1 &
disown 2>/dev/null

# ── Aliases ─────────────────────────────────────────────
nsh_query() { history -s -- "? $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query -- "$@"; }
nsh_query_think() { history -s -- "?? $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query --think -- "$@"; }
nsh_query_private() { history -s -- "?! $*"; __nsh_clear_pending_command; __nsh_query_ignore_exit_code "$@" && return 0; command nsh query --private -- "$@"; }
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

    # Synchronous CWD persist — atomic tmp+mv, no subprocess
    if [[ -n "$NSH_TTY" ]]; then
        local _tty_safe="${NSH_TTY//\//_}"
        local _cwd_tmp="$HOME/.nsh/cwd_${_tty_safe}.tmp"
        printf '%s' "$PWD" >| "$_cwd_tmp" 2>/dev/null && \
            command mv -f "$_cwd_tmp" "$HOME/.nsh/cwd_${_tty_safe}" 2>/dev/null
    fi

    if [[ -n "$cmd" ]]; then
        # Deduplication guard
        if [[ "$cmd" == "$__nsh_last_recorded_cmd" && "$start" == "$__nsh_last_recorded_start" ]]; then
            return
        fi
        __nsh_last_recorded_cmd="$cmd"
        __nsh_last_recorded_start="$start"

        # Hint after failure
        if [[ $exit_code -ne 0 ]]; then
            export NSH_LAST_FAILED_EXIT_CODE="$exit_code"
            if __nsh_is_suppressed_exit_code "$exit_code"; then
                :
            else
                case "$cmd" in
                    grep*|test*|"["*|diff*|cmp*|nsh*|ssh*|scp*|sftp*|rsync*|mosh*|ping*|curl*|wget*|ftp*|telnet*|nc*|exit*|logout*|fg*|bg*) ;;
                    *)
                        printf '\x1b[2m  nsh: command failed (exit %d) — type ? fix or ? ignore\x1b[0m\n' "$exit_code" >&2
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

    # --- Update notifications ---
    local msg_file="$HOME/.nsh/nsh_msg_${NSH_SESSION_ID}"
    if [[ -f "$msg_file" ]]; then
        command cat "$msg_file" >&2
        command rm -f "$msg_file" 2>/dev/null
    fi
    local restart_flag="$HOME/.nsh/restart_needed_${NSH_SESSION_ID}"
    if [[ -f "$restart_flag" ]]; then
        local now
        now=$(date +%s)
        if (( now - ${__nsh_last_restart_warn:-0} > 3600 )); then
            printf '\x1b[33m  nsh: A protocol update requires you to restart this terminal session for full functionality.\x1b[0m\n' >&2
            __nsh_last_restart_warn=$now
        fi
    fi
    local update_flag="$HOME/.nsh/update_available_${NSH_SESSION_ID}"
    if [[ -f "$update_flag" ]]; then
        local now
        now=$(date +%s)
        if (( now - ${__nsh_last_update_notify:-0} > 3600 )); \
        then command cat "$update_flag" >&2; __nsh_last_update_notify=$now; fi
    fi
    local notice_file="$HOME/.nsh/update_notice"
    if [[ -f "$notice_file" ]]; then
        printf '\x1b[2m  nsh: %s\x1b[0m\n' "$(command cat "$notice_file" 2>/dev/null)" >&2
        command rm -f "$notice_file" 2>/dev/null
    fi

        # ── Project switch detection for memory system ────
    if [[ "$PWD" != "${_NSH_LAST_DIR:-}" ]]; then
        _NSH_LAST_DIR="$PWD"
        if [[ -f "$PWD/.git/HEAD" || -f "$PWD/Cargo.toml" || -f "$PWD/package.json" || -f "$PWD/go.mod" || -f "$PWD/pyproject.toml" ]]; then
            nsh daemon-send record \
                --session "$NSH_SESSION_ID" \
                --command "__nsh_project_switch" \
                --cwd "$PWD" \
                --exit-code 0 \
                --started-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                --tty "$NSH_TTY" \
                --pid "$$" \
                --shell "bash" >/dev/null 2>&1 &
            disown 2>/dev/null
        fi
    fi

    __nsh_emit_iterm2_cwd
}

# ── Check for pending commands from nsh query ───────────
__nsh_check_pending() {
    local cmd_file="$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}"
    local autorun_file="$HOME/.nsh/pending_autorun_${NSH_SESSION_ID}"
    if [[ -f "$cmd_file" ]]; then
        local cmd
        cmd="$(command cat "$cmd_file")"
        command rm -f "$cmd_file"
        if [[ -n "$cmd" ]]; then
            __nsh_pending_cmd="$cmd"
            if [[ -f "$autorun_file" ]]; then
                command rm -f "$autorun_file"
                history -s -- "$cmd"
                builtin eval -- "$cmd"
                return
            fi
            # Method 1: READLINE_LINE (bash 5.1+)
            READLINE_LINE="$cmd"
            READLINE_POINT=${#cmd}
            # Method 2: Fallback — push to history so user presses Up
            history -s -- "$cmd"
        fi
    fi
    # Periodic hook version check (~every 100 commands)
    (( __nsh_cmd_counter = ${__nsh_cmd_counter:-0} + 1 ))
    if (( __nsh_cmd_counter % 100 == 0 )); then
        local _disk_hook_hash
        _disk_hook_hash="$(command nsh init bash --hash 2>/dev/null)"
        if [[ -n "$_disk_hook_hash" && "$_disk_hook_hash" != "$NSH_HOOK_HASH" ]]; then
            printf '\x1b[2m  nsh: shell hooks updated — run `exec $SHELL` or open a new terminal to refresh\x1b[0m\n' >&2
        fi
    fi
}

trap '__nsh_debug_trap' DEBUG
PROMPT_COMMAND="__nsh_check_pending;__nsh_prompt_command${PROMPT_COMMAND:+;$PROMPT_COMMAND}"

__nsh_cleanup() {
    nsh session end --session "$NSH_SESSION_ID" 2>/dev/null
    # Remove per-TTY CWD file
    if [[ -n "$NSH_TTY" ]]; then
        local _tty_safe="${NSH_TTY//\//_}"
        command rm -f "$HOME/.nsh/cwd_${_tty_safe}" 2>/dev/null
    fi
}
trap '__nsh_cleanup' EXIT
