# nsh — Natural Shell integration for zsh
# Eval this: eval "$(nsh init zsh)"

# Auto-wrap once so init and daemon share the same session identity.
if [[ -z "${NSH_PTY_ACTIVE:-}" && -z "${NSH_NO_WRAP:-}" && -o interactive && -t 0 && -t 1 ]]; then
    exec nsh wrap
    return 0
fi

# ── Raw `?` query handler (before shell parsing) ────────
# Captures lines like `? what's up` before zsh treats punctuation as syntax.
__nsh_handle_nl_query_line() {
    local line="$BUFFER"

    case "$line" in
        '?? '*)
            print -s -- "$line"
            typeset -g __NSH_DEFERRED_QUERY="${line#\?\? }"
            typeset -g __NSH_DEFERRED_TYPE="think"
            BUFFER=""
            zle __nsh_accept_line_orig
            return 0
            ;;
        '?! '*)
            print -s -- "$line"
            typeset -g __NSH_DEFERRED_QUERY="${line#\?! }"
            typeset -g __NSH_DEFERRED_TYPE="private"
            BUFFER=""
            zle __nsh_accept_line_orig
            return 0
            ;;
        '? '*)
            print -s -- "$line"
            typeset -g __NSH_DEFERRED_QUERY="${line#\? }"
            typeset -g __NSH_DEFERRED_TYPE="query"
            BUFFER=""
            zle __nsh_accept_line_orig
            return 0
            ;;
    esac

    return 1
}

# Runs deferred queries outside ZLE context (triggered from precmd)
__nsh_run_deferred() {
    if [[ -n "${__NSH_DEFERRED_QUERY:-}" ]]; then
        local q="$__NSH_DEFERRED_QUERY"
        local t="$__NSH_DEFERRED_TYPE"
        __NSH_DEFERRED_QUERY=""
        __NSH_DEFERRED_TYPE=""
        case "$t" in
            think) nsh_query_think "$q" ;;
            private) nsh_query_private "$q" ;;
            *) nsh_query "$q" ;;
        esac
    fi
}

__nsh_accept_line() {
    if __nsh_handle_nl_query_line; then
        return 0
    fi

    # Safety guard: if wrapper chaining got corrupted, fall back to builtin.
    local orig_widget="${widgets[__nsh_accept_line_orig]:-}"
    if [[ "$orig_widget" == "user:__nsh_accept_line" ]]; then
        zle .accept-line
    else
        zle __nsh_accept_line_orig
    fi
}

__nsh_install_accept_line_widget() {
    # Non-interactive shells don't have ZLE widgets.
    zle -l >/dev/null 2>&1 || return 0

    local current_widget="${widgets[accept-line]:-}"
    if [[ "$current_widget" == "user:__nsh_accept_line" ]]; then
        # Heal broken state where __nsh_accept_line_orig points to wrapper.
        if [[ "${widgets[__nsh_accept_line_orig]:-}" == "user:__nsh_accept_line" ]]; then
            zle -N __nsh_accept_line_orig .accept-line
        fi
        return 0
    fi

    zle -A accept-line __nsh_accept_line_orig 2>/dev/null || zle -N __nsh_accept_line_orig .accept-line
    if [[ "${widgets[__nsh_accept_line_orig]:-}" == "user:__nsh_accept_line" ]]; then
        zle -N __nsh_accept_line_orig .accept-line
    fi
    zle -N accept-line __nsh_accept_line
}

__nsh_clear_pending_command() {
    [[ -z "${NSH_SESSION_ID:-}" ]] && return 0
    command rm -f \
        "$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}" \
        "$HOME/.nsh/pending_flag_${NSH_SESSION_ID}" 2>/dev/null
    __NSH_PENDING_CMD=""
}

__nsh_emit_iterm2_cwd() {
    [[ "${TERM_PROGRAM:-}" == "iTerm.app" ]] || return 0
    local path="$PWD"
    path="${path//%/%25}"
    path="${path// /%20}"
    path="${path//\#/%23}"
    path="${path//\?/%3F}"
    path="${path//;/%3B}"
    local host="${HOST:-localhost}"
    printf '\033]7;file://%s%s\007' "$host" "$path"
    printf '\033]1337;CurrentDir=%s\007' "$PWD"
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
    for c in ${(s: :)NSH_HINT_SUPPRESSED_EXIT_CODES}; do
        [[ "$c" == "$code" ]] && return 0
    done
    return 1
}

__nsh_query_ignore_exit_code() {
    local code=""
    if [[ "${1:-}" == "ignore" ]]; then
        if [[ "${2:-}" == <-> ]]; then
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

nsh_query() {
    __nsh_clear_pending_command
    __nsh_query_ignore_exit_code "$@" && return 0
    printf '\x1b[2m? %s\x1b[0m\n' "$*" >&2
    command nsh query -- "$@"
}
nsh_query_think() {
    __nsh_clear_pending_command
    __nsh_query_ignore_exit_code "$@" && return 0
    printf '\x1b[2m?? %s\x1b[0m\n' "$*" >&2
    command nsh query --think -- "$@"
}
nsh_query_private() {
    __nsh_clear_pending_command
    __nsh_query_ignore_exit_code "$@" && return 0
    printf '\x1b[2m?! %s\x1b[0m\n' "$*" >&2
    command nsh query --private -- "$@"
}

# ── Nested shell guard ──────────────────────────────────
if [[ -n "${NSH_SESSION_ID:-}" ]]; then
    __nsh_load_suppressed_exit_codes
    # Already inside nsh — only reinstall hooks, skip session init
    alias '?'='noglob nsh_query'
    alias '??'='noglob nsh_query_think'
    alias '?!'='noglob nsh_query_private'
    autoload -Uz add-zsh-hook
    __nsh_install_accept_line_widget
    add-zsh-hook preexec __nsh_preexec
    add-zsh-hook precmd __nsh_run_deferred
    add-zsh-hook precmd __nsh_precmd
    add-zsh-hook precmd __nsh_check_pending
    return 0
fi

# ── Session management ──────────────────────────────────
export NSH_SESSION_ID="__SESSION_ID__"
export NSH_TTY="${NSH_ORIG_TTY:-$(tty)}"
export NSH_HISTFILE="${HISTFILE:-$HOME/.zsh_history}"
__nsh_load_suppressed_exit_codes

__nsh_restore_last_cwd() {
    local restore_cwd
    restore_cwd="$(command nsh session last-cwd --tty "$NSH_TTY" 2>/dev/null)" || return 0
    restore_cwd="${restore_cwd%$'\n'}"
    if [[ -n "$restore_cwd" && -d "$restore_cwd" && "$PWD" != "$restore_cwd" ]]; then
        builtin cd -- "$restore_cwd" 2>/dev/null || true
    fi
}
__nsh_restore_last_cwd

# Start session asynchronously
nsh session start --session "$NSH_SESSION_ID" --tty "$NSH_TTY" --shell "zsh" --pid "$$" >/dev/null 2>&1 &!

# ── Aliases for ? and ?? ────────────────────────────────
alias '?'='noglob nsh_query'
alias '??'='noglob nsh_query_think'
alias '?!'='noglob nsh_query_private'

# ── State variables ─────────────────────────────────────
__NSH_LAST_RECORDED_CMD=""
__NSH_LAST_RECORDED_START=""

# ── preexec: fires BEFORE each command executes ─────────
__nsh_preexec() {
    case "$1" in
        nsh_query\ *|nsh_query_think\ *|nsh_query_private\ *) return ;;
    esac
    export __NSH_CMD="$1"
    export __NSH_CMD_START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    export __nsh_cmd_start_epoch=$(date +%s)
    export __NSH_CWD="$PWD"

    # Mark scrollback position for per-command output capture
    nsh daemon-send capture-mark --session "$NSH_SESSION_ID" 2>/dev/null

    # Redact-next-command mechanism
    local redact_next="$HOME/.nsh/redact_next_${NSH_SESSION_ID}"
    if [[ -f "$redact_next" ]]; then
        command rm -f "$redact_next"
        command touch "$HOME/.nsh/redact_active_${NSH_SESSION_ID}"
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

    # Compute duration
    local duration_ms=0
    if [[ -n "${__nsh_cmd_start_epoch:-}" ]]; then
        duration_ms=$(( ($(date +%s) - ${__nsh_cmd_start_epoch}) * 1000 ))
        __nsh_cmd_start_epoch=""
    fi

    # Remove redact_active flag
    command rm -f "$HOME/.nsh/redact_active_${NSH_SESSION_ID}" 2>/dev/null

    # Skip if no command was recorded
    [[ -z "${cmd:-}" ]] && return

    # Deduplication guard
    if [[ "$cmd" == "$__NSH_LAST_RECORDED_CMD" && "$start" == "$__NSH_LAST_RECORDED_START" ]]; then
        return
    fi
    __NSH_LAST_RECORDED_CMD="$cmd"
    __NSH_LAST_RECORDED_START="$start"

    case "$cmd" in
        nsh_query\ *|nsh_query_think\ *|nsh_query_private\ *) ;;
        *)
            # Hint after failure
            if [[ $exit_code -ne 0 && -n "$cmd" ]]; then
                export NSH_LAST_FAILED_EXIT_CODE="$exit_code"
                if __nsh_is_suppressed_exit_code "$exit_code"; then
                    :
                else
                    case "$cmd" in
                        grep*|test*|"["*|diff*|cmp*|nsh*|ssh*|scp*|sftp*|rsync*|mosh*|ping*|curl*|wget*|ftp*|telnet*|nc*|exit*|logout*|fg*|bg*) ;;
                        *)
                            if [[ -n "${NSH_HINT_IGNORE:-}" ]]; then
                                local _skip=0
                                for pattern in ${(s: :)NSH_HINT_IGNORE}; do
                                    [[ "$cmd" == ${~pattern} ]] && _skip=1 && break
                                done
                                (( _skip )) || printf '\x1b[2m  nsh: command failed (exit %d) — type ? fix or ? ignore\x1b[0m\n' "$exit_code" >&2
                            else
                                printf '\x1b[2m  nsh: command failed (exit %d) — type ? fix or ? ignore\x1b[0m\n' "$exit_code" >&2
                            fi
                            ;;
                    esac
                fi
            fi

            # Record command asynchronously (daemon-send with fallback to record)
            nsh daemon-send record \
                --session "$NSH_SESSION_ID" \
                --command "$cmd" \
                --cwd "$cwd" \
                --exit-code "$exit_code" \
                --started-at "$start" \
                --duration-ms "$duration_ms" \
                --tty "$NSH_TTY" \
                --pid "$$" \
                --shell "zsh" >/dev/null 2>&1 &!
            ;;
    esac

    # Heartbeat for cross-TTY detection (~60s)
    local now=$(date +%s)
    if (( now - ${__NSH_LAST_HEARTBEAT:-0} > 60 )); then
        __NSH_LAST_HEARTBEAT=$now
        nsh daemon-send heartbeat --session "$NSH_SESSION_ID" >/dev/null 2>&1 &!
    fi

    # Auto-continue pending multi-step task
    local pending_flag="$HOME/.nsh/pending_flag_${NSH_SESSION_ID}"
    if [[ -f "$pending_flag" ]]; then
        if [[ -n "${__NSH_PENDING_CMD:-}" && "$cmd" == "$__NSH_PENDING_CMD" ]]; then
            command rm -f "$pending_flag"
            __NSH_PENDING_CMD=""
            nsh query -- "__NSH_CONTINUE__" >/dev/null 2>&1 &!
        fi
    fi

    __nsh_emit_iterm2_cwd
}

# ── Check for pending commands from nsh query ───────────
__nsh_check_pending() {
    local cmd_file="$HOME/.nsh/pending_cmd_${NSH_SESSION_ID}"
    if [[ -f "$cmd_file" ]]; then
        local cmd="$(command cat "$cmd_file")"
        command rm -f "$cmd_file"
        if [[ -n "$cmd" ]]; then
            __NSH_PENDING_CMD="$cmd"
            print -s -- "$cmd"
            # print -z pushes text onto the editing buffer
            print -z "$cmd"
        fi
    fi
}

# Install hooks
autoload -Uz add-zsh-hook
__nsh_install_accept_line_widget
add-zsh-hook preexec __nsh_preexec
add-zsh-hook precmd __nsh_run_deferred
add-zsh-hook precmd __nsh_precmd
add-zsh-hook precmd __nsh_check_pending

# ── Cleanup on exit ─────────────────────────────────────
__nsh_cleanup() {
    nsh session end --session "$NSH_SESSION_ID" 2>/dev/null
}
trap __nsh_cleanup EXIT
