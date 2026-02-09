# nsh — Natural Shell integration for fish
# Source this: nsh init fish | source

# ── Nested shell guard ──────────────────────────────────
if set -q NSH_SESSION_ID
    function nsh_query --wraps='nsh query --'
        nsh query -- $argv
    end
    abbr -a '?' -- 'nsh query --'
    abbr -a '??' -- 'nsh query --'
    return 0
end

set -gx NSH_SESSION_ID "__SESSION_ID__"
set -gx NSH_TTY (tty)

# Start session asynchronously
nsh session start --session $NSH_SESSION_ID --tty $NSH_TTY --shell fish --pid $fish_pid &>/dev/null &
disown 2>/dev/null

# ── Abbreviations for ? and ?? ──────────────────────────
function nsh_query --wraps='nsh query --'
    nsh query -- $argv
end
abbr -a '?' -- 'nsh query --'
abbr -a '??' -- 'nsh query --'

# ── State variables ─────────────────────────────────────
set -g __nsh_cmd ""
set -g __nsh_cmd_start ""
set -g __nsh_cwd ""
set -g __nsh_last_recorded_cmd ""
set -g __nsh_last_recorded_start ""
set -g __nsh_pending_cmd ""
set -g __nsh_last_heartbeat 0

# ── preexec: fires BEFORE each command executes ─────────
function __nsh_preexec --on-event fish_preexec
    set -g __nsh_cmd $argv[1]
    set -g __nsh_cmd_start (date -u +%Y-%m-%dT%H:%M:%SZ)
    set -g __nsh_cwd $PWD

    # Redact-next-command mechanism
    set -l redact_next "$HOME/.nsh/redact_next_$NSH_SESSION_ID"
    if test -f $redact_next
        rm -f $redact_next
        touch "$HOME/.nsh/redact_active_$NSH_SESSION_ID"
    end
end

# ── postexec: fires AFTER each command completes ────────
function __nsh_postexec --on-event fish_postexec
    set -l exit_code $status
    set -l cmd $__nsh_cmd
    set -l start $__nsh_cmd_start
    set -l cwd $__nsh_cwd
    set -g __nsh_cmd ""
    set -g __nsh_cmd_start ""
    set -g __nsh_cwd ""

    # Remove redact_active flag
    rm -f "$HOME/.nsh/redact_active_$NSH_SESSION_ID" 2>/dev/null

    if test -z "$cmd"
        return
    end

    # Deduplication guard
    if test "$cmd" = "$__nsh_last_recorded_cmd" -a "$start" = "$__nsh_last_recorded_start"
        return
    end
    set -g __nsh_last_recorded_cmd $cmd
    set -g __nsh_last_recorded_start $start

    nsh record \
        --session $NSH_SESSION_ID \
        --command "$cmd" \
        --cwd "$cwd" \
        --exit-code $exit_code \
        --started-at "$start" \
        --tty $NSH_TTY \
        --pid $fish_pid \
        --shell fish &>/dev/null &
    disown 2>/dev/null

    # Heartbeat for cross-TTY detection (~60s)
    set -l now (date +%s)
    if test (math "$now - $__nsh_last_heartbeat") -gt 60
        set -g __nsh_last_heartbeat $now
        nsh heartbeat --session $NSH_SESSION_ID &>/dev/null &
        disown 2>/dev/null
    end

    # Auto-continue pending multi-step task
    set -l pending_flag "$HOME/.nsh/pending_flag_$NSH_SESSION_ID"
    if test -f $pending_flag
        rm -f $pending_flag
        if test -n "$__nsh_pending_cmd" -a "$cmd" = "$__nsh_pending_cmd"
            set -g __nsh_pending_cmd ""
            nsh query -- "__NSH_CONTINUE__" &>/dev/null &
            disown 2>/dev/null
        end
    end
end

# ── Check for pending commands ──────────────────────────
function __nsh_check_pending --on-event fish_prompt
    set -l cmd_file "$HOME/.nsh/pending_cmd_$NSH_SESSION_ID"
    if test -f $cmd_file
        set -l cmd (cat $cmd_file)
        rm -f $cmd_file
        if test -n "$cmd"
            set -g __nsh_pending_cmd $cmd
            commandline -r -- "$cmd"
            commandline -f repaint
        end
    end
end

# ── Cleanup on exit ─────────────────────────────────────
function __nsh_cleanup --on-event fish_exit
    nsh session end --session $NSH_SESSION_ID 2>/dev/null
end
