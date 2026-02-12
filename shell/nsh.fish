# nsh — Natural Shell integration for fish
# Source this: nsh init fish | source

function __nsh_clear_pending_command
    if not set -q NSH_SESSION_ID
        return
    end
    command rm -f \
        "$HOME/.nsh/pending_cmd_$NSH_SESSION_ID" \
        "$HOME/.nsh/pending_flag_$NSH_SESSION_ID" 2>/dev/null
    set -g __nsh_pending_cmd ""
end

# ── Nested shell guard ──────────────────────────────────
if set -q NSH_SESSION_ID
    function nsh_query --wraps='nsh query --'
        builtin history add -- "? $argv" 2>/dev/null
        __nsh_clear_pending_command
        command nsh query -- $argv
    end
    function nsh_query_think --wraps='nsh query --think --'
        builtin history add -- "?? $argv" 2>/dev/null
        __nsh_clear_pending_command
        command nsh query --think -- $argv
    end
    function nsh_query_private --wraps='nsh query --private --'
        builtin history add -- "?! $argv" 2>/dev/null
        __nsh_clear_pending_command
        command nsh query --private -- $argv
    end
    abbr -a '?' -- 'nsh_query'
    abbr -a '??' -- 'nsh_query_think'
    abbr -a '?!' -- 'nsh_query_private'
    return 0
end

set -gx NSH_SESSION_ID "__SESSION_ID__"
if set -q NSH_ORIG_TTY
    set -gx NSH_TTY "$NSH_ORIG_TTY"
else
    set -gx NSH_TTY (tty)
end
set -gx NSH_HISTFILE ~/.local/share/fish/fish_history

# Start session asynchronously
nsh session start --session $NSH_SESSION_ID --tty $NSH_TTY --shell fish --pid $fish_pid &>/dev/null &
disown 2>/dev/null

# ── Abbreviations for ? and ?? ──────────────────────────
function nsh_query --wraps='nsh query --'
    builtin history add -- "? $argv" 2>/dev/null
    __nsh_clear_pending_command
    command nsh query -- $argv
end
function nsh_query_think --wraps='nsh query --think --'
    builtin history add -- "?? $argv" 2>/dev/null
    __nsh_clear_pending_command
    command nsh query --think -- $argv
end
function nsh_query_private --wraps='nsh query --private --'
    builtin history add -- "?! $argv" 2>/dev/null
    __nsh_clear_pending_command
    command nsh query --private -- $argv
end
abbr -a '?' -- 'nsh_query'
abbr -a '??' -- 'nsh_query_think'
abbr -a '?!' -- 'nsh_query_private'

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
    set -g __nsh_cmd_start_epoch (date +%s)
    set -g __nsh_cwd $PWD

    # Mark scrollback position for per-command output capture
    nsh daemon-send capture-mark --session $NSH_SESSION_ID 2>/dev/null

    # Redact-next-command mechanism
    set -l redact_next "$HOME/.nsh/redact_next_$NSH_SESSION_ID"
    if test -f $redact_next
        command rm -f $redact_next
        command touch "$HOME/.nsh/redact_active_$NSH_SESSION_ID"
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

    set -l duration_ms 0
    if test -n "$__nsh_cmd_start_epoch"
        set duration_ms (math "( "(date +%s)" - $__nsh_cmd_start_epoch) * 1000")
        set -g __nsh_cmd_start_epoch ""
    end

    # Remove redact_active flag
    command rm -f "$HOME/.nsh/redact_active_$NSH_SESSION_ID" 2>/dev/null

    if test -z "$cmd"
        return
    end

    # Deduplication guard
    if test "$cmd" = "$__nsh_last_recorded_cmd" -a "$start" = "$__nsh_last_recorded_start"
        return
    end
    set -g __nsh_last_recorded_cmd $cmd
    set -g __nsh_last_recorded_start $start

    # Hint after failure
    if test $exit_code -ne 0
        if test $exit_code -eq 130 -o $exit_code -eq 143 -o $exit_code -eq 137
            # Signal-based exit (Ctrl-C, SIGTERM, SIGKILL) — suppress
        else
            switch "$cmd"
                case 'grep*' 'test*' '\[*' 'diff*' 'cmp*' 'nsh*' 'ssh*' 'scp*' 'sftp*' 'rsync*' 'mosh*' 'ping*' 'curl*' 'wget*' 'ftp*' 'telnet*' 'nc*' 'exit*' 'logout*' 'fg*' 'bg*'
                    # benign failures
                case '*'
                    printf '\x1b[2m  nsh: command failed (exit %d) — type ? fix to diagnose\x1b[0m\n' $exit_code >&2
            end
        end
    end

    nsh daemon-send record \
        --session $NSH_SESSION_ID \
        --command "$cmd" \
        --cwd "$cwd" \
        --exit-code $exit_code \
        --started-at "$start" \
        --duration-ms $duration_ms \
        --tty $NSH_TTY \
        --pid $fish_pid \
        --shell fish &>/dev/null &
    disown 2>/dev/null

    # Heartbeat for cross-TTY detection (~60s)
    set -l now (date +%s)
    if test (math "$now - $__nsh_last_heartbeat") -gt 60
        set -g __nsh_last_heartbeat $now
        nsh daemon-send heartbeat --session $NSH_SESSION_ID &>/dev/null &
        disown 2>/dev/null
    end

    # Auto-continue pending multi-step task
    set -l pending_flag "$HOME/.nsh/pending_flag_$NSH_SESSION_ID"
    if test -f $pending_flag
        if test -n "$__nsh_pending_cmd" -a "$cmd" = "$__nsh_pending_cmd"
            command rm -f $pending_flag
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
        set -l cmd (command cat $cmd_file)
        command rm -f $cmd_file
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
