# nsh - Natural Shell integration for PowerShell
# Invoke with: Invoke-Expression (nsh init powershell)

# Auto-wrap once on non-Windows platforms so init and daemon share
# the same session identity. Native Windows currently has no PTY wrap.
if (-not $IsWindows -and -not $env:NSH_PTY_ACTIVE -and -not $env:NSH_NO_WRAP) {
    if (-not $env:NSH_WRAP_SESSION_ID) {
        $env:NSH_WRAP_SESSION_ID = "__SESSION_ID__"
    }
    & nsh wrap
    return
}

# ── Always-run: exports, functions, prompt ──────────────
$env:NSH_HOOK_HASH = "__HOOK_HASH__"
$env:NSH_HOOKS_VERSION = "__NSH_VERSION__"

function global:? {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$args)
    nsh query -- @args
}

function global:?? {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$args)
    nsh query --think -- @args
}

$global:NshLastHistoryId = -1
function global:prompt {
    $ec = if ($LASTEXITCODE) { $LASTEXITCODE } else { 0 }

    # OSC 133;D — command finished with exit code
    [Console]::Write("`e]133;D;$ec`a")
    # OSC 133;A — prompt start
    [Console]::Write("`e]133;A`a")

    try {
        $h = Get-History -Count 1 -ErrorAction SilentlyContinue
        if ($h -and $h.Id -ne $global:NshLastHistoryId) {
            $global:NshLastHistoryId = $h.Id
            nsh daemon-send record --session "$env:NSH_SESSION_ID" --command "$($h.CommandLine)" --cwd "$pwd" --exit-code $ec --started-at "$(Get-Date -Format o)" --tty "" --pid $PID --shell "pwsh" 2>$null
        }
    } catch {}

    # --- Check for pending commands from nsh query ---
    $pendingFile = Join-Path $HOME ".nsh\pending_$env:NSH_SESSION_ID.json"
    if (Test-Path $pendingFile) {
        $raw = Get-Content $pendingFile -Raw -ErrorAction SilentlyContinue
        Remove-Item $pendingFile -Force -ErrorAction SilentlyContinue
        if ($raw) {
            try {
                $parsed = $raw | ConvertFrom-Json
                if ($parsed.command) {
                    if ($parsed.autorun -eq $true) {
                        Invoke-Expression $parsed.command
                    } else {
                        Write-Host "  nsh: next step from previous task - Enter to continue, edit to modify, Ctrl-C to cancel" -ForegroundColor DarkGray
                        [Microsoft.PowerShell.PSConsoleReadLine]::Insert($parsed.command)
                    }
                }
            } catch {}
        }
    }

    # --- Update notifications ---
    $msgFile = Join-Path $HOME ".nsh\nsh_msg_$env:NSH_SESSION_ID"
    if (Test-Path $msgFile) {
        Get-Content $msgFile | Write-Host
        Remove-Item $msgFile -Force -ErrorAction SilentlyContinue
    }
    # restart_needed and update_available markers are obsolete under shim/core split
    $noticeFile = Join-Path $HOME ".nsh\update_notice"
    if (Test-Path $noticeFile) {
        # Auto-reload hooks by re-evaluating init script
        try {
            $env:NSH_NO_WRAP = "1"
            Invoke-Expression (& nsh init powershell 2>$null)
            Remove-Item Env:\NSH_NO_WRAP -ErrorAction SilentlyContinue
            $env:NSH_HOOK_HASH = (& nsh init powershell --hash 2>$null)
            # Only delete notice after successful reload
            Remove-Item $noticeFile -Force -ErrorAction SilentlyContinue
            Write-Host "  nsh: shell hooks updated - hooks reloaded automatically." -ForegroundColor DarkGray
        } catch {
            Remove-Item Env:\NSH_NO_WRAP -ErrorAction SilentlyContinue
            # Leave notice in place so reload is retried on next prompt
        }
    }
    "PS $pwd> "
}

if (Get-Command Set-PSReadLineKeyHandler -ErrorAction SilentlyContinue) {
    Set-PSReadLineKeyHandler -Key Enter -ScriptBlock {
        $line = $null
        $cursor = 0
        [Microsoft.PowerShell.PSConsoleReadLine]::GetBufferState([ref]$line, [ref]$cursor)
        if ($line -match '^\?\?\s+') {
            $q = $line.Substring(3)
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            nsh query --think -- $q
            return
        }
        if ($line -match '^\?\s+') {
            $q = $line.Substring(2)
            [Microsoft.PowerShell.PSConsoleReadLine]::RevertLine()
            nsh query -- $q
            return
        }
        [Microsoft.PowerShell.PSConsoleReadLine]::AcceptLine()
    }
}

# ── Session init (ONE TIME ONLY) ────────────────────────
if (-not $env:NSH_SESSION_ID) {
    $env:NSH_SESSION_ID = if ($env:NSH_WRAP_SESSION_ID) { $env:NSH_WRAP_SESSION_ID } else { "__SESSION_ID__" }
    $env:NSH_PTY_ACTIVE = "0"
    $env:__NSH_SESSION_OWNER_PID = $PID
    $global:NshLastRestartWarn = $null
    $global:NshLastUpdateNotify = $null
    $global:NshCmdCounter = 0

    Register-EngineEvent PowerShell.Exiting -Action {
        if ($PID -eq $env:__NSH_SESSION_OWNER_PID) {
            try {
                nsh session end --session "$env:NSH_SESSION_ID" 2>$null
            } catch {}
        }
    } | Out-Null
}
