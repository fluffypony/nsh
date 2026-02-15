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

if ($env:NSH_SESSION_ID) {
    return
}

$env:NSH_SESSION_ID = if ($env:NSH_WRAP_SESSION_ID) { $env:NSH_WRAP_SESSION_ID } else { "__SESSION_ID__" }
$env:NSH_PTY_ACTIVE = "0"

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
    try {
        $h = Get-History -Count 1 -ErrorAction SilentlyContinue
        if ($h -and $h.Id -ne $global:NshLastHistoryId) {
            $global:NshLastHistoryId = $h.Id
            nsh daemon-send record --session "$env:NSH_SESSION_ID" --command "$($h.CommandLine)" --cwd "$pwd" --exit-code 0 --started-at "$(Get-Date -Format o)" --tty "" --pid $PID --shell "pwsh" 2>$null
        }
    } catch {}
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

Register-EngineEvent PowerShell.Exiting -Action {
    try {
        nsh session end --session "$env:NSH_SESSION_ID" 2>$null
    } catch {}
} | Out-Null
