$ErrorActionPreference = "Stop"

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "aarch64" } else { "x86_64" }
$target = "$arch-pc-windows-msvc"
$repo = "fluffypony/nsh"

$latest = (Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest").tag_name
$baseUrl = "https://github.com/$repo/releases/download/$latest"
$zipUrl = "$baseUrl/nsh-$target.zip"
$shaUrl = "$baseUrl/nsh-$target.zip.sha256"

$installDir = if ($env:CARGO_HOME) { Join-Path $env:CARGO_HOME "bin" } else { Join-Path $env:LOCALAPPDATA "nsh\bin" }
New-Item -ItemType Directory -Force -Path $installDir | Out-Null

$tmpDir = Join-Path $env:TEMP "nsh-install-$PID"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$zipPath = Join-Path $tmpDir "nsh.zip"
$shaPath = Join-Path $tmpDir "nsh.sha256"

Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
Invoke-WebRequest -Uri $shaUrl -OutFile $shaPath

$expected = (Get-Content $shaPath).Split(" ")[0].Trim()
$actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected.ToLowerInvariant()) {
    throw "Checksum verification failed. Expected $expected got $actual"
}

Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force
Copy-Item (Join-Path $tmpDir "nsh.exe") (Join-Path $installDir "nsh.exe") -Force

$pathUser = [Environment]::GetEnvironmentVariable("Path", "User")
if ($pathUser -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$pathUser;$installDir", "User")
    Write-Host "Added $installDir to user PATH"
}

$nshDir = Join-Path $HOME ".nsh"
New-Item -ItemType Directory -Force -Path $nshDir | Out-Null
$configPath = Join-Path $nshDir "config.toml"
if (-not (Test-Path $configPath)) {
    Write-Host ""
    Write-Host "Running initial configuration..."
    try {
        & (Join-Path $installDir "nsh.exe") autoconfigure
    } catch {
        Write-Host "Auto-configuration skipped. Run 'nsh autoconfigure' to configure later."
    }
}

if (Get-Command wsl.exe -ErrorAction SilentlyContinue) {
    Write-Host "WSL detected. For full PTY functionality, consider running nsh inside WSL."
}

if (Test-Path $PROFILE) {
    $initLine = 'if (Get-Command nsh -ErrorAction SilentlyContinue) { Invoke-Expression (nsh init powershell) }'
    if (-not (Select-String -Path $PROFILE -Pattern "nsh init powershell" -Quiet)) {
        Add-Content -Path $PROFILE -Value "`n$initLine"
    }
}

Write-Host "nsh installed successfully at $(Join-Path $installDir 'nsh.exe')"
