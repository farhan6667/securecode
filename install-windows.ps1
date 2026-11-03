$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path

$py = Get-Command py -ErrorAction SilentlyContinue
if (-not $py) {
    $py = Get-Command python -ErrorAction SilentlyContinue
}

if (-not $py) {
    Write-Error "Python 3 is required. Install it from your approved enterprise software source, then run this installer again."
    exit 1
}

# Every argument is passed on to install-global.py, for example:
#   powershell -ExecutionPolicy Bypass -File .\install-windows.ps1 --no-update-task --agent cursor
$pyArgs = @()
if ($py.Name -ieq "py.exe") { $pyArgs += "-3" }   # the launcher: newest Python 3, never Python 2
& $py.Source @pyArgs "$Root\install-global.py" @args
exit $LASTEXITCODE
