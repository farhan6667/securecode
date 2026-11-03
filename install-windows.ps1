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

& $py.Source "$Root\install-global.py"
exit $LASTEXITCODE
