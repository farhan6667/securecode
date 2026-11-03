# Installs pinned Semgrep, Trivy and Gitleaks on a Windows x64 CI runner, the Windows twin of
# install-ci-scanners.sh. Versions, URLs and SHA-256 values come from scripts/engines/engines.lock.json (the
# reviewed lock the setup command uses too), so a hijacked release or tag cannot swap the trivy or gitleaks
# binary: a hash mismatch stops the job before anything is extracted. Semgrep is pinned by version only (pip),
# like in install-ci-scanners.sh; its dependencies are resolved by pip. Also puts the Windows OpenSSH folder (ssh-keygen, used by the
# signed-update tests) on PATH.
# Usage (GitHub Actions, shell: pwsh): ./scripts/install-ci-scanners.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$lock = Get-Content -Raw -Encoding UTF8 (Join-Path $PSScriptRoot 'engines/engines.lock.json') | ConvertFrom-Json
$bin = if ($env:SCANNER_BIN) { $env:SCANNER_BIN } else { Join-Path $env:RUNNER_TEMP 'nfsc-scanners' }
New-Item -ItemType Directory -Force -Path $bin | Out-Null
$work = Join-Path ([IO.Path]::GetTempPath()) ("nfsc-dl-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $work | Out-Null

function Install-Pinned([string]$name) {
    $a = $lock.engines.$name.artifacts.'windows-amd64'
    if (-not $a) { throw "engines.lock.json has no windows-amd64 artifact for $name" }
    $uri = [Uri]$a.url
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'github.com') { throw "refusing $name download from $($a.url)" }
    if ($a.sha256 -notmatch '^[0-9a-f]{64}$') { throw "bad pinned hash for $name" }
    $file = Join-Path $work ([IO.Path]::GetFileName($uri.AbsolutePath))
    Invoke-WebRequest -Uri $a.url -OutFile $file -UseBasicParsing -MaximumRedirection 5
    $got = (Get-FileHash -Algorithm SHA256 -Path $file).Hash.ToLowerInvariant()
    if ($got -ne $a.sha256) { throw "SHA-256 mismatch for ${name}: expected $($a.sha256), got $got" }
    Write-Host "$name $($lock.engines.$name.version): SHA-256 verified"
    if ($a.archive -ne 'zip' -or $a.member -notmatch '^[A-Za-z0-9._-]+\.exe$') { throw "unexpected archive layout for $name" }
    $x = Join-Path $work "$name-x"
    Expand-Archive -Path $file -DestinationPath $x -Force
    $exe = Join-Path $x $a.member
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "$($a.member) not found in the $name archive" }
    Copy-Item -LiteralPath $exe -Destination (Join-Path $bin $a.exe) -Force
}

try {
    Install-Pinned 'trivy'
    Install-Pinned 'gitleaks'
} finally {
    Remove-Item -Recurse -Force -LiteralPath $work -ErrorAction SilentlyContinue
}

$semgrep = $lock.engines.semgrep.version
if ($semgrep -notmatch '^\d+\.\d+\.\d+$') { throw "bad pinned semgrep version" }
python -m pip install --disable-pip-version-check "semgrep==$semgrep"
if ($LASTEXITCODE -ne 0) { throw "pip install semgrep==$semgrep failed" }

$ssh = Join-Path $env:SystemRoot 'System32\OpenSSH'
if (-not (Test-Path -LiteralPath (Join-Path $ssh 'ssh-keygen.exe'))) { throw "ssh-keygen.exe not found in $ssh" }
if ($env:GITHUB_PATH) {
    Add-Content -Path $env:GITHUB_PATH -Value $bin -Encoding utf8
    Add-Content -Path $env:GITHUB_PATH -Value $ssh -Encoding utf8
}
$env:PATH = "$bin;$ssh;$env:PATH"
& (Join-Path $bin 'trivy.exe') --version | Select-Object -First 1
& (Join-Path $bin 'gitleaks.exe') version
semgrep --version
Write-Host "ssh-keygen: $(Join-Path $ssh 'ssh-keygen.exe')"
