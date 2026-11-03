Write-Host 'Checking optional AppSec tools...'
$tools = @('python','semgrep','trivy','gitleaks','docker')
foreach ($t in $tools) {
  if (Get-Command $t -ErrorAction SilentlyContinue) { Write-Host "[OK] $t" } else { Write-Host "[--] $t not installed (optional)" }
}
Write-Host 'Use your approved corporate package manager or internal binaries to install optional scanners.'
