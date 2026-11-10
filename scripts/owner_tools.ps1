param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Bootstrap', 'PurgeSmokeDryRun', 'PurgeSmokeApply')]
    [string]$Action
)
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot
if (-not $env:VIRTUAL_ENV) { throw 'Activate the venv first: .\.venv\Scripts\Activate.ps1' }

$mode = switch ($Action) {
    'Bootstrap'        { 'bootstrap' }
    'PurgeSmokeDryRun' { 'purge-dry' }
    'PurgeSmokeApply'  { 'purge-apply' }
}

if ($Action -eq 'PurgeSmokeApply') {
    Write-Host 'This permanently deletes dev smoke-test accounts (dev-smoke-<digits>@example.com).' -ForegroundColor Yellow
    if ((Read-Host 'Type DELETE to continue') -cne 'DELETE') { throw 'Cancelled. Nothing was deleted.' }
}

$dsn = $env:ELDORADO_MIGRATION_DSN
if (-not $dsn) {
    $dbHost = Read-Host 'Host [localhost]';                if (-not $dbHost) { $dbHost = 'localhost' }
    $dbPort = Read-Host 'Port [5432]';                     if (-not $dbPort) { $dbPort = '5432' }
    $dbName = Read-Host 'Database name [postgres]';        if (-not $dbName) { $dbName = 'postgres' }
    $dbUser = Read-Host 'Database-OWNER user [postgres]';  if (-not $dbUser) { $dbUser = 'postgres' }

    $secure = Read-Host "Password for $dbUser (hidden)" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }

    $dsn = "host=$dbHost port=$dbPort dbname=$dbName user=$dbUser"
    if ($plain) {
        $escaped = $plain.Replace('\', '\\').Replace("'", "\'")
        $dsn += " password='$escaped'"
    }
}

$env:ELDORADO_MIGRATION_DSN = $dsn
$env:PYTHONPATH = $repoRoot

try {
    python (Join-Path $PSScriptRoot 'owner_tools.py') $mode
    if ($LASTEXITCODE -ne 0) { throw "owner_tools failed with exit code $LASTEXITCODE" }
}
finally {
    Remove-Item Env:\ELDORADO_MIGRATION_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
}