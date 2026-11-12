$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path $PSScriptRoot -Parent
Set-Location $repoRoot
$helper = Join-Path $PSScriptRoot 'migration_helper.py'
if (-not (Test-Path $helper)) { throw 'scripts\migration_helper.py is missing.' }

function Find-PgTool([string]$Name) {
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    $hit = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\$Name.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if ($hit) { return $hit.FullName }
    throw "$Name not found. Add the PostgreSQL bin folder to PATH."
}
$pgDump    = Find-PgTool 'pg_dump'
$pgRestore = Find-PgTool 'pg_restore'

$dsn = $env:ELDORADO_MIGRATION_DSN
if (-not $dsn) {
    $defaultHost = 'localhost'; $defaultPort = '5432'; $defaultDb = ''
    if ($env:ELDORADO_DATABASE_DSN) {
        $json = python (Join-Path $PSScriptRoot 'dsn_defaults.py')
        if ($LASTEXITCODE -eq 0 -and $json) {
            $parsed = $json | ConvertFrom-Json
            if ($parsed.host)   { $defaultHost = $parsed.host }
            if ($parsed.port)   { $defaultPort = $parsed.port }
            if ($parsed.dbname) { $defaultDb   = $parsed.dbname }
        }
    }
    $dbHost = Read-Host "Host [$defaultHost]";          if (-not $dbHost) { $dbHost = $defaultHost }
    $dbPort = Read-Host "Port [$defaultPort]";          if (-not $dbPort) { $dbPort = $defaultPort }
    $dbName = Read-Host "Database name [$defaultDb]";   if (-not $dbName) { $dbName = $defaultDb }
    $dbUser = Read-Host 'Database-OWNER user (NOT the app role)'
    if (-not $dbName -or -not $dbUser) { throw 'Database name and owner user are required.' }

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
if ($dsn -notmatch '=|://') { throw 'That does not look like a connection string.' }

function Get-DbStatus {
    $out = python $helper status
    if ($LASTEXITCODE -ne 0) { throw 'Database status check failed (wrong DSN?).' }
    $files = ($out | Where-Object { $_ -like 'FILES:*' } | Select-Object -First 1).Substring(6)
    $applied = ($out | Where-Object { $_ -like 'APPLIED:*' } | Select-Object -First 1).Substring(8).Trim()
    return @{ Files = $files; Applied = $applied }
}

$env:ELDORADO_MIGRATION_DSN = $dsn
$env:PYTHONPATH = $repoRoot

try {
    $before = Get-DbStatus
    Write-Host "Migration files found : $($before.Files)"
    Write-Host "Applied before        : $($before.Applied)"
    $fileCount = [int]$before.Files
    $appliedCount = @($before.Applied -split ',' | Where-Object { $_ }).Count
    if ($before.Applied -ne ((1..$appliedCount) -join ',')) {
        throw "Applied migrations are not a contiguous run from 0001 (applied: '$($before.Applied)'). Stopping."
    }
    if ($appliedCount -ge $fileCount) { throw 'Nothing to migrate: the database already has every migration.' }
    if ($fileCount - $appliedCount -gt 3) {
        throw "Dev DB is $($fileCount - $appliedCount) migrations behind (applied: '$($before.Applied)'). Review before migrating."
    }
    $nextLabel = '{0:D4}' -f (($before.Applied -split ',').Count + 1)
    Write-Host "Next migration to apply: $nextLabel"

    $backupDir = 'C:\Backups\eldorado'
    if (-not (Test-Path $backupDir)) { New-Item -ItemType Directory -Path $backupDir | Out-Null }
    $dump = Join-Path $backupDir ("postgres-pre-$nextLabel-{0}.dump" -f (Get-Date -Format 'yyyyMMdd-HHmm'))

    & $pgDump -Fc -d $dsn -f $dump
    if ($LASTEXITCODE -ne 0) { throw 'pg_dump failed. Nothing migrated.' }
    if (-not (Test-Path $dump) -or (Get-Item $dump).Length -le 0) { throw 'Backup is missing or empty. Nothing migrated.' }
    & $pgRestore --list $dump | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Backup failed verification. Nothing migrated.' }
    Write-Host ("Backup verified: {0} ({1:N0} bytes)" -f $dump, (Get-Item $dump).Length) -ForegroundColor Green

    $out = python $helper migrate
    if ($LASTEXITCODE -ne 0) { throw 'Migration failed. Restore from the backup above if the DB is in doubt.' }
    Write-Host ($out | Where-Object { $_ -like 'APPLIED_NOW:*' })

    $after = Get-DbStatus
    Write-Host "Applied after         : $($after.Applied)"
    $finalLabel = '{0:D4}' -f $fileCount
    if ($after.Applied -ne ((1..$fileCount) -join ',')) { throw "DB is not at migration $finalLabel after migrating." }
    Write-Host "`nDev database is now at migration $finalLabel." -ForegroundColor Green
}
finally {
    Remove-Item Env:\ELDORADO_MIGRATION_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:\PYTHONPATH -ErrorAction SilentlyContinue
}