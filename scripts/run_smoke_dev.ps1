param([switch]$WaitForCooldown)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)

$env:ELDORADO_ENV = 'development'
$env:ELDORADO_ENABLE_CONSOLE_VERIFICATION_EMAIL = 'true'
$env:ELDORADO_ENABLE_CONSOLE_RESET_EMAIL = 'true'

$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:ELDORADO_JWT_SECRET = [Convert]::ToBase64String($bytes)

$secure = Read-Host 'Password for role eldorado_app (hidden)' -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
if (-not $plain) { throw 'Password must not be empty.' }
$escaped = $plain.Replace('\', '\\').Replace("'", "\'")
$env:ELDORADO_DATABASE_DSN = "host=localhost port=5432 dbname=postgres user=eldorado_app password='$escaped'"

$log = Join-Path $env:TEMP 'eldorado-server.log'
$server = $null
$smokeFailed = $false

try {
    $who = python -c "import os,psycopg; c=psycopg.connect(os.environ['ELDORADO_DATABASE_DSN']); print(c.execute('select current_user').fetchone()[0])"
    if ($LASTEXITCODE -ne 0) { throw 'Could not connect as eldorado_app (wrong password, or the role cannot log in).' }
    if ($who.Trim() -ne 'eldorado_app') { throw "Connected as '$who', expected eldorado_app. Stopping." }
    Write-Host "Connected as $($who.Trim())" -ForegroundColor Green

    Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue
    $server = Start-Process python -ArgumentList '-m','uvicorn','backend.api.app:create_app','--factory','--no-proxy-headers' `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
    Start-Sleep -Seconds 5

    & (Join-Path $PSScriptRoot 'smoke_auth.ps1') -ServerLog $log -WaitForCooldown:$WaitForCooldown
    if ($LASTEXITCODE -ne 0) { $smokeFailed = $true }
}
finally {
    if ($server) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
    Remove-Item Env:\ELDORADO_DATABASE_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:\ELDORADO_JWT_SECRET -ErrorAction SilentlyContinue
}

if ($smokeFailed) {
    Write-Host "`n=== server error log (tail, redacted) ===" -ForegroundColor Yellow
    Get-Content "$log.err" -Tail 25 -ErrorAction SilentlyContinue |
        ForEach-Object { $_ -replace 'password\s*=\s*\S+','password=***' -replace '(://[^:/@\s]+:)[^@\s]*@','$1***@' }
}