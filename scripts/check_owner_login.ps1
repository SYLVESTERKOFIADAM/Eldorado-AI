$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
if (-not $env:VIRTUAL_ENV) { throw 'Activate the venv first: .\.venv\Scripts\Activate.ps1' }

function ConvertTo-Plain([System.Security.SecureString]$Secure) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

$bytes = New-Object byte[] 48
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$env:ELDORADO_JWT_SECRET = [Convert]::ToBase64String($bytes)

# The eldorado_app password comes from pgpass.conf (libpq), so it is never typed
# and never placed in the connection string.
$pgpass = Join-Path $env:APPDATA 'postgresql\pgpass.conf'
if (-not (Test-Path $pgpass) -or -not (Select-String -Path $pgpass -Pattern '^localhost:5432:postgres:eldorado_app:' -Quiet)) {
    throw "No eldorado_app entry for localhost:5432:postgres in $pgpass."
}
$env:ELDORADO_DATABASE_DSN = 'host=localhost port=5432 dbname=postgres user=eldorado_app'

$log = Join-Path $env:TEMP 'eldorado-server.log'
$server = $null

try {
    $who = python -c "import os,psycopg; c=psycopg.connect(os.environ['ELDORADO_DATABASE_DSN']); print(c.execute('select current_user').fetchone()[0])"
    if ($LASTEXITCODE -ne 0) { throw 'Could not connect as eldorado_app.' }
    if ($who.Trim() -ne 'eldorado_app') { throw "Connected as '$who', expected eldorado_app." }

    Remove-Item $log, "$log.err" -ErrorAction SilentlyContinue
    $server = Start-Process python -ArgumentList '-m','uvicorn','backend.api.app:create_app','--factory','--no-proxy-headers' `
        -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow

    $up = $false
    for ($i = 0; $i -lt 30 -and -not $up; $i++) {
        try {
            $client = New-Object Net.Sockets.TcpClient
            $client.Connect('127.0.0.1', 8000)
            $client.Close()
            $up = $true
        } catch { Start-Sleep -Milliseconds 500 }
    }
    if (-not $up) { throw 'Server did not start. See the log tail below.' }

    $email = Read-Host 'Owner email'
    $ownerPassword = ConvertTo-Plain (Read-Host 'Owner password (hidden)' -AsSecureString)
    $body = @{ email = $email; password = $ownerPassword } | ConvertTo-Json

    try {
        $r = Invoke-RestMethod -Uri 'http://127.0.0.1:8000/auth/login' -Method Post -ContentType 'application/json' -Body $body
        Write-Host ("OK  login succeeded: token_type={0}, expires_in={1}, refresh_token_present={2}" -f $r.token_type, $r.expires_in, [bool]$r.refresh_token) -ForegroundColor Green
    }
    catch {
        $code = $null
        if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
        Write-Host "FAIL  login returned HTTP $code" -ForegroundColor Red
        if ($code -eq 401) { Write-Host 'Wrong email or password, or the owner account was not created or verified.' }
        exit 1
    }
}
finally {
    if ($server) { Stop-Process -Id $server.Id -ErrorAction SilentlyContinue }
    Remove-Item Env:\ELDORADO_DATABASE_DSN -ErrorAction SilentlyContinue
    Remove-Item Env:\ELDORADO_JWT_SECRET -ErrorAction SilentlyContinue
    $ownerPassword = $null
    if (Test-Path "$log.err") {
        Write-Host "`n=== server error log (tail, redacted) ===" -ForegroundColor Yellow
        Get-Content "$log.err" -Tail 8 |
            ForEach-Object { $_ -replace 'password\s*=\s*\S+','password=***' -replace '(://[^:/@\s]+:)[^@\s]*@','$1***@' }
    }
}