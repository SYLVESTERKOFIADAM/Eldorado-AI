param(
    [string]$Base = "http://127.0.0.1:8000",
    [Parameter(Mandatory = $true)][string]$ServerLog
)

$email = "dev-smoke-$(Get-Random)@example.com"
$password = "smoke-" + [guid]::NewGuid().ToString("N")

function Call-Api($path, $body) {
    try {
        $r = Invoke-WebRequest -Uri "$Base$path" -Method Post -ContentType "application/json" -Body ($body | ConvertTo-Json) -UseBasicParsing
        $parsed = $null
        if ($r.Content) { $parsed = $r.Content | ConvertFrom-Json }
        return @{ Status = [int]$r.StatusCode; Body = $parsed }
    } catch {
        if ($_.Exception.Response) { return @{ Status = [int]$_.Exception.Response.StatusCode; Body = $null } }
        throw
    }
}
function Check($label, $got, $want) {
    if ($got -eq $want) {
        Write-Host ("OK    {0}: {1}" -f $label, $got) -ForegroundColor Green
    } else {
        Write-Host ("FAIL  {0}: got {1}, wanted {2}" -f $label, $got, $want) -ForegroundColor Red
        Write-Host "Stopping at the first failure." -ForegroundColor Red
        exit 1
    }
}

function Get-VerificationToken($address, $logPath) {
    for ($i = 0; $i -lt 20; $i++) {
        if (Test-Path $logPath) {
            $line = Get-Content $logPath | Where-Object { $_ -like "*$address*" } | Select-Object -Last 1
            if ($line -and $line -match '#token=([A-Za-z0-9_-]{43})') { return $Matches[1] }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}
$r = Call-Api "/auth/register" @{ email = $email; password = $password }
Check "register" $r.Status 202

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "login before verification" $r.Status 401

$token = Get-VerificationToken $email $ServerLog
if (-not $token) { Write-Host "FAIL  no verification token found in $ServerLog" -ForegroundColor Red; exit 1 }
Check "verification token found in server log" $token.Length 43

$r = Call-Api "/auth/verify-email" @{ token = $token }
Check "verify-email" $r.Status 200

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "login after verification" $r.Status 200
$first = $r.Body
Check "login returned a refresh token" ([bool]$first.refresh_token) $true
$r = Call-Api "/auth/refresh" @{ refresh_token = $first.refresh_token }
Check "refresh" $r.Status 200
$second = $r.Body
Check "refresh returned a refresh token" ([bool]$second.refresh_token) $true
Check "refresh token rotated" ($second.refresh_token -ne $first.refresh_token) $true

$r = Call-Api "/auth/refresh" @{ refresh_token = $first.refresh_token }
Check "replay of old refresh token" $r.Status 401

$r = Call-Api "/auth/refresh" @{ refresh_token = $second.refresh_token }
Check "successor after replay (family revoked)" $r.Status 401

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "fresh login" $r.Status 200
$third = $r.Body
Check "fresh login returned a refresh token" ([bool]$third.refresh_token) $true
$r = Call-Api "/auth/logout" @{ refresh_token = $third.refresh_token }
Check "logout" $r.Status 204

$r = Call-Api "/auth/logout" @{ refresh_token = $third.refresh_token }
Check "logout again (idempotent)" $r.Status 204

$r = Call-Api "/auth/refresh" @{ refresh_token = $third.refresh_token }
Check "refresh after logout" $r.Status 401

$r = Call-Api "/auth/refresh" @{ refresh_token = "never-issued-token" }
Check "garbage refresh token" $r.Status 401

Write-Host ""
Write-Host "ALL CHECKS PASSED. Smoke account: $email" -ForegroundColor Green