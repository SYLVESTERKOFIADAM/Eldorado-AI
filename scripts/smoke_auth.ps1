param(
    [string]$Base = "http://127.0.0.1:8000",
    [Parameter(Mandatory = $true)][string]$ServerLog,
    [switch]$WaitForCooldown
)

$email = "dev-smoke-$(Get-Random)@example.com"
$password = "smoke-" + [guid]::NewGuid().ToString("N")

function Call-Api($path, $body, $headers = @{}) {
    try {
        $r = Invoke-WebRequest -Uri "$Base$path" -Method Post -Headers $headers -ContentType "application/json" -Body ($body | ConvertTo-Json) -UseBasicParsing
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
function Get-LoggedToken($address, $logPath, $marker, $exclude) {
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-Path $logPath) {
            $line = Get-Content $logPath | Where-Object { $_ -like "*$marker*$address*" } | Select-Object -Last 1
            if ($line -and $line -match '#token=([A-Za-z0-9_-]+)') {
                if (-not $exclude -or $Matches[1] -ne $exclude) { return $Matches[1] }
            }
        }
        Start-Sleep -Milliseconds 500
    }
    return $null
}
$r = Call-Api "/auth/register" @{ email = $email; password = $password }
Check "register" $r.Status 202

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "login before verification" $r.Status 401

$firstToken = Get-LoggedToken $email $ServerLog "Verification email for" $null
if (-not $firstToken) { Write-Host "FAIL  no verification token found in $ServerLog" -ForegroundColor Red; exit 1 }

$r = Call-Api "/auth/resend-verification" @{ email = "dev-smoke-unknown-$(Get-Random)@example.com" }
Check "resend-verification (unknown address, same response)" $r.Status 202

$r = Call-Api "/auth/resend-verification" @{ email = $email }
Check "resend-verification inside 60s cooldown (accepted)" $r.Status 202

Start-Sleep -Seconds 3
$emailCount = @(Get-Content $ServerLog | Where-Object { $_ -like "*Verification email for*$email*" }).Count
Check "no extra email sent inside cooldown" $emailCount 1

if ($WaitForCooldown) {
    Write-Host "Waiting 65s for the resend cooldown..." -ForegroundColor Yellow
    Start-Sleep -Seconds 65

    $r = Call-Api "/auth/resend-verification" @{ email = $email }
    Check "resend-verification after cooldown" $r.Status 202

    $resentToken = Get-LoggedToken $email $ServerLog "Verification email for" $firstToken
    if (-not $resentToken) { Write-Host "FAIL  no new verification token after the cooldown" -ForegroundColor Red; exit 1 }
    Check "resend after cooldown delivered a new token" ($resentToken -ne $firstToken) $true

    $r = Call-Api "/auth/verify-email" @{ token = $firstToken }
    Check "superseded verification token is rejected" $r.Status 400
}
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
Write-Host "-- password change and reset --"
$changedPassword = "smoke-chg-" + [guid]::NewGuid().ToString("N")
$resetPassword = "smoke-rst-" + [guid]::NewGuid().ToString("N")

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "login for password change" $r.Status 200
$access = $r.Body.access_token
$preChangeRefresh = $r.Body.refresh_token
$auth = @{ Authorization = "Bearer $access" }

$r = Call-Api "/auth/change-password" @{ current_password = ("wrong-" + [guid]::NewGuid().ToString("N")); new_password = $changedPassword } $auth
Check "change-password with wrong current password" $r.Status 400

$r = Call-Api "/auth/change-password" @{ current_password = $password; new_password = $changedPassword } $auth
Check "change-password" $r.Status 200

$r = Call-Api "/auth/refresh" @{ refresh_token = $preChangeRefresh }
Check "refresh after password change (sessions revoked)" $r.Status 401

$r = Call-Api "/auth/login" @{ email = $email; password = $password }
Check "login with old password after change" $r.Status 401

$r = Call-Api "/auth/login" @{ email = $email; password = $changedPassword }
Check "login with changed password" $r.Status 200

$r = Call-Api "/auth/forgot-password" @{ email = "dev-smoke-unknown-$(Get-Random)@example.com" }
Check "forgot-password (unknown address, same response)" $r.Status 202

$r = Call-Api "/auth/forgot-password" @{ email = $email }
Check "forgot-password (known address)" $r.Status 202

$resetToken = Get-LoggedToken $email $ServerLog "Password reset email for" $null
if (-not $resetToken) { Write-Host "FAIL  no password reset token found in $ServerLog" -ForegroundColor Red; exit 1 }
Check "reset token found in server log" ([bool]$resetToken) $true

$r = Call-Api "/auth/reset-password" @{ token = "never-issued-token"; new_password = $resetPassword }
Check "reset-password with garbage token" $r.Status 400

$r = Call-Api "/auth/reset-password" @{ token = $resetToken; new_password = $resetPassword }
Check "reset-password" $r.Status 200

$r = Call-Api "/auth/reset-password" @{ token = $resetToken; new_password = $resetPassword }
Check "reset token cannot be reused" $r.Status 400

$r = Call-Api "/auth/login" @{ email = $email; password = $changedPassword }
Check "login with pre-reset password" $r.Status 401

$r = Call-Api "/auth/login" @{ email = $email; password = $resetPassword }
Check "login with reset password" $r.Status 200
Write-Host ""
Write-Host "ALL CHECKS PASSED. Smoke account: $email" -ForegroundColor Green