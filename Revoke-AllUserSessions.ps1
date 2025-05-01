# Revoke All User Sessions in Microsoft 365

$requiredModules = @(
    "ExchangeOnlineManagement",
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Users"
)

foreach ($module in $requiredModules) {
    if (!(Get-Module -ListAvailable -Name $module)) {
        Write-Host "Installing $module module..." -ForegroundColor Yellow
        Install-Module -Name $module -Force -Scope CurrentUser
    }
    Import-Module $module -ErrorAction Stop
}


$logFile = "RevokeSessions_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
"Session revocation started at $(Get-Date)" | Out-File $logFile


try {
    Connect-ExchangeOnline -ShowBanner:$false
    Connect-MgGraph -Scopes "User.ReadWrite.All" -UseDeviceAuthentication
}
catch {
    Write-Host "Failed to connect: $($_.Exception.Message)" -ForegroundColor Red
    "ERROR: Failed to connect: $($_.Exception.Message)" | Out-File $logFile -Append
    exit
}

try {
    $users = Get-User -ResultSize Unlimited
    $totalUsers = $users.Count
    Write-Host "Found $totalUsers users." -ForegroundColor Green
    "Total users found: $totalUsers" | Out-File $logFile -Append
}
catch {
    Write-Host "Failed to retrieve users: $($_.Exception.Message)" -ForegroundColor Red
    "ERROR: Failed to retrieve users: $($_.Exception.Message)" | Out-File $logFile -Append
    exit
}

# Counters
$processedUsers = 0
$successCount = 0
$failCount = 0

foreach ($user in $users) {
    $processedUsers++
    $percentage = [math]::Round(($processedUsers / $totalUsers) * 100, 2)
    
    Write-Progress -Activity "Revoking Sessions" -Status "Processing $($user.UserPrincipalName)" -PercentComplete $percentage
    
    if ($user.RecipientTypeDetails -like "*Mailbox" -and $user.RecipientTypeDetails -notlike "*System*" -and $user.RecipientTypeDetails -notlike "*Resource*") {
        try {
            $mgUser = Get-MgUser -Filter "UserPrincipalName eq '$($user.UserPrincipalName)'" -ErrorAction Stop
            
            if ($mgUser) {
                Revoke-MgUserSignInSession -UserId $mgUser.Id -ErrorAction Stop
                "SUCCESS: Revoked sessions for $($user.UserPrincipalName)" | Out-File $logFile -Append
                Write-Host "Revoked sessions for $($user.UserPrincipalName)" -ForegroundColor Green
                $successCount++
            }
            else {
                "WARNING: User not found in Graph: $($user.UserPrincipalName)" | Out-File $logFile -Append
                Write-Host "User not found in Graph: $($user.UserPrincipalName)" -ForegroundColor Yellow
                $failCount++
            }
        }
        catch {
            "ERROR: Failed to revoke sessions for $($user.UserPrincipalName). Error: $($_.Exception.Message)" | Out-File $logFile -Append
            Write-Host "Failed to revoke sessions for $($user.UserPrincipalName): $($_.Exception.Message)" -ForegroundColor Red
            $failCount++
        }
    }
}

Write-Host "`nGlobal session revocation complete!" -ForegroundColor Cyan
Write-Host "Total users processed: $totalUsers" -ForegroundColor White
Write-Host "Successfully revoked: $successCount" -ForegroundColor Green
Write-Host "Failed to revoke: $failCount" -ForegroundColor Red
Write-Host "Log: $($logFile)" -ForegroundColor Yellow

"Session revocation completed at $(Get-Date)" | Out-File $logFile -Append
"Total users processed: $totalUsers" | Out-File $logFile -Append
"Successfully revoked: $successCount" | Out-File $logFile -Append
"Failed to revoke: $failCount" | Out-File $logFile -Append

Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
Disconnect-MgGraph -ErrorAction SilentlyContinue
