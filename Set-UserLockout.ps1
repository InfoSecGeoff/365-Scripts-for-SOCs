<#
.SYNOPSIS
    Locks Azure AD user accounts and revokes all active sessions using client credentials from CSV lookup.

.DESCRIPTION
    This script performs emergency user account lockdown operations by:
    1. Looking up Azure app registration credentials from a CSV file based on client name
    2. Authenticating to Microsoft Graph API using client credentials flow
    3. Finding the specified user by email, UPN, or user ID
    4. Revoking all active sign-in sessions for the user
    5. Disabling the user account to prevent new logins
    
    Designed for SOC analysts to quickly respond to security incidents across multiple Azure AD tenants.

.PARAMETER ClientName
    The name of the client as it appears in the "Client" column of the CSV file.
    This is used to look up the corresponding Tenant ID, Client ID, and Client Secret.
    
.PARAMETER UserIdentifier
    The user to be locked. Can be specified as:
    - User Principal Name (UPN): user@domain.com
    - Email address: user@company.com
    - Azure AD User ID (GUID): 12345678-1234-1234-1234-123456789012

.PARAMETER CsvPath
    Full path to the CSV file containing client credentials.
    The CSV must have the following columns:
    - Client: Display name for the client/organization
    - Tenant ID: Azure AD tenant GUID
    - Client ID: Azure app registration client ID
    - Key Value: Client secret value
    - Expiry: Expiration date of the client secret (optional)

.INPUTS
    None. You cannot pipe objects to this script.

.OUTPUTS
    Console output with operation status and results. No objects are returned.

.EXAMPLE
    .\Set-UserLockout.ps1 -ClientName "Contoso Corp" -UserIdentifier "jdoe@contoso.com" -CsvPath "C:\SOC\AzureKeys.csv"
    
    Looks up credentials for "Contoso Corp" from the CSV file and locks the account for jdoe@contoso.com.

.EXAMPLE
    .\Set-UserLockout.ps1 -ClientName "Fabrikam Inc" -UserIdentifier "12345678-1234-1234-1234-123456789012" -CsvPath ".\credentials.csv"
    
    Uses a user ID (GUID) to identify the target user and relative path for the CSV file.

.EXAMPLE
    .\Set-UserLockout.ps1 -ClientName "Invalid Client" -UserIdentifier "user@domain.com" -CsvPath ".\keys.csv"
    
    If the client name doesn't exist, the script will display all available clients from the CSV.

.NOTES
    File Name      : Set-UserLockout.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or higher
    Required Perms : The Azure app registration must have the following Microsoft Graph permissions:
                    - User.ReadWrite.All (to disable accounts)
                    - User.RevokeSessions.All (to revoke sign-in sessions)
                    - User.Read.All (to search for users)
    
    Security Note  : This script performs irreversible account lockdown operations.
                    Always verify the target user before execution.
    
    CSV Format     : Ensure your CSV has these exact column headers:
                    Client,Tenant ID,Client ID,Key Value,Expiry
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ClientName,
    
    [Parameter(Mandatory=$true)]
    [string]$UserIdentifier,
    
    [Parameter(Mandatory=$true)]
    [string]$CsvPath
)


function Get-ClientCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientName
    )
    

    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }
    
    try {
        # Import CSV data
        $csvData = Import-Csv -Path $CsvPath
        
        Write-Host "Successfully loaded CSV with $($csvData.Count) client entries"
        
        # Find the matching client (handle potential whitespace in client names)
        $clientRow = $csvData | Where-Object { 
            ($_.Client -replace '\s+', ' ').Trim() -eq ($ClientName -replace '\s+', ' ').Trim() 
        }
        
        if (-not $clientRow) {
            Write-Warning "Client '$ClientName' not found in CSV file."
            Write-Host "`nAvailable clients:"
            $csvData | ForEach-Object { 
                $cleanClientName = ($_.Client -replace '\s+', ' ').Trim()
                Write-Host "  - $cleanClientName" 
            }
            exit 1
        }
        
        # Get CSV column names
        $tenantIdField = ($clientRow.PSObject.Properties | Where-Object { $_.Name -like "*Tenant*ID*" -or $_.Name -like "*TenantId*" }).Name
        $clientIdField = ($clientRow.PSObject.Properties | Where-Object { $_.Name -like "*Client*ID*" -or $_.Name -like "*ClientId*" }).Name
        $keyValueField = ($clientRow.PSObject.Properties | Where-Object { $_.Name -like "*Key*Value*" -or $_.Name -like "*Secret*" -or $_.Name -like "*Key*" }).Name
        $expiryField = ($clientRow.PSObject.Properties | Where-Object { $_.Name -like "*Expiry*" -or $_.Name -like "*Expiration*" }).Name
        
        # Validate column names
        if (-not $tenantIdField) {
            Write-Error "Could not find Tenant ID column in CSV. Expected column name containing 'Tenant' and 'ID'"
            exit 1
        }
        if (-not $clientIdField) {
            Write-Error "Could not find Client ID column in CSV. Expected column name containing 'Client' and 'ID'"
            exit 1
        }
        if (-not $keyValueField) {
            Write-Error "Could not find Key Value column in CSV. Expected column name containing 'Key' or 'Secret'"
            exit 1
        }
        
        # Get CSV values
        $tenantId = $clientRow.$tenantIdField
        $clientId = $clientRow.$clientIdField
        $keyValue = $clientRow.$keyValueField
        
        if ([string]::IsNullOrWhiteSpace($tenantId)) {
            Write-Error "Missing or empty Tenant ID for client '$ClientName'"
            exit 1
        }
        if ([string]::IsNullOrWhiteSpace($clientId)) {
            Write-Error "Missing or empty Client ID for client '$ClientName'"
            exit 1
        }
        if ([string]::IsNullOrWhiteSpace($keyValue)) {
            Write-Error "Missing or empty Key Value for client '$ClientName'"
            exit 1
        }
        
        # Check certificate expiry if provided
        if ($expiryField -and -not [string]::IsNullOrWhiteSpace($clientRow.$expiryField)) {
            try {
                $expiryDate = [DateTime]::Parse($clientRow.$expiryField)
                if ($expiryDate -lt (Get-Date)) {
                    Write-Warning "Client secret for '$ClientName' expired on $($expiryDate.ToString('yyyy-MM-dd'))"
                } elseif ($expiryDate -lt (Get-Date).AddDays(30)) {
                    Write-Warning "Client secret for '$ClientName' expires soon on $($expiryDate.ToString('yyyy-MM-dd'))"
                }
            }
            catch {
                Write-Warning "Could not parse expiry date for client '$ClientName': $($clientRow.$expiryField)"
            }
        }
        
        Write-Host "Found credentials for client: $ClientName"
        
        return @{
            TenantId = $tenantId.Trim()
            ClientId = $clientId.Trim()
            ClientSecret = $keyValue.Trim()
        }
    }
    catch {
        Write-Error "Failed to process CSV file: $_"
        exit 1
    }
}

function Get-AuthToken {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret
    )
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        client_id     = $ClientId
        scope         = "https://graph.microsoft.com/.default"
        client_secret = $ClientSecret
        grant_type    = "client_credentials"
    }
    
    try {
        Write-Host "Authenticating to Microsoft Graph..."
        $response = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Host "Successfully authenticated to tenant: $TenantId"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to obtain authentication token: $_"
        Write-Error "Please verify the client credentials for tenant: $TenantId"
        exit 1
    }
}

function Get-UserDetails {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Token,
        
        [Parameter(Mandatory=$true)]
        [string]$UserIdentifier
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    # Try to get user by ID first (if the identifier is a valid GUID)
    if ($UserIdentifier -match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$') {
        try {
            $userUrl = "https://graph.microsoft.com/v1.0/users/$UserIdentifier"
            $user = Invoke-RestMethod -Method Get -Uri $userUrl -Headers $headers
            Write-Host "Found user by ID: $($user.displayName) ($($user.userPrincipalName))"
            return $user
        }
        catch {
            Write-Warning "User not found with ID $UserIdentifier. Trying as email/UPN..."
        }
    }
    
    try {
        # Search by userPrincipalName or mail
        $filterUrl = "https://graph.microsoft.com/v1.0/users?`$filter=userPrincipalName eq '$UserIdentifier' or mail eq '$UserIdentifier'"
        $result = Invoke-RestMethod -Method Get -Uri $filterUrl -Headers $headers
        
        if ($result.value.Count -eq 0) {
            Write-Error "No user found with identifier: $UserIdentifier"
            return $null
        }
        elseif ($result.value.Count -gt 1) {
            Write-Warning "Multiple users found with identifier: $UserIdentifier. Using the first match."
            Write-Host "Matched users:"
            $result.value | ForEach-Object { Write-Host "  - $($_.displayName) ($($_.userPrincipalName))" }
        }
        
        $user = $result.value[0]
        Write-Host "Found user: $($user.displayName) ($($user.userPrincipalName))"
        return $user
    }
    catch {
        Write-Error "Error searching for user: $_"
        return $null
    }
}

function Disable-UserAccount {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Token,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    $body = @{
        accountEnabled = $false
    } | ConvertTo-Json
    
    $updateUrl = "https://graph.microsoft.com/v1.0/users/$UserId"
    
    try {
        Invoke-RestMethod -Method Patch -Uri $updateUrl -Headers $headers -Body $body
        Write-Host "✓ User account disabled: $DisplayName (ID: $UserId)" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "✗ Failed to disable user account: $_"
        return $false
    }
}

function Revoke-UserSessions {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Token,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$DisplayName
    )
    
    $headers = @{
        "Authorization" = "Bearer $Token"
        "Content-Type"  = "application/json"
    }
    
    $revokeUrl = "https://graph.microsoft.com/v1.0/users/$UserId/revokeSignInSessions"
    
    try {
        $response = Invoke-RestMethod -Method Post -Uri $revokeUrl -Headers $headers
        Write-Host "✓ All sign-in sessions revoked: $DisplayName (ID: $UserId)" -ForegroundColor Green
        Write-Host "  Note: There may be a delay of a few minutes before sessions are fully revoked" -ForegroundColor Yellow
        return $true
    }
    catch {
        Write-Error "✗ Failed to revoke user sessions: $_"
        return $false
    }
}

# Main
try {
    Write-Host "=== Azure AD User Lockout Script ===" -ForegroundColor Cyan
    Write-Host "Target User: $UserIdentifier"
    Write-Host "Client: $ClientName"
    Write-Host "CSV Path: $CsvPath"
    Write-Host ""
    
    $credentials = Get-ClientCredentials -CsvPath $CsvPath -ClientName $ClientName
    
    $authToken = Get-AuthToken -TenantId $credentials.TenantId -ClientId $credentials.ClientId -ClientSecret $credentials.ClientSecret
    
    Write-Host "Searching for user: $UserIdentifier"
    $user = Get-UserDetails -Token $authToken -UserIdentifier $UserIdentifier
    
    if ($null -eq $user) {
        Write-Error "User not found. Exiting script."
        exit 1
    }
    
    Write-Host ""
    Write-Host "=== EXECUTING LOCKOUT OPERATIONS ===" -ForegroundColor Red
    Write-Host "Target: $($user.displayName) ($($user.userPrincipalName))"
    Write-Host "User ID: $($user.id)"
    Write-Host ""
    
    $sessionsRevoked = Revoke-UserSessions -Token $authToken -UserId $user.id -DisplayName $user.displayName
    $accountDisabled = Disable-UserAccount -Token $authToken -UserId $user.id -DisplayName $user.displayName
    
    Write-Host ""
    Write-Host "=== OPERATION SUMMARY ===" -ForegroundColor Cyan
    if ($sessionsRevoked -and $accountDisabled) {
        Write-Host "✓ All operations completed successfully" -ForegroundColor Green
        Write-Host "User $($user.displayName) has been locked out:" -ForegroundColor Green
        Write-Host "  - Account disabled (cannot sign in)" -ForegroundColor Green
        Write-Host "  - All active sessions revoked" -ForegroundColor Green
    }
    else {
        Write-Warning "Some operations failed:"
        Write-Host "  - Sessions revoked: $(if($sessionsRevoked){'✓'}else{'✗'})"
        Write-Host "  - Account disabled: $(if($accountDisabled){'✓'}else{'✗'})"
        exit 1
    }
}
catch {
    Write-Error "An error occurred during script execution: $_"
    exit 1
}
