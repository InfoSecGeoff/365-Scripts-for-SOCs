<#
.SYNOPSIS
    Checks for and optionally deletes specific suspicious Azure applications across multiple tenants.

.DESCRIPTION
    This script identifies potentially malicious Azure applications (both App Registrations and Enterprise Applications)
    across one or multiple Azure AD tenants. It can operate in read-only mode to generate reports, or in delete mode
    to remove identified applications.
    
    The script supports:
    - Single tenant checking via direct credentials
    - Multi-tenant checking via CSV import
    - Fuzzy matching for client name filtering
    - Detailed reporting with owner and user assignment information
    - Safe deletion with confirmation prompts
    
    Target applications checked: PERFECTDATA SOFTWARE, eM Client, CloudSponge, 
    rClone, Newsletter Software Supermailer, Zoominfo Login, SigParser, Fastmail, PostBox, Spike

.PARAMETER CsvPath
    Path to a CSV file containing tenant credentials. The CSV should have columns:
    'Client', 'Tenant ID', 'Client ID', 'Key Value', 'Expiry'

.PARAMETER TenantId
    Azure AD Tenant ID for single tenant operations.

.PARAMETER ClientId
    Azure AD Application (Client) ID with appropriate permissions.

.PARAMETER AppSecret
    Client secret for the application.

.PARAMETER ClientName
    Filter to a specific client from the CSV file. Supports fuzzy matching.

.PARAMETER DeleteApps
    Switch to enable deletion mode. Will prompt for confirmation unless -Force is used.

.PARAMETER Force
    Skip confirmation prompt when deleting apps. Use with extreme caution.

.EXAMPLE
    .\Get-TenantSusApps.ps1 -TenantId 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' -ClientId 'yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy' -AppSecret 'your-secret'
    
    Checks a single tenant for suspicious applications.

.EXAMPLE
    .\Get-TenantSusApps.ps1 -CsvPath 'C:\Credentials\tenants.csv'
    
    Checks all tenants listed in the CSV file.

.EXAMPLE
    .\Get-TenantSusApps.ps1 -CsvPath 'C:\Credentials\tenants.csv' -ClientName 'Contoso'
    
    Checks only the tenant(s) matching "Contoso" from the CSV file.

.EXAMPLE
    .\Get-TenantSusApps.ps1 -CsvPath 'C:\Credentials\tenants.csv' -DeleteApps
    
    Deletes suspicious apps from all tenants (prompts for confirmation).

.EXAMPLE
    .\Get-TenantSusApps.ps1 -CsvPath 'C:\Credentials\tenants.csv' -DeleteApps -Force
    
    Deletes suspicious apps without confirmation. Use with caution.

.NOTES
    File Name      : Get-TenantSusApps.ps1
    Prerequisite   : Application must have appropriate Microsoft Graph API permissions:
                     - Application.Read.All (or Application.ReadWrite.All for deletion)
                     - Directory.Read.All
#>

# Parameters
param(
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$AppSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientName = $null,
    
    [Parameter(Mandatory=$false)]
    [switch]$DeleteApps,
    
    [Parameter(Mandatory=$false)]
    [switch]$Force
)

# Fuzzy matching
function Test-FuzzyMatch {
    param(
        [string]$SearchTerm,
        [string]$TargetString
    )
    
    # Convert both to lowercase for case-insensitive matching
    $search = $SearchTerm.ToLower().Trim()
    $target = $TargetString.ToLower().Trim()
    
    if ($target -eq $search) {
        return $true
    }
    
    if ($target -like "*$search*") {
        return $true
    }
    
    $commonWords = @('the', 'a', 'an', 'and', 'or', 'but', 'of', 'in', 'on', 'at', 'to', 'for')
    $searchWords = $search -split '\s+' | Where-Object { $_ -notin $commonWords -and $_.Length -gt 0 }
    $targetWords = $target -split '\s+' | Where-Object { $_ -notin $commonWords -and $_.Length -gt 0 }
    
    $allWordsFound = $true
    foreach ($word in $searchWords) {
        $wordFound = $false
        foreach ($targetWord in $targetWords) {
            if ($targetWord -like "*$word*") {
                $wordFound = $true
                break
            }
        }
        if (-not $wordFound) {
            $allWordsFound = $false
            break
        }
    }
    
    return $allWordsFound
}

function Get-MsGraphToken {
    param (
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
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Error obtaining access token: $_"
        throw $_
    }
}

function Get-GraphAppRegistrations {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $apps = @()
    $nextLink = "https://graph.microsoft.com/v1.0/applications?`$top=100"

    try {
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $apps += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)

        return $apps
    }
    catch {
        throw "Error retrieving app registrations: $_"
    }
}

function Get-GraphEnterpriseApplications {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $apps = @()
    $nextLink = "https://graph.microsoft.com/v1.0/servicePrincipals?`$top=100"

    try {
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $apps += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)

        return $apps
    }
    catch {
        throw "Error retrieving enterprise applications: $_"
    }
}

function Remove-AppRegistration {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$ApplicationId,
        
        [Parameter(Mandatory=$true)]
        [string]$AppName
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$ApplicationId" -Method Delete -Headers $headers
        Write-Host "    ✓ Successfully deleted app registration: $AppName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "    ✗ Failed to delete app registration: $AppName - $_" -ForegroundColor Red
        return $false
    }
}

function Remove-EnterpriseApp {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId,
        
        [Parameter(Mandatory=$true)]
        [string]$AppName
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId" -Method Delete -Headers $headers
        Write-Host "    ✓ Successfully deleted enterprise application: $AppName" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "    ✗ Failed to delete enterprise application: $AppName - $_" -ForegroundColor Red
        return $false
    }
}

function Get-AppRegistrationOwners {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$ApplicationId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/applications/$ApplicationId/owners" -Method Get -Headers $headers
        return $response.value
    }
    catch {
        Write-Warning "Could not retrieve owners for app registration $ApplicationId"
        return @()
    }
}

function Get-EnterpriseAppOwners {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/owners" -Method Get -Headers $headers
        return $response.value
    }
    catch {
        Write-Warning "Could not retrieve owners for enterprise app $ServicePrincipalId"
        return @()
    }
}

function Get-EnterpriseAppUsers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$ServicePrincipalId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    $users = @()
    $nextLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalId/appRoleAssignedTo?`$top=100"
    
    try {
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $users += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        return $users
    }
    catch {
        Write-Warning "Could not retrieve user assignments for enterprise app $ServicePrincipalId"
        return @()
    }
}

$clients = @()

if (![string]::IsNullOrWhiteSpace($TenantId) -and 
    ![string]::IsNullOrWhiteSpace($ClientId) -and 
    ![string]::IsNullOrWhiteSpace($AppSecret)) {
    
    $directClient = [PSCustomObject]@{
        'Client' = "Direct Input Client"
        'Tenant ID' = $TenantId
        'Client ID' = $ClientId
        'Key Value' = $AppSecret
        'Expiry' = "N/A"
    }
    
    $clients += $directClient
    Write-Host "Using direct credential input for tenant: $TenantId" -ForegroundColor Green
}
elseif (![string]::IsNullOrWhiteSpace($CsvPath)) {
    try {
        $allClients = Import-Csv -Path $CsvPath
        Write-Host "Successfully imported CSV data with $($allClients.Count) entries" -ForegroundColor Green
        
        # Filter by ClientName if provided
        if (![string]::IsNullOrWhiteSpace($ClientName)) {
            Write-Host "Searching for client: '$ClientName'" -ForegroundColor Cyan
            
            $matchedClient = $null
            foreach ($client in $allClients) {
                if ($null -ne $client.Client -and (Test-FuzzyMatch -SearchTerm $ClientName -TargetString $client.Client)) {
                    $matchedClient = $client
                    Write-Host "  Found match: $($client.Client)" -ForegroundColor Green
                    break
                }
            }
            
            if ($null -eq $matchedClient) {
                Write-Host "No client matched the search term: '$ClientName'" -ForegroundColor Yellow
                Write-Host "Available clients in CSV:" -ForegroundColor Cyan
                $allClients | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Gray }
                exit 0
            }
            
            $clients = @($matchedClient)
        } else {
            $clients = $allClients
        }
    } 
    catch {
        Write-Host "Error importing CSV file: $_" -ForegroundColor Red
        Write-Host "`nUse 'Get-Help .\Get-TenantSusApps.ps1 -Full' for usage information" -ForegroundColor Yellow
        exit 1
    }
}
else {
    Write-Host "Error: You must either provide a CSV file path or individual tenant credentials" -ForegroundColor Red
    Write-Host "`nUse 'Get-Help .\Get-TenantSusApps.ps1 -Full' for usage information" -ForegroundColor Yellow
    exit 1
}

$results = @()
$deletionResults = @()

# Apps to look for
$targetApps = @("PERFECTDATA SOFTWARE", "eM Client", "CloudSponge", "rClone", "Newsletter Software Supermailer", "Zoominfo Login", "SigParser", "Fastmail", "PostBox", "Spike")

function Find-TargetAppsInTenant {
    param(
        [string]$tenantId,
        [string]$clientId,
        [string]$keyValue,
        [string]$clientName,
        [bool]$deleteMode
    )
    
    $localResults = @()
    $localDeletions = @()
    
    try {
        Write-Host "  Authenticating to $clientName tenant..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $keyValue
        
        Write-Host "  Successfully authenticated to $clientName tenant" -ForegroundColor Green
        
        Write-Host "  Retrieving app registrations..." -ForegroundColor Yellow
        $appRegs = Get-GraphAppRegistrations -AccessToken $accessToken
        Write-Host "  Found $($appRegs.Count) app registrations" -ForegroundColor Green
        
        foreach ($app in $appRegs) {
            foreach ($targetApp in $targetApps) {
                if ($app.displayName -like "*$targetApp*") {
                    Write-Host "  Found APP REGISTRATION match: $($app.displayName)" -ForegroundColor Magenta
                    
                    $owners = Get-AppRegistrationOwners -AccessToken $accessToken -ApplicationId $app.id
                    $ownerDetails = @()
                    foreach ($owner in $owners) {
                        if ($owner.displayName) {
                            $ownerDetails += "$($owner.displayName) ($($owner.userPrincipalName))"
                        } else {
                            $ownerDetails += "Unknown (ID: $($owner.id))"
                        }
                    }

                    $resultObj = [PSCustomObject]@{
                        ClientName = $clientName
                        TenantId = $tenantId
                        AppType = "App Registration"
                        AppName = $app.displayName
                        AppId = $app.id
                        ApplicationId = $app.appId
                        CreatedDateTime = $app.createdDateTime
                        Owners = ($ownerDetails -join "; ")
                        OwnerCount = $owners.Count
                        AssignedUsers = "N/A (App Registrations don't have user assignments)"
                        UserCount = "N/A"
                        AppRoles = ($app.appRoles | ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique) -join ", "
                        Deleted = $false
                    }
                    
                    if ($deleteMode) {
                        $deleted = Remove-AppRegistration -AccessToken $accessToken -ApplicationId $app.id -AppName $app.displayName
                        $resultObj.Deleted = $deleted
                        
                        $localDeletions += [PSCustomObject]@{
                            ClientName = $clientName
                            AppType = "App Registration"
                            AppName = $app.displayName
                            Success = $deleted
                        }
                    }
                    
                    $localResults += $resultObj
                    break
                }
            }
        }

        Write-Host "  Retrieving enterprise applications..." -ForegroundColor Yellow
        $enterpriseApps = Get-GraphEnterpriseApplications -AccessToken $accessToken
        Write-Host "  Found $($enterpriseApps.Count) enterprise applications" -ForegroundColor Green
        
        foreach ($app in $enterpriseApps) {
            foreach ($targetApp in $targetApps) {
                if ($app.displayName -like "*$targetApp*") {
                    Write-Host "  Found ENTERPRISE APP match: $($app.displayName)" -ForegroundColor Cyan
                    
                    $owners = Get-EnterpriseAppOwners -AccessToken $accessToken -ServicePrincipalId $app.id
                    $ownerDetails = @()
                    foreach ($owner in $owners) {
                        if ($owner.displayName) {
                            $ownerDetails += "$($owner.displayName) ($($owner.userPrincipalName))"
                        } else {
                            $ownerDetails += "Unknown (ID: $($owner.id))"
                        }
                    }
                    
                    $assignedUsers = Get-EnterpriseAppUsers -AccessToken $accessToken -ServicePrincipalId $app.id
                    $userDetails = @()
                    foreach ($assignment in $assignedUsers) {
                        $principalType = $assignment.principalType
                        $principalName = $assignment.principalDisplayName
                        $userDetails += "$principalName ($principalType)"
                    }
                    
                    $resultObj = [PSCustomObject]@{
                        ClientName = $clientName
                        TenantId = $tenantId
                        AppType = "Enterprise Application"
                        AppName = $app.displayName
                        AppId = $app.id
                        ApplicationId = $app.appId
                        CreatedDateTime = $app.createdDateTime
                        Owners = if ($ownerDetails.Count -gt 0) { ($ownerDetails -join "; ") } else { "No owners" }
                        OwnerCount = $owners.Count
                        AssignedUsers = if ($userDetails.Count -gt 0) { ($userDetails -join "; ") } else { "No user assignments or all users" }
                        UserCount = $assignedUsers.Count
                        AppRoles = ($app.appRoles | ForEach-Object { $_.displayName } | Where-Object { $_ } | Sort-Object -Unique) -join ", "
                        Deleted = $false
                    }
                    
                    if ($deleteMode) {
                        $deleted = Remove-EnterpriseApp -AccessToken $accessToken -ServicePrincipalId $app.id -AppName $app.displayName
                        $resultObj.Deleted = $deleted
                        
                        $localDeletions += [PSCustomObject]@{
                            ClientName = $clientName
                            AppType = "Enterprise Application"
                            AppName = $app.displayName
                            Success = $deleted
                        }
                    }
                    
                    $localResults += $resultObj
                    break
                }
            }
        }
        
    } catch {
        Write-Host "  Error processing $clientName : $_" -ForegroundColor Red
    }
    
    return @{
        Results = $localResults
        Deletions = $localDeletions
    }
}

if ($DeleteApps) {
    Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "║                    ⚠️  DELETE MODE ENABLED  ⚠️                  ║" -ForegroundColor Red
    Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host "This will DELETE the following apps from matching tenants:" -ForegroundColor Yellow
    foreach ($app in $targetApps) {
        Write-Host "  • $app" -ForegroundColor Yellow
    }
    Write-Host "`nClients to process: $($clients.Count)" -ForegroundColor Yellow
    
    if (-not $Force) {
        Write-Host "`nType 'DELETE' to confirm deletion: " -ForegroundColor Red -NoNewline
        $confirmation = Read-Host
        
        if ($confirmation -ne "DELETE") {
            Write-Host "Deletion cancelled. Exiting." -ForegroundColor Yellow
            exit 0
        }
    } else {
        Write-Host "`n-Force flag detected. Skipping confirmation." -ForegroundColor Red
    }
    
    Write-Host "`nProceeding with deletion..." -ForegroundColor Red
}

$totalProcessed = 0
$totalFound = 0
$totalDeleted = 0

foreach ($client in $clients) {
    $clientName = if ($null -ne $client.Client) { $client.Client.Trim() } else { "Unnamed Client" }
    $tenantId = if ($null -ne $client.'Tenant ID') { $client.'Tenant ID'.Trim() } else { $null }
    $clientId = if ($null -ne $client.'Client ID') { $client.'Client ID'.Trim() } else { $null }
    $keyValue = if ($null -ne $client.'Key Value') { $client.'Key Value'.Trim() } else { $null }

    if ([string]::IsNullOrWhiteSpace($tenantId) -or 
        [string]::IsNullOrWhiteSpace($clientId) -or 
        [string]::IsNullOrWhiteSpace($keyValue)) {
        Write-Host "Skipping $clientName - Missing required credential information" -ForegroundColor Yellow
        continue
    }
    
    $totalProcessed++
    Write-Host "`nProcessing $clientName ($totalProcessed of $($clients.Count))..." -ForegroundColor Cyan
    
    # Check the tenant for target apps
    $tenantResults = Find-TargetAppsInTenant -tenantId $tenantId -clientId $clientId -keyValue $keyValue -clientName $clientName -deleteMode $DeleteApps
    $results += $tenantResults.Results
    $deletionResults += $tenantResults.Deletions
    
    $totalFound += $tenantResults.Results.Count
    if ($DeleteApps) {
        $successfulDeletions = ($tenantResults.Deletions | Where-Object { $_.Success }).Count
        $totalDeleted += $successfulDeletions
    }
}

# Generate report
Write-Host "`n╔═══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                      EXECUTION SUMMARY                        ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host "Clients processed: $totalProcessed" -ForegroundColor Yellow
Write-Host "Malicious apps found: $totalFound" -ForegroundColor Yellow

if ($DeleteApps) {
    Write-Host "Apps successfully deleted: $totalDeleted" -ForegroundColor $(if ($totalDeleted -gt 0) { "Green" } else { "Yellow" })
    Write-Host "Apps failed to delete: $($totalFound - $totalDeleted)" -ForegroundColor $(if (($totalFound - $totalDeleted) -gt 0) { "Red" } else { "Yellow" })
}

if ($results.Count -gt 0) {
    Write-Host "`n========= REPORT: FOUND TARGET APPLICATIONS =========" -ForegroundColor Cyan
    
    if ($DeleteApps) {
        $results | Format-Table -AutoSize -Property ClientName, AppType, AppName, OwnerCount, UserCount, Deleted
    } else {
        $results | Format-Table -AutoSize -Property ClientName, AppType, AppName, OwnerCount, UserCount, CreatedDateTime
    }
    
    Write-Host "`nDetailed view:" -ForegroundColor Cyan
    foreach ($result in $results) {
        $statusColor = if ($DeleteApps -and $result.Deleted) { "Green" } elseif ($DeleteApps -and -not $result.Deleted) { "Red" } else { "Yellow" }
        $statusText = if ($DeleteApps) { if ($result.Deleted) { "[DELETED]" } else { "[FAILED TO DELETE]" } } else { "" }
        
        Write-Host "`n--- $($result.AppName) ($($result.AppType)) $statusText ---" -ForegroundColor $statusColor
        Write-Host "  Client: $($result.ClientName)" -ForegroundColor Gray
        Write-Host "  App ID: $($result.AppId)" -ForegroundColor Gray
        Write-Host "  Application ID: $($result.ApplicationId)" -ForegroundColor Gray
        Write-Host "  Created: $($result.CreatedDateTime)" -ForegroundColor Gray
        Write-Host "  Owners ($($result.OwnerCount)): $($result.Owners)" -ForegroundColor Gray
        Write-Host "  Assigned Users/Groups ($($result.UserCount)): $($result.AssignedUsers)" -ForegroundColor Gray
        if ($result.AppRoles) {
            Write-Host "  App Roles: $($result.AppRoles)" -ForegroundColor Gray
        }
    }
    
    # Export results to CSV
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPath = "AzureAppReport_$timestamp.csv"
    $results | Export-Csv -Path $outputPath -NoTypeInformation
    Write-Host "`nDetailed report exported to: $outputPath" -ForegroundColor Green
    
    if ($DeleteApps -and $deletionResults.Count -gt 0) {
        $deletionOutputPath = "AzureAppDeletions_$timestamp.csv"
        $deletionResults | Export-Csv -Path $deletionOutputPath -NoTypeInformation
        Write-Host "Deletion report exported to: $deletionOutputPath" -ForegroundColor Green
    }
} else {
    Write-Host "`nNo matching applications found across all tenants." -ForegroundColor Yellow
}
