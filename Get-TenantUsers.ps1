<#
.SYNOPSIS
    Generates comprehensive user inventory reports from Azure AD/Entra ID tenants using Microsoft Graph API.

.DESCRIPTION
    This script connects to Microsoft Graph API headlessly using application credentials to enumerate all users within specified Azure AD/Entra ID tenant(s). 
    It retrieves detailed user information including account status, administrative roles, licensing, group memberships, and authentication activity. Instead of PowerShell modules it uses raw Graph API calls which increases reliability.
    
    The script can process either a single tenant or multiple tenants from a CSV file, generating both summary and detailed reports 
    in CSV format as well as interactive HTML reports with tabbed sections for different user categories.

    Key features:
    - Enumerates all user types (Regular Users, Administrators, Guest Users)
    - Identifies Global Administrators and other privileged roles
    - Retrieves licensing information and usage statistics
    - Tracks sign-in activity and account status
    - Optional group membership enumeration
    - Supports batch processing of multiple tenants
    - Generates interactive HTML reports with filtering capabilities
    - Provides security-focused analytics and recommendations
    - Robust error handling with detailed failure reporting

.PARAMETER TenantId
    The Azure AD/Entra ID Tenant ID (GUID format) for single tenant processing.
    Required when not using CSV file input.
    
    Example: "12345678-1234-1234-1234-123456789abc"

.PARAMETER ClientId
    The Application (Client) ID of the registered Azure AD application with appropriate Microsoft Graph permissions.
    Required when not using CSV file input.
    
    Example: "87654321-4321-4321-4321-abcdef123456"

.PARAMETER ClientSecret
    The client secret (application password) for the registered Azure AD application.
    Required when not using CSV file input.
    
    Note: Ensure this value is kept secure and consider using Azure Key Vault or other secure storage methods.

.PARAMETER CsvPath
    Path to a CSV file containing multiple client tenant information for batch processing.
    When specified, individual credential parameters are ignored.
    
    Required CSV columns:
    - Client: Display name for the tenant/organization
    - Tenant ID: Azure AD Tenant ID
    - Client ID: Application ID with Graph permissions  
    - Key Value: Client secret for the application
    
    Example: "C:\Scripts\client-credentials.csv"

.PARAMETER ClientName
    When using CSV input, specifies a specific client to process instead of all clients in the CSV.
    Must match the value in the "Client" column exactly.
    
    Example: "Contoso Corporation"

.PARAMETER IncludeAllProperties
    Retrieves all available user properties from Microsoft Graph instead of the default subset.
    This provides more comprehensive user information but may impact performance for large tenants.
    
    Default behavior retrieves: id, userPrincipalName, displayName, mail, givenName, surname, 
    jobTitle, accountEnabled, userType, createdDateTime, signInActivity, assignedLicenses, onPremisesSyncEnabled

.PARAMETER IncludeGroupMemberships
    Retrieves group membership information for each user account.
    This provides detailed group membership data but significantly increases processing time for large tenants.
    
    Note: Requires Group.Read.All permission, adds substantial processing overhead.

.OUTPUTS
    For single tenant:
    - UserInventory-[ClientName]-[timestamp].html: Interactive HTML report with tabbed sections
    - Users-[ClientName]-[timestamp].csv: Detailed user data export
    
    For multiple tenants:
    - UserInventory-Report-[timestamp]/ folder containing:
      - Individual tenant HTML and CSV reports
      - UserInventory-AllTenants-[timestamp].csv: Consolidated summary
      - MasterUserInventory-[timestamp].html: Multi-tenant dashboard

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Internet connectivity to Microsoft Graph API endpoints
    - Required Graph API Permissions:
      - User.Read.All (Application permission)
      - Directory.Read.All (Application permission)
      - RoleManagement.Read.Directory (Application permission)
      - Organization.Read.All (Application permission)
      - Group.Read.All (Application permission) - if using IncludeGroupMemberships
      
    Security Considerations:
    - Client secrets should be stored securely
    - Application should use least-privilege permissions
    - Consider using certificate-based authentication for production
    - Audit application access regularly
    - Review Global Administrator accounts regularly (Microsoft recommends 2-4 per tenant)
    
    Performance Notes:
    - Large tenants may take significant time to process
    - IncludeGroupMemberships parameter adds substantial processing overhead
    
    Security Analytics:
    - Identifies excessive Global Administrator accounts
    - Highlights guest user accounts requiring review
    - Reports on disabled accounts with active licenses
    - Tracks last sign-in activity for admin accounts
    - Provides license utilization statistics

.EXAMPLE
    .\Get-UserInventory.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret"
    
    Processes a single tenant and generates individual user inventory reports.

.EXAMPLE
    .\Get-UserInventory.ps1 -CsvPath "C:\Scripts\clients.csv"
    
    Processes all tenants listed in the CSV file and generates consolidated user inventory reports.

.EXAMPLE
    .\Get-UserInventory.ps1 -CsvPath "C:\Scripts\clients.csv" -ClientName "Contoso Corporation"
    
    Processes only the "Contoso Corporation" tenant from the CSV file.

.EXAMPLE
    .\Get-UserInventory.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret" -IncludeAllProperties -IncludeGroupMemberships
    
    Processes a single tenant with comprehensive user properties and group membership data.

.EXAMPLE
    .\Get-UserInventory.ps1 -CsvPath "C:\Scripts\clients.csv" -ClientName "Contoso" -IncludeAllProperties
    
    Processes a specific tenant from CSV with extended user properties but without group memberships for faster processing.
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientName,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAllProperties,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeGroupMemberships
)

# Validate parameter combo
if (-not $CsvPath -and (-not $TenantId -or -not $ClientId -or -not $ClientSecret)) {
    Write-Host "Error: You must provide either:" -ForegroundColor Red
    Write-Host "  1. Individual parameters: -TenantId, -ClientId, and -ClientSecret" -ForegroundColor Yellow
    Write-Host "  2. CSV file with -CsvPath (optionally with -ClientName for specific client)" -ForegroundColor Yellow
    Write-Host "`nExample usage:" -ForegroundColor Cyan
    Write-Host "  # Single tenant" -ForegroundColor Gray
    Write-Host "  .\script.ps1 -TenantId 'xxx' -ClientId 'xxx' -ClientSecret 'xxx'" -ForegroundColor Gray
    Write-Host "  # All tenants from CSV" -ForegroundColor Gray
    Write-Host "  .\script.ps1 -CsvPath 'clients.csv'" -ForegroundColor Gray
    Write-Host "  # Specific client from CSV" -ForegroundColor Gray
    Write-Host "  .\script.ps1 -CsvPath 'clients.csv' -ClientName 'Client1'" -ForegroundColor Gray
    exit 1
}

if ($CsvPath -and (-not (Test-Path $CsvPath))) {
    Write-Host "Error: CSV file not found at path: $CsvPath" -ForegroundColor Red
    exit 1
}

function Import-ClientCsv {
    param (
        [string]$Path
    )
    
    try {
        $clients = Import-Csv -Path $Path
        
        # Validate required columns
        $requiredColumns = @('Client', 'Tenant ID', 'Client ID', 'Key Value')
        $csvColumns = $clients[0].PSObject.Properties.Name
        
        foreach ($requiredColumn in $requiredColumns) {
            if ($requiredColumn -notin $csvColumns) {
                throw "Missing required column: '$requiredColumn'. Required columns: $($requiredColumns -join ', ')"
            }
        }
        
        Write-Host "Successfully loaded $($clients.Count) clients from CSV" -ForegroundColor Green
        return $clients
    }
    catch {
        Write-Host "Error loading CSV file: $_" -ForegroundColor Red
        throw
    }
}

function Get-ClientFromCsv {
    param (
        [array]$Clients,
        [string]$ClientName
    )
    
    $client = $Clients | Where-Object { $_.Client -eq $ClientName }
    
    if (-not $client) {
        Write-Host "Client '$ClientName' not found in CSV. Available clients:" -ForegroundColor Red
        $Clients | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Yellow }
        throw "Client not found"
    }
    
    return $client
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

function Get-TenantBasicInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [string]$TenantId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $domainUri = "https://graph.microsoft.com/v1.0/domains"
        $domainsResponse = Invoke-RestMethod -Uri $domainUri -Method Get -Headers $headers
        
        $initialDomain = ($domainsResponse.value | Where-Object { $_.isInitial -eq $true }).id

        if (-not $initialDomain) {
            $initialDomain = "unknown.onmicrosoft.com"
        }
        
        $displayName = "Unknown"
        try {
            $orgUri = "https://graph.microsoft.com/v1.0/organization"
            $orgResponse = Invoke-RestMethod -Uri $orgUri -Method Get -Headers $headers
            $displayName = $orgResponse.value[0].displayName
        }
        catch {
            Write-Verbose "Could not retrieve organization display name: $_"
            if ($TenantId) {
                $displayName = "Tenant $TenantId"
            }
        }
        
        return [PSCustomObject]@{
            TenantId = $TenantId
            DisplayName = $displayName
            InitialDomain = $initialDomain
            VerifiedDomains = ($domainsResponse.value | ForEach-Object { $_.id }) -join ", "
        }
    }
    catch {
        Write-Warning "Error retrieving tenant information: $_"
        # Return minimal info 
        return [PSCustomObject]@{
            TenantId = $TenantId
            DisplayName = "Unknown"
            InitialDomain = "unknown.onmicrosoft.com"
            VerifiedDomains = ""
        }
    }
}

function Get-TenantUsers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAllProperties
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "ConsistencyLevel" = "eventual"
    }
    
    try {
        $select = "id,userPrincipalName,displayName,mail,givenName,surname,jobTitle,accountEnabled,userType,createdDateTime,signInActivity,assignedLicenses,onPremisesSyncEnabled"
        
        if ($IncludeAllProperties) {
            $select = "*"
        }
        
        $users = @()
        $nextLink = "https://graph.microsoft.com/v1.0/users?`$select=$select&`$top=100"
        $batchCounter = 0
        
        do {
            $batchCounter++
            Write-Progress -Activity "Retrieving Users" -Status "Batch $batchCounter" -Id 1
            
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $users += $response.value
            $nextLink = $response.'@odata.nextLink'
            
            Write-Host "Retrieved batch $batchCounter - Added $($response.value.Count) users (Total: $($users.Count))" -ForegroundColor Cyan
            
            # Small delay to avoid throttling
            if ($nextLink) {
                Start-Sleep -Milliseconds 100
            }
        } while ($nextLink)
        
        Write-Progress -Activity "Retrieving Users" -Id 1 -Completed
        
        return $users
    }
    catch {
        Write-Error "Error retrieving users: $_"
        throw $_
    }
}

function Get-TenantRoles {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $roles = @()
        $nextLink = "https://graph.microsoft.com/v1.0/directoryRoles?`$expand=members"
        
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $roles += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        return $roles
    }
    catch {
        Write-Error "Error retrieving directory roles: $_"
        throw $_
    }
}

function Get-TenantLicenses {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        # Get SKUs
        $licensesUri = "https://graph.microsoft.com/v1.0/subscribedSkus"
        $response = Invoke-RestMethod -Uri $licensesUri -Method Get -Headers $headers
        
        return $response.value
    }
    catch {
        Write-Error "Error retrieving license information: $_"
        throw $_
    }
}

function Get-UserGroupMemberships {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        # Get group membership
        $memberOfUri = "https://graph.microsoft.com/v1.0/users/$UserId/memberOf"
        $response = Invoke-RestMethod -Uri $memberOfUri -Method Get -Headers $headers
        
        # Filter to just security groups and mail-enabled security groups
        $groups = $response.value | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' }
        
        return $groups
    }
    catch {
        Write-Warning "Error retrieving group memberships for user $UserId`: $_"
        return @()
    }
}

function Format-UserData {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Users,
        
        [Parameter(Mandatory=$true)]
        [array]$Roles,
        
        [Parameter(Mandatory=$true)]
        [array]$Licenses,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeGroupMemberships,
        
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    # License lookups
    $licenseLookup = @{}
    foreach ($license in $Licenses) {
        $licenseLookup[$license.skuId] = @{
            SkuPartNumber = $license.skuPartNumber
            ConsumedUnits = $license.consumedUnits
            AvailableUnits = $license.prepaidUnits.enabled - $license.consumedUnits
        }
    }
    
    $adminRolesLookup = @{}
    
    # Process Global Admin roles
    $globalAdminRole = $Roles | Where-Object { $_.displayName -eq "Global Administrator" -or $_.displayName -eq "Company Administrator" }
    if ($globalAdminRole) {
        foreach ($member in $globalAdminRole.members) {
            if (-not $adminRolesLookup.ContainsKey($member.id)) {
                $adminRolesLookup[$member.id] = @()
            }
            $adminRolesLookup[$member.id] += "Global Administrator"
        }
    }
    
    foreach ($role in $Roles) {
        if ($role.displayName -eq "Global Administrator" -or $role.displayName -eq "Company Administrator") {
            continue  # Already processed
        }
        
        foreach ($member in $role.members) {
            if (-not $adminRolesLookup.ContainsKey($member.id)) {
                $adminRolesLookup[$member.id] = @()
            }
            $adminRolesLookup[$member.id] += $role.displayName
        }
    }
    
    $formattedUsers = @()
    $totalUsers = $Users.Count
    $currentUser = 0
    
    foreach ($user in $Users) {
        $currentUser++
        Write-Progress -Activity "Processing User Data" -Status "User $currentUser of $totalUsers" -PercentComplete (($currentUser / $totalUsers) * 100)
        
        # Get user roles
        $userRoles = if ($adminRolesLookup.ContainsKey($user.id)) { $adminRolesLookup[$user.id] -join ", " } else { "None" }
        
        # Get user licenses
        $userLicenses = @()
        foreach ($license in $user.assignedLicenses) {
            if ($licenseLookup.ContainsKey($license.skuId)) {
                $userLicenses += $licenseLookup[$license.skuId].SkuPartNumber
            }
            else {
                $userLicenses += $license.skuId
            }
        }
        
        # Get last sign-in time
        $lastSignIn = if ($user.signInActivity.lastSignInDateTime) { $user.signInActivity.lastSignInDateTime } else { "Never" }
        
        # Get group memberships
        $groupMemberships = @()
        if ($IncludeGroupMemberships) {
            $groups = Get-UserGroupMemberships -AccessToken $AccessToken -UserId $user.id
            $groupMemberships = ($groups | Select-Object -ExpandProperty displayName) -join ", "
        }
        
        # Determine user category
        $userCategory = "Regular"
        if ($userRoles -like "*Global Administrator*") {
            $userCategory = "Global Admin"
        }
        elseif ($userRoles -ne "None") {
            $userCategory = "Admin"
        }
        elseif ($user.userType -eq "Guest") {
            $userCategory = "Guest"
        }
        
        $formattedUser = [PSCustomObject]@{
            UserPrincipalName = $user.userPrincipalName
            DisplayName = $user.displayName
            FirstName = $user.givenName
            LastName = $user.surname
            JobTitle = $user.jobTitle
            Mail = $user.mail
            UserType = $user.userType
            AccountEnabled = $user.accountEnabled
            CreatedDate = $user.createdDateTime
            LastSignIn = $lastSignIn
            AdminRoles = $userRoles
            Category = $userCategory
            Licenses = $userLicenses -join ", "
            LicenseCount = $user.assignedLicenses.Count
            IsOnPremisesSynced = $user.onPremisesSyncEnabled
            Groups = $groupMemberships
            UserId = $user.id
        }
        
        $formattedUsers += $formattedUser
    }
    
    Write-Progress -Activity "Processing User Data" -Completed
    
    return $formattedUsers
}

function Get-UserInventoryHtml {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantName,
        
        [Parameter(Mandatory=$true)]
        [string]$TenantDomain,
        
        [Parameter(Mandatory=$true)]
        [array]$FormattedUsers
    )

    $totalUsers = $FormattedUsers.Count
    $globalAdmins = ($FormattedUsers | Where-Object { $_.Category -eq "Global Admin" }).Count
    $otherAdmins = ($FormattedUsers | Where-Object { $_.Category -eq "Admin" }).Count
    $guestUsers = ($FormattedUsers | Where-Object { $_.UserType -eq "Guest" }).Count
    $disabledUsers = ($FormattedUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
    $licensedUsers = ($FormattedUsers | Where-Object { $_.LicenseCount -gt 0 }).Count
    $onPremUsers = ($FormattedUsers | Where-Object { $_.IsOnPremisesSynced -eq $true }).Count

    $guestPercentage = [math]::Round(($guestUsers / $totalUsers) * 100, 2)
    $disabledPercentage = [math]::Round(($disabledUsers / $totalUsers) * 100, 2)
    $properAccountsCount = ($FormattedUsers | Where-Object { $_.AccountEnabled -eq $true -and $_.UserType -ne "Guest" -and $_.LicenseCount -gt 0 }).Count
    $properAccountsPercentage = [math]::Round(($properAccountsCount / $totalUsers) * 100, 2)

    $licenseDistribution = @{}
    foreach ($user in $FormattedUsers) {
        if ($user.Licenses) {
            $licenses = $user.Licenses -split ", "
            foreach ($license in $licenses) {
                if (-not $licenseDistribution.ContainsKey($license)) {
                    $licenseDistribution[$license] = 0
                }
                $licenseDistribution[$license]++
            }
        }
    }
    
    $topLicenses = $licenseDistribution.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 5

    $globalAdminRows = ""
    foreach ($user in ($FormattedUsers | Where-Object { $_.Category -eq "Global Admin" } | Sort-Object -Property DisplayName)) {
        $statusClass = if ($user.AccountEnabled) { "enabled" } else { "disabled" }
        $globalAdminRows += @"
        <tr>
            <td>$($user.DisplayName)</td>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.JobTitle)</td>
            <td class="$statusClass">$($user.AccountEnabled)</td>
            <td>$($user.LastSignIn)</td>
            <td>$($user.Licenses)</td>
        </tr>
"@
    }

    $otherAdminRows = ""
    foreach ($user in ($FormattedUsers | Where-Object { $_.Category -eq "Admin" } | Sort-Object -Property DisplayName)) {
        $statusClass = if ($user.AccountEnabled) { "enabled" } else { "disabled" }
        $otherAdminRows += @"
        <tr>
            <td>$($user.DisplayName)</td>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.JobTitle)</td>
            <td>$($user.AdminRoles)</td>
            <td class="$statusClass">$($user.AccountEnabled)</td>
            <td>$($user.LastSignIn)</td>
            <td>$($user.Licenses)</td>
        </tr>
"@
    }
    
    $guestUserRows = ""
    foreach ($user in ($FormattedUsers | Where-Object { $_.UserType -eq "Guest" } | Sort-Object -Property DisplayName)) {
        $statusClass = if ($user.AccountEnabled) { "enabled" } else { "disabled" }
        $guestUserRows += @"
        <tr>
            <td>$($user.DisplayName)</td>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.CreatedDate)</td>
            <td class="$statusClass">$($user.AccountEnabled)</td>
            <td>$($user.LastSignIn)</td>
        </tr>
"@
    }
    
    $disabledUserRows = ""
    foreach ($user in ($FormattedUsers | Where-Object { $_.AccountEnabled -eq $false } | Sort-Object -Property DisplayName)) {
        $disabledUserRows += @"
        <tr>
            <td>$($user.DisplayName)</td>
            <td>$($user.UserPrincipalName)</td>
            <td>$($user.UserType)</td>
            <td>$($user.Category)</td>
            <td>$($user.LastSignIn)</td>
            <td>$($user.Licenses)</td>
        </tr>
"@
    }
    
    # HTML Template
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>User Inventory Report - $TenantName</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        h1, h2, h3 { 
            color: #0078D4; 
            margin-top: 0;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .header-card {
            background-color: #E5F1FA;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .dashboard-card {
            text-align: center;
            padding: 15px;
        }
        .dashboard-number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .dashboard-label {
            font-size: 14px;
            color: #666;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 10px;
            font-size: 0.9rem;
        }
        th, td { 
            padding: 8px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #0078D4; 
            color: white;
            position: sticky;
            top: 0;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .enabled { color: #107C10; }
        .disabled { color: #E81123; }
        .admin { color: #0078D4; font-weight: bold; }
        .global-admin { color: #E81123; font-weight: bold; }
        .guest { color: #FF8C00; }
        .table-container {
            max-height: 400px;
            overflow-y: auto;
            margin-bottom: 10px;
        }
        .search-box {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }
        .tab-container {
            margin-bottom: 15px;
        }
        .tab-button {
            background-color: #f0f0f0;
            border: none;
            padding: 10px 20px;
            cursor: pointer;
            font-weight: bold;
            border-radius: 4px 4px 0 0;
        }
        .tab-button.active {
            background-color: #0078D4;
            color: white;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        .percentage-box {
            background-color: #f9f9f9;
            border-radius: 6px;
            padding: 15px;
            margin: 15px 0;
            border-left: 4px solid #0078D4;
        }
        .percentage-item {
            display: flex;
            justify-content: space-between;
            margin-bottom: 10px;
            align-items: center;
        }
        .percentage-label {
            font-weight: bold;
        }
        .percentage-bar-container {
            flex-grow: 1;
            margin: 0 15px;
            background-color: #e0e0e0;
            height: 12px;
            border-radius: 6px;
            overflow: hidden;
        }
        .percentage-bar {
            height: 100%;
            width: 0%; /* Will be set by inline style */
            border-radius: 6px;
        }
        .percentage-value {
            min-width: 60px;
            text-align: right;
        }
        .proper-accounts { background-color: #107C10; }
        .guest-accounts { background-color: #FF8C00; }
        .disabled-accounts { background-color: #E81123; }
    </style>
    <script>
        function filterTable(tableId) {
            var input = document.getElementById('searchInput-' + tableId);
            var filter = input.value.toUpperCase();
            var table = document.getElementById(tableId);
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var found = false;
                var cells = rows[i].getElementsByTagName('td');
                
                for (var j = 0; j < cells.length; j++) {
                    var cell = cells[j];
                    if (cell) {
                        var text = cell.textContent || cell.innerText;
                        if (text.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if (found) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
        
        function openTab(evt, tabName) {
            var i, tabContent, tabButtons;
            
            tabContent = document.getElementsByClassName('tab-content');
            for (i = 0; i < tabContent.length; i++) {
                tabContent[i].classList.remove('active');
            }
            
            tabButtons = document.getElementsByClassName('tab-button');
            for (i = 0; i < tabButtons.length; i++) {
                tabButtons[i].classList.remove('active');
            }
            
            document.getElementById(tabName).classList.add('active');
            evt.currentTarget.classList.add('active');
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="card header-card">
            <h1>User Inventory Report</h1>
            <p><strong>Tenant:</strong> $TenantName</p>
            <p><strong>Domain:</strong> $TenantDomain</p>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card card">
                <div class="dashboard-label">Total Users</div>
                <div class="dashboard-number">$totalUsers</div>
            </div>
            <div class="dashboard-card card">
                <div class="dashboard-label">Global Admins</div>
                <div class="dashboard-number" style="color: #E81123;">$globalAdmins</div>
            </div>
            <div class="dashboard-card card">
                <div class="dashboard-label">Other Admins</div>
                <div class="dashboard-number" style="color: #0078D4;">$otherAdmins</div>
            </div>
            <div class="dashboard-card card">
                <div class="dashboard-label">Guest Users</div>
                <div class="dashboard-number" style="color: #FF8C00;">$guestUsers</div>
            </div>
            <div class="dashboard-card card">
                <div class="dashboard-label">Disabled Users</div>
                <div class="dashboard-number" style="color: #E81123;">$disabledUsers</div>
            </div>
            <div class="dashboard-card card">
                <div class="dashboard-label">Licensed Users</div>
                <div class="dashboard-number" style="color: #107C10;">$licensedUsers</div>
            </div>
        </div>
        
        <div class="tab-container">
            <button class="tab-button active" onclick="openTab(event, 'tab-global-admins')">Global Admins</button>
            <button class="tab-button" onclick="openTab(event, 'tab-other-admins')">Other Admins</button>
            <button class="tab-button" onclick="openTab(event, 'tab-guest-users')">Guest Users</button>
            <button class="tab-button" onclick="openTab(event, 'tab-disabled-users')">Disabled Users</button>
            <button class="tab-button" onclick="openTab(event, 'tab-all-users')">All Users</button>
            <button class="tab-button" onclick="openTab(event, 'tab-licenses')">License Summary</button>
        </div>
        
        <div id="tab-global-admins" class="tab-content card active">
            <h2>Global Administrators ($globalAdmins)</h2>
            <input type="text" id="searchInput-globalAdmins" class="search-box" onkeyup="filterTable('globalAdmins')" placeholder="Search global admins...">
            <div class="table-container">
                <table id="globalAdmins">
                    <tr>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Job Title</th>
                        <th>Enabled</th>
                        <th>Last Sign-in</th>
                        <th>Licenses</th>
                    </tr>
                    $globalAdminRows
                </table>
            </div>
        </div>
        
        <div id="tab-other-admins" class="tab-content card">
            <h2>Other Administrators ($otherAdmins)</h2>
            <input type="text" id="searchInput-otherAdmins" class="search-box" onkeyup="filterTable('otherAdmins')" placeholder="Search other admins...">
            <div class="table-container">
                <table id="otherAdmins">
                    <tr>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Job Title</th>
                        <th>Admin Roles</th>
                        <th>Enabled</th>
                        <th>Last Sign-in</th>
                        <th>Licenses</th>
                    </tr>
                    $otherAdminRows
                </table>
            </div>
        </div>
        
        <div id="tab-guest-users" class="tab-content card">
            <h2>Guest Users ($guestUsers)</h2>
            <input type="text" id="searchInput-guestUsers" class="search-box" onkeyup="filterTable('guestUsers')" placeholder="Search guest users...">
            <div class="table-container">
                <table id="guestUsers">
                    <tr>
                        <th>Name</th>
                        <th>Username</th>
                        <th>Created Date</th>
                        <th>Enabled</th>
                        <th>Last Sign-in</th>
                    </tr>
                    $guestUserRows
                </table>
            </div>
        </div>
        
        <div id="tab-disabled-users" class="tab-content card">
            <h2>Disabled Users ($disabledUsers)</h2>
            <input type="text" id="searchInput-disabledUsers" class="search-box" onkeyup="filterTable('disabledUsers')" placeholder="Search disabled users...">
            <div class="table-container">
                <table id="disabledUsers">
                    <tr>
                        <th>Name</th>
                        <th>Username</th>
                        <th>User Type</th>
                        <th>Category</th>
                        <th>Last Sign-in</th>
                        <th>Licenses</th>
                    </tr>
                    $disabledUserRows
                </table>
            </div>
        </div>
        
        <div id="tab-all-users" class="tab-content card">
            <h2>All Users ($totalUsers)</h2>
            <input type="text" id="searchInput-allUsers" class="search-box" onkeyup="filterTable('allUsers')" placeholder="Search all users...">
            <div class="table-container">
                <table id="allUsers">
                    <tr>
                        <th>Name</th>
                        <th>Username</th>
                        <th>User Type</th>
                        <th>Category</th>
                        <th>Enabled</th>
                        <th>Last Sign-in</th>
                        <th>Licenses</th>
                    </tr>
$(
    foreach ($user in ($FormattedUsers | Sort-Object -Property DisplayName)) {
        $statusClass = if ($user.AccountEnabled) { "enabled" } else { "disabled" }
        $categoryClass = switch ($user.Category) {
            "Global Admin" { "global-admin" }
            "Admin" { "admin" }
            "Guest" { "guest" }
            default { "" }
        }
        
@"
                    <tr>
                        <td>$($user.DisplayName)</td>
                        <td>$($user.UserPrincipalName)</td>
                        <td>$($user.UserType)</td>
                        <td class="$categoryClass">$($user.Category)</td>
                        <td class="$statusClass">$($user.AccountEnabled)</td>
                        <td>$($user.LastSignIn)</td>
                        <td>$($user.Licenses)</td>
                    </tr>
"@
    }
)
                </table>
            </div>
        </div>
        
        <div id="tab-licenses" class="tab-content card">
            <h2>Account Type Distribution</h2>
            <div class="percentage-box">
                <div class="percentage-item">
                    <span class="percentage-label">Proper Accounts:</span>
                    <div class="percentage-bar-container">
                        <div class="percentage-bar proper-accounts" style="width: $properAccountsPercentage%;"></div>
                    </div>
                    <span class="percentage-value">$properAccountsCount ($properAccountsPercentage%)</span>
                </div>
                <div class="percentage-item">
                    <span class="percentage-label">Guest Accounts:</span>
                    <div class="percentage-bar-container">
                        <div class="percentage-bar guest-accounts" style="width: $guestPercentage%;"></div>
                    </div>
                    <span class="percentage-value">$guestUsers ($guestPercentage%)</span>
                </div>
                <div class="percentage-item">
                    <span class="percentage-label">Disabled Accounts:</span>
                    <div class="percentage-bar-container">
                        <div class="percentage-bar disabled-accounts" style="width: $disabledPercentage%;"></div>
                    </div>
                    <span class="percentage-value">$disabledUsers ($disabledPercentage%)</span>
                </div>
            </div>
            
            <h2>License Distribution</h2>
            <div class="table-container">
                <table>
                    <tr>
                        <th>License</th>
                        <th>Assigned Users</th>
                        <th>Percentage</th>
                    </tr>
$(
    foreach ($license in $topLicenses) {
        $percentage = [math]::Round(($license.Value / $totalUsers) * 100, 2)
        
@"
                    <tr>
                        <td>$($license.Name)</td>
                        <td>$($license.Value)</td>
                        <td>$percentage%</td>
                    </tr>
"@
    }
)
                </table>
            </div>
            
            <h3>On-Premises Synchronized Users: $onPremUsers</h3>
            <p>$([math]::Round(($onPremUsers / $totalUsers) * 100, 2))% of users are synchronized from on-premises Active Directory.</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Get-MasterUserInventoryHtml {
    param (
        [Parameter(Mandatory=$true)]
        [array]$TenantUserData
    )
    
    # Prepare summary
    $totalTenants = $TenantUserData.Count
    $totalUsers = ($TenantUserData | Measure-Object -Property TotalUsers -Sum).Sum
    $totalGlobalAdmins = ($TenantUserData | Measure-Object -Property GlobalAdmins -Sum).Sum
    $totalGuests = ($TenantUserData | Measure-Object -Property GuestUsers -Sum).Sum
    $totalDisabled = ($TenantUserData | Measure-Object -Property DisabledUsers -Sum).Sum
    
    $tenantRows = ""
    foreach ($tenant in ($TenantUserData | Sort-Object -Property ClientName)) {
        $tenantRows += @"
        <tr>
            <td>$($tenant.ClientName)</td>
            <td>$($tenant.TenantDomain)</td>
            <td>$($tenant.TotalUsers)</td>
            <td>$($tenant.GlobalAdmins)</td>
            <td>$($tenant.OtherAdmins)</td>
            <td>$($tenant.GuestUsers)</td>
            <td>$($tenant.DisabledUsers)</td>
            <td>$($tenant.LicensedUsers)</td>
            <td>$($tenant.TopLicense)</td>
            <td><a href="$($tenant.ReportLink)" target="_blank">View Details</a></td>
        </tr>
"@
    }
    
    # HTML Template
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Master User Inventory Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0;
            padding: 0;
            background-color: #f5f5f5;
            color: #333;
        }
        h1, h2, h3 { 
            color: #0078D4; 
            margin-top: 0;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
            padding: 20px;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .header-card {
            background-color: #E5F1FA;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .dashboard-card {
            text-align: center;
            padding: 15px;
        }
        .dashboard-number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        .dashboard-label {
            font-size: 14px;
            color: #666;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 10px;
            font-size: 0.9rem;
        }
        th, td { 
            padding: 10px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #0078D4; 
            color: white;
            position: sticky;
            top: 0;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        a {
            color: #0078D4;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        .search-box {
            width: 100%;
            padding: 8px;
            margin-bottom: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 1rem;
        }
        .metrics {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin-bottom: 20px;
        }
        .metric-card {
            flex: 1 1 200px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            text-align: center;
            padding: 15px;
            margin: 10px;
        }
        .metric-value {
            font-size: 24px;
            font-weight: bold;
        }
        .metric-label {
            font-size: 14px;
            color: #666;
        }
        .security-concern {
            color: #E81123;
            font-weight: bold;
        }
        .warning {
            color: #FF8C00;
            font-weight: bold;
        }
    </style>
    <script>
        function filterTable() {
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('tenantsTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var found = false;
                var cells = rows[i].getElementsByTagName('td');
                
                for (var j = 0; j < cells.length; j++) {
                    var cell = cells[j];
                    if (cell) {
                        var text = cell.textContent || cell.innerText;
                        if (text.toUpperCase().indexOf(filter) > -1) {
                            found = true;
                            break;
                        }
                    }
                }
                
                if (found) {
                    rows[i].style.display = '';
                } else {
                    rows[i].style.display = 'none';
                }
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <div class="card header-card">
            <h1>Master User Inventory Report</h1>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Total Tenants:</strong> $totalTenants</p>
        </div>
        
        <div class="metrics">
            <div class="metric-card">
                <div class="metric-value">$totalUsers</div>
                <div class="metric-label">Total Users</div>
            </div>
            <div class="metric-card">
                <div class="metric-value security-concern">$totalGlobalAdmins</div>
                <div class="metric-label">Global Admins</div>
            </div>
            <div class="metric-card">
                <div class="metric-value warning">$totalGuests</div>
                <div class="metric-label">Guest Users</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$totalDisabled</div>
                <div class="metric-label">Disabled Users</div>
            </div>
            <div class="metric-card">
                <div class="metric-value">$([math]::Round($totalGlobalAdmins / $totalTenants, 1))</div>
                <div class="metric-label">Avg Global Admins per Tenant</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Tenant User Inventory</h2>
            <input type="text" id="searchInput" class="search-box" onkeyup="filterTable()" placeholder="Search tenants...">
            <table id="tenantsTable">
                <tr>
                    <th>Tenant Name</th>
                    <th>Domain</th>
                    <th>Total Users</th>
                    <th>Global Admins</th>
                    <th>Other Admins</th>
                    <th>Guest Users</th>
                    <th>Disabled Users</th>
                    <th>Licensed Users</th>
                    <th>Top License</th>
                    <th>Details</th>
                </tr>
                $tenantRows
            </table>
        </div>
        
        <div class="card">
            <h2>Security Recommendations</h2>
            <ul>
                <li><strong>Global Administrator Review:</strong> The Microsoft recommended practice is to have 2-4 global administrators per tenant. Review tenants with higher numbers.</li>
                <li><strong>Guest User Accounts:</strong> Guest accounts should be reviewed regularly and disabled when no longer needed.</li>
                <li><strong>Disabled Accounts:</strong> Consider removing licenses from disabled accounts to save costs.</li>
                <li><strong>Regular Audits:</strong> Perform regular user account audits, especially for privileged admin accounts.</li>
            </ul>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

# Main
$ErrorActionPreference = "Continue"

$clientsToProcess = @()
$isSpecificClient = $false

if ($CsvPath) {
    Write-Host "Loading clients from CSV: $CsvPath" -ForegroundColor Cyan
    $csvClients = Import-ClientCsv -Path $CsvPath
    
    if ($ClientName) {
        $selectedClient = Get-ClientFromCsv -Clients $csvClients -ClientName $ClientName
        $clientsToProcess = @($selectedClient)
        $isSpecificClient = $true
        Write-Host "Processing specific client: $ClientName" -ForegroundColor Yellow
    } else {
        $clientsToProcess = $csvClients
        Write-Host "Processing all $($csvClients.Count) clients from CSV" -ForegroundColor Yellow
    }
} else {
    $singleClient = [PSCustomObject]@{
        Client = "Single Client"
        'Tenant ID' = $TenantId
        'Client ID' = $ClientId
        'Key Value' = $ClientSecret
    }
    $clientsToProcess = @($singleClient)
    $isSpecificClient = $true
    Write-Host "Processing single client with provided parameters" -ForegroundColor Yellow
}

# Output folders
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
if ($isSpecificClient) {
    $clientFolderName = if ($ClientName) { $ClientName -replace '[\\\/\:\*\?"<>\|]', '_' } else { "SingleClient" }
    $outputFolder = "UserInventory-$clientFolderName-$timestamp"
} else {

    $outputFolder = "UserInventory-Report-$timestamp"
}

New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
Write-Host "Created output folder: $outputFolder" -ForegroundColor Green

$allTenantsUserInfo = @()

foreach ($client in $clientsToProcess) {
    if ([string]::IsNullOrWhiteSpace($client.'Tenant ID') -or 
        [string]::IsNullOrWhiteSpace($client.'Client ID') -or 
        [string]::IsNullOrWhiteSpace($client.'Key Value')) {
        Write-Warning "Skipping client '$($client.Client)' - Missing required credential information"
        continue
    }
    
    $clientName = $client.Client.Trim()
    $tenantId = $client.'Tenant ID'.Trim()
    $clientId = $client.'Client ID'.Trim()
    $clientSecret = $client.'Key Value'.Trim()
    
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "Processing tenant: $clientName ($tenantId)" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    try {
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret

        Write-Host "Retrieving tenant information..." -ForegroundColor Yellow
        $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $tenantId

        Write-Host "Retrieving users..." -ForegroundColor Yellow
        $users = Get-TenantUsers -AccessToken $accessToken -IncludeAllProperties:$IncludeAllProperties
        
        if ($users.Count -gt 0) {
            Write-Host "Retrieving directory roles..." -ForegroundColor Yellow
            $roles = Get-TenantRoles -AccessToken $accessToken
            
            Write-Host "Retrieving license information..." -ForegroundColor Yellow
            $licenses = Get-TenantLicenses -AccessToken $accessToken

            Write-Host "Processing user data..." -ForegroundColor Yellow
            $formattedUsers = Format-UserData -Users $users -Roles $roles -Licenses $licenses -IncludeGroupMemberships:$IncludeGroupMemberships -AccessToken $accessToken

            $totalUsers = $formattedUsers.Count
            $globalAdmins = ($formattedUsers | Where-Object { $_.Category -eq "Global Admin" }).Count
            $otherAdmins = ($formattedUsers | Where-Object { $_.Category -eq "Admin" }).Count
            $guestUsers = ($formattedUsers | Where-Object { $_.UserType -eq "Guest" }).Count
            $disabledUsers = ($formattedUsers | Where-Object { $_.AccountEnabled -eq $false }).Count
            $licensedUsers = ($formattedUsers | Where-Object { $_.LicenseCount -gt 0 }).Count

            $licenseDistribution = @{}
            foreach ($user in $formattedUsers) {
                if ($user.Licenses) {
                    $userLicenses = $user.Licenses -split ", "
                    foreach ($license in $userLicenses) {
                        if (-not $licenseDistribution.ContainsKey($license)) {
                            $licenseDistribution[$license] = 0
                        }
                        $licenseDistribution[$license]++
                    }
                }
            }
            
            $topLicense = "None"
            $topLicenseCount = 0
            
            if ($licenseDistribution.Count -gt 0) {
                $topLicenseInfo = $licenseDistribution.GetEnumerator() | Sort-Object -Property Value -Descending | Select-Object -First 1
                $topLicense = $topLicenseInfo.Key
                $topLicenseCount = $topLicenseInfo.Value
            }

            $safeClientName = $clientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $tenantReportFilename = "UserInventory-$safeClientName-$timestamp.html"
            $tenantReportPath = Join-Path -Path $outputFolder -ChildPath $tenantReportFilename
            $tenantReportContent = Get-UserInventoryHtml -TenantName $clientName -TenantDomain $tenantInfo.InitialDomain -FormattedUsers $formattedUsers
            $tenantReportContent | Out-File -FilePath $tenantReportPath -Encoding utf8

            $usersCsvFile = Join-Path -Path $outputFolder -ChildPath "Users-$safeClientName-$timestamp.csv"
            $formattedUsers | Export-Csv -Path $usersCsvFile -NoTypeInformation

            if (-not $isSpecificClient) {
                $tenantSummary = [PSCustomObject]@{
                    ClientName = $clientName
                    TenantId = $tenantId
                    TenantDomain = $tenantInfo.InitialDomain
                    TotalUsers = $totalUsers
                    GlobalAdmins = $globalAdmins
                    OtherAdmins = $otherAdmins
                    GuestUsers = $guestUsers
                    DisabledUsers = $disabledUsers
                    LicensedUsers = $licensedUsers
                    TopLicense = $topLicense
                    TopLicenseCount = $topLicenseCount
                    ReportLink = $tenantReportFilename
                }
                
                $allTenantsUserInfo += $tenantSummary
            }
            
            Write-Host "Processed $totalUsers users for tenant $clientName" -ForegroundColor Green
            Write-Host "- Global Admins: $globalAdmins" -ForegroundColor $(if ($globalAdmins -gt 4) { "Red" } else { "Green" })
            Write-Host "- Guest Users: $guestUsers" -ForegroundColor Yellow
            Write-Host "- Disabled Users: $disabledUsers" -ForegroundColor Cyan
            
            Write-Host "User inventory report saved to: $tenantReportPath" -ForegroundColor Green
            Write-Host "User details exported to: $usersCsvFile" -ForegroundColor Green
            
            if ($isSpecificClient) {
                Write-Host "`nUser Inventory Summary for $clientName :" -ForegroundColor Cyan
                Write-Host "Total Users: $totalUsers" -ForegroundColor White
                Write-Host "Global Administrators: $globalAdmins" -ForegroundColor $(if ($globalAdmins -gt 4) { "Red" } else { "Green" })
                Write-Host "Other Administrative Roles: $otherAdmins" -ForegroundColor Yellow
                Write-Host "Guest Users: $guestUsers" -ForegroundColor Yellow
                Write-Host "Disabled Users: $disabledUsers" -ForegroundColor Cyan
                Write-Host "Licensed Users: $licensedUsers" -ForegroundColor Green
                
                Write-Host "`n=== REPORTS GENERATED ===" -ForegroundColor Magenta
                Write-Host "HTML Report: $tenantReportPath" -ForegroundColor Green
                Write-Host "CSV Report: $usersCsvFile" -ForegroundColor Green
                
                if ($PSVersionTable.Platform -ne 'Unix') {
                    Write-Host "Opening HTML report..."
                    Invoke-Item $tenantReportPath
                }
                
                exit
            }
        }
        else {
            Write-Host "No users found in tenant $clientName" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error processing tenant $clientName ($tenantId): $_"
    }
}

if (-not $isSpecificClient -and $allTenantsUserInfo.Count -gt 0) {
    # Export consolidated CSV report
    $summaryFile = Join-Path -Path $outputFolder -ChildPath "UserInventory-AllTenants-$timestamp.csv"
    $allTenantsUserInfo | Export-Csv -Path $summaryFile -NoTypeInformation
    
    # Generate master HTML report
    $masterReportFile = Join-Path -Path $outputFolder -ChildPath "MasterUserInventory-$timestamp.html"
    $masterReportContent = Get-MasterUserInventoryHtml -TenantUserData $allTenantsUserInfo
    $masterReportContent | Out-File -FilePath $masterReportFile -Encoding utf8
    
    Write-Host "`n=== EXECUTION SUMMARY ===" -ForegroundColor Magenta
    Write-Host "All processing complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
    Write-Host "Summary CSV: $summaryFile" -ForegroundColor Green
    Write-Host "Master Report: $masterReportFile" -ForegroundColor Green
    
    if ($PSVersionTable.Platform -ne 'Unix') {
        Write-Host "Opening master report..."
        Invoke-Item $masterReportFile
    }
}
elseif (-not $isSpecificClient) {
    Write-Host "`nNo user data was collected for any tenant" -ForegroundColor Yellow
}

Write-Host "`nScript execution completed at $(Get-Date)" -ForegroundColor Green
