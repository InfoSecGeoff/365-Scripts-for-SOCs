<#
.SYNOPSIS
    Microsoft 365 Hybrid Identity Assessment Script
    
    Analyzes and reports on hybrid identity configurations across Microsoft 365 tenants,
    including Azure AD Connect sync status, federation settings, and domain authentication types. 

.DESCRIPTION
    This script performs comprehensive analysis of Microsoft 365 hybrid identity configurations across either a single client or all clients contained in a CSV file.
    It can process either a single tenant or multiple tenants from a CSV file, generating detailed reports on:
    
    - Azure AD Connect sync status and health
    - Domain federation configuration (AD FS)
    - Authentication types for all domains
    - Password synchronization status
    - Sync timing and issues detection
    - Overall hybrid identity architecture assessment
    
    The script outputs both CSV and HTML reports with interactive filtering and color-coded
    status indicators for easy identification of issues requiring attention.

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID) for single tenant analysis. Required when not using CSV file input.

.PARAMETER ClientId
    The Application (also known as Client) ID of the Azure AD app registration with appropriate permissions.
    Required when not using CSV file input.
    
    Required Microsoft Graph API permissions:
    - Directory.Read.All
    - Domain.Read.All
    - Organization.Read.All

.PARAMETER ClientSecret
    The client secret value for the Azure AD app registration.
    Required when not using CSV file input.

.PARAMETER CsvPath
    Path to CSV file containing multiple tenant credentials.
    When specified, the script processes all tenants in the file.
    
    Required CSV columns:
    - Client: Friendly name for the tenant
    - Tenant ID: Azure AD Tenant ID (GUID)
    - Client ID: Application ID with required permissions
    - Key Value: Client secret for authentication

.OUTPUTS
    Creates a timestamped folder containing:
    - HybridIdentityReport.csv: Detailed data in CSV format
    - HybridIdentityReport.html: Interactive HTML report with filtering and search

.EXAMPLE
    .\Get-TenantIdentityConfig.ps1.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-client-secret-here"
    
    Analyzes a single Microsoft 365 tenant for hybrid identity configuration.

.EXAMPLE
    .\Get-TenantIdentityConfig.ps1.ps1 -CsvPath "C:\Scripts\TenantCredentials.csv"
    
    Processes multiple tenants from a CSV file containing tenant credentials.

.EXAMPLE
    # CSV file format example:
    # Client,Tenant ID,Client ID,Key Value
    # "Contoso Corp","12345678-1234-1234-1234-123456789012","87654321-4321-4321-4321-210987654321","secret123"
    # "Fabrikam Inc","87654321-4321-4321-4321-210987654321","12345678-1234-1234-1234-123456789012","secret456"

.NOTES
    File Name      : Get-TenantIdentityConfig.ps1.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or later
    
    SECURITY CONSIDERATIONS:
    - Store client secrets securely and never commit to source control
    - Use Azure Key Vault or secure credential storage in production
    - Ensure app registration has minimum required permissions
    - Review and rotate client secrets regularly
    
    SYNC THRESHOLD CONFIGURATION:
    - Warning threshold: 12 hours since last sync
    - Critical threshold: 24 hours since last sync
    - These can be modified in the script variables section
    
    TROUBLESHOOTING:
    - Verify app registration permissions in Azure AD
    - Ensure client secret hasn't expired
    - Check network connectivity to Microsoft Graph endpoints
    - Review Azure AD audit logs for authentication failures
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$CsvPath
)

# Sync thresholds
$syncWarningThresholdHours = 12  
$syncCriticalThresholdHours = 24  

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

function Get-DomainFederationStatus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$DomainName
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/domains/$DomainName"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        
        return $response.authenticationType
    }
    catch {
        Write-Warning "Could not retrieve federation status for domain $DomainName`: $_"
        return "Unknown"
    }
}

function Get-TenantDomains {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $domains = @()
        $nextLink = "https://graph.microsoft.com/v1.0/domains"
        
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $domains += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        return $domains
    }
    catch {
        Write-Error "Error retrieving domains: $_"
        throw $_
    }
}

function Get-AADConnectStatus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    # First, check if directory sync is enabled at all
    try {
        $uri = "https://graph.microsoft.com/v1.0/organization"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
        
        $orgInfo = $response.value[0]
        $dirSyncEnabled = $orgInfo.onPremisesSyncEnabled
        
        if (-not $dirSyncEnabled) {
            return @{
                Enabled = $false
                LastSyncTime = $null
                NextSyncTime = $null
                FolderSync = $null
                PasswordSync = $null
                SyncIssues = $null
            }
        }
        
        # Directory sync details
        $lastSyncTime = $null
        $nextSyncTime = $null
        $passwordSync = $orgInfo.passwordSyncEnabled
        $folderSync = $true # Assumed if directory sync is enabled
        $syncIssues = $null
        
        if ($orgInfo.onPremisesLastSyncDateTime) {
            $lastSyncTime = [DateTime]$orgInfo.onPremisesLastSyncDateTime
            $timeSinceLastSync = (Get-Date) - $lastSyncTime
            if ($timeSinceLastSync.TotalHours -gt $syncCriticalThresholdHours) {
                $syncIssues = "CRITICAL: No sync for over $syncCriticalThresholdHours hours"
            }
            elseif ($timeSinceLastSync.TotalHours -gt $syncWarningThresholdHours) {
                $syncIssues = "WARNING: No sync for over $syncWarningThresholdHours hours"
            }
            
            $syncInterval = New-TimeSpan -Minutes 30
            $nextSyncTime = $lastSyncTime + $syncInterval
            
            if ($nextSyncTime -lt (Get-Date)) {
                $nextSyncTime = "Overdue (Expected: $(Get-Date $nextSyncTime -Format 'yyyy-MM-dd HH:mm:ss'))"
            }
        }
        else {
            $syncIssues = "No sync timestamp found"
        }
        
        try {
            $uri = "https://graph.microsoft.com/beta/directory/onPremisesDirectoryConnectors"
            $connectors = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers -ErrorAction SilentlyContinue
            
            if ($connectors.value.Count -eq 0) {
                if (!$syncIssues) {
                    $syncIssues = "Cannot find Azure AD Connect connector details"
                }
            }
            else {
                $connector = $connectors.value[0]
                if ($connector.connectorStatus -ne "healthy") {
                    $syncIssues = "Connector status: $($connector.connectorStatus)"
                }
            }
        }
        catch {
            # Just continue if we can't get this info
            Write-Verbose "Could not retrieve connector details: $_"
        }
        
        return @{
            Enabled = $true
            LastSyncTime = $lastSyncTime
            NextSyncTime = $nextSyncTime
            FolderSync = $folderSync
            PasswordSync = $passwordSync
            SyncIssues = $syncIssues
        }
        
    }
    catch {
        Write-Warning "Error checking directory sync status: $_"
        return @{
            Enabled = "Unknown"
            LastSyncTime = $null
            NextSyncTime = $null
            FolderSync = $null
            PasswordSync = $null
            SyncIssues = "Error checking sync status: $_"
        }
    }
}

# Main script execution
$ErrorActionPreference = "Continue"  # Don't stop on errors
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "HybridIdentityReport-$timestamp"
New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

# Create arrays to hold all reports
$allTenantsData = @()

# Check which parameter set is being used
if ($CsvPath) {
    # Process multiple tenants from CSV
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }
    
    try {
        $tenants = Import-Csv -Path $CsvPath
        
        # Process each tenant
        $totalTenants = $tenants.Count
        $currentTenant = 0
        
        foreach ($tenant in $tenants) {
            $currentTenant++
            
            # Skip entries with missing required values
            if ([string]::IsNullOrWhiteSpace($tenant.'Tenant ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Client ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Key Value')) {
                Write-Warning "Skipping tenant '$($tenant.Client)' - Missing required credential information"
                continue
            }
            
            $clientName = $tenant.Client.Trim()
            $tenantId = $tenant.'Tenant ID'.Trim()
            $clientId = $tenant.'Client ID'.Trim()
            $clientSecret = $tenant.'Key Value'.Trim()
            
            Write-Host "`n=======================================================" -ForegroundColor Cyan
            Write-Host "Processing tenant $currentTenant of $totalTenants`: $clientName ($tenantId)" -ForegroundColor Cyan
            Write-Host "=======================================================" -ForegroundColor Cyan
            
            try {
                Write-Progress -Activity "Processing Tenants" -Status "Tenant $currentTenant of $totalTenants`: $clientName" -PercentComplete (($currentTenant / $totalTenants) * 100)
                
                # Get authentication token
                Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                
                # Check federation status for primary domain
                Write-Host "Retrieving tenant domains..." -ForegroundColor Yellow
                $domains = Get-TenantDomains -AccessToken $accessToken
                
                $primaryDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
                if (-not $primaryDomain) {
                    $primaryDomain = $domains | Select-Object -First 1
                }
                
                Write-Host "Checking federation status for primary domain: $($primaryDomain.id)" -ForegroundColor Yellow
                $federationStatus = Get-DomainFederationStatus -AccessToken $accessToken -DomainName $primaryDomain.id
                
                # Get Azure AD Connect status
                Write-Host "Checking Azure AD Connect status..." -ForegroundColor Yellow
                $aadConnectStatus = Get-AADConnectStatus -AccessToken $accessToken
                
                # Count federated domains
                $federatedDomains = $domains | Where-Object { $_.authenticationType -eq "Federated" }
                $federatedDomainsCount = $federatedDomains.Count
                $managedDomainsCount = $domains.Count - $federatedDomainsCount
                
                # Determine hybrid identity configuration type
                $hybridType = "None"
                $needsAttention = $false
                $attentionReason = ""
                
                if ($federatedDomainsCount -gt 0 -and $aadConnectStatus.Enabled) {
                    $hybridType = "Full Hybrid (AD FS + Azure AD Connect)"
                }
                elseif ($federatedDomainsCount -gt 0) {
                    $hybridType = "Federation Only (AD FS)"
                }
                elseif ($aadConnectStatus.Enabled) {
                    $hybridType = "Sync Only (Azure AD Connect)"
                }
                
                # Determine if tenant needs attention
                if ($aadConnectStatus.Enabled -and $aadConnectStatus.SyncIssues) {
                    $needsAttention = $true
                    $attentionReason = $aadConnectStatus.SyncIssues
                }
                
                # Add tenant data to collection
                $allTenantsData += [PSCustomObject]@{
                    ClientName = $clientName
                    TenantId = $tenantId
                    PrimaryDomain = $primaryDomain.id
                    TotalDomains = $domains.Count
                    FederatedDomains = $federatedDomainsCount
                    ManagedDomains = $managedDomainsCount
                    PrimaryDomainAuth = $federationStatus
                    HybridType = $hybridType
                    AADConnectEnabled = $aadConnectStatus.Enabled
                    LastSyncTime = $aadConnectStatus.LastSyncTime
                    NextSyncTime = $aadConnectStatus.NextSyncTime
                    PasswordSync = $aadConnectStatus.PasswordSync
                    FolderSync = $aadConnectStatus.FolderSync
                    SyncIssues = $aadConnectStatus.SyncIssues
                    NeedsAttention = $needsAttention
                    AttentionReason = $attentionReason
                }
                
                Write-Host "Hybrid configuration for $clientName`: $hybridType" -ForegroundColor Yellow
                if ($needsAttention) {
                    Write-Host "ATTENTION NEEDED: $attentionReason" -ForegroundColor Red
                }
                
            }
            catch {
                Write-Error "Error processing tenant $clientName ($tenantId): $_"
                
                # Still add the tenant to the report but mark as error
                $allTenantsData += [PSCustomObject]@{
                    ClientName = $clientName
                    TenantId = $tenantId
                    PrimaryDomain = "Error"
                    TotalDomains = 0
                    FederatedDomains = 0
                    ManagedDomains = 0
                    PrimaryDomainAuth = "Error"
                    HybridType = "Error"
                    AADConnectEnabled = "Error"
                    LastSyncTime = "Error"
                    NextSyncTime = "Error"
                    PasswordSync = "Error"
                    FolderSync = "Error"
                    SyncIssues = "Error processing tenant: $_"
                    NeedsAttention = $true
                    AttentionReason = "Error processing tenant: $_"
                }
            }
        }
        
        Write-Progress -Activity "Processing Tenants" -Completed
        
        # Export CSV report
        $csvFile = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.csv"
        $allTenantsData | Export-Csv -Path $csvFile -NoTypeInformation
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.html"
        
        # Count tenants by category
        $totalTenants = $allTenantsData.Count
        $tenantsNeedingAttention = ($allTenantsData | Where-Object { $_.NeedsAttention -eq $true }).Count
        $tenantsWithErrors = ($allTenantsData | Where-Object { $_.HybridType -eq "Error" }).Count
        $tenantsWithHybrid = ($allTenantsData | Where-Object { $_.HybridType -ne "None" -and $_.HybridType -ne "Error" }).Count
        $tenantsWithAADConnect = ($allTenantsData | Where-Object { $_.AADConnectEnabled -eq $true }).Count
        $tenantsWithFederation = ($allTenantsData | Where-Object { $_.FederatedDomains -gt 0 }).Count
        
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Hybrid Identity Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        h1, h2, h3 { 
            color: #0078D4; 
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .dashboard {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-bottom: 20px;
        }
        .dashboard-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 15px;
            flex: 1;
            min-width: 200px;
            text-align: center;
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
        .attention {
            background-color: #FDE7E9;
            border-left: 4px solid #E81123;
        }
        .hybrid {
            background-color: #E5F1FA;
            border-left: 4px solid #0078D4;
        }
        .none {
            background-color: #f0f0f0;
        }
        .error {
            background-color: #FEF0F1;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
        }
        th, td { 
            padding: 10px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #0078D4; 
            color: white;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .warning { 
            color: #FF8C00; 
            font-weight: bold;
        }
        .critical { 
            color: #E81123; 
            font-weight: bold;
        }
        .good { 
            color: #107C10; 
        }
        .summary { 
            background-color: #E5F1FA; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
        }
        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .btn {
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
        }
        .btn-primary {
            background-color: #0078D4;
            color: white;
        }
        .btn-secondary {
            background-color: #f0f0f0;
            color: #333;
        }
        .btn:hover {
            opacity: 0.9;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .badge-blue {
            background-color: #0078D4;
        }
        .badge-red {
            background-color: #E81123;
        }
        .badge-green {
            background-color: #107C10;
        }
        .badge-orange {
            background-color: #FF8C00;
        }
        .badge-grey {
            background-color: #666;
        }
    </style>
    <script>
        function filterTable(filterType) {
            var table = document.getElementById('tenantsTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var row = rows[i];
                
                if (filterType === 'all') {
                    row.style.display = '';
                }
                else if (filterType === 'attention') {
                    if (row.classList.contains('attention')) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
                else if (filterType === 'hybrid') {
                    if (row.classList.contains('hybrid')) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
                else if (filterType === 'nonhybrid') {
                    if (row.classList.contains('none')) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
                else if (filterType === 'error') {
                    if (row.classList.contains('error')) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
            }
        }

        function searchTable() {
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('tenantsTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var row = rows[i];
                var cells = row.getElementsByTagName('td');
                var found = false;
                
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
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>Microsoft 365 Hybrid Identity Report</h1>
        <div class="summary card">
            <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>Report contains data from $totalTenants tenant(s)</p>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card attention">
                <div class="dashboard-number">$tenantsNeedingAttention</div>
                <div class="dashboard-label">Tenants Needing Attention</div>
            </div>
            <div class="dashboard-card hybrid">
                <div class="dashboard-number">$tenantsWithHybrid</div>
                <div class="dashboard-label">Hybrid Tenants</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsWithAADConnect</div>
                <div class="dashboard-label">Tenants with AAD Connect</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsWithFederation</div>
                <div class="dashboard-label">Tenants with Federation</div>
            </div>
            <div class="dashboard-card error">
                <div class="dashboard-number">$tenantsWithErrors</div>
                <div class="dashboard-label">Tenants with Errors</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Tenant Hybrid Identity Status</h2>
            
            <div class="filter-controls">
                <button class="btn btn-primary" onclick="filterTable('all')">Show All</button>
                <button class="btn btn-secondary" onclick="filterTable('attention')">Needs Attention</button>
                <button class="btn btn-secondary" onclick="filterTable('hybrid')">Hybrid Only</button>
                <button class="btn btn-secondary" onclick="filterTable('nonhybrid')">Non-Hybrid Only</button>
                <button class="btn btn-secondary" onclick="filterTable('error')">Errors Only</button>
                <input type="text" id="searchInput" onkeyup="searchTable()" placeholder="Search..." style="padding: 8px; flex-grow: 1; min-width: 200px;">
            </div>
            
            <table id="tenantsTable">
                <tr>
                    <th>Client Name</th>
                    <th>Primary Domain</th>
                    <th>Hybrid Type</th>
                    <th>Authentication</th>
                    <th>AAD Connect Status</th>
                    <th>Last Sync</th>
                    <th>Next Sync</th>
                    <th>Password Sync</th>
                    <th>Issues/Attention</th>
                </tr>
"@
        
        $htmlTableRows = ""
        
        foreach ($tenant in $allTenantsData) {
            $rowClass = "none"
            if ($tenant.NeedsAttention -eq $true) {
                $rowClass = "attention"
            }
            elseif ($tenant.HybridType -eq "Error") {
                $rowClass = "error"
            }
            elseif ($tenant.HybridType -ne "None") {
                $rowClass = "hybrid"
            }
            
            # Format the last sync time with color coding
            $lastSyncFormatted = "N/A"
            $syncStatus = ""
            
            if ($tenant.LastSyncTime -and $tenant.LastSyncTime -ne "Error" -and $tenant.LastSyncTime -ne "Unknown") {
                $lastSyncTime = [DateTime]$tenant.LastSyncTime
                $timeSinceLastSync = (Get-Date) - $lastSyncTime
                $lastSyncFormatted = $lastSyncTime.ToString("yyyy-MM-dd HH:mm:ss")
                
                if ($timeSinceLastSync.TotalHours -gt $syncCriticalThresholdHours) {
                    $syncStatus = "<span class='critical'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
                }
                elseif ($timeSinceLastSync.TotalHours -gt $syncWarningThresholdHours) {
                    $syncStatus = "<span class='warning'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
                }
                else {
                    $syncStatus = "<span class='good'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
                }
            }
            elseif ($tenant.LastSyncTime -eq "Error" -or $tenant.LastSyncTime -eq "Unknown") {
                $lastSyncFormatted = $tenant.LastSyncTime
            }
            
            # Format hybrid type with badge
            $hybridTypeBadge = ""
            switch ($tenant.HybridType) {
                "Full Hybrid (AD FS + Azure AD Connect)" {
                    $hybridTypeBadge = "<span class='badge badge-blue'>Full Hybrid</span>"
                }
                "Federation Only (AD FS)" {
                    $hybridTypeBadge = "<span class='badge badge-orange'>Federation Only</span>"
                }
                "Sync Only (Azure AD Connect)" {
                    $hybridTypeBadge = "<span class='badge badge-green'>Sync Only</span>"
                }
                "Error" {
                    $hybridTypeBadge = "<span class='badge badge-red'>Error</span>"
                }
                default {
                    $hybridTypeBadge = "<span class='badge badge-grey'>None</span>"
                }
            }
            
            # Format password sync status
            $passwordSyncStatus = "N/A"
            if ($tenant.PasswordSync -eq $true) {
                $passwordSyncStatus = "<span class='good'>Enabled</span>"
            }
            elseif ($tenant.PasswordSync -eq $false) {
                $passwordSyncStatus = "<span class='warning'>Disabled</span>"
            }
            elseif ($tenant.PasswordSync -eq "Error" -or $tenant.PasswordSync -eq "Unknown") {
                $passwordSyncStatus = $tenant.PasswordSync
            }
            
            # Format issues with warning
            $issuesFormatted = ""
            if ($tenant.SyncIssues) {
                if ($tenant.SyncIssues.StartsWith("CRITICAL")) {
                    $issuesFormatted = "<span class='critical'>$($tenant.SyncIssues)</span>"
                }
                elseif ($tenant.SyncIssues.StartsWith("WARNING")) {
                    $issuesFormatted = "<span class='warning'>$($tenant.SyncIssues)</span>"
                }
                else {
                    $issuesFormatted = $tenant.SyncIssues
                }
            }
            else {
                $issuesFormatted = "<span class='good'>No issues detected</span>"
            }
            
            $htmlTableRows += @"
                <tr class="$rowClass">
                    <td>$($tenant.ClientName)</td>
                    <td>$($tenant.PrimaryDomain)</td>
                    <td>$hybridTypeBadge</td>
                    <td>$($tenant.PrimaryDomainAuth)</td>
                    <td>$($tenant.AADConnectEnabled)</td>
                    <td>$lastSyncFormatted $syncStatus</td>
                    <td>$($tenant.NextSyncTime)</td>
                    <td>$passwordSyncStatus</td>
                    <td>$issuesFormatted</td>
                </tr>
"@
        }
        
        $htmlFooter = @"
            </table>
        </div>
        
        <div class="card">
            <h3>Legend</h3>
            <p><span class='badge badge-blue'>Full Hybrid</span> - Both AD FS and Azure AD Connect are configured</p>
            <p><span class='badge badge-green'>Sync Only</span> - Only Azure AD Connect is configured</p>
            <p><span class='badge badge-orange'>Federation Only</span> - Only AD FS federation is configured</p>
            <p><span class='badge badge-grey'>None</span> - No hybrid identity components detected</p>
            <p><span class='badge badge-red'>Error</span> - Error occurred while analyzing this tenant</p>
            <p><span class='critical'>CRITICAL</span> - Indicates a critical issue that requires immediate attention</p>
            <p><span class='warning'>WARNING</span> - Indicates a potential issue that should be investigated</p>
            <p><span class='good'>Good</span> - Indicates normal operation with no issues detected</p>
        </div>
    </div>
</body>
</html>
"@
        
        $htmlReport = $htmlHeader + $htmlTableRows + $htmlFooter
        $htmlReport | Out-File -FilePath $htmlReportPath -Encoding utf8
        
        Write-Host "`nAll processing complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
        Write-Host "CSV Report: $csvFile" -ForegroundColor Green
        Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error processing CSV file: $_"
    }
}
else {
    # Process single tenant with parameters
    if ([string]::IsNullOrWhiteSpace($TenantId) -or 
        [string]::IsNullOrWhiteSpace($ClientId) -or 
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "When not using a CSV file, you must provide TenantId, ClientId, and ClientSecret parameters."
        return
    }
    
    try {
        # Get authentication token
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        
        # Check federation status for primary domain
        Write-Host "Retrieving tenant domains..." -ForegroundColor Yellow
        $domains = Get-TenantDomains -AccessToken $accessToken
        
        $primaryDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
        if (-not $primaryDomain) {
            $primaryDomain = $domains | Select-Object -First 1
        }
        
        Write-Host "Checking federation status for primary domain: $($primaryDomain.id)" -ForegroundColor Yellow
        $federationStatus = Get-DomainFederationStatus -AccessToken $accessToken -DomainName $primaryDomain.id
        
        # Get Azure AD Connect status
        Write-Host "Checking Azure AD Connect status..." -ForegroundColor Yellow
        $aadConnectStatus = Get-AADConnectStatus -AccessToken $accessToken
        
        # Count federated domains
        $federatedDomains = $domains | Where-Object { $_.authenticationType -eq "Federated" }
        $federatedDomainsCount = $federatedDomains.Count
        $managedDomainsCount = $domains.Count - $federatedDomainsCount
        
        # Determine hybrid identity configuration type
        $hybridType = "None"
        $needsAttention = $false
        $attentionReason = ""
        
        if ($federatedDomainsCount -gt 0 -and $aadConnectStatus.Enabled) {
            $hybridType = "Full Hybrid (AD FS + Azure AD Connect)"
        }
        elseif ($federatedDomainsCount -gt 0) {
            $hybridType = "Federation Only (AD FS)"
        }
        elseif ($aadConnectStatus.Enabled) {
            $hybridType = "Sync Only (Azure AD Connect)"
        }
        
        # Determine if tenant needs attention
        if ($aadConnectStatus.Enabled -and $aadConnectStatus.SyncIssues) {
            $needsAttention = $true
            $attentionReason = $aadConnectStatus.SyncIssues
        }
        
        # Add tenant data to collection
        $tenantData = [PSCustomObject]@{
            ClientName = "Direct Access"
            TenantId = $TenantId
            PrimaryDomain = $primaryDomain.id
            TotalDomains = $domains.Count
            FederatedDomains = $federatedDomainsCount
            ManagedDomains = $managedDomainsCount
            PrimaryDomainAuth = $federationStatus
            HybridType = $hybridType
            AADConnectEnabled = $aadConnectStatus.Enabled
            LastSyncTime = $aadConnectStatus.LastSyncTime
            NextSyncTime = $aadConnectStatus.NextSyncTime
            PasswordSync = $aadConnectStatus.PasswordSync
            FolderSync = $aadConnectStatus.FolderSync
            SyncIssues = $aadConnectStatus.SyncIssues
            NeedsAttention = $needsAttention
            AttentionReason = $attentionReason
        }
        
        $allTenantsData += $tenantData
        
        # Export CSV report
        $csvFile = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.csv"
        $allTenantsData | Export-Csv -Path $csvFile -NoTypeInformation
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.html"
        
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Hybrid Identity Report</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        h1, h2, h3 { 
            color: #0078D4; 
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px; 
        }
        th, td { 
            padding: 10px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #0078D4; 
            color: white;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .warning { 
            color: #FF8C00; 
            font-weight: bold;
        }
        .critical { 
            color: #E81123; 
            font-weight: bold;
        }
        .good { 
            color: #107C10; 
        }
        .summary { 
            background-color: #E5F1FA; 
            padding: 15px; 
            border-radius: 5px; 
            margin-bottom: 20px; 
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            color: white;
        }
        .badge-blue {
            background-color: #0078D4;
        }
        .badge-red {
            background-color: #E81123;
        }
        .badge-green {
            background-color: #107C10;
        }
        .badge-orange {
            background-color: #FF8C00;
        }
        .badge-grey {
            background-color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Microsoft 365 Hybrid Identity Report</h1>
        <div class="summary card">
            <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>Tenant ID: $TenantId</p>
            <p>Primary Domain: $($primaryDomain.id)</p>
        </div>
        
        <div class="card">
            <h2>Hybrid Identity Status</h2>
"@
        
        # Format hybrid type with badge
        $hybridTypeBadge = ""
        switch ($hybridType) {
            "Full Hybrid (AD FS + Azure AD Connect)" {
                $hybridTypeBadge = "<span class='badge badge-blue'>Full Hybrid</span>"
            }
            "Federation Only (AD FS)" {
                $hybridTypeBadge = "<span class='badge badge-orange'>Federation Only</span>"
            }
            "Sync Only (Azure AD Connect)" {
                $hybridTypeBadge = "<span class='badge badge-green'>Sync Only</span>"
            }
            "Error" {
                $hybridTypeBadge = "<span class='badge badge-red'>Error</span>"
            }
            default {
                $hybridTypeBadge = "<span class='badge badge-grey'>None</span>"
            }
        }
            
        # Format the last sync time with color coding
        $lastSyncFormatted = "N/A"
        $syncStatus = ""
        
        if ($aadConnectStatus.LastSyncTime -and $aadConnectStatus.LastSyncTime -ne "Error" -and $aadConnectStatus.LastSyncTime -ne "Unknown") {
            $lastSyncTime = [DateTime]$aadConnectStatus.LastSyncTime
            $timeSinceLastSync = (Get-Date) - $lastSyncTime
            $lastSyncFormatted = $lastSyncTime.ToString("yyyy-MM-dd HH:mm:ss")
            
            if ($timeSinceLastSync.TotalHours -gt $syncCriticalThresholdHours) {
                $syncStatus = "<span class='critical'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
            }
            elseif ($timeSinceLastSync.TotalHours -gt $syncWarningThresholdHours) {
                $syncStatus = "<span class='warning'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
            }
            else {
                $syncStatus = "<span class='good'>($([Math]::Round($timeSinceLastSync.TotalHours, 1)) hrs ago)</span>"
            }
        }
        elseif ($aadConnectStatus.LastSyncTime -eq "Error" -or $aadConnectStatus.LastSyncTime -eq "Unknown") {
            $lastSyncFormatted = $aadConnectStatus.LastSyncTime
        }
        
        # Format password sync status
        $passwordSyncStatus = "N/A"
        if ($aadConnectStatus.PasswordSync -eq $true) {
            $passwordSyncStatus = "<span class='good'>Enabled</span>"
        }
        elseif ($aadConnectStatus.PasswordSync -eq $false) {
            $passwordSyncStatus = "<span class='warning'>Disabled</span>"
        }
        elseif ($aadConnectStatus.PasswordSync -eq "Error" -or $aadConnectStatus.PasswordSync -eq "Unknown") {
            $passwordSyncStatus = $aadConnectStatus.PasswordSync
        }
        
        # Format issues with warning
        $issuesFormatted = ""
        if ($aadConnectStatus.SyncIssues) {
            if ($aadConnectStatus.SyncIssues.StartsWith("CRITICAL")) {
                $issuesFormatted = "<span class='critical'>$($aadConnectStatus.SyncIssues)</span>"
            }
            elseif ($aadConnectStatus.SyncIssues.StartsWith("WARNING")) {
                $issuesFormatted = "<span class='warning'>$($aadConnectStatus.SyncIssues)</span>"
            }
            else {
                $issuesFormatted = $aadConnectStatus.SyncIssues
            }
        }
        else {
            $issuesFormatted = "<span class='good'>No issues detected</span>"
        }
        
        $htmlContent = @"
            <table>
                <tr>
                    <th>Configuration Type</th>
                    <td>$hybridTypeBadge $hybridType</td>
                </tr>
                <tr>
                    <th>Primary Domain Authentication</th>
                    <td>$federationStatus</td>
                </tr>
                <tr>
                    <th>Total Domains</th>
                    <td>$($domains.Count)</td>
                </tr>
                <tr>
                    <th>Federated Domains</th>
                    <td>$federatedDomainsCount</td>
                </tr>
                <tr>
                    <th>Managed Domains</th>
                    <td>$managedDomainsCount</td>
                </tr>
                <tr>
                    <th>Azure AD Connect Enabled</th>
                    <td>$($aadConnectStatus.Enabled)</td>
                </tr>
                <tr>
                    <th>Last Sync Time</th>
                    <td>$lastSyncFormatted $syncStatus</td>
                </tr>
                <tr>
                    <th>Next Sync Time</th>
                    <td>$($aadConnectStatus.NextSyncTime)</td>
                </tr>
                <tr>
                    <th>Password Sync</th>
                    <td>$passwordSyncStatus</td>
                </tr>
                <tr>
                    <th>Issues/Attention</th>
                    <td>$issuesFormatted</td>
                </tr>
            </table>
"@
        
        $htmlFooter = @"
        </div>
        
        <div class="card">
            <h3>Legend</h3>
            <p><span class='badge badge-blue'>Full Hybrid</span> - Both AD FS and Azure AD Connect are configured</p>
            <p><span class='badge badge-green'>Sync Only</span> - Only Azure AD Connect is configured</p>
            <p><span class='badge badge-orange'>Federation Only</span> - Only AD FS federation is configured</p>
            <p><span class='badge badge-grey'>None</span> - No hybrid identity components detected</p>
            <p><span class='critical'>CRITICAL</span> - Indicates a critical issue that requires immediate attention</p>
            <p><span class='warning'>WARNING</span> - Indicates a potential issue that should be investigated</p>
            <p><span class='good'>Good</span> - Indicates normal operation with no issues detected</p>
        </div>
    </div>
</body>
</html>
"@
        
        $htmlReport = $htmlHeader + $htmlContent + $htmlFooter
        $htmlReport | Out-File -FilePath $htmlReportPath -Encoding utf8
        
        Write-Host "`nScan complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
        Write-Host "CSV Report: $csvFile" -ForegroundColor Green
        Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error processing tenant: $_"
    }
}
