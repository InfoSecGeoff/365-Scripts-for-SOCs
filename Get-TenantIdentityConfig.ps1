<#
.SYNOPSIS
    Reports hybrid identity configuration for one or more M365 tenants via Microsoft Graph.

.DESCRIPTION
    Checks federation status, Azure AD Connect sync health, and domain auth types.
    Outputs a CSV and HTML report. Supports single-tenant (direct params) or batch mode (CSV).

    Required Graph app permissions: Directory.Read.All, Organization.Read.All

.PARAMETER TenantId
    Tenant ID (GUID). Used for single-tenant mode.

.PARAMETER ClientId
    App registration client ID. Used for single-tenant mode.

.PARAMETER ClientSecret
    App registration client secret. Used for single-tenant mode.

.PARAMETER CsvPath
    CSV file for batch mode. Required columns: Client, Tenant ID, Client ID, Key Value.

.PARAMETER ClientName
    Filter batch mode to a single client by name (supports partial match).

.PARAMETER OutputFolder
    Output directory for reports. Defaults to current directory.

.EXAMPLE
    .\Get-TenantIdentityConfig.ps1 -TenantId "<guid>" -ClientId "<guid>" -ClientSecret "<secret>"

.EXAMPLE
    .\Get-TenantIdentityConfig.ps1 -CsvPath ".\tenants.csv" -OutputFolder "C:\Reports"

.NOTES
    Requires PowerShell 7+ for parallel batch processing.
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
    [string]$OutputFolder
)

$syncWarningThresholdHours  = 12
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
        $nextLink = "https://graph.microsoft.com/v1.0/domains?`$select=id,isDefault,authenticationType"
        
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
    
    try {
        $uri = "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime"
        $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers

        $orgInfo = $response.value[0]
        $dirSyncEnabled = $orgInfo.onPremisesSyncEnabled

        if (-not $dirSyncEnabled) {
            return @{
                Enabled = $false
                LastSyncTime = $null
                NextSyncTime = $null
                FolderSync = $false
                SyncIssues = $null
            }
        }

        $lastSyncTime       = $null
        $nextSyncTime       = $null
        $folderSync         = $true
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
            
            $nextSyncTime = $lastSyncTime + (New-TimeSpan -Minutes 30)
            if ($nextSyncTime -lt (Get-Date)) {
                $nextSyncTime = "Overdue (Expected: $(Get-Date $nextSyncTime -Format 'yyyy-MM-dd HH:mm:ss'))"
            }
        }
        else {
            $syncIssues = "No sync timestamp found"
        }
        
        try {
            $connectors = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/directory/onPremisesDirectoryConnectors" -Method Get -Headers $headers -ErrorAction SilentlyContinue
            
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
            Write-Verbose "Could not retrieve connector details: $_"
        }

        return @{
            Enabled = $true
            LastSyncTime = $lastSyncTime
            NextSyncTime = $nextSyncTime
            FolderSync = $folderSync
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
            SyncIssues = "Error checking sync status: $_"
        }
    }
}

function Get-ClientFromCsv {
    param (
        [array]$Clients,
        [string]$ClientName
    )

    $client = $Clients | Where-Object { $_.Client -eq $ClientName }

    if (-not $client) {
        Write-Verbose "No exact match found for '$ClientName', trying fuzzy match..."
        $client = $Clients | Where-Object { $_.Client -like "*$ClientName*" }

        if ($client -is [array] -and $client.Count -gt 1) {
            Write-Host "Multiple clients match '$ClientName':" -ForegroundColor Yellow
            $client | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Cyan }
            throw "Multiple matches found. Please be more specific."
        }

        if ($client) {
            Write-Host "Fuzzy match found: '$($client.Client)'" -ForegroundColor Green
        }
    }

    if (-not $client) {
        Write-Host "Client '$ClientName' not found in CSV. Available clients:" -ForegroundColor Red
        $Clients | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Yellow }
        throw "Client not found"
    }

    return $client
}

$ErrorActionPreference = "Continue"
$outputFolder = if ($OutputFolder) { $OutputFolder } else { ".\" }
$allTenantsData = @()

if ($CsvPath) {
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }
    
    try {
        $tenants = Import-Csv -Path $CsvPath

        if ($ClientName) {
            Write-Host "Filtering to specific client: $ClientName" -ForegroundColor Cyan
            $selectedClient = Get-ClientFromCsv -Clients $tenants -ClientName $ClientName
            $tenants = @($selectedClient)
            Write-Host "Found client: $($selectedClient.Client)" -ForegroundColor Green
        }

        # ThrottleLimit 20 keeps Graph API rate limits in check at scale.
        # Functions redefined inline because -Parallel doesn't support $using: scriptblocks.
        Write-Host "Processing $($tenants.Count) tenants in parallel (throttle: 20)..." -ForegroundColor Cyan
        $allTenantsData = $tenants | ForEach-Object -ThrottleLimit 20 -Parallel {
            $syncWarningThresholdHours  = $using:syncWarningThresholdHours
            $syncCriticalThresholdHours = $using:syncCriticalThresholdHours

            function Get-MsGraphToken {
                param(
                    [Parameter(Mandatory=$true)] [string]$TenantId,
                    [Parameter(Mandatory=$true)] [string]$ClientId,
                    [Parameter(Mandatory=$true)] [string]$ClientSecret
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

            function Get-TenantDomains {
                param([Parameter(Mandatory=$true)] [string]$AccessToken)
                $headers = @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" }
                try {
                    $domains  = @()
                    $nextLink = "https://graph.microsoft.com/v1.0/domains?`$select=id,isDefault,authenticationType"
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
                param([Parameter(Mandatory=$true)] [string]$AccessToken)
                $headers = @{ "Authorization" = "Bearer $AccessToken"; "Content-Type" = "application/json" }
                try {
                    $uri      = "https://graph.microsoft.com/v1.0/organization?`$select=onPremisesSyncEnabled,onPremisesLastSyncDateTime"
                    $response = Invoke-RestMethod -Uri $uri -Method Get -Headers $headers
                    $orgInfo  = $response.value[0]

                    if (-not $orgInfo.onPremisesSyncEnabled) {
                        return @{ Enabled = $false; LastSyncTime = $null; NextSyncTime = $null; FolderSync = $false; SyncIssues = $null }
                    }

                    $lastSyncTime = $null
                    $nextSyncTime = $null
                    $syncIssues   = $null

                    if ($orgInfo.onPremisesLastSyncDateTime) {
                        $lastSyncTime      = [DateTime]$orgInfo.onPremisesLastSyncDateTime
                        $timeSinceLastSync = (Get-Date) - $lastSyncTime
                        if ($timeSinceLastSync.TotalHours -gt $syncCriticalThresholdHours) {
                            $syncIssues = "CRITICAL: No sync for over $syncCriticalThresholdHours hours"
                        } elseif ($timeSinceLastSync.TotalHours -gt $syncWarningThresholdHours) {
                            $syncIssues = "WARNING: No sync for over $syncWarningThresholdHours hours"
                        }
                        $nextSyncTime = $lastSyncTime + (New-TimeSpan -Minutes 30)
                        if ($nextSyncTime -lt (Get-Date)) {
                            $nextSyncTime = "Overdue (Expected: $(Get-Date $nextSyncTime -Format 'yyyy-MM-dd HH:mm:ss'))"
                        }
                    } else {
                        $syncIssues = "No sync timestamp found"
                    }

                    try {
                        $connectors = Invoke-RestMethod -Uri "https://graph.microsoft.com/beta/directory/onPremisesDirectoryConnectors" -Method Get -Headers $headers -ErrorAction SilentlyContinue
                        if ($connectors.value.Count -eq 0) {
                            if (!$syncIssues) { $syncIssues = "Cannot find Azure AD Connect connector details" }
                        } elseif ($connectors.value[0].connectorStatus -ne "healthy") {
                            $syncIssues = "Connector status: $($connectors.value[0].connectorStatus)"
                        }
                    } catch {
                        Write-Verbose "Could not retrieve connector details: $_"
                    }

                    return @{ Enabled = $true; LastSyncTime = $lastSyncTime; NextSyncTime = $nextSyncTime; FolderSync = $true; SyncIssues = $syncIssues }
                }
                catch {
                    return @{ Enabled = "Unknown"; LastSyncTime = $null; NextSyncTime = $null; FolderSync = $null; SyncIssues = "Error checking sync status: $_" }
                }
            }

            $tenant = $_

            if ([string]::IsNullOrWhiteSpace($tenant.'Tenant ID') -or
                [string]::IsNullOrWhiteSpace($tenant.'Client ID') -or
                [string]::IsNullOrWhiteSpace($tenant.'Key Value')) {
                Write-Warning "Skipping tenant '$($tenant.Client)' - Missing required credential information"
                return
            }

            $clientName   = $tenant.Client.Trim()
            $tenantId     = $tenant.'Tenant ID'.Trim()
            $clientId     = $tenant.'Client ID'.Trim()
            $clientSecret = $tenant.'Key Value'.Trim()

            try {
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                $domains     = Get-TenantDomains -AccessToken $accessToken

                $primaryDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
                if (-not $primaryDomain) { $primaryDomain = $domains | Select-Object -First 1 }

                $federationStatus = $primaryDomain.authenticationType
                $aadConnectStatus = Get-AADConnectStatus -AccessToken $accessToken

                $federatedDomains      = $domains | Where-Object { $_.authenticationType -eq "Federated" }
                $federatedDomainsCount = $federatedDomains.Count
                $managedDomainsCount   = $domains.Count - $federatedDomainsCount

                $hybridType      = "None"
                $needsAttention  = $false
                $attentionReason = ""

                if ($federatedDomainsCount -gt 0 -and $aadConnectStatus.Enabled) {
                    $hybridType = "Full Hybrid (AD FS + Azure AD Connect)"
                } elseif ($federatedDomainsCount -gt 0) {
                    $hybridType = "Federation Only (AD FS)"
                } elseif ($aadConnectStatus.Enabled) {
                    $hybridType = "Sync Only (Azure AD Connect)"
                }

                if ($aadConnectStatus.Enabled -and $aadConnectStatus.SyncIssues) {
                    $needsAttention  = $true
                    $attentionReason = $aadConnectStatus.SyncIssues
                }

                [PSCustomObject]@{
                    ClientName        = $clientName
                    TenantId          = $tenantId
                    PrimaryDomain     = $primaryDomain.id
                    TotalDomains      = $domains.Count
                    FederatedDomains  = $federatedDomainsCount
                    ManagedDomains    = $managedDomainsCount
                    PrimaryDomainAuth = $federationStatus
                    HybridType        = $hybridType
                    AADConnectEnabled = $aadConnectStatus.Enabled
                    LastSyncTime      = $aadConnectStatus.LastSyncTime
                    NextSyncTime      = $aadConnectStatus.NextSyncTime
                    FolderSync        = $aadConnectStatus.FolderSync
                    SyncIssues        = $aadConnectStatus.SyncIssues
                    NeedsAttention    = $needsAttention
                    AttentionReason   = $attentionReason
                }
            }
            catch {
                [PSCustomObject]@{
                    ClientName        = $clientName
                    TenantId          = $tenantId
                    PrimaryDomain     = "Error"
                    TotalDomains      = 0
                    FederatedDomains  = 0
                    ManagedDomains    = 0
                    PrimaryDomainAuth = "Error"
                    HybridType        = "Error"
                    AADConnectEnabled = "Error"
                    LastSyncTime      = "Error"
                    NextSyncTime      = "Error"
                    FolderSync        = "Error"
                    SyncIssues        = "Error processing tenant: $_"
                    NeedsAttention    = $true
                    AttentionReason   = "Error processing tenant: $_"
                }
            }
        }
        
        # Export CSV report
        $csvFile = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.csv"
        $allTenantsData | Export-Csv -Path $csvFile -NoTypeInformation
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "HybridIdentityReport.html"
        
        # Count tenants by category
        $totalTenants         = $allTenantsData.Count
        $tenantsAuthFailed    = ($allTenantsData | Where-Object { $_.HybridType -eq "Error" }).Count
        $tenantsWithSyncIssues = ($allTenantsData | Where-Object { $_.NeedsAttention -eq $true -and $_.HybridType -ne "Error" }).Count
        $tenantsWithHybrid    = ($allTenantsData | Where-Object { $_.HybridType -ne "None" -and $_.HybridType -ne "Error" }).Count
        $tenantsWithAADConnect = ($allTenantsData | Where-Object { $_.AADConnectEnabled -eq $true }).Count
        $tenantsWithFederation = ($allTenantsData | Where-Object { $_.FederatedDomains -gt 0 }).Count
        
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Hybrid Identity Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        h1, h2, h3 { color: #0078D4; }
        .container { max-width: 1600px; margin: 0 auto; }
        .card { background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        .dashboard { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
        .dashboard-card { background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 15px; flex: 1; min-width: 180px; text-align: center; }
        .dashboard-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .dashboard-label { font-size: 14px; color: #666; }
        .attention { background-color: #FFF4CE; border-left: 4px solid #FF8C00; }
        .hybrid { background-color: #E5F1FA; border-left: 4px solid #0078D4; }
        .none { background-color: #f0f0f0; }
        .error { background-color: #FDE7E9; border-left: 4px solid #E81123; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078D4; color: white; white-space: nowrap; }
        th.sortable { cursor: pointer; user-select: none; }
        th.sortable:hover { background-color: #005a9e; }
        th.sort-asc::after { content: ' \25B2'; font-size: 10px; }
        th.sort-desc::after { content: ' \25BC'; font-size: 10px; }
        tr:hover { background-color: #f5f5f5; }
        .warning { color: #FF8C00; font-weight: bold; }
        .critical { color: #E81123; font-weight: bold; }
        .good { color: #107C10; }
        .summary { background-color: #E5F1FA; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .filter-controls { margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }
        .btn { padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; }
        .btn-primary { background-color: #0078D4; color: white; }
        .btn-secondary { background-color: #f0f0f0; color: #333; }
        .btn-warning { background-color: #FF8C00; color: white; }
        .btn-danger { background-color: #E81123; color: white; }
        .btn-federation { background-color: #8764B8; color: white; }
        .btn:hover { opacity: 0.85; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 12px; font-size: 12px; font-weight: bold; color: white; }
        .badge-blue { background-color: #0078D4; }
        .badge-red { background-color: #E81123; }
        .badge-green { background-color: #107C10; }
        .badge-orange { background-color: #FF8C00; }
        .badge-purple { background-color: #8764B8; }
        .badge-grey { background-color: #666; }
    </style>
    <script>
        var currentFilter = 'all';

        function filterTable(filterType) {
            currentFilter = filterType;
            var tbody = document.getElementById('tenantsBody');
            var rows = tbody.getElementsByTagName('tr');
            for (var i = 0; i < rows.length; i++) {
                var row = rows[i];
                var show = false;
                if (filterType === 'all')        show = true;
                else if (filterType === 'syncissues') show = row.classList.contains('attention');
                else if (filterType === 'hybrid')     show = row.classList.contains('hybrid');
                else if (filterType === 'nonhybrid')  show = row.classList.contains('none');
                else if (filterType === 'error')      show = row.classList.contains('error');
                else if (filterType === 'federated')  show = row.classList.contains('federated');
                row.style.display = show ? '' : 'none';
            }
        }

        function searchTable() {
            var filter = document.getElementById('searchInput').value.toUpperCase();
            var tbody = document.getElementById('tenantsBody');
            var rows = tbody.getElementsByTagName('tr');
            for (var i = 0; i < rows.length; i++) {
                var text = rows[i].textContent || rows[i].innerText;
                rows[i].style.display = text.toUpperCase().indexOf(filter) > -1 ? '' : 'none';
            }
        }

        var sortCol = -1;
        var sortAsc = true;
        function sortTable(col) {
            var table = document.getElementById('tenantsTable');
            var tbody = document.getElementById('tenantsBody');
            var rows = Array.from(tbody.getElementsByTagName('tr'));
            sortAsc = (sortCol === col) ? !sortAsc : true;
            sortCol = col;
            rows.sort(function(a, b) {
                var aVal = a.cells[col].textContent.trim();
                var bVal = b.cells[col].textContent.trim();
                return sortAsc ? aVal.localeCompare(bVal, undefined, {numeric: true}) : bVal.localeCompare(aVal, undefined, {numeric: true});
            });
            rows.forEach(function(r) { tbody.appendChild(r); });
            var headers = table.getElementsByTagName('th');
            for (var i = 0; i < headers.length; i++) {
                headers[i].classList.remove('sort-asc', 'sort-desc');
            }
            headers[col].classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
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
                <div class="dashboard-number">$tenantsWithSyncIssues</div>
                <div class="dashboard-label">Sync Issues</div>
            </div>
            <div class="dashboard-card error">
                <div class="dashboard-number">$tenantsAuthFailed</div>
                <div class="dashboard-label">Auth Failures</div>
            </div>
            <div class="dashboard-card hybrid">
                <div class="dashboard-number">$tenantsWithHybrid</div>
                <div class="dashboard-label">Hybrid Tenants</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsWithAADConnect</div>
                <div class="dashboard-label">AAD Connect</div>
            </div>
            <div class="dashboard-card" style="border-left: 4px solid #8764B8;">
                <div class="dashboard-number">$tenantsWithFederation</div>
                <div class="dashboard-label">Federated</div>
            </div>
        </div>

        <div class="card">
            <h2>Tenant Hybrid Identity Status</h2>
            <div class="filter-controls">
                <button class="btn btn-primary"     onclick="filterTable('all')">Show All</button>
                <button class="btn btn-warning"     onclick="filterTable('syncissues')">Sync Issues</button>
                <button class="btn btn-danger"      onclick="filterTable('error')">Auth Failures</button>
                <button class="btn btn-secondary"   onclick="filterTable('hybrid')">Hybrid Only</button>
                <button class="btn btn-federation"  onclick="filterTable('federated')">Federated</button>
                <button class="btn btn-secondary"   onclick="filterTable('nonhybrid')">Cloud Only</button>
                <input type="text" id="searchInput" onkeyup="searchTable()" placeholder="Search..." style="padding: 8px; flex-grow: 1; min-width: 200px;">
            </div>

            <table id="tenantsTable">
                <thead><tr>
                    <th class="sortable" onclick="sortTable(0)">Client Name</th>
                    <th class="sortable" onclick="sortTable(1)">Primary Domain</th>
                    <th class="sortable" onclick="sortTable(2)">Hybrid Type</th>
                    <th class="sortable" onclick="sortTable(3)">Authentication</th>
                    <th class="sortable" onclick="sortTable(4)">AAD Connect</th>
                    <th class="sortable" onclick="sortTable(5)">Last Dir Sync</th>
                    <th class="sortable" onclick="sortTable(6)">Next Sync</th>
                    <th class="sortable" onclick="sortTable(7)">Issues</th>
                </tr></thead>
                <tbody id="tenantsBody">
"@
        
        $htmlTableRows = ""
        
        foreach ($tenant in $allTenantsData) {
            $rowClass = "none"
            if ($tenant.HybridType -eq "Error") {
                $rowClass = "error"
            }
            elseif ($tenant.NeedsAttention -eq $true) {
                $rowClass = "attention"
            }
            elseif ($tenant.HybridType -ne "None") {
                $rowClass = "hybrid"
                if ($tenant.FederatedDomains -gt 0) { $rowClass = "hybrid federated" }
            }
            
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
            
            $hybridTypeBadge = ""
            switch ($tenant.HybridType) {
                "Full Hybrid (AD FS + Azure AD Connect)" {
                    $hybridTypeBadge = "<span class='badge badge-blue'>Full Hybrid</span>"
                }
                "Federation Only (AD FS)" {
                    $hybridTypeBadge = "<span class='badge badge-purple'>Federation Only</span>"
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
                    <td>$issuesFormatted</td>
                </tr>
"@
        }

        $htmlFooter = @"
                </tbody>
            </table>
        </div>

        <div class="card">
            <h3>Legend</h3>
            <p><span class='badge badge-blue'>Full Hybrid</span> - Both AD FS and Azure AD Connect are configured</p>
            <p><span class='badge badge-green'>Sync Only</span> - Only Azure AD Connect is configured</p>
            <p><span class='badge badge-purple'>Federation Only</span> - Only AD FS federation is configured</p>
            <p><span class='badge badge-grey'>None</span> - Cloud-only, no hybrid components</p>
            <p><span class='badge badge-red'>Auth Failure</span> - Could not connect to tenant (bad/expired credentials)</p>
            <p><span class='critical'>CRITICAL</span> - Directory sync has not run in over 24 hours</p>
            <p><span class='warning'>WARNING</span> - Directory sync has not run in over 12 hours</p>
            <p><span class='good'>Good</span> - Sync healthy, no issues detected</p>
            <p><small>Note: Password hash sync status is not exposed by the Microsoft Graph organization endpoint and is not shown.</small></p>
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
    if ([string]::IsNullOrWhiteSpace($TenantId) -or
        [string]::IsNullOrWhiteSpace($ClientId) -or 
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "When not using a CSV file, you must provide TenantId, ClientId, and ClientSecret parameters."
        return
    }
    
    try {
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret

        Write-Host "Retrieving tenant domains..." -ForegroundColor Yellow
        $domains = Get-TenantDomains -AccessToken $accessToken

        $primaryDomain = $domains | Where-Object { $_.isDefault -eq $true } | Select-Object -First 1
        if (-not $primaryDomain) { $primaryDomain = $domains | Select-Object -First 1 }

        $federationStatus  = $primaryDomain.authenticationType

        Write-Host "Checking Azure AD Connect status..." -ForegroundColor Yellow
        $aadConnectStatus = Get-AADConnectStatus -AccessToken $accessToken

        $federatedDomains      = $domains | Where-Object { $_.authenticationType -eq "Federated" }
        $federatedDomainsCount = $federatedDomains.Count
        $managedDomainsCount   = $domains.Count - $federatedDomainsCount

        $hybridType      = "None"
        $needsAttention  = $false
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
        
        if ($aadConnectStatus.Enabled -and $aadConnectStatus.SyncIssues) {
            $needsAttention = $true
            $attentionReason = $aadConnectStatus.SyncIssues
        }
        
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
            FolderSync = $aadConnectStatus.FolderSync
            SyncIssues = $aadConnectStatus.SyncIssues
            NeedsAttention = $needsAttention
            AttentionReason = $attentionReason
        }
        
        $allTenantsData = @($tenantData)
        
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
