<#
.SYNOPSIS
    Azure AD User Statistics Report Generator - Comprehensive user analytics across single or multiple Microsoft 365 tenants.

.DESCRIPTION
    This PowerShell script generates detailed HTML reports containing user counts and security insights for Microsoft 365 
    tenants. It supports both CSV-based bulk processing of Azure applications for multiple clients and manual single-tenant analysis. The script 
    is designed for SOC teams who need to monitor user account health, licensing utilization, 
    and security posture across their managed environments.

    Key Features:
    - Multi-tenant support via CSV configuration
    - Comprehensive user statistics (enabled/disabled, member/guest, licensed/unlicensed)
    - Security insights and warnings for account hygiene
    - Visual HTML reports with charts and rankings
    - Top 25 client rankings by various metrics
    - Recently created user tracking (30-day window)
    - Professional report styling with responsive design

.PARAMETER CsvPath
    Path to a CSV file containing client configurations. Required when using CSV mode.
    
    Expected CSV format:
    Client,Tenant ID,Client ID,Key Value,Expiry
    "Company A",12345678-1234-1234-1234-123456789012,87654321-4321-4321-4321-210987654321,your-secret-here,2025-12-31

.PARAMETER ClientName
    Specific client name to process from the CSV file. If omitted, all clients in the CSV will be processed.
    Must match the "Client" column value exactly (case-sensitive).

.PARAMETER TenantId
    Azure AD Tenant ID (GUID format). Required when using manual mode.
    Example: 12345678-1234-1234-1234-123456789012

.PARAMETER ClientId
    Azure AD Application (Client) ID. Required when using manual mode.
    This is the Application ID of your registered Azure AD app.

.PARAMETER AppSecret
    Azure AD Application Secret (Client Secret). Required when using manual mode.
    This should be a currently valid secret for your Azure AD application.

.PARAMETER ManualClientName
    Display name for the client when using manual mode. Defaults to "Manual Configuration".
    This name will appear in the generated report.

.PARAMETER OutputPath
    Full path where the HTML report should be saved. If not specified, the script will automatically 
    generate a filename based on the client name(s) and current timestamp in the current directory 
    or Documents folder.

.PARAMETER ShowTopClients
    Switch parameter to include Top 25 client rankings in multi-client reports. Enabled by default.
    Use -ShowTopClients:$false to disable rankings section.

.INPUTS
    CSV file with client configurations (when using -CsvPath)
    Manual parameters (when using manual mode)

.OUTPUTS
    HTML report file containing:
    - Executive summary with key metrics
    - Per-client detailed statistics
    - Security insights and recommendations
    - Top 25 client rankings (multi-client mode)
    - Visual charts and responsive styling

.NOTES
    File Name      : Get-TenantUserCount.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or later, Internet connectivity
    Version        : 2.0
    
    Required Azure AD Application Permissions:
    - User.Read.All 
    - Directory.Read.All 
    - Organization.Read.All 
    
.EXAMPLE
    .\Get-TenantUserCount.ps1 -CsvPath "C:\Config\Clients.csv"
    
    Description:
    Processes all clients listed in the CSV file and generates a comprehensive multi-client HTML report.

.EXAMPLE
    .\Get-TenantUserCount.ps1 -CsvPath "C:\Config\Clients.csv" -ClientName "Contoso Corp"
    
    Description:
    Processes only the "Contoso Corp" client from the CSV file and generates a single-client report.

.EXAMPLE
    .\Get-TenantUserCount.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -AppSecret "your-secret-here" -ManualClientName "Test Tenant"
    
    Description:
    Manually processes a single tenant using provided credentials without requiring a CSV file.

.EXAMPLE
    .\Get-TenantUserCount.ps1 -CsvPath "C:\Config\Clients.csv" -OutputPath "C:\Reports\UserStats_$(Get-Date -Format 'yyyyMMdd').html" -ShowTopClients:$false
    
    Description:
    Processes all clients with a custom output path and disables the Top 25 rankings section.

.EXAMPLE
    .\Get-TenantUserCount.ps1 -CsvPath ".\clients.csv" -ClientName "Priority Client" -OutputPath "C:\SOC\Reports\Priority_Analysis.html"
    
    Description:
    Processes a specific high-priority client and saves the report to a designated SOC reports folder.
#>

param(
    [Parameter(Mandatory=$true, ParameterSetName='CSV')]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false, ParameterSetName='CSV')]
    [string]$ClientName,
    
    [Parameter(Mandatory=$true, ParameterSetName='Manual')]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true, ParameterSetName='Manual')]
    [string]$ClientId,
    
    [Parameter(Mandatory=$true, ParameterSetName='Manual')]
    [string]$AppSecret,
    
    [Parameter(Mandatory=$false, ParameterSetName='Manual')]
    [string]$ManualClientName = "Manual Configuration",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowTopClients = $true
)


function Get-ClientCredentialsFromCsv {
    param(
        [string]$CsvPath,
        [string]$ClientName
    )
    
    if (-not (Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return $null
    }
    
    try {
        $csvData = Import-Csv -Path $CsvPath
        
        if ($ClientName) {
            $clientRecord = $csvData | Where-Object { $_.Client -eq $ClientName }
            if (-not $clientRecord) {
                Write-Error "Client '$ClientName' not found in CSV. Available clients: $($csvData.Client -join ', ')"
                return $null
            }
            return @($clientRecord)
        } else {
            # If no specific client name provided, return all records
            return $csvData
        }
    }
    catch {
        Write-Error "Failed to read CSV file: $($_.Exception.Message)"
        return $null
    }
}

function Get-GraphAccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$AppSecret
    )
    
    $body = @{
        grant_type    = "client_credentials"
        scope         = "https://graph.microsoft.com/.default"
        client_id     = $ClientId
        client_secret = $AppSecret
    }
    
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    try {
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        return $response.access_token
    }
    catch {
        Write-Error "Failed to obtain access token: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-CustomGraphRequest {
    param(
        [string]$Uri,
        [string]$AccessToken,
        [string]$Method = "GET"
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type" = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $Uri -Headers $headers -Method $Method
        return $response
    }
    catch {
        Write-Error "Graph API request failed for $Uri : $($_.Exception.Message)"
        return $null
    }
}

function Get-AllUsers {
    param(
        [string]$AccessToken,
        [string]$Filter = ""
    )
    
    $allUsers = @()

    $selectProperties = "id,displayName,userPrincipalName,accountEnabled,userType,createdDateTime,assignedLicenses"
    $uri = "https://graph.microsoft.com/v1.0/users?`$select=$selectProperties"
    
    if ($Filter) {
        $uri += "&`$filter=$Filter"
    }
    
    do {
        $response = Invoke-CustomGraphRequest -Uri $uri -AccessToken $AccessToken
        if ($response -and $response.value) {
            $allUsers += $response.value
            Write-Host "Retrieved $($response.value.Count) users (Total so far: $($allUsers.Count))" -ForegroundColor Gray
        }
        $uri = $response.'@odata.nextLink'
    } while ($uri)
    
    return $allUsers
}

# Report for a single client
function Generate-ClientReport {
    param(
        [string]$ClientName,
        [string]$TenantId,
        [string]$ClientId,
        [string]$AppSecret
    )
    
    # Handle empty tenant IDs
    if ([string]::IsNullOrEmpty($TenantId) -or [string]::IsNullOrWhiteSpace($TenantId)) {
        Write-Warning "Empty or invalid Tenant ID for $ClientName. Skipping."
        return $null
    }
    
    Write-Host "Processing client: $ClientName" -ForegroundColor Cyan
    Write-Host "Tenant ID: $TenantId" -ForegroundColor Gray
    
    # Get access token
    Write-Host "Obtaining access token for $ClientName..." -ForegroundColor Yellow
    $accessToken = Get-GraphAccessToken -TenantId $TenantId -ClientId $ClientId -AppSecret $AppSecret

    if (-not $accessToken) {
        Write-Error "Failed to obtain access token for $ClientName. Skipping."
        return $null
    }

    Write-Host "Access token obtained successfully for $ClientName!" -ForegroundColor Green

    # Get org/user info
    Write-Host "Retrieving organization information for $ClientName..." -ForegroundColor Yellow
    $orgInfo = Invoke-CustomGraphRequest -Uri "https://graph.microsoft.com/v1.0/organization" -AccessToken $accessToken
    Write-Host "Retrieving all users for $ClientName..." -ForegroundColor Yellow
    $allUsers = Get-AllUsers -AccessToken $accessToken

    if (-not $allUsers -or $allUsers.Count -eq 0) {
        Write-Warning "No users found for $ClientName"
        return $null
    }

    # Calculate stats
    Write-Host "Calculating user statistics for $ClientName..." -ForegroundColor Yellow

  
    if ($allUsers.Count -gt 0) {
        Write-Host "Sample user accountEnabled: $($allUsers[0].accountEnabled), userType: $($allUsers[0].userType)" -ForegroundColor Gray
    }

    $stats = @{
        ClientName = $ClientName
        TenantId = $TenantId
        TotalUsers = $allUsers.Count
        EnabledUsers = ($allUsers | Where-Object { $_.accountEnabled -eq $true }).Count
        DisabledUsers = ($allUsers | Where-Object { $_.accountEnabled -eq $false }).Count
        GuestUsers = ($allUsers | Where-Object { $_.userType -eq "Guest" }).Count
        MemberUsers = ($allUsers | Where-Object { $_.userType -eq "Member" }).Count
        EnabledGuests = ($allUsers | Where-Object { $_.userType -eq "Guest" -and $_.accountEnabled -eq $true }).Count
        DisabledGuests = ($allUsers | Where-Object { $_.userType -eq "Guest" -and $_.accountEnabled -eq $false }).Count
        EnabledMembers = ($allUsers | Where-Object { $_.userType -eq "Member" -and $_.accountEnabled -eq $true }).Count
        DisabledMembers = ($allUsers | Where-Object { $_.userType -eq "Member" -and $_.accountEnabled -eq $false }).Count
        LicensedUsers = ($allUsers | Where-Object { $_.assignedLicenses -and $_.assignedLicenses.Count -gt 0 }).Count
        OrgName = if ($orgInfo.value) { $orgInfo.value[0].displayName } else { "Unknown Organization" }
    }

    # Get recently created users (last 30 days)
    $thirtyDaysAgo = (Get-Date).AddDays(-30)
    $recentUsers = $allUsers | Where-Object { 
        $_.createdDateTime -and 
        [DateTime]::Parse($_.createdDateTime) -gt $thirtyDaysAgo 
    }
    $stats.RecentlyCreatedUsers = $recentUsers.Count

    Write-Host "Statistics calculated for $ClientName - Total Users: $($stats.TotalUsers)" -ForegroundColor Green
    
    return $stats
}

# Main 
Write-Host "Azure AD User Statistics Report Generator" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

$allClientStats = @()
$totalLicensed = 0

if ($PSCmdlet.ParameterSetName -eq 'CSV') {
    # CSV mode
    $clientRecords = Get-ClientCredentialsFromCsv -CsvPath $CsvPath -ClientName $ClientName
    
    if (-not $clientRecords) {
        exit 1
    }
    
    foreach ($record in $clientRecords) {
        $stats = Generate-ClientReport -ClientName $record.Client -TenantId $record.'Tenant ID' -ClientId $record.'Client ID' -AppSecret $record.'Key Value'
        if ($stats) {
            $allClientStats += $stats
        }
    }
} else {
    # Manual mode
    $stats = Generate-ClientReport -ClientName $ManualClientName -TenantId $TenantId -ClientId $ClientId -AppSecret $AppSecret
    if ($stats) {
        $allClientStats += $stats
    }
}

if ($allClientStats.Count -eq 0) {
    Write-Error "No client statistics were generated. Exiting."
    exit 1
}

if (-not $OutputPath) {
    $baseDirectory = Get-Location
    try {
        # Test if we can write to current directory
        $testFile = Join-Path $baseDirectory "test_write_access.tmp"
        "test" | Out-File -FilePath $testFile -Force
        Remove-Item $testFile -Force
    }
    catch {
        # If current directory doesn't work, use Documents folder
        $baseDirectory = [Environment]::GetFolderPath("MyDocuments")
        Write-Host "Using Documents folder: $baseDirectory" -ForegroundColor Yellow
    }
    
    if ($allClientStats.Count -eq 1) {
        $clientNameSafe = $allClientStats[0].ClientName -replace '[^a-zA-Z0-9\-_]', '_'
        $OutputPath = Join-Path $baseDirectory "UserReport_$($clientNameSafe)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    } else {
        $OutputPath = Join-Path $baseDirectory "UserReport_MultiClient_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    }
}

# HTML Report
$reportDate = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"

$clientSectionsHtml = ""
$summaryCardsHtml = ""
$totalUsers = 0
$totalEnabled = 0
$totalGuests = 0

foreach ($stats in $allClientStats) {
    $totalUsers += $stats.TotalUsers
    $totalEnabled += $stats.EnabledUsers
    $totalGuests += $stats.GuestUsers
    $totalLicensed += $stats.LicensedUsers
    
    $clientSectionsHtml += @"
        <div class="client-section">
            <h2>$($stats.ClientName)</h2>
            <div class="info-section">
                <strong>Organization:</strong> $($stats.OrgName)<br>
                <strong>Tenant ID:</strong> $($stats.TenantId)
            </div>
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">$($stats.TotalUsers)</div>
                    <div class="stat-label">Total Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$($stats.EnabledUsers)</div>
                    <div class="stat-label">Enabled Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$($stats.DisabledUsers)</div>
                    <div class="stat-label">Disabled Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$($stats.GuestUsers)</div>
                    <div class="stat-label">Guest Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$($stats.MemberUsers)</div>
                    <div class="stat-label">Member Users</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">$($stats.LicensedUsers)</div>
                    <div class="stat-label">Licensed Users</div>
                </div>
            </div>

            <h3>Detailed Breakdown - $($stats.ClientName)</h3>
            <table>
                <tr><th>Category</th><th>Count</th><th>Percentage</th></tr>
                <tr><td>Enabled Members</td><td>$($stats.EnabledMembers)</td><td>$([math]::Round(($stats.EnabledMembers / $stats.TotalUsers) * 100, 2))%</td></tr>
                <tr><td>Disabled Members</td><td>$($stats.DisabledMembers)</td><td>$([math]::Round(($stats.DisabledMembers / $stats.TotalUsers) * 100, 2))%</td></tr>
                <tr><td>Enabled Guests</td><td>$($stats.EnabledGuests)</td><td>$([math]::Round(($stats.EnabledGuests / $stats.TotalUsers) * 100, 2))%</td></tr>
                <tr><td>Disabled Guests</td><td>$($stats.DisabledGuests)</td><td>$([math]::Round(($stats.DisabledGuests / $stats.TotalUsers) * 100, 2))%</td></tr>
                <tr><td>Recently Created (30 days)</td><td>$($stats.RecentlyCreatedUsers)</td><td>$([math]::Round(($stats.RecentlyCreatedUsers / $stats.TotalUsers) * 100, 2))%</td></tr>
            </table>

            <div class="security-insights">
                <h3>Security Insights - $($stats.ClientName)</h3>
                <div class="info-section">
                    <strong>Guest User Ratio:</strong> $([math]::Round(($stats.GuestUsers / $stats.TotalUsers) * 100, 2))% of total users are guests<br>
                    <strong>Account Status:</strong> $([math]::Round(($stats.EnabledUsers / $stats.TotalUsers) * 100, 2))% of accounts are enabled<br>
                    <strong>Licensing Coverage:</strong> $([math]::Round(($stats.LicensedUsers / $stats.TotalUsers) * 100, 2))% of users have assigned licenses
                </div>

                $(if ($stats.DisabledUsers -gt ($stats.TotalUsers * 0.1)) {
                    "<div class='warning'><strong>Security Note:</strong> High number of disabled accounts detected ($($stats.DisabledUsers)). Consider reviewing and cleaning up unused accounts.</div>"
                })

                $(if ($stats.GuestUsers -gt ($stats.TotalUsers * 0.2)) {
                    "<div class='warning'><strong>Security Note:</strong> High percentage of guest users detected ($([math]::Round(($stats.GuestUsers / $stats.TotalUsers) * 100, 2))%). Review guest access policies and permissions.</div>"
                })
            </div>
        </div>
"@
}

# Generate summary section for multi-client reports
$summarySection = ""
if ($allClientStats.Count -gt 1) {
    $summarySection = @"
        <div class="summary-section">
            <h2>Multi-Client Summary</h2>
            <div class="stats-grid">
                <div class="stat-card summary-card">
                    <div class="stat-number">$($allClientStats.Count)</div>
                    <div class="stat-label">Total Clients</div>
                </div>
                <div class="stat-card summary-card">
                    <div class="stat-number">$totalUsers</div>
                    <div class="stat-label">Combined Users</div>
                </div>
                <div class="stat-card summary-card">
                    <div class="stat-number">$totalEnabled</div>
                    <div class="stat-label">Combined Enabled</div>
                </div>
                <div class="stat-card summary-card">
                    <div class="stat-number">$totalLicensed</div>
                    <div class="stat-label">Combined Licensed</div>
                </div>
                <div class="stat-card summary-card">
                    <div class="stat-number">$totalGuests</div>
                    <div class="stat-label">Combined Guests</div>
                </div>
            </div>
        </div>
"@
}

# Generate Top 25 Rankings section
$topClientsSection = ""
if ($allClientStats.Count -gt 1 -and $ShowTopClients) {
    # Sort clients by different metrics
    $topByTotalUsers = $allClientStats | Sort-Object TotalUsers -Descending | Select-Object -First 25
    $topByEnabledUsers = $allClientStats | Sort-Object EnabledUsers -Descending | Select-Object -First 25
    $topByLicensedUsers = $allClientStats | Sort-Object LicensedUsers -Descending | Select-Object -First 25
    $topByGuestUsers = $allClientStats | Sort-Object GuestUsers -Descending | Select-Object -First 25
    
    $topClientsSection = @"
        <div class="top-clients-section">
            <h2>Top 25 Client Rankings</h2>
            
            <div class="rankings-container">
                <div class="ranking-column">
                    <h3>Top 25 by Total Users</h3>
                    <table class="ranking-table">
                        <tr><th>Rank</th><th>Client</th><th>Total Users</th></tr>
"@
    
    $rank = 1
    foreach ($client in $topByTotalUsers) {
        $topClientsSection += "<tr><td>$rank</td><td>$($client.ClientName)</td><td>$($client.TotalUsers)</td></tr>"
        $rank++
    }
    
    $topClientsSection += @"
                    </table>
                </div>
                
                <div class="ranking-column">
                    <h3>Top 25 by Enabled Users</h3>
                    <table class="ranking-table">
                        <tr><th>Rank</th><th>Client</th><th>Enabled Users</th></tr>
"@
    
    $rank = 1
    foreach ($client in $topByEnabledUsers) {
        $topClientsSection += "<tr><td>$rank</td><td>$($client.ClientName)</td><td>$($client.EnabledUsers)</td></tr>"
        $rank++
    }
    
    $topClientsSection += @"
                    </table>
                </div>
                
                <div class="ranking-column">
                    <h3>Top 25 by Licensed Users</h3>
                    <table class="ranking-table">
                        <tr><th>Rank</th><th>Client</th><th>Licensed Users</th></tr>
"@
    
    $rank = 1
    foreach ($client in $topByLicensedUsers) {
        $topClientsSection += "<tr><td>$rank</td><td>$($client.ClientName)</td><td>$($client.LicensedUsers)</td></tr>"
        $rank++
    }
    
    $topClientsSection += @"
                    </table>
                </div>
                
                <div class="ranking-column">
                    <h3>Top 25 by Guest Users</h3>
                    <table class="ranking-table">
                        <tr><th>Rank</th><th>Client</th><th>Guest Users</th></tr>
"@
    
    $rank = 1
    foreach ($client in $topByGuestUsers) {
        $topClientsSection += "<tr><td>$rank</td><td>$($client.ClientName)</td><td>$($client.GuestUsers)</td></tr>"
        $rank++
    }
    
    $topClientsSection += @"
                    </table>
                </div>
            </div>
        </div>
"@
}

$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Azure AD User Statistics Report</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5; 
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h1 { 
            color: #2c3e50; 
            text-align: center; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 10px; 
        }
        h2 { 
            color: #34495e; 
            border-left: 4px solid #3498db; 
            padding-left: 15px; 
            margin-top: 30px;
        }
        h3 { 
            color: #2c3e50; 
            margin-top: 20px;
        }
        .client-section {
            margin-bottom: 40px;
            padding: 20px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background-color: #fafafa;
        }
        .summary-section {
            margin-bottom: 30px;
            padding: 20px;
            background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
            border-radius: 8px;
            color: white;
        }
        .summary-card {
            background: rgba(255,255,255,0.2) !important;
            backdrop-filter: blur(10px);
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
            gap: 20px; 
            margin: 20px 0; 
        }
        .stat-card { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 20px; 
            border-radius: 8px; 
            text-align: center; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
        }
        .stat-number { 
            font-size: 2.5em; 
            font-weight: bold; 
            margin-bottom: 5px; 
        }
        .stat-label { 
            font-size: 1.1em; 
            opacity: 0.9; 
        }
        .info-section { 
            background-color: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            margin: 15px 0; 
        }
        .security-insights {
            margin-top: 20px;
        }
        .warning { 
            background-color: #f39c12; 
            color: white; 
            padding: 10px; 
            border-radius: 5px; 
            margin: 10px 0; 
        }
        .footer { 
            text-align: center; 
            margin-top: 30px; 
            padding-top: 20px; 
            border-top: 1px solid #bdc3c7; 
            color: #7f8c8d; 
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
        }
        th, td { 
            padding: 12px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
        }
        th { 
            background-color: #3498db; 
            color: white; 
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .top-clients-section {
            margin: 30px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 8px;
        }
        .rankings-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        .ranking-column {
            background-color: white;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .ranking-table {
            margin: 10px 0;
            font-size: 0.9em;
        }
        .ranking-table th {
            background-color: #6c757d;
            font-size: 0.85em;
            padding: 8px;
        }
        .ranking-table td {
            padding: 6px 8px;
            font-size: 0.85em;
        }
        .ranking-table tr:nth-child(even) {
            background-color: #f8f9fa;
        }
        .ranking-table tr:nth-child(-n+3) td:first-child {
            font-weight: bold;
            color: #dc3545;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Azure AD User Statistics Report</h1>
        
        <div class="info-section">
            <strong>Report Generated:</strong> $reportDate<br>
            <strong>Clients Processed:</strong> $($allClientStats.Count)
        </div>

        $summarySection

        $topClientsSection

        $clientSectionsHtml

        <div class="footer">
            <p>Report generated by Azure AD User Statistics PowerShell Script</p>
            <p>For SOC analysis and security monitoring purposes</p>
        </div>
    </div>
</body>
</html>
"@

# Save HTML
try {
    $htmlContent | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report generated successfully!" -ForegroundColor Green
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Cyan
    
    # Display report
    Write-Host "`nOverall Summary:" -ForegroundColor Yellow
    Write-Host "===============" -ForegroundColor Yellow
    Write-Host "Clients Processed: $($allClientStats.Count)"
    Write-Host "Total Combined Users: $totalUsers"
    Write-Host "Total Combined Enabled: $totalEnabled"
    Write-Host "Total Combined Licensed: $totalLicensed"
    Write-Host "Total Combined Guests: $totalGuests"
    
    Write-Host "`nPer-Client Summary:" -ForegroundColor Yellow
    Write-Host "==================" -ForegroundColor Yellow
    foreach ($stats in $allClientStats) {
        Write-Host "$($stats.ClientName): $($stats.TotalUsers) total, $($stats.EnabledUsers) enabled, $($stats.LicensedUsers) licensed, $($stats.GuestUsers) guests"
    }
    
    if (Get-Command "Invoke-Item" -ErrorAction SilentlyContinue) {
        $openReport = Read-Host "`nWould you like to open the HTML report? (Y/N)"
        if ($openReport -eq "Y" -or $openReport -eq "y") {
            Invoke-Item $OutputPath
        }
    }
}
catch {
    Write-Error "Failed to save report: $($_.Exception.Message)"
    exit 1
}
