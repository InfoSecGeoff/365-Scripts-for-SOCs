<#
.SYNOPSIS
    Generates comprehensive Microsoft 365/Office 365 license reports from Azure AD/Entra ID tenants using Microsoft Graph API.

.DESCRIPTION
    This script connects to Microsoft Graph API using application credentials to enumerate all subscribed licenses within specified Azure AD/Entra ID tenant(s). 
    It retrieves detailed licensing information including total seats, consumed units, available capacity, and license status across all SKUs.
    
    The script can process either a single tenant or multiple tenants from a CSV file, providing clear visibility into license utilization 
    and helping identify optimization opportunities for cost management and compliance.

    Key features:
    - Enumerates all Microsoft 365/Office 365 license SKUs
    - Maps technical SKU names to friendly license names
    - Calculates utilization rates and available capacity
    - Supports batch processing of multiple tenants
    - Exports detailed CSV reports for analysis
    - Provides cost optimization insights
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

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Required Graph API Permissions:
        - Organization.Read.All (Application permission)
        - Directory.Read.All (Application permission)

.EXAMPLE
    .\Get-LicenseReport.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret"
    
    Processes a single tenant and generates HTML and CSV reports.

.EXAMPLE
    .\Get-LicenseReport.ps1 -CsvPath "C:\Scripts\clients.csv"
    
    Processes all tenants listed in the CSV file and generates consolidated reports.

.EXAMPLE
    .\Get-LicenseReport.ps1 -CsvPath "C:\Scripts\clients.csv" -ClientName "Contoso Corporation"
    
    Processes only the "Contoso Corporation" tenant from the CSV file.

.EXAMPLE
    $licenses = .\Get-LicenseReport.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret"
    $licenses | Where-Object { $_.AvailableSeats -gt 0 }
    
    Retrieves license data and filters to show only licenses with available capacity.
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
    [string]$ClientName
)

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

function Get-SubscribedSkus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/subscribedSkus" -Method Get -Headers $headers
        return $response.value
    }
    catch {
        Write-Error "Error retrieving subscribed SKUs: $_"
        throw $_
    }
}

function Get-FriendlyLicenseName {
    param (
        [Parameter(Mandatory=$true)]
        [string]$SkuPartNumber
    )
    
    $licenseMap = @{
        "AAD_PREMIUM"                    = "Azure AD Premium P1"
        "AAD_PREMIUM_P2"                 = "Azure AD Premium P2"
        "ADALLOM_S_O365"                 = "Office 365 Advanced Security Management"
        "ADALLOM_S_STANDALONE"           = "Microsoft Cloud App Security"
        "ATP_ENTERPRISE"                 = "Exchange Online Advanced Threat Protection"
        "CRMSTANDARD"                    = "Microsoft Dynamics CRM Online Professional"
        "DYN365_ENTERPRISE_PLAN1"        = "Dynamics 365 Plan 1 Enterprise"
        "DYN365_ENTERPRISE_CUSTOMER_SERVICE" = "Dynamics 365 for Customer Service Enterprise"
        "DYN365_ENTERPRISE_SALES"        = "Dynamics 365 for Sales Enterprise"
        "EMS"                            = "Enterprise Mobility + Security E3"
        "EMSPREMIUM"                     = "Enterprise Mobility + Security E5"
        "EXCHANGESTANDARD"               = "Exchange Online Plan 1"
        "EXCHANGEENTERPRISE"             = "Exchange Online Plan 2"
        "EXCHANGEARCHIVE_ADDON"          = "Exchange Online Archiving"
        "EXCHANGEDESKLESS"               = "Exchange Online Kiosk"
        "FLOW_FREE"                      = "Microsoft Power Automate Free"
        "FLOW_P2"                        = "Microsoft Power Automate Premium"
        "INTUNE_A"                       = "Intune"
        "MCOEV"                          = "Microsoft Phone System"
        "MCOPSTN1"                       = "Microsoft 365 Domestic Calling Plan"
        "MCOPSTN2"                       = "Microsoft 365 Domestic and International Calling Plan"
        "MCOMEETADV"                     = "Microsoft 365 Audio Conferencing"
        "MCOSTANDARD"                    = "Skype for Business Online Plan 2"
        "MS_TEAMS_IW"                    = "Microsoft Teams"
        "OFFICESUBSCRIPTION"             = "Microsoft 365 Apps for Enterprise"
        "O365_BUSINESS_ESSENTIALS"       = "Microsoft 365 Business Basic"
        "O365_BUSINESS_PREMIUM"          = "Microsoft 365 Business Standard"
        "O365_BUSINESS"                  = "Microsoft 365 Apps for Business"
        "SPE_E3"                         = "Microsoft 365 E3"
        "SPE_E5"                         = "Microsoft 365 E5"
        "SHAREPOINTSTANDARD"             = "SharePoint Online Plan 1"
        "SHAREPOINTENTERPRISE"           = "SharePoint Online Plan 2"
        "PROJECTPROFESSIONAL"            = "Project Online Professional"
        "PROJECTPREMIUM"                 = "Project Online Premium"
        "POWER_BI_STANDARD"              = "Power BI Free"
        "POWER_BI_PRO"                   = "Power BI Pro"
        "POWER_BI_PREMIUM_P1"            = "Power BI Premium P1"
        "VISIO_PLAN1_DEPT"               = "Visio Online Plan 1"
        "VISIO_PLAN2_DEPT"               = "Visio Online Plan 2"
        "WIN_DEF_ATP"                    = "Microsoft Defender for Endpoint"
        "WINDOWS_STORE"                  = "Windows Store for Business"
        "WINDOWS10_PRO_ENT_SUB"          = "Windows 10 Enterprise E3"
        "WINDOWS10_VDA_E3"               = "Windows 10 Enterprise E3"
        "WINDOWS10_VDA_E5"               = "Windows 10 Enterprise E5"
        "TEAMS_COMMERCIAL_TRIAL"         = "Microsoft Teams Commercial Trial"
        "TEAMS_EXPLORATORY"              = "Microsoft Teams Exploratory"
        "ENTERPRISEPACK"                 = "Office 365 E3"
        "ENTERPRISEPREMIUM"              = "Office 365 E5"
        "ENTERPRISEPREMIUM_NOPSTNCONF"   = "Office 365 E5 without Audio Conferencing"
        "ENTERPRISEPACK_USGOV_DOD"       = "Office 365 E3 for Government"
        "ENTERPRISEWITHSCAL"             = "Office 365 E4"
    }
    
    if ($licenseMap.ContainsKey($SkuPartNumber)) {
        return $licenseMap[$SkuPartNumber]
    } else {
        return $SkuPartNumber
    }
}

function Generate-LicenseHtmlReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$ClientsData,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $successfulClients = $ClientsData | Where-Object { $_.Success }
    $failedClients = $ClientsData | Where-Object { -not $_.Success }
    
    $htmlHeader = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>License Utilization Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        h1 {
            color: #0078d4;
            border-bottom: 2px solid #0078d4;
            padding-bottom: 10px;
        }
        h2 {
            color: #0078d4;
            margin-top: 30px;
        }
        .client-section {
            margin-bottom: 40px;
            border: 2px solid #0078d4;
            border-radius: 8px;
            padding: 20px;
            background-color: #fff;
        }
        .client-header {
            background: linear-gradient(135deg, #0078d4, #005a9e);
            color: white;
            padding: 15px;
            margin: -20px -20px 20px -20px;
            border-radius: 6px 6px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .client-name {
            font-size: 20px;
            font-weight: bold;
            margin: 0;
        }
        .client-stats {
            font-size: 14px;
            opacity: 0.9;
        }
        .license-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        .license-table th,
        .license-table td {
            border: 1px solid #ddd;
            padding: 12px;
            text-align: left;
        }
        .license-table th {
            background-color: #0078d4;
            color: white;
            font-weight: bold;
        }
        .license-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .license-table tr:hover {
            background-color: #e8f4f8;
        }
        .utilization-bar {
            width: 100px;
            height: 20px;
            background-color: #e0e0e0;
            border-radius: 10px;
            overflow: hidden;
            position: relative;
        }
        .utilization-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        .util-high { background-color: #d32f2f; }
        .util-medium { background-color: #ff9800; }
        .util-low { background-color: #4caf50; }
        .util-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 12px;
            font-weight: bold;
            color: #333;
            text-shadow: 1px 1px 1px rgba(255,255,255,0.7);
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #0078d4;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #0078d4;
            font-size: 16px;
        }
        .summary-card .value {
            font-size: 24px;
            font-weight: bold;
            color: #333;
        }
        .timestamp {
            font-style: italic;
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }
        .search-box {
            width: 100%;
            padding: 10px;
            margin-bottom: 20px;
            border: 1px solid #ddd;
            border-radius: 4px;
            font-size: 16px;
        }
        .no-licenses {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 40px;
        }
        .status-enabled { color: #4caf50; font-weight: bold; }
        .status-warning { color: #ff9800; font-weight: bold; }
        .status-disabled { color: #d32f2f; font-weight: bold; }
    </style>
    <script>
        function filterTable(clientName) {
            const searchInput = document.getElementById('search-' + clientName);
            const filter = searchInput.value.toUpperCase();
            const table = document.getElementById('table-' + clientName);
            const rows = table.getElementsByTagName('tr');
            
            for (let i = 1; i < rows.length; i++) {
                let found = false;
                const cells = rows[i].getElementsByTagName('td');
                
                for (let j = 0; j < cells.length; j++) {
                    const text = cells[j].textContent || cells[j].innerText;
                    if (text.toUpperCase().indexOf(filter) > -1) {
                        found = true;
                        break;
                    }
                }
                
                rows[i].style.display = found ? '' : 'none';
            }
        }
    </script>
</head>
<body>
    <div class="container">
        <h1>License Utilization Report</h1>
        <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
"@

    if ($ClientsData.Count -gt 1) {
        $totalLicenses = ($successfulClients | Measure-Object -Property TotalLicenses -Sum).Sum
        $totalConsumed = ($successfulClients | Measure-Object -Property TotalConsumed -Sum).Sum
        $totalAvailable = ($successfulClients | Measure-Object -Property TotalAvailable -Sum).Sum
        $avgUtilization = if ($totalLicenses -gt 0) { [math]::Round(($totalConsumed / $totalLicenses) * 100, 1) } else { 0 }
        
        $htmlHeader += @"
        
        <div class="summary-cards">
            <div class="summary-card">
                <h3>Total Clients</h3>
                <div class="value">$($ClientsData.Count)</div>
            </div>
            <div class="summary-card">
                <h3>Total Licenses</h3>
                <div class="value">$totalLicenses</div>
            </div>
            <div class="summary-card">
                <h3>Total Consumed</h3>
                <div class="value">$totalConsumed</div>
            </div>
            <div class="summary-card">
                <h3>Total Available</h3>
                <div class="value">$totalAvailable</div>
            </div>
            <div class="summary-card">
                <h3>Avg Utilization</h3>
                <div class="value">$avgUtilization%</div>
            </div>
        </div>
"@
    }

    $clientsHtml = ""
    
    foreach ($client in $successfulClients) {
        $safeClientName = $client.ClientName -replace '[^a-zA-Z0-9]', ''
        
        $clientsHtml += @"
        <div class="client-section">
            <div class="client-header">
                <span class="client-name">$($client.ClientName)</span>
                <div class="client-stats">
                    $($client.TotalLicenses) Total | $($client.TotalConsumed) Used | $($client.TotalAvailable) Available
                </div>
            </div>
"@
        
        if ($client.LicenseReport.Count -eq 0) {
            $clientsHtml += @"
            <div class="no-licenses">No licenses found for this client.</div>
"@
        } else {
            $clientsHtml += @"
            <input type="text" id="search-$safeClientName" class="search-box" onkeyup="filterTable('$safeClientName')" placeholder="Search licenses for $($client.ClientName)...">
            
            <table class="license-table" id="table-$safeClientName">
                <thead>
                    <tr>
                        <th>License Name</th>
                        <th>SKU</th>
                        <th>Total Seats</th>
                        <th>Used</th>
                        <th>Available</th>
                        <th>Utilization</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
"@
            
            foreach ($license in ($client.LicenseReport | Sort-Object DisplayName)) {
                $utilization = if ($license.TotalSeats -gt 0) { [math]::Round(($license.ActiveSeats / $license.TotalSeats) * 100, 1) } else { 0 }
                
                $utilizationClass = if ($utilization -ge 90) { "util-high" } elseif ($utilization -ge 70) { "util-medium" } else { "util-low" }
                
                $statusClass = switch ($license.Status) {
                    "Enabled" { "status-enabled" }
                    "Warning" { "status-warning" }
                    default { "status-disabled" }
                }
                
                $clientsHtml += @"
                    <tr>
                        <td><strong>$($license.DisplayName)</strong></td>
                        <td>$($license.SkuPartNumber)</td>
                        <td>$($license.TotalSeats)</td>
                        <td>$($license.ActiveSeats)</td>
                        <td>$($license.AvailableSeats)</td>
                        <td>
                            <div class="utilization-bar">
                                <div class="utilization-fill $utilizationClass" style="width: $utilization%;"></div>
                                <div class="util-text">$utilization%</div>
                            </div>
                        </td>
                        <td class="$statusClass">$($license.Status)</td>
                    </tr>
"@
            }
            
            $clientsHtml += @"
                </tbody>
            </table>
"@
        }
        
        $clientsHtml += @"
        </div>
"@
    }
    
    if ($failedClients.Count -gt 0) {
        $clientsHtml += @"
        <h2 style="color: #D13438;">Failed Clients</h2>
"@
        
        foreach ($client in $failedClients) {
            $clientsHtml += @"
        <div class="client-section">
            <div class="client-header" style="background: linear-gradient(135deg, #D13438, #a91b1b);">
                <span class="client-name">$($client.ClientName)</span>
                <span style="background-color: rgba(255,255,255,0.2); padding: 3px 8px; border-radius: 3px;">Failed</span>
            </div>
            <div style="background-color: #fef2f2; border: 1px solid #fecaca; color: #dc2626; padding: 10px; border-radius: 5px;">
                <strong>Error:</strong> $($client.Error)
            </div>
        </div>
"@
        }
    }

    $htmlFooter = @"
    </div>
</body>
</html>
"@

    $htmlReport = $htmlHeader + $clientsHtml + $htmlFooter
    
    $htmlReport | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "License HTML report generated: $OutputPath" -ForegroundColor Green
    
    return $OutputPath
}

function Process-SingleClient {
    param (
        [string]$ClientName,
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret
    )
    
    $clientData = @{
        ClientName = $ClientName
        TenantId = $TenantId
        ClientId = $ClientId
        TotalLicenses = 0
        TotalConsumed = 0
        TotalAvailable = 0
        Success = $false
        Error = ""
        LicenseReport = @()
    }
    
    try {
        Write-Host "`n=======================================================" -ForegroundColor Cyan
        Write-Host "Processing tenant: $ClientName ($TenantId)" -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan
        
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        
        Write-Host "Retrieving license information..." -ForegroundColor Yellow
        $subscribedSkus = Get-SubscribedSkus -AccessToken $accessToken
        
        $licenseReport = @()
        $totalLicenses = 0
        $totalConsumed = 0
        
        foreach ($sku in $subscribedSkus) {
            $friendlyName = Get-FriendlyLicenseName -SkuPartNumber $sku.skuPartNumber
            
            $licenseData = [PSCustomObject]@{
                ClientName     = $ClientName
                TenantId       = $TenantId
                DisplayName    = $friendlyName
                SkuPartNumber  = $sku.skuPartNumber
                SkuId          = $sku.skuId
                TotalSeats     = $sku.prepaidUnits.enabled
                ActiveSeats    = $sku.consumedUnits
                AvailableSeats = $sku.prepaidUnits.enabled - $sku.consumedUnits
                Status         = $sku.capabilityStatus
            }
            
            $licenseReport += $licenseData
            $totalLicenses += $sku.prepaidUnits.enabled
            $totalConsumed += $sku.consumedUnits
        }
        
        $clientData.TotalLicenses = $totalLicenses
        $clientData.TotalConsumed = $totalConsumed
        $clientData.TotalAvailable = $totalLicenses - $totalConsumed
        $clientData.LicenseReport = $licenseReport
        
        $licenseReport | Sort-Object DisplayName | Format-Table -AutoSize | Out-Host
        
        Write-Host "`nLicense Summary for $ClientName :" -ForegroundColor Green
        Write-Host "  Total License Seats: $totalLicenses" -ForegroundColor Cyan
        Write-Host "  Consumed Seats: $totalConsumed" -ForegroundColor Cyan
        Write-Host "  Available Seats: $($totalLicenses - $totalConsumed)" -ForegroundColor Cyan
        Write-Host "  Utilization: $([math]::Round(($totalConsumed / $totalLicenses) * 100, 1))%" -ForegroundColor Cyan
        
        $clientData.Success = $true
        Write-Host "Successfully processed $ClientName" -ForegroundColor Green
        
    } catch {
        $clientData.Error = $_.Exception.Message
        Write-Host "Failed to process $ClientName : $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $clientData
}

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

$outputFolder = $null
if ($clientsToProcess.Count -gt 1 -and -not $isSpecificClient) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $outputFolder = "LicenseReports-$timestamp"
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    Write-Host "Created output folder: $outputFolder" -ForegroundColor Green
}

$allClientResults = @()

foreach ($client in $clientsToProcess) {
    if ([string]::IsNullOrWhiteSpace($client.'Tenant ID') -or 
        [string]::IsNullOrWhiteSpace($client.'Client ID') -or 
        [string]::IsNullOrWhiteSpace($client.'Key Value')) {
        Write-Warning "Skipping client '$($client.Client)' - Missing required credential information"
        continue
    }
    
    $clientResult = Process-SingleClient -ClientName $client.Client.Trim() -TenantId $client.'Tenant ID'.Trim() -ClientId $client.'Client ID'.Trim() -ClientSecret $client.'Key Value'.Trim()
    
    if ($clientResult -and $clientResult.ClientName) {
        $allClientResults += $clientResult
    }
}

if ($isSpecificClient) {
    if ($allClientResults.Count -eq 1) {
        $result = $allClientResults[0]
        if ($result.Success) {
            $htmlReportPath = "License-Report-$($result.ClientName -replace '[\\\/\:\*\?"<>\|]', '_')-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
            Generate-LicenseHtmlReport -ClientsData @($result) -OutputPath $htmlReportPath
            
            $safeClientName = $result.ClientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $csvOutputFile = "$safeClientName-Licenses-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            $result.LicenseReport | Export-Csv -Path $csvOutputFile -NoTypeInformation
            
            Write-Host "`n=== REPORTS GENERATED ===" -ForegroundColor Magenta
            Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
            Write-Host "CSV Report: $csvOutputFile" -ForegroundColor Green
        } else {
            Write-Host "Processing failed: $($result.Error)" -ForegroundColor Red
        }
    } else {
        Write-Host "Error: Expected 1 client result but got $($allClientResults.Count)" -ForegroundColor Red
    }
    
    exit
}

elseif ($allClientResults.Count -gt 1 -and -not $isSpecificClient) {
    Write-Host "`n=== EXECUTION SUMMARY ===" -ForegroundColor Magenta
    $successfulResults = $allClientResults | Where-Object { $_.Success }
    $failedResults = $allClientResults | Where-Object { -not $_.Success }
    
    $successCount = $successfulResults.Count
    $failCount = $failedResults.Count
    
    $totalLicenses = 0
    $totalConsumed = 0
    
    if ($successfulResults.Count -gt 0) {
        $totalLicenses = ($successfulResults | Measure-Object -Property TotalLicenses -Sum).Sum
        $totalConsumed = ($successfulResults | Measure-Object -Property TotalConsumed -Sum).Sum
    }
    
    Write-Host "Clients processed: $($allClientResults.Count)" -ForegroundColor Cyan
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "Total licenses found: $totalLicenses" -ForegroundColor Yellow
    Write-Host "Total consumed: $totalConsumed" -ForegroundColor Yellow
    
    if ($outputFolder) {
        Write-Host "Reports saved to folder: $outputFolder" -ForegroundColor Green
    }
    
    if ($failCount -gt 0) {
        Write-Host "`nFailed clients:" -ForegroundColor Red
        $failedResults | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ClientName) } | ForEach-Object {
            Write-Host "  - $($_.ClientName): $($_.Error)" -ForegroundColor Yellow
        }
    }
    
    if ($outputFolder) {
        $consolidatedLicenses = @()
        
        foreach ($result in $successfulResults) {
            $consolidatedLicenses += $result.LicenseReport
        }
        
        $consolidatedLicenseFile = Join-Path -Path $outputFolder -ChildPath "All-Clients-Licenses.csv"
        $consolidatedLicenses | Export-Csv -Path $consolidatedLicenseFile -NoTypeInformation
        
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "All-Clients-License-Report.html"
        Generate-LicenseHtmlReport -ClientsData $allClientResults -OutputPath $htmlReportPath
        
        Write-Host "`nConsolidated reports created:" -ForegroundColor Green
        Write-Host "  CSV: $consolidatedLicenseFile" -ForegroundColor Cyan
        Write-Host "  HTML Report: $htmlReportPath" -ForegroundColor Cyan
        
        foreach ($result in $successfulResults) {
            $safeClientName = $result.ClientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $clientCsvFile = Join-Path -Path $outputFolder -ChildPath "$safeClientName-Licenses.csv"
            $result.LicenseReport | Export-Csv -Path $clientCsvFile -NoTypeInformation
        }
    }
}
else {
    if ($allClientResults.Count -eq 0) {
        Write-Host "No clients were processed." -ForegroundColor Red
    }
}
