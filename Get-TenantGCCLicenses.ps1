<#
.SYNOPSIS
    Detects whether Microsoft 365 tenants are in Government Community Cloud (GCC/GCC High) or Commercial environments.

.DESCRIPTION
    This script analyzes Azure AD/Entra ID tenants to determine their cloud environment type using multiple detection methods:
    - SKU Analysis: Identifies government licenses with _GOV suffix
    - OpenID Configuration: Checks tenant_region_scope from authentication endpoints
    - Endpoint Authentication: Tests GCC High (graph.microsoft.us) endpoints
    - Process of Elimination: Classifies as Commercial when no government indicators found
    
    The script generates a professional HTML report with interactive expandable sections and exports data to CSV.
    Results are automatically sorted to display GCC/GCC High tenants at the top for quick review.
    
    Key features:
    - Supports single tenant or batch processing from CSV
    - Fuzzy matching for client names (e.g., "AME" matches "The AME Group")
    - Retrieves license information and tenant metadata
    - Identifies Commercial, GCC, GCC High, and Unknown environments
    - Color-coded visual indicators and section headers
    - Multiple output formats (HTML and CSV)

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
    Supports fuzzy matching (e.g., "Landrum" matches "Landrum & Shouse", "AME" matches "The AME Group").
    
    Example: "Contoso Corporation"

.INPUTS
    CSV file with tenant credentials (optional)
    Individual tenant parameters via command line

.OUTPUTS
    HTML Report: <ClientName>GCCTenantReport.html (single client) or GCCGlobalTenantReport.html (multiple clients)
    CSV Report: <ClientName>GCCTenantReport.csv (single client) or GCCGlobalTenantReport.csv (multiple clients)

.EXAMPLE
    .\Get-TenantGCCLicenses.ps1.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret"
    
    Analyzes a single tenant and generates <OrganizationName>GCCTenantReport.html and .csv files.

.EXAMPLE
    .\Get-TenantGCCLicenses.ps1.ps1 -CsvPath "C:\Scripts\clients.csv"
    
    Processes all tenants listed in the CSV file and generates GCCGlobalTenantReport.html with GCC tenants at the top.

.EXAMPLE
    .\Get-TenantGCCLicenses.ps1.ps1 -CsvPath "C:\Scripts\clients.csv" -ClientName "Contoso"
    
    Processes only the "Contoso" tenant (or any tenant containing "Contoso" in the name) from the CSV file.
    Generates ContosoGCCTenantReport.html and .csv files.

.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Required Graph API Permissions:
      - Organization.Read.All (Application permission)
      - Directory.Read.All (Application permission)
    
    Cloud Environments Detected:
    - Microsoft 365 Commercial: Standard commercial tenants
    - Microsoft 365 GCC: Government Community Cloud (uses commercial endpoints with _GOV licenses)
    - Microsoft 365 GCC High: Isolated government cloud (uses graph.microsoft.us endpoints)
    - Unknown: Authentication failures
    
    Security Considerations:
    - Client secrets should be stored securely
    - Application should use least-privilege permissions
    - Consider using certificate-based authentication for production
    - Audit application access regularly
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

function Get-MsGraphToken {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret,
        
        [Parameter(Mandatory=$false)]
        [string]$GraphEndpoint = "https://graph.microsoft.com"
    )
    
    $loginEndpoint = if ($GraphEndpoint -eq "https://graph.microsoft.us") {
        "https://login.microsoftonline.us"
    } else {
        "https://login.microsoftonline.com"
    }
    
    $tokenUrl = "$loginEndpoint/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "$GraphEndpoint/.default"
        grant_type    = "client_credentials"
    }
    
    try {
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
        return $response.access_token
    }
    catch {
        return $null
    }
}

function Get-TenantRegionScope {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Domain
    )
    
    try {
        $uri = "https://login.windows.net/$Domain/.well-known/openid-configuration"
        $response = Invoke-RestMethod -Uri $uri -Method Get -ErrorAction Stop
        return $response.tenant_region_scope
    }
    catch {
        return $null
    }
}

function Get-TenantDomain {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [string]$GraphEndpoint = "https://graph.microsoft.com"
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$GraphEndpoint/v1.0/domains" -Method Get -Headers $headers -ErrorAction Stop
        $initialDomain = $response.value | Where-Object { $_.isInitial -eq $true } | Select-Object -First 1
        return $initialDomain.id
    }
    catch {
        return $null
    }
}

function Get-SubscribedSkus {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [string]$GraphEndpoint = "https://graph.microsoft.com"
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$GraphEndpoint/v1.0/subscribedSkus" -Method Get -Headers $headers -ErrorAction Stop
        return $response.value
    }
    catch {
        return @()
    }
}

function Get-OrganizationInfo {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [string]$GraphEndpoint = "https://graph.microsoft.com"
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "$GraphEndpoint/v1.0/organization" -Method Get -Headers $headers -ErrorAction Stop
        return $response.value | Select-Object -First 1
    }
    catch {
        return $null
    }
}

function Test-CloudEnvironment {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientId,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientSecret
    )
    
    $result = [PSCustomObject]@{
        TenantId = $TenantId
        CloudType = "Unknown"
        CloudEnvironment = "Unknown"
        AuthenticationEndpoint = "Unknown"
        GraphEndpoint = "Unknown"
        InitialDomain = "Unknown"
        TenantRegionScope = "Unknown"
        HasGovLicenses = $false
        GovLicenseCount = 0
        TotalLicenseCount = 0
        GovLicenses = @()
        AllLicenses = @()
        OrganizationName = "Unknown"
        VerifiedDomains = @()
        DetectionMethod = "Unknown"
        Notes = @()
    }
    
    Write-Verbose "Testing Commercial Cloud authentication..."
    $commercialToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint "https://graph.microsoft.com"
    
    if ($commercialToken) {
        Write-Verbose "Successfully authenticated to Commercial Cloud"
        $result.AuthenticationEndpoint = "https://login.microsoftonline.com"
        $result.GraphEndpoint = "https://graph.microsoft.com"
        
        $orgInfo = Get-OrganizationInfo -AccessToken $commercialToken -GraphEndpoint "https://graph.microsoft.com"
        if ($orgInfo) {
            $result.OrganizationName = $orgInfo.displayName
            $result.VerifiedDomains = ($orgInfo.verifiedDomains | Where-Object { $_.isInitial -eq $true }).name -join ", "
        }
        
        $domain = Get-TenantDomain -AccessToken $commercialToken -GraphEndpoint "https://graph.microsoft.com"
        if ($domain) {
            $result.InitialDomain = $domain
            $regionScope = Get-TenantRegionScope -Domain $domain
            $result.TenantRegionScope = if ($regionScope) { $regionScope } else { "WW (Assumed)" }
        }
        
        $skus = Get-SubscribedSkus -AccessToken $commercialToken -GraphEndpoint "https://graph.microsoft.com"
        $result.TotalLicenseCount = $skus.Count
        $result.AllLicenses = $skus | ForEach-Object { $_.skuPartNumber }
        
        $govSkus = $skus | Where-Object { $_.skuPartNumber -match "_GOV$|_USGOV_" }
        $result.GovLicenseCount = $govSkus.Count
        $result.GovLicenses = $govSkus | ForEach-Object { $_.skuPartNumber }
        
        if ($result.GovLicenseCount -gt 0) {
            $result.HasGovLicenses = $true
            $result.CloudType = "Government"
            $result.CloudEnvironment = "Microsoft 365 GCC"
            $result.DetectionMethod = "SKU Analysis (_GOV suffix detected)"
            $result.Notes += "Tenant has $($result.GovLicenseCount) government SKUs out of $($result.TotalLicenseCount) total SKUs"
            $result.Notes += "Government licenses detected: $($result.GovLicenses -join ', ')"
        }
        elseif ($result.TenantRegionScope -like "*USG*") {
            $result.CloudType = "Government"
            $result.CloudEnvironment = "Microsoft 365 GCC (via tenant_region_scope)"
            $result.DetectionMethod = "OpenID tenant_region_scope"
            $result.Notes += "tenant_region_scope indicates US Government: $($result.TenantRegionScope)"
        }
        else {
            $result.CloudType = "Commercial"
            $result.CloudEnvironment = "Microsoft 365 Commercial"
            $result.DetectionMethod = "Process of Elimination"
            $result.Notes += "No government indicators found in SKUs or tenant configuration"
            $result.Notes += "tenant_region_scope: $($result.TenantRegionScope)"
        }
    }
    else {
        Write-Verbose "Commercial authentication failed. Testing GCC High..."
        $gccHighToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -GraphEndpoint "https://graph.microsoft.us"
        
        if ($gccHighToken) {
            Write-Verbose "Successfully authenticated to GCC High"
            $result.CloudType = "Government"
            $result.CloudEnvironment = "Microsoft 365 GCC High"
            $result.AuthenticationEndpoint = "https://login.microsoftonline.us"
            $result.GraphEndpoint = "https://graph.microsoft.us"
            $result.DetectionMethod = "Endpoint Authentication (GCC High)"
            $result.Notes += "Tenant authenticates exclusively to GCC High endpoints"
            $result.Notes += "This indicates a GCC High or DoD environment with full isolation from commercial cloud"
            
            $orgInfo = Get-OrganizationInfo -AccessToken $gccHighToken -GraphEndpoint "https://graph.microsoft.us"
            if ($orgInfo) {
                $result.OrganizationName = $orgInfo.displayName
                $result.VerifiedDomains = ($orgInfo.verifiedDomains | Where-Object { $_.isInitial -eq $true }).name -join ", "
            }
            
            $skus = Get-SubscribedSkus -AccessToken $gccHighToken -GraphEndpoint "https://graph.microsoft.us"
            $result.TotalLicenseCount = $skus.Count
            $result.AllLicenses = $skus | ForEach-Object { $_.skuPartNumber }
            $result.HasGovLicenses = $true
            $result.GovLicenseCount = $skus.Count
            $result.GovLicenses = $skus | ForEach-Object { $_.skuPartNumber }
        }
        else {
            $result.CloudType = "Unknown"
            $result.CloudEnvironment = "Unable to Authenticate"
            $result.DetectionMethod = "Authentication Failed"
            $result.Notes += "Unable to authenticate to either Commercial or GCC High endpoints"
            $result.Notes += "This may indicate incorrect credentials or a DoD environment"
        }
    }
    
    return $result
}

function Generate-HTMLReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $timestamp = Get-Date -Format "MMMM dd, yyyy HH:mm:ss"
    $summaryStats = @{
        Total = $Results.Count
        Commercial = ($Results | Where-Object { $_.CloudType -eq "Commercial" }).Count
        GCC = ($Results | Where-Object { $_.CloudEnvironment -like "*GCC*" -and $_.CloudEnvironment -notlike "*GCC High*" }).Count
        GCCHigh = ($Results | Where-Object { $_.CloudEnvironment -like "*GCC High*" }).Count
        Unknown = ($Results | Where-Object { $_.CloudType -eq "Unknown" }).Count
    }
    
    $sortedResults = @()
    $sortedResults += $Results | Where-Object { $_.CloudEnvironment -like "*GCC High*" } | Sort-Object ClientName
    $sortedResults += $Results | Where-Object { $_.CloudEnvironment -like "*GCC*" -and $_.CloudEnvironment -notlike "*GCC High*" } | Sort-Object ClientName
    $sortedResults += $Results | Where-Object { $_.CloudType -eq "Commercial" } | Sort-Object ClientName
    $sortedResults += $Results | Where-Object { $_.CloudType -eq "Unknown" } | Sort-Object ClientName
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft 365 Cloud Environment Detection Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #0078d4 0%, #106ebe 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            font-weight: 300;
        }
        
        .header p {
            font-size: 1.1em;
            opacity: 0.9;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f5f5f5;
        }
        
        .summary-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-5px);
        }
        
        .summary-card .number {
            font-size: 3em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        
        .summary-card .label {
            font-size: 0.9em;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        .commercial .number { color: #0078d4; }
        .gcc .number { color: #107c10; }
        .gcc-high .number { color: #d83b01; }
        .unknown .number { color: #8a8886; }
        
        .content {
            padding: 30px;
        }
        
        .tenant-card {
            background: white;
            border: 1px solid #e1e1e1;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .tenant-header {
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background 0.2s;
        }
        
        .tenant-header:hover {
            background: #f9f9f9;
        }
        
        .tenant-header h3 {
            font-size: 1.3em;
            margin-bottom: 5px;
        }
        
        .tenant-header .tenant-id {
            color: #666;
            font-size: 0.9em;
            font-family: 'Courier New', monospace;
        }
        
        .badge {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .badge.commercial {
            background: #e3f2fd;
            color: #0078d4;
        }
        
        .badge.gcc {
            background: #e8f5e9;
            color: #107c10;
        }
        
        .badge.gcc-high {
            background: #fbe9e7;
            color: #d83b01;
        }
        
        .badge.unknown {
            background: #f5f5f5;
            color: #8a8886;
        }
        
        .tenant-details {
            padding: 0 20px 20px 20px;
            display: none;
            border-top: 1px solid #e1e1e1;
            background: #fafafa;
        }
        
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }
        
        .detail-section {
            background: white;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #0078d4;
        }
        
        .detail-section h4 {
            color: #0078d4;
            margin-bottom: 10px;
            font-size: 1.1em;
        }
        
        .detail-item {
            margin-bottom: 8px;
        }
        
        .detail-label {
            font-weight: 600;
            color: #333;
            display: inline-block;
            min-width: 180px;
        }
        
        .detail-value {
            color: #666;
            font-family: 'Courier New', monospace;
            font-size: 0.95em;
        }
        
        .licenses {
            background: white;
            padding: 15px;
            border-radius: 5px;
            margin-top: 15px;
        }
        
        .licenses h4 {
            color: #107c10;
            margin-bottom: 10px;
        }
        
        .license-list {
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }
        
        .license-tag {
            background: #f0f0f0;
            padding: 5px 12px;
            border-radius: 4px;
            font-size: 0.85em;
            font-family: 'Courier New', monospace;
        }
        
        .license-tag.gov {
            background: #e8f5e9;
            color: #107c10;
            font-weight: bold;
        }
        
        .notes {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 15px;
            border-radius: 5px;
        }
        
        .notes h4 {
            color: #856404;
            margin-bottom: 10px;
        }
        
        .notes ul {
            list-style: none;
            padding-left: 0;
        }
        
        .notes li {
            padding: 5px 0;
            color: #856404;
        }
        
        .notes li:before {
            content: "▸ ";
            color: #ffc107;
            font-weight: bold;
        }
        
        .footer {
            background: #f5f5f5;
            padding: 20px;
            text-align: center;
            color: #666;
            border-top: 1px solid #e1e1e1;
        }
        
        .expand-icon {
            transition: transform 0.3s;
            font-size: 1.5em;
            color: #666;
        }
        
        .expanded .expand-icon {
            transform: rotate(180deg);
        }
        
        @media print {
            body {
                background: white;
            }
            .container {
                box-shadow: none;
            }
            .tenant-details {
                display: block !important;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Microsoft 365 Cloud Environment Report</h1>
            <p>Generated on $timestamp</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <div class="number">$($summaryStats.Total)</div>
                <div class="label">Total Tenants</div>
            </div>
            <div class="summary-card commercial">
                <div class="number">$($summaryStats.Commercial)</div>
                <div class="label">Commercial</div>
            </div>
            <div class="summary-card gcc">
                <div class="number">$($summaryStats.GCC)</div>
                <div class="label">GCC</div>
            </div>
            <div class="summary-card gcc-high">
                <div class="number">$($summaryStats.GCCHigh)</div>
                <div class="label">GCC High</div>
            </div>
            <div class="summary-card unknown">
                <div class="number">$($summaryStats.Unknown)</div>
                <div class="label">Unknown</div>
            </div>
        </div>
        
        <div class="content">
"@
    
    # Track which section we're in for headers
    $currentSection = ""
    
    foreach ($result in $sortedResults) {
        # Determine section for this tenant
        $section = if ($result.CloudEnvironment -like "*GCC High*") {
            "GCC High Tenants"
        } elseif ($result.CloudEnvironment -like "*GCC*") {
            "GCC Tenants"
        } elseif ($result.CloudType -eq "Commercial") {
            "Commercial Tenants"
        } else {
            "Unknown/Failed Tenants"
        }
        
        # Add section header if we're entering a new section
        if ($section -ne $currentSection) {
            if ($currentSection -ne "") {
                $html += "</div>" # Close previous section
            }
            
            $sectionColor = switch ($section) {
                "GCC High Tenants" { "#d83b01" }
                "GCC Tenants" { "#107c10" }
                "Commercial Tenants" { "#0078d4" }
                default { "#8a8886" }
            }
            
            $html += @"
            <div style="margin: 30px 0 20px 0; padding: 15px; background: linear-gradient(135deg, $sectionColor 0%, $(
                switch ($section) {
                    "GCC High Tenants" { "#a91b1b" }
                    "GCC Tenants" { "#0e5a0e" }
                    "Commercial Tenants" { "#005a9e" }
                    default { "#605e5c" }
                }
            ) 100%); color: white; border-radius: 8px; font-size: 1.3em; font-weight: bold; text-align: center;">
                $section
            </div>
            <div>
"@
            $currentSection = $section
        }
        $badgeClass = switch ($result.CloudEnvironment) {
            { $_ -like "*Commercial*" } { "commercial" }
            { $_ -like "*GCC High*" } { "gcc-high" }
            { $_ -like "*GCC*" } { "gcc" }
            default { "unknown" }
        }
        
        $notesHtml = if ($result.Notes.Count -gt 0) {
            $notesList = ($result.Notes | ForEach-Object { "<li>$_</li>" }) -join "`n"
            @"
            <div class="notes">
                <h4>Detection Notes</h4>
                <ul>
                    $notesList
                </ul>
            </div>
"@
        } else { "" }
        
        $govLicensesHtml = if ($result.GovLicenses.Count -gt 0) {
            $govLicenseTags = ($result.GovLicenses | ForEach-Object { "<span class='license-tag gov'>$_</span>" }) -join "`n"
            @"
            <div class="licenses">
                <h4>Government Licenses ($($result.GovLicenseCount))</h4>
                <div class="license-list">
                    $govLicenseTags
                </div>
            </div>
"@
        } else { "" }
        
        $allLicensesHtml = if ($result.AllLicenses.Count -gt 0 -and $result.AllLicenses.Count -le 20) {
            $licenseTags = ($result.AllLicenses | ForEach-Object { 
                $class = if ($_ -match "_GOV$|_USGOV_") { "license-tag gov" } else { "license-tag" }
                "<span class='$class'>$_</span>"
            }) -join "`n"
            @"
            <div class="licenses">
                <h4>All Licenses ($($result.TotalLicenseCount))</h4>
                <div class="license-list">
                    $licenseTags
                </div>
            </div>
"@
        } elseif ($result.TotalLicenseCount -gt 20) {
            "<div class='licenses'><h4>All Licenses</h4><p>$($result.TotalLicenseCount) licenses (too many to display)</p></div>"
        } else { "" }
        
        $orgName = if ($result.OrganizationName -ne "Unknown") { $result.OrganizationName } else { "Unknown" }
        
        $html += @"
            <div class="tenant-card">
                <div class="tenant-header" onclick="toggleDetails(this)">
                    <div>
                        <h3>$orgName</h3>
                        <div class="tenant-id">$($result.TenantId)</div>
                    </div>
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <span class="badge $badgeClass">$($result.CloudEnvironment)</span>
                        <span class="expand-icon">▼</span>
                    </div>
                </div>
                <div class="tenant-details">
                    <div class="detail-grid">
                        <div class="detail-section">
                            <h4>Authentication Details</h4>
                            <div class="detail-item">
                                <span class="detail-label">Cloud Type:</span>
                                <span class="detail-value">$($result.CloudType)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Environment:</span>
                                <span class="detail-value">$($result.CloudEnvironment)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Auth Endpoint:</span>
                                <span class="detail-value">$($result.AuthenticationEndpoint)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Graph Endpoint:</span>
                                <span class="detail-value">$($result.GraphEndpoint)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Detection Method:</span>
                                <span class="detail-value">$($result.DetectionMethod)</span>
                            </div>
                        </div>
                        
                        <div class="detail-section">
                            <h4>Tenant Information</h4>
                            <div class="detail-item">
                                <span class="detail-label">Organization:</span>
                                <span class="detail-value">$($result.OrganizationName)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Initial Domain:</span>
                                <span class="detail-value">$($result.InitialDomain)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Tenant Region Scope:</span>
                                <span class="detail-value">$($result.TenantRegionScope)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Total Licenses:</span>
                                <span class="detail-value">$($result.TotalLicenseCount)</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Government Licenses:</span>
                                <span class="detail-value">$($result.GovLicenseCount)</span>
                            </div>
                        </div>
                    </div>
                    
                    $govLicensesHtml
                    $allLicensesHtml
                    $notesHtml
                </div>
            </div>
"@
    }
    
    # Close the final section
    if ($currentSection -ne "") {
        $html += "</div>"
    }
    
    $html += @"
        </div>
        
        <div class="footer">
            <p><strong>Detection Methods:</strong></p>
            <p style="margin-top: 10px;">
                <strong>SKU Analysis:</strong> Detects government licenses with _GOV suffix<br>
                <strong>OpenID Configuration:</strong> Checks tenant_region_scope from login endpoint<br>
                <strong>Endpoint Authentication:</strong> Tests GCC High (graph.microsoft.us) endpoints<br>
                <strong>Process of Elimination:</strong> Commercial when no government indicators found
            </p>
            <p style="margin-top: 15px; font-size: 0.9em;">
                Generated by Microsoft 365 Cloud Detection Tool
            </p>
        </div>
    </div>
    
    <script>
        function toggleDetails(header) {
            const card = header.parentElement;
            const details = card.querySelector('.tenant-details');
            const isExpanded = details.style.display === 'block';
            
            details.style.display = isExpanded ? 'none' : 'block';
            card.classList.toggle('expanded', !isExpanded);
        }
    </script>
</body>
</html>
"@
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
}

# Main execution
$results = @()

if ($CsvPath) {
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }
    
    try {
        $tenants = Import-Csv -Path $CsvPath
        
        $requiredColumns = @('Client', 'Tenant ID', 'Client ID', 'Key Value')
        if ($tenants.Count -gt 0) {
            $csvColumns = $tenants[0].PSObject.Properties.Name
            foreach ($requiredColumn in $requiredColumns) {
                if ($requiredColumn -notin $csvColumns) {
                    Write-Error "Missing required column: '$requiredColumn'. Required columns: $($requiredColumns -join ', ')"
                    return
                }
            }
        }
        
        if ($ClientName) {
            Write-Host "Filtering to specific client: $ClientName" -ForegroundColor Cyan
            $selectedClient = Get-ClientFromCsv -Clients $tenants -ClientName $ClientName
            $tenants = @($selectedClient)
            Write-Host "Found client: $($selectedClient.Client)" -ForegroundColor Green
        }
        
        $counter = 0
        foreach ($tenant in $tenants) {
            $counter++
            
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
            
            Write-Host "`n[$counter] Processing: $clientName" -ForegroundColor Cyan
            Write-Progress -Activity "Analyzing Tenants" -Status "Processing $clientName ($counter of $($tenants.Count))" -PercentComplete (($counter / $tenants.Count) * 100)
            
            try {
                $result = Test-CloudEnvironment -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret -Verbose:$VerbosePreference
                $result | Add-Member -NotePropertyName "ClientName" -NotePropertyValue $clientName -Force
                $results += $result
                
                Write-Host "  Cloud Type: $($result.CloudType)" -ForegroundColor $(if ($result.CloudType -eq "Government") { "Yellow" } else { "Green" })
                Write-Host "  Environment: $($result.CloudEnvironment)" -ForegroundColor $(if ($result.CloudType -eq "Government") { "Yellow" } else { "Green" })
            }
            catch {
                Write-Error "Error processing tenant $clientName ($tenantId): $_"
            }
        }
        
        Write-Progress -Activity "Analyzing Tenants" -Completed
        
        if ($ClientName -and $results.Count -eq 1) {
            $safeClientName = $results[0].ClientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $htmlPath = "${safeClientName}GCCTenantReport.html"
            $csvOutputPath = "${safeClientName}GCCTenantReport.csv"
        } else {
            $htmlPath = "GCCGlobalTenantReport.html"
            $csvOutputPath = "GCCGlobalTenantReport.csv"
        }
        
        Write-Host "`nGenerating HTML report..." -ForegroundColor Cyan
        Generate-HTMLReport -Results $results -OutputPath $htmlPath
        
        Write-Host "`nReport generated: $htmlPath" -ForegroundColor Green
        Write-Host "`nSummary:" -ForegroundColor Cyan
        Write-Host "  Total Tenants: $($results.Count)"
        Write-Host "  Commercial: $(($results | Where-Object { $_.CloudType -eq 'Commercial' }).Count)"
        Write-Host "  GCC: $(($results | Where-Object { $_.CloudEnvironment -like '*GCC*' -and $_.CloudEnvironment -notlike '*GCC High*' }).Count)"
        Write-Host "  GCC High: $(($results | Where-Object { $_.CloudEnvironment -like '*GCC High*' }).Count)"
        Write-Host "  Unknown: $(($results | Where-Object { $_.CloudType -eq 'Unknown' }).Count)"
        
        $results | Select-Object ClientName, TenantId, CloudType, CloudEnvironment, AuthenticationEndpoint, GraphEndpoint, `
            OrganizationName, InitialDomain, TenantRegionScope, HasGovLicenses, GovLicenseCount, TotalLicenseCount, DetectionMethod | `
            Export-Csv -Path $csvOutputPath -NoTypeInformation
        Write-Host "CSV export: $csvOutputPath" -ForegroundColor Green
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
    
    Write-Host "Analyzing tenant: $TenantId" -ForegroundColor Cyan
    
    $result = Test-CloudEnvironment -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret -Verbose:$VerbosePreference
    $results += $result
    
    Write-Host "`nCloud Detection Results:" -ForegroundColor Cyan
    Write-Host "========================" -ForegroundColor Cyan
    Write-Host "Tenant ID: $($result.TenantId)"
    Write-Host "Cloud Type: $($result.CloudType)" -ForegroundColor $(if ($result.CloudType -eq "Government") { "Yellow" } else { "Green" })
    Write-Host "Cloud Environment: $($result.CloudEnvironment)" -ForegroundColor $(if ($result.CloudType -eq "Government") { "Yellow" } else { "Green" })
    Write-Host "Organization: $($result.OrganizationName)"
    Write-Host "Initial Domain: $($result.InitialDomain)"
    Write-Host "Authentication Endpoint: $($result.AuthenticationEndpoint)"
    Write-Host "Graph Endpoint: $($result.GraphEndpoint)"
    Write-Host "Tenant Region Scope: $($result.TenantRegionScope)"
    Write-Host "Has Government Licenses: $($result.HasGovLicenses)"
    Write-Host "Government License Count: $($result.GovLicenseCount)"
    Write-Host "Total License Count: $($result.TotalLicenseCount)"
    Write-Host "Detection Method: $($result.DetectionMethod)"
    
    if ($result.Notes.Count -gt 0) {
        Write-Host "`nNotes:" -ForegroundColor Yellow
        foreach ($note in $result.Notes) {
            Write-Host "  - $note" -ForegroundColor Yellow
        }
    }
    
    $safeOrgName = if ($result.OrganizationName -and $result.OrganizationName -ne "Unknown") {
        $result.OrganizationName -replace '[\\\/\:\*\?"<>\|]', '_'
    } else {
        "Tenant"
    }
    $htmlPath = "${safeOrgName}GCCTenantReport.html"
    $csvPath = "${safeOrgName}GCCTenantReport.csv"
    
    Generate-HTMLReport -Results $results -OutputPath $htmlPath
    
    $results | Select-Object TenantId, CloudType, CloudEnvironment, AuthenticationEndpoint, GraphEndpoint, `
        OrganizationName, InitialDomain, TenantRegionScope, HasGovLicenses, GovLicenseCount, TotalLicenseCount, DetectionMethod | `
        Export-Csv -Path $csvPath -NoTypeInformation
    
    Write-Host "`nHTML Report: $htmlPath" -ForegroundColor Green
    Write-Host "CSV Report: $csvPath" -ForegroundColor Green
    
    return $result
}
