<#
.SYNOPSIS
    Generates comprehensive reports of Microsoft 365 and Security Groups from Azure AD/Entra ID tenants using Microsoft Graph API.

.DESCRIPTION
    This script uses Azure application credentials to enumerate all groups within specified Azure AD/Entra ID tenant(s) via raw Graph API calls. 
    It retrieves detailed information about groups including membership, ownership, group types, and configuration settings.
    
    The script can process either a single tenant or multiple tenants from a CSV file, generating both summary and detailed reports 
    in CSV format as well as an interactive HTML report with collapsible sections for easy analysis.

    Key features:
    - Enumerates all group types (Security Groups, Microsoft 365 Groups, Dynamic Groups)
    - Retrieves complete membership and ownership information
    - Handles pagination for large tenant environments
    - Generates multiple output formats (CSV summary, CSV detailed, interactive HTML)
    - Supports batch processing of multiple tenants
    - Provides verbose logging for troubleshooting
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

.PARAMETER VerboseLogging
    Enables detailed verbose output for troubleshooting and monitoring script execution.
    Useful for debugging authentication issues or API call problems.

.INPUTS
    CSV file with tenant credentials (optional)
    Individual tenant parameters via command line
    
.NOTES
    Author: Geoff Tankersley
    Version: 1.0
    
    Prerequisites:
    - PowerShell 5.1 or later
    - Required Graph API Permissions:
      - Group.Read.All (Application permission)
      - GroupMember.Read.All (Application permission)
      - User.Read.All (Application permission)
    
    Security Considerations:
    - Client secrets should be stored securely
    - Application should use least-privilege permissions
    - Consider using certificate-based authentication for production
    - Audit application access regularly
    
    Performance Notes:
    - Large tenants may take significant time to process
    - Script uses pagination to handle large result sets
    - Progress indicators show current processing status

.EXAMPLE
    .\Get-GroupsReport.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret"
    
    Processes a single tenant and generates individual reports for that tenant.

.EXAMPLE
    .\Get-GroupsReport.ps1 -CsvPath "C:\Scripts\clients.csv"
    
    Processes all tenants listed in the CSV file and generates consolidated reports.

.EXAMPLE
    .\Get-GroupsReport.ps1 -CsvPath "C:\Scripts\clients.csv" -ClientName "Contoso Corporation"
    
    Processes only the "Contoso Corporation" tenant from the CSV file.

.EXAMPLE
    .\Get-GroupsReport.ps1 -TenantId "12345678-1234-1234-1234-123456789abc" -ClientId "87654321-4321-4321-4321-abcdef123456" -ClientSecret "your-client-secret" -VerboseLogging
    
    Processes a single tenant with detailed verbose output for troubleshooting.

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
    [switch]$VerboseLogging
)

if ($VerboseLogging) {
    $VerbosePreference = "Continue"
}

# Validate parameters
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

function Generate-GroupsHtmlReport {
    param (
        [array]$ClientsData,
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
    <title>Groups and Members Report</title>
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
        .group {
            margin-bottom: 25px;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            background-color: #fafafa;
        }
        .group-header {
            background-color: #f0f0f0;
            padding: 10px;
            margin: -15px -15px 15px -15px;
            border-radius: 5px 5px 0 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .group-name {
            font-size: 16px;
            font-weight: bold;
            color: #0078d4;
            margin: 0;
        }
        .group-type {
            padding: 3px 8px;
            border-radius: 3px;
            font-weight: bold;
            font-size: 12px;
            background-color: #e3f2fd;
            color: #1565c0;
        }
        .dynamic {
            background-color: #fff3e0;
            color: #ef6c00;
        }
        .m365 {
            background-color: #e8f5e8;
            color: #2e7d32;
        }
        .security {
            background-color: #fff8e1;
            color: #f57c00;
        }
        .group-info {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            margin-bottom: 15px;
        }
        .info-item {
            background-color: white;
            padding: 8px;
            border-radius: 3px;
            border-left: 3px solid #0078d4;
        }
        .info-label {
            font-weight: bold;
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .info-value {
            font-size: 14px;
            color: #333;
            word-break: break-all;
        }
        .members-section {
            margin-top: 15px;
        }
        .members-header {
            font-weight: bold;
            margin-bottom: 10px;
            color: #0078d4;
            border-bottom: 1px solid #0078d4;
            padding-bottom: 5px;
        }
        .member-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 10px;
        }
        .member-card {
            background-color: white;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            padding: 10px;
            position: relative;
        }
        .member-name {
            font-weight: bold;
            color: #333;
            margin-bottom: 5px;
        }
        .member-email {
            color: #666;
            font-size: 12px;
            margin-bottom: 5px;
        }
        .member-type {
            font-size: 11px;
            color: #888;
        }
        .owner-badge {
            position: absolute;
            top: 5px;
            right: 5px;
            background-color: #d32f2f;
            color: white;
            font-size: 10px;
            padding: 2px 6px;
            border-radius: 3px;
        }
        .no-members {
            text-align: center;
            color: #666;
            font-style: italic;
            padding: 20px;
            background-color: white;
            border-radius: 5px;
        }
        .summary-table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        .summary-table th,
        .summary-table td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: left;
        }
        .summary-table th {
            background-color: #0078d4;
            color: white;
        }
        .summary-table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .timestamp {
            font-style: italic;
            color: #666;
            font-size: 14px;
            margin-top: 10px;
        }
        .collapsible {
            background-color: #f1f1f1;
            color: #555;
            cursor: pointer;
            padding: 10px;
            width: 100%;
            border: none;
            text-align: left;
            outline: none;
            font-size: 15px;
            margin-top: 10px;
            border-radius: 3px;
        }
        .active, .collapsible:hover {
            background-color: #e1e1e1;
        }
        .content {
            padding: 0 15px;
            max-height: 0;
            overflow: hidden;
            transition: max-height 0.2s ease-out;
            background-color: white;
        }
        .collapsible:after {
            content: '\002B';
            color: #777;
            font-weight: bold;
            float: right;
            margin-left: 5px;
        }
        .active:after {
            content: "\2212";
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Groups and Members Report</h1>
        <div class="timestamp">Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
"@

    if ($ClientsData.Count -gt 1) {
        $htmlHeader += @"
        
        <h2>Overview</h2>
        <table class="summary-table">
            <thead>
                <tr>
                    <th>Client Name</th>
                    <th>Total Groups</th>
                    <th>Security Groups</th>
                    <th>M365 Groups</th>
                    <th>Dynamic Groups</th>
                    <th>Total Members</th>
                </tr>
            </thead>
            <tbody>
"@
        
        foreach ($client in $successfulClients) {
            $htmlHeader += @"
                <tr>
                    <td><strong>$($client.ClientName)</strong></td>
                    <td>$($client.GroupsCount)</td>
                    <td>$($client.SecurityGroups)</td>
                    <td>$($client.M365Groups)</td>
                    <td>$($client.DynamicGroups)</td>
                    <td>$($client.TotalMembers)</td>
                </tr>
"@
        }
        
        $htmlHeader += @"
            </tbody>
        </table>
"@
    }

    $clientsHtml = ""
    
    foreach ($client in $successfulClients) {
        $clientsHtml += @"
        <div class="client-section">
            <div class="client-header">
                <span class="client-name">$($client.ClientName)</span>
                <div class="client-stats">
                    $($client.GroupsCount) Groups | $($client.TotalMembers) Total Members<br>
                    Sec: $($client.SecurityGroups) | M365: $($client.M365Groups) | Dynamic: $($client.DynamicGroups)
                </div>
            </div>
"@
        
        if ($client.GroupsReport.Count -eq 0) {
            $clientsHtml += @"
            <p><em>No groups found for this client.</em></p>
"@
        } else {
            $groupedMembers = $client.GroupsDetailedReport | Group-Object -Property GroupId
            
            foreach ($group in $client.GroupsReport | Sort-Object DisplayName) {
                # Get group type class for styling
                $groupTypeClass = "group-type"
                if ($group.GroupType -like "*Dynamic*") {
                    $groupTypeClass += " dynamic"
                } elseif ($group.GroupType -like "*Microsoft 365*") {
                    $groupTypeClass += " m365"
                } else {
                    $groupTypeClass += " security"
                }
                
                $clientsHtml += @"
            <div class="group">
                <div class="group-header">
                    <span class="group-name">$($group.DisplayName)</span>
                    <span class="$groupTypeClass">$($group.GroupType)</span>
                </div>
                
                <div class="group-info">
                    <div class="info-item">
                        <div class="info-label">Description</div>
                        <div class="info-value">$(if ($group.Description) { $group.Description } else { "No description" })</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Email</div>
                        <div class="info-value">$(if ($group.Email) { $group.Email } else { "No email" })</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Member Count</div>
                        <div class="info-value">$($group.MemberCount)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Owner Count</div>
                        <div class="info-value">$($group.OwnerCount)</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Visibility</div>
                        <div class="info-value">$(if ($group.Visibility) { $group.Visibility } else { "Not specified" })</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Created</div>
                        <div class="info-value">$(if ($group.CreatedDateTime) { ([DateTime]$group.CreatedDateTime).ToString("yyyy-MM-dd") } else { "Unknown" })</div>
                    </div>
                </div>
                
                <button class="collapsible">Members ($($group.MemberCount))</button>
                <div class="content">
                    <div class="members-section">
"@
                
                # Retrieve group members
                $groupMembers = $groupedMembers | Where-Object { $_.Name -eq $group.GroupId }
                
                if ($groupMembers -and $groupMembers.Group.Count -gt 0 -and $groupMembers.Group[0].MemberDisplayName -ne "No members or unable to retrieve") {
                    $clientsHtml += @"
                        <div class="member-grid">
"@
                    foreach ($member in $groupMembers.Group | Sort-Object MemberDisplayName) {
                        $ownerBadge = if ($member.IsOwner) { '<div class="owner-badge">OWNER</div>' } else { '' }
                        
                        $clientsHtml += @"
                            <div class="member-card">
                                $ownerBadge
                                <div class="member-name">$($member.MemberDisplayName)</div>
                                <div class="member-email">$(if ($member.MemberEmail) { $member.MemberEmail } else { "No email" })</div>
                                <div class="member-type">$($member.MemberType)</div>
                            </div>
"@
                    }
                    $clientsHtml += @"
                        </div>
"@
                } else {
                    $clientsHtml += @"
                        <div class="no-members">No members found or unable to retrieve member information</div>
"@
                }
                
                $clientsHtml += @"
                    </div>
                </div>
            </div>
"@
            }
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
        <script>
            var coll = document.getElementsByClassName("collapsible");
            var i;
            
            for (i = 0; i < coll.length; i++) {
                coll[i].addEventListener("click", function() {
                    this.classList.toggle("active");
                    var content = this.nextElementSibling;
                    if (content.style.maxHeight){
                        content.style.maxHeight = null;
                    } else {
                        content.style.maxHeight = content.scrollHeight + "px";
                    }
                });
            }
        </script>
    </div>
</body>
</html>
"@

    $htmlReport = $htmlHeader + $clientsHtml + $htmlFooter
    
    # Save the HTML report
    $htmlReport | Out-File -FilePath $OutputPath -Encoding utf8
    Write-Host "Groups HTML report generated: $OutputPath" -ForegroundColor Green
    
    return $OutputPath
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
        Write-Verbose "Requesting access token from: $tokenUrl"
        $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
        Write-Verbose "Successfully obtained access token"
        return $response.access_token
    }
    catch {
        $errorDetails = ""
        if ($_.Exception.Response) {
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                $errorObj = ConvertFrom-Json $responseBody -ErrorAction SilentlyContinue
                $errorDetails = " - $($errorObj.error_description)"
            }
            catch {
                $errorDetails = " - Unable to parse error details"
            }
        }
        
        Write-Error "Error obtaining access token: $_$errorDetails"
        throw $_
    }
}

function Get-GraphGroups {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $groups = @()
    $baseUrl = "https://graph.microsoft.com/v1.0/groups"
    $nextLink = $baseUrl + "?`$top=100"

    try {
        Write-Verbose "Retrieving groups from Microsoft Graph"
        # Pagination
        do {
            Write-Verbose "Calling: $nextLink"
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $groups += $response.value
            $nextLink = $response.'@odata.nextLink'
            Write-Verbose "Retrieved $($response.value.Count) groups in this batch. Total so far: $($groups.Count)"
        } while ($nextLink)

        Write-Verbose "Total groups retrieved: $($groups.Count)"
        return $groups
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        $statusDescription = $_.Exception.Response.StatusDescription
        
        try {
            $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd()
            $errorDetails = ConvertFrom-Json $responseBody -ErrorAction SilentlyContinue
            
            throw "HTTP $statusCode - $($errorDetails.error.message)"
        }
        catch {
            throw "HTTP $statusCode - $statusDescription"
        }
    }
}

function Get-GroupMembers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    $members = @()
    $nextLink = "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$top=100"
    
    try {
        Write-Verbose "Retrieving members for group: $GroupId"
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $members += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        Write-Verbose "Retrieved $($members.Count) members for group $GroupId"
        return $members
    }
    catch {
        $errorMessage = "Could not retrieve members for group " + $GroupId + ": " + $_.Exception.Message
        Write-Warning $errorMessage
        return @()
    }
}

function Get-GroupOwners {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    $owners = @()
    $nextLink = "https://graph.microsoft.com/v1.0/groups/$GroupId/owners?`$top=100"
    
    try {
        Write-Verbose "Retrieving owners for group: $GroupId"
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $owners += $response.value
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)
        
        Write-Verbose "Retrieved $($owners.Count) owners for group $GroupId"
        return $owners
    }
    catch {
        $errorMessage = "Could not retrieve owners for group " + $GroupId + ": " + $_.Exception.Message
        Write-Warning $errorMessage
        return @()
    }
}

function Get-GroupSettings {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$GroupId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/settings" -Method Get -Headers $headers
        return $response.value
    }
    catch {
        return @()
    }
}

function Get-GroupType {
    param (
        [Parameter(Mandatory=$false)]
        [array]$GroupTypes = @(),
        
        [Parameter(Mandatory=$true)]
        [bool]$IsDynamic
    )
    
    if ($GroupTypes -contains "Unified") {
        if ($IsDynamic) {
            return "Microsoft 365 Group (Dynamic)"
        } else {
            return "Microsoft 365 Group"
        }
    } elseif ($IsDynamic) {
        return "Security Group (Dynamic)"
    } elseif ($GroupTypes.Count -eq 0) {
        return "Security Group"
    } else {
        return "$($GroupTypes -join ', ') Group"
    }
}

function Process-SingleClient {
    param (
        [string]$ClientName,
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$OutputFolder = $null
    )
    
    $clientData = @{
        ClientName = $ClientName
        TenantId = $TenantId
        ClientId = $ClientId
        GroupsCount = 0
        SecurityGroups = 0
        M365Groups = 0
        DynamicGroups = 0
        TotalMembers = 0
        Success = $false
        Error = ""
        GroupsReport = @()
        GroupsDetailedReport = @()
    }
    
    try {
        Write-Host "`n=======================================================" -ForegroundColor Cyan
        Write-Host "Processing tenant: $ClientName ($TenantId)" -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan

        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        
        Write-Host "Retrieving groups information..." -ForegroundColor Yellow
        $groups = Get-GraphGroups -AccessToken $accessToken
        
        Write-Host "Found $($groups.Count) groups. Gathering detailed information..." -ForegroundColor Yellow

        $clientData.GroupsCount = $groups.Count
        $totalMembersCount = 0

        $groupsReport = @()
        $groupsDetailedReport = @()
        $counter = 0
        
        foreach ($group in $groups) {
            $counter++
            Write-Progress -Activity "Processing Groups for $ClientName" -Status "Processing group $counter of $($groups.Count): $($group.displayName)" -PercentComplete (($counter / $groups.Count) * 100)
            
            # Count group members
            $members = Get-GroupMembers -AccessToken $accessToken -GroupId $group.id
            $memberCount = $members.Count
            $totalMembersCount += $memberCount
            
            # Find group owners
            $owners = Get-GroupOwners -AccessToken $accessToken -GroupId $group.id
            $ownerCount = $owners.Count
            
            # Find static/dynamic typing
            $isDynamic = -not [string]::IsNullOrEmpty($group.membershipRule)
            
            $groupTypeArray = @()
            if ($group.groupTypes -ne $null) {
                $groupTypeArray = $group.groupTypes
            }
            
            $groupType = Get-GroupType -GroupTypes $groupTypeArray -IsDynamic $isDynamic
            
            if ($groupType -like "*Microsoft 365*") {
                $clientData.M365Groups++
            } else {
                $clientData.SecurityGroups++
            }
            
            if ($isDynamic) {
                $clientData.DynamicGroups++
            }
            
            # Basic group information for summary report
            $groupsReport += [PSCustomObject]@{
                ClientName     = $ClientName
                TenantId       = $TenantId
                DisplayName    = $group.displayName
                GroupId        = $group.id
                Description    = $group.description
                Email          = $group.mail
                GroupType      = $groupType
                IsDynamic      = $isDynamic
                MembershipRule = $group.membershipRule
                MemberCount    = $memberCount
                OwnerCount     = $ownerCount
                CreatedDateTime = $group.createdDateTime
                RenewedDateTime = $group.renewedDateTime
                ExpirationDateTime = $group.expirationDateTime
                Visibility     = $group.visibility
            }
            
            foreach ($member in $members) {
                $isOwner = $owners.id -contains $member.id
                
                $groupsDetailedReport += [PSCustomObject]@{
                    ClientName      = $ClientName
                    TenantId        = $TenantId
                    GroupDisplayName = $group.displayName
                    GroupId         = $group.id
                    GroupType       = $groupType
                    IsDynamic       = $isDynamic
                    MemberType      = $member.'@odata.type' -replace "#microsoft.graph.", ""
                    MemberDisplayName = $member.displayName
                    MemberEmail     = $member.mail
                    MemberId        = $member.id
                    IsOwner         = $isOwner
                }
            }
            
            # Placeholder entry
            if ($memberCount -eq 0) {
                $groupsDetailedReport += [PSCustomObject]@{
                    ClientName      = $ClientName
                    TenantId        = $TenantId
                    GroupDisplayName = $group.displayName
                    GroupId         = $group.id
                    GroupType       = $groupType
                    IsDynamic       = $isDynamic
                    MemberType      = "N/A"
                    MemberDisplayName = "No members or unable to retrieve"
                    MemberEmail     = "N/A"
                    MemberId        = "N/A"
                    IsOwner         = $false
                }
            }
        }
        
        Write-Progress -Activity "Processing Groups for $ClientName" -Completed
        
        $clientData.TotalMembers = $totalMembersCount
        $clientData.GroupsReport = $groupsReport
        $clientData.GroupsDetailedReport = $groupsDetailedReport
        
        # Console summary
        Write-Host "`nGroups Summary for $ClientName :" -ForegroundColor Green
        Write-Host "  Total Groups: $($clientData.GroupsCount)" -ForegroundColor Cyan
        Write-Host "  Security Groups: $($clientData.SecurityGroups)" -ForegroundColor Cyan
        Write-Host "  Microsoft 365 Groups: $($clientData.M365Groups)" -ForegroundColor Cyan
        Write-Host "  Dynamic Groups: $($clientData.DynamicGroups)" -ForegroundColor Cyan
        Write-Host "  Total Members: $($clientData.TotalMembers)" -ForegroundColor Cyan
        
        $groupsReport | Sort-Object DisplayName | Format-Table DisplayName, GroupType, MemberCount, OwnerCount, IsDynamic, Visibility -AutoSize | Out-Host

        if ($OutputFolder) {
            $safeClientName = $ClientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $summaryOutputFile = Join-Path -Path $OutputFolder -ChildPath "$safeClientName-Groups-Summary.csv"
            $detailedOutputFile = Join-Path -Path $OutputFolder -ChildPath "$safeClientName-Groups-Detailed.csv"
            
            $groupsReport | Export-Csv -Path $summaryOutputFile -NoTypeInformation
            $groupsDetailedReport | Export-Csv -Path $detailedOutputFile -NoTypeInformation
            
            Write-Host "Groups summary report exported to: $summaryOutputFile" -ForegroundColor Green
            Write-Host "Groups detailed report exported to: $detailedOutputFile" -ForegroundColor Green
        }
        
        $clientData.Success = $true
        Write-Host "Successfully processed $ClientName" -ForegroundColor Green
        
    } catch {
        $clientData.Error = $_.Exception.Message
        Write-Host "Failed to process $ClientName : $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $clientData
}

# Main 
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
    $outputFolder = "GroupsReports-$timestamp"
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
    
    $clientResult = Process-SingleClient -ClientName $client.Client.Trim() -TenantId $client.'Tenant ID'.Trim() -ClientId $client.'Client ID'.Trim() -ClientSecret $client.'Key Value'.Trim() -OutputFolder $outputFolder
    
    if ($clientResult -and $clientResult.ClientName) {
        $allClientResults += $clientResult
    }
}

Write-Verbose "Total clients to process: $($clientsToProcess.Count)"
Write-Verbose "Total client results: $($allClientResults.Count)"
Write-Verbose "Is specific client: $isSpecificClient"

if ($isSpecificClient) {
    if ($allClientResults.Count -eq 1) {
        $result = $allClientResults[0]
        if ($result.Success) {
            $htmlReportPath = "Groups-Report-$($result.ClientName -replace '[\\\/\:\*\?"<>\|]', '_')-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
            Generate-GroupsHtmlReport -ClientsData @($result) -OutputPath $htmlReportPath
            
            $safeClientName = $result.ClientName -replace '[\\\/\:\*\?"<>\|]', '_'
            $summaryOutputFile = "$safeClientName-Groups-Summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            $detailedOutputFile = "$safeClientName-Groups-Detailed-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            
            $result.GroupsReport | Export-Csv -Path $summaryOutputFile -NoTypeInformation
            $result.GroupsDetailedReport | Export-Csv -Path $detailedOutputFile -NoTypeInformation
            
            Write-Host "`n=== REPORTS GENERATED ===" -ForegroundColor Magenta
            Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
            Write-Host "Summary CSV: $summaryOutputFile" -ForegroundColor Green
            Write-Host "Detailed CSV: $detailedOutputFile" -ForegroundColor Green
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
    
    $totalGroups = 0
    $totalMembers = 0
    
    if ($successfulResults.Count -gt 0) {
        $totalGroups = ($successfulResults | Measure-Object -Property GroupsCount -Sum).Sum
        $totalMembers = ($successfulResults | Measure-Object -Property TotalMembers -Sum).Sum
    }
    
    Write-Host "Clients processed: $($allClientResults.Count)" -ForegroundColor Cyan
    Write-Host "Successful: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor Red
    Write-Host "Total groups found: $totalGroups" -ForegroundColor Yellow
    Write-Host "Total members found: $totalMembers" -ForegroundColor Yellow
    
    if ($outputFolder) {
        Write-Host "Reports saved to folder: $outputFolder" -ForegroundColor Green
    }
    
    if ($failCount -gt 0) {
        Write-Host "`nFailed clients:" -ForegroundColor Red
        $failedResults | Where-Object { -not [string]::IsNullOrWhiteSpace($_.ClientName) } | ForEach-Object {
            Write-Host "  - $($_.ClientName): $($_.Error)" -ForegroundColor Yellow
        }
    }
    
    # Create consolidated summary
    if ($outputFolder) {
        $consolidatedSummary = @()
        $consolidatedDetailed = @()
        
        foreach ($result in $successfulResults) {
            $consolidatedSummary += $result.GroupsReport
            $consolidatedDetailed += $result.GroupsDetailedReport
        }
        
        $consolidatedSummaryFile = Join-Path -Path $outputFolder -ChildPath "All-Clients-Groups-Summary.csv"
        $consolidatedDetailedFile = Join-Path -Path $outputFolder -ChildPath "All-Clients-Groups-Detailed.csv"
        
        $consolidatedSummary | Export-Csv -Path $consolidatedSummaryFile -NoTypeInformation
        $consolidatedDetailed | Export-Csv -Path $consolidatedDetailedFile -NoTypeInformation
        
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "All-Clients-Groups-Report.html"
        Generate-GroupsHtmlReport -ClientsData $allClientResults -OutputPath $htmlReportPath
        
        Write-Host "`nConsolidated reports created:" -ForegroundColor Green
        Write-Host "  Summary: $consolidatedSummaryFile" -ForegroundColor Cyan
        Write-Host "  Detailed: $consolidatedDetailedFile" -ForegroundColor Cyan
        Write-Host "  HTML Report: $htmlReportPath" -ForegroundColor Cyan
    }
}
else {
    if ($allClientResults.Count -eq 0) {
        Write-Host "No clients were processed." -ForegroundColor Red
    }
}
