#Requires -Version 5.1

<#
.SYNOPSIS
    Tests Microsoft Graph API connections across multiple tenants and generates HTML status report
.DESCRIPTION
    Validates API keys by testing connections to Microsoft Graph across all tenants 
    in CSV file and generates comprehensive HTML status report. This allows for bulk 
    headless determination of Azure app key viability and expiry. 
.PARAMETER CsvPath
    Path to CSV file containing tenant/app information
.PARAMETER ClientName
    Specific client name to test (optional - tests all if not specified)
.PARAMETER OutputPath
    Path to export results
.PARAMETER TimeoutSeconds
    Connection timeout in seconds (default: 30)
.EXAMPLE
    .\Test-TenantAPIKeys.ps1.ps1 -CsvPath "TestAzureAppKeys.csv"
    .\Test-TenantAPIKeys.ps1.ps1 -CsvPath "TestAzureAppKeys.csv" -ClientName "Contoso Corp"
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,
    
    [Parameter(Mandatory = $false)]
    [string]$ClientName,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [int]$TimeoutSeconds = 30
)

function Write-ColorOutput {
    param([string]$Message, [string]$Color = "White")
    Write-Host $Message -ForegroundColor $Color
}

function Get-AccessToken {
    param(
        [string]$TenantId,
        [string]$ClientId,
        [string]$ClientSecret,
        [string]$Scope = "https://graph.microsoft.com/.default"
    )
    
    try {
        $body = @{
            client_id     = $ClientId
            client_secret = $ClientSecret
            scope         = $Scope
            grant_type    = "client_credentials"
        }
        
        $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded" -TimeoutSec $TimeoutSeconds
        
        return @{
            Success = $true
            Token = $response.access_token
            ExpiresIn = $response.expires_in
            Error = $null
        }
    } catch {
        return @{
            Success = $false
            Token = $null
            ExpiresIn = 0
            Error = $_.Exception.Message
            StatusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
        }
    }
}

function Test-GraphConnection {
    param(
        [string]$AccessToken,
        [string]$TenantId
    )
    
    try {
        $headers = @{
            'Authorization' = "Bearer $AccessToken"
            'Content-Type' = 'application/json'
        }
        
        $orgUrl = "https://graph.microsoft.com/v1.0/organization"
        $orgResponse = Invoke-RestMethod -Uri $orgUrl -Headers $headers -Method GET -TimeoutSec $TimeoutSeconds
        
        $userUrl = "https://graph.microsoft.com/v1.0/users?`$top=1"
        $userResponse = Invoke-RestMethod -Uri $userUrl -Headers $headers -Method GET -TimeoutSec $TimeoutSeconds
        
        return @{
            Success = $true
            OrganizationName = $orgResponse.value[0].displayName
            TenantName = $orgResponse.value[0].displayName
            UserCount = "Access Granted"
            Error = $null
            ResponseTime = $null
        }
    } catch {
        return @{
            Success = $false
            OrganizationName = "Unknown"
            TenantName = "Unknown"
            UserCount = "Access Denied"
            Error = $_.Exception.Message
            StatusCode = if ($_.Exception.Response) { $_.Exception.Response.StatusCode } else { "Unknown" }
            ResponseTime = $null
        }
    }
}

function New-HtmlConnectionReport {
    param(
        [array]$ConnectionResults,
        [string]$OutputPath
    )
    
    $reportDate = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $totalTenants = $ConnectionResults.Count
    
    # Stats
    $successCount = ($ConnectionResults | Where-Object { $_.GraphSuccess -eq $true }).Count
    $failureCount = ($ConnectionResults | Where-Object { $_.GraphSuccess -eq $false }).Count
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Tenant Connection Status Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .header { background-color: #0078d4; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .summary { background-color: white; padding: 15px; border-radius: 5px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .results-table { width: 100%; border-collapse: collapse; background-color: white; border-radius: 5px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .results-table th { background-color: #f8f9fa; padding: 12px; text-align: left; border-bottom: 2px solid #ddd; font-weight: bold; }
        .results-table td { padding: 10px 12px; border-bottom: 1px solid #eee; vertical-align: top; }
        .success { background-color: #d4edda; color: #155724; }
        .failure { background-color: #f8d7da; color: #721c24; }
        .warning { background-color: #fff3cd; color: #856404; }
        .status-icon { font-weight: bold; font-size: 1.2em; }
        .error-details { font-size: 0.9em; max-width: 300px; word-wrap: break-word; }
        .footer { margin-top: 30px; text-align: center; color: #666; font-size: 0.9em; }
        .stats { display: flex; justify-content: space-around; margin: 15px 0; }
        .stat-box { background-color: #f8f9fa; padding: 15px; border-radius: 5px; text-align: center; min-width: 120px; }
        .stat-number { font-size: 1.5em; font-weight: bold; }
        .success-number { color: #28a745; }
        .failure-number { color: #dc3545; }
        .warning-number { color: #ffc107; }
        .tenant-name { font-weight: bold; }
        .status-good { color: #28a745; }
        .status-bad { color: #dc3545; }
        .status-warn { color: #ffc107; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Tenant Graph API Connection Status Report</h1>
        <p>Generated on: $reportDate</p>
        <p>Total Tenants Tested: $totalTenants</p>
    </div>
    
    <div class="summary">
        <h2>Connection Summary</h2>
        <div class="stats">
            <div class="stat-box">
                <div class="stat-number success-number">$successCount</div>
                <div>Graph API Success</div>
            </div>
            <div class="stat-box">
                <div class="stat-number failure-number">$failureCount</div>
                <div>Graph API Failures</div>
            </div>
        </div>
    </div>
    
    <table class="results-table">
        <thead>
            <tr>
                <th>Client Name</th>
                <th>Tenant ID</th>
                <th>Secret Expiry</th>
                <th>Graph API Status</th>
                <th>Organization Name</th>
                <th>Token Status</th>
                <th>Error Details</th>
            </tr>
        </thead>
        <tbody>
"@

    foreach ($result in $ConnectionResults) {
        $graphStatusClass = if ($result.GraphSuccess) { "success" } else { "failure" }
        $graphStatusIcon = if ($result.GraphSuccess) { "&#10003;" } else { "&#10007;" }
        $graphStatusText = if ($result.GraphSuccess) { "Connected" } else { "Failed" }
        
        $tokenStatusClass = if ($result.TokenSuccess) { "success" } else { "failure" }
        $tokenStatusIcon = if ($result.TokenSuccess) { "&#10003;" } else { "&#10007;" }
        $tokenStatusText = if ($result.TokenSuccess) { "Valid" } else { "Invalid" }
        
        $expiryClass = "success"
        $expiryWarning = ""
        try {
            $expiryDate = [DateTime]::Parse($result.SecretExpiry)
            $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
            if ($daysUntilExpiry -le 30 -and $daysUntilExpiry -gt 7) {
                $expiryClass = "warning"
                $expiryWarning = " (Expires in $daysUntilExpiry days)"
            } elseif ($daysUntilExpiry -le 7) {
                $expiryClass = "failure"
                $expiryWarning = " (Expires in $daysUntilExpiry days)"
            } elseif ($daysUntilExpiry -lt 0) {
                $expiryClass = "failure"
                $expiryWarning = " (EXPIRED)"
            }
        } catch {
                $expiryClass = "warning"
                $expiryWarning = " (Invalid date format)"
        }
        
        $errorDetails = ""
        if ($result.TokenError) { $errorDetails += "Token: $($result.TokenError)<br>" }
        if ($result.GraphError) { $errorDetails += "Graph: $($result.GraphError)" }
        
        $htmlContent += @"
            <tr>
                <td class="tenant-name">$($result.ClientName)</td>
                <td>$($result.TenantId)</td>
                <td class="$expiryClass">$($result.SecretExpiry)$expiryWarning</td>
                <td class="$graphStatusClass">
                    <span class="status-icon">$graphStatusIcon</span> $graphStatusText
                </td>
                <td>$($result.OrganizationName)</td>
                <td class="$tokenStatusClass">
                    <span class="status-icon">$tokenStatusIcon</span> $tokenStatusText
                </td>
                <td class="error-details">$errorDetails</td>
            </tr>
"@
    }

    $processingTime = (Get-Date) - $script:StartTime
    $htmlContent += @"
        </tbody>
    </table>
    
    <div class="footer">
        <p>Report generated by Tenant Connection Test Script | Processing Time: $processingTime</p>
        <p>Status Codes: 200=OK, 401=Unauthorized, 403=Forbidden, 404=Not Found, 500=Server Error</p>
    </div>
</body>
</html>
"@

    # Save report
    $htmlPath = if ($OutputPath) { 
        $OutputPath -replace '\.[^.]+$', '.html' 
    } else { 
        "TenantConnectionReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html" 
    }
    
    $htmlContent | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-ColorOutput "HTML report generated: $htmlPath" "Green"
    
    return $htmlPath
}

# Main 
try {
    $script:StartTime = Get-Date
    Write-ColorOutput "=== Tenant Graph API Connection Testing ===" "Cyan"
    
    # Validate CSV 
    if (-not (Test-Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }

    $tenantData = Import-Csv $CsvPath
    
    $requiredColumns = @('Client', 'Tenant ID', 'Client ID', 'Key Value')
    foreach ($col in $requiredColumns) {
        if (-not ($tenantData[0].PSObject.Properties.Name -contains $col)) {
            throw "Required column missing: $col"
        }
    }

    if ($ClientName) {
        $matchingTenants = $tenantData | Where-Object { $_.Client -like "*$ClientName*" }
        if ($matchingTenants.Count -eq 0) {
            throw "No tenants found matching client name: $ClientName"
        } elseif ($matchingTenants.Count -eq 1) {
            $tenantData = @($matchingTenants)
            Write-ColorOutput "Found matching client: $($matchingTenants.Client)" "Green"
        } else {
            Write-ColorOutput "Multiple clients found matching '$ClientName':" "Yellow"
            $matchingTenants | ForEach-Object { Write-ColorOutput "  - $($_.Client)" "White" }

            $exactMatch = $matchingTenants | Where-Object { $_.Client -eq $ClientName }
            if ($exactMatch) {
                $tenantData = @($exactMatch)
                Write-ColorOutput "Using exact match: $($exactMatch.Client)" "Green"
            } else {
                throw "Multiple clients found. Please specify exact client name or use partial match with single result."
            }
        }
    }
    
    Write-ColorOutput "Testing Graph API connections for $($tenantData.Count) tenant(s)" "Green"
    
    $connectionResults = @()
    $processedCount = 0
    
    foreach ($tenant in $tenantData) {
        $processedCount++
        Write-ColorOutput "`n[$processedCount/$($tenantData.Count)] Testing: $($tenant.Client)" "Cyan"

        $result = [PSCustomObject]@{
            ClientName = $tenant.Client
            TenantId = $tenant.'Tenant ID'
            ClientId = $tenant.'Client ID'
            SecretExpiry = $tenant.Expiry
            TokenSuccess = $false
            TokenError = $null
            GraphSuccess = $false
            GraphError = $null
            OrganizationName = "Unknown"
            TestTimestamp = Get-Date
        }
        
        Write-ColorOutput "  Getting access token..." "Yellow"
        $tokenResult = Get-AccessToken -TenantId $tenant.'Tenant ID' -ClientId $tenant.'Client ID' -ClientSecret $tenant.'Key Value'
        
        $result.TokenSuccess = $tokenResult.Success
        $result.TokenError = $tokenResult.Error
        
        if ($tokenResult.Success) {
            Write-ColorOutput "  [OK] Token acquired successfully" "Green"
            
            Write-ColorOutput "  Testing Graph API connection..." "Yellow"
            $graphResult = Test-GraphConnection -AccessToken $tokenResult.Token -TenantId $tenant.'Tenant ID'
            
            $result.GraphSuccess = $graphResult.Success
            $result.GraphError = $graphResult.Error
            $result.OrganizationName = $graphResult.OrganizationName
            
            if ($graphResult.Success) {
                Write-ColorOutput "  [OK] Graph API connection successful" "Green"
                Write-ColorOutput "  Organization: $($graphResult.OrganizationName)" "White"
                Write-ColorOutput "  Secret Expires: $($tenant.Expiry)" "White"
            } else {
                Write-ColorOutput "  [FAIL] Graph API connection failed: $($graphResult.Error)" "Red"
            }
        } else {
            Write-ColorOutput "  [FAIL] Token acquisition failed: $($tokenResult.Error)" "Red"
            if ($tokenResult.StatusCode) {
                Write-ColorOutput "  Status Code: $($tokenResult.StatusCode)" "Red"
            }
        }
        
        $connectionResults += $result
        
        $percentComplete = [math]::Round(($processedCount / $tenantData.Count) * 100, 1)
        Write-ColorOutput "Progress: $percentComplete% ($processedCount/$($tenantData.Count))" "Cyan"
    }
    
    # Results summary
    Write-ColorOutput "`n=== Connection Test Summary ===" "Cyan"
    $successfulTokens = ($connectionResults | Where-Object { $_.TokenSuccess }).Count
    $successfulGraph = ($connectionResults | Where-Object { $_.GraphSuccess }).Count
    
    Write-ColorOutput "Token Success: $successfulTokens/$($connectionResults.Count)" "Green"
    Write-ColorOutput "Graph API Success: $successfulGraph/$($connectionResults.Count)" "Green"
    

    $failedConnections = $connectionResults | Where-Object { -not $_.GraphSuccess }
    if ($failedConnections.Count -gt 0) {
        Write-ColorOutput "`nFailed Connections:" "Red"
        foreach ($failed in $failedConnections) {
            Write-ColorOutput "  $($failed.ClientName): $($failed.TokenError) $($failed.GraphError)" "Red"
        }
    }
    

    if ($OutputPath) {
        $jsonPath = $OutputPath -replace '\.[^.]+$', '.json'
        $connectionResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-ColorOutput "Detailed results exported to: $jsonPath" "Green"
    }
    
    #  HTML report
    Write-ColorOutput "`nGenerating HTML report..." "Yellow"
    $htmlPath = New-HtmlConnectionReport -ConnectionResults $connectionResults -OutputPath $OutputPath
    
    try {
        Start-Process $htmlPath
        Write-ColorOutput "HTML report opened in default browser" "Green"
    } catch {
        Write-ColorOutput "HTML report saved but could not open automatically: $htmlPath" "Yellow"
    }
    
} catch {
    Write-ColorOutput "Critical Error: $($_.Exception.Message)" "Red"
    Write-ColorOutput $_.Exception.ToString() "Red"
}

#>
