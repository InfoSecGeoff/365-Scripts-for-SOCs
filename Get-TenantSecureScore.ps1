<#
.SYNOPSIS
    Retrieves and generates comprehensive Microsoft 365 Secure Score reports for single or multiple tenants.

.DESCRIPTION
    Get-TenantSecureScore.ps1 connects to Microsoft Graph API to retrieve Secure Score data,
    control profiles, and historical trends for Microsoft 365 tenants. It generates detailed
    HTML reports with actionable recommendations and CSV exports for further analysis.
    
    The script can process:
    - Single tenant using direct credential parameters
    - Multiple tenants using a CSV file with credentials
    - Filtered client from CSV using -ClientName parameter
    
    Generated reports include:
    - Visual dashboard with key metrics
    - Quick wins (low effort, high impact improvements)
    - High priority recommendations based on Microsoft rankings
    - Detailed control analysis with remediation steps
    - Category summaries and trend analysis
    - Consolidated multi-tenant overview (when using CSV)

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID format).
    Required when not using -CsvPath.
    
    Example: "12345678-1234-1234-1234-123456789012"

.PARAMETER ClientId
    The Azure AD Application (Client) ID with Microsoft Graph permissions.
    Required when not using -CsvPath.
    
    Required API Permissions:
    - SecurityEvents.Read.All
    - Organization.Read.All
    - Domain.Read.All
    
    Example: "87654321-4321-4321-4321-210987654321"

.PARAMETER ClientSecret
    The client secret (application password) for the Azure AD application.
    Required when not using -CsvPath.
    
    Note: Store secrets securely. Consider using Azure Key Vault or secure credential storage.

.PARAMETER CsvPath
    Path to a CSV file containing credentials for multiple tenants.
    When specified, processes all tenants in the CSV and generates a consolidated report.
    
    Required CSV columns:
    - Client: Friendly name for the tenant
    - Tenant ID: Azure AD Tenant ID
    - Client ID: Application ID
    - Key Value: Client Secret
    
    Example: "C:\Credentials\Tenants.csv"

.PARAMETER ClientName
    When using -CsvPath, filter to process only the specified client.
    Must exactly match a value in the "Client" column of the CSV.
    
    Example: "Contoso Ltd"

.PARAMETER OutputPath
    Custom output directory path for generated reports.
    If not specified, creates a timestamped folder: "SecureScore-Report-YYYYMMDD-HHMMSS"
    
    Example: "C:\Reports\SecureScore"

.OUTPUTS
    For each tenant processed:
    - HTML Report: Comprehensive visual report with recommendations
    - CSV Export: Detailed control data for analysis
    
    When processing multiple tenants:
    - Consolidated HTML: Multi-tenant overview dashboard
    - Summary CSV: Aggregated scores and metrics

.EXAMPLE
    .\Get-TenantSecureScore.ps1 -TenantId "12345678-90ab-cdef-1234-567890abcdef" `
                                -ClientId "abcdef12-3456-7890-abcd-ef1234567890" `
                                -ClientSecret "your-secret-here"
    
    Processes a single tenant and generates HTML and CSV reports in a timestamped folder.

.EXAMPLE
    .\Get-TenantSecureScore.ps1 -TenantId $tid -ClientId $cid -ClientSecret $secret `
                                -OutputPath "C:\Reports\SecureScore\Contoso"
    
    Processes a single tenant with output saved to a custom directory.

.EXAMPLE
    .\Get-TenantSecureScore.ps1 -CsvPath "C:\Credentials\Tenants.csv"
    
    Processes all tenants listed in the CSV file and generates individual reports
    plus a consolidated multi-tenant dashboard.

.EXAMPLE
    .\Get-TenantSecureScore.ps1 -CsvPath "C:\Credentials\Tenants.csv" `
                                -ClientName "Contoso Ltd"
    
    Processes only the "Contoso Ltd" tenant from the CSV file.

.EXAMPLE
    .\Get-TenantSecureScore.ps1 -CsvPath ".\tenants.csv" -OutputPath "C:\SecureScore\Reports"
    
    Processes all tenants from CSV with output to a custom directory.

.NOTES
    File Name      : Get-TenantSecureScore.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or higher
    Version        : 2.0
    
    Requirements:
    - Azure AD App Registration with appropriate permissions
    - Microsoft Graph API access
    - Internet connectivity to Microsoft Graph endpoints
    
    API Permissions Required:
    - SecurityEvents.Read.All (Application)
    - Organization.Read.All (Application)
    - Domain.Read.All (Application)
    
    CSV File Format:
    Create a CSV file with these exact column headers:
    
    Client,Tenant ID,Client ID,Key Value
    "Contoso Ltd","tenant-guid-here","app-guid-here","secret-here"
    "Fabrikam Inc","tenant-guid-here","app-guid-here","secret-here"

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
    [string]$OutputPath
)

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
        Write-Error "Error obtaining access token: $($_.Exception.Message)"
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
            if ($orgResponse.value -and $orgResponse.value.Count -gt 0) {
                $displayName = $orgResponse.value[0].displayName
            }
        }
        catch {
            if ($TenantId) {
                $displayName = "Tenant $TenantId"
            }
        }
        
        return [PSCustomObject]@{
            TenantId = $TenantId
            DisplayName = $displayName
            InitialDomain = $initialDomain
        }
    }
    catch {
        Write-Warning "Error retrieving tenant information: $($_.Exception.Message)"
        return [PSCustomObject]@{
            TenantId = $TenantId
            DisplayName = if ($TenantId) { "Tenant $TenantId" } else { "Unknown" }
            InitialDomain = "unknown.onmicrosoft.com"
        }
    }
}

function Get-SecureScore {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $scoreUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1"
        Write-Host "  Calling: $scoreUri" -ForegroundColor Gray
        $scoreResponse = Invoke-RestMethod -Uri $scoreUri -Method Get -Headers $headers
        
        if ($scoreResponse.value.Count -eq 0) {
            Write-Warning "No secure score data available"
            return $null
        }
        
        return $scoreResponse.value[0]
    }
    catch {
        Write-Error "Error retrieving secure score: $($_.Exception.Message)"
        return $null
    }
}

function Get-SecureScoreHistory {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [int]$Months = 3
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $startDate = (Get-Date).AddMonths(-$Months).ToString("yyyy-MM-dd")
        $historyUri = "https://graph.microsoft.com/v1.0/security/secureScores?`$filter=createdDateTime ge $startDate&`$orderby=createdDateTime"
        Write-Host "  Calling: $historyUri" -ForegroundColor Gray
        $historyResponse = Invoke-RestMethod -Uri $historyUri -Method Get -Headers $headers
        
        return $historyResponse.value
    }
    catch {
        Write-Warning "Error retrieving secure score history: $($_.Exception.Message)"
        return @()
    }
}

function Get-SecureScoreControlProfiles {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $controlProfilesUri = "https://graph.microsoft.com/v1.0/security/secureScoreControlProfiles"
        Write-Host "Retrieving secure score control profiles..." -ForegroundColor Yellow
        Write-Host "  Calling: $controlProfilesUri" -ForegroundColor Gray
        
        $allControlProfiles = @()
        $nextLink = $controlProfilesUri
        
        # Handle pagination
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $allControlProfiles += $response.value
            $nextLink = $response.'@odata.nextLink'
            
            if ($nextLink) {
                Write-Host "  Retrieved $($allControlProfiles.Count) control profiles, fetching more..." -ForegroundColor Gray
            }
        } while ($nextLink)
        
        Write-Host "  Total control profiles retrieved: $($allControlProfiles.Count)" -ForegroundColor Green
        
        return $allControlProfiles
    }
    catch {
        Write-Error "Error retrieving secure score control profiles: $($_.Exception.Message)"
        return @()
    }
}

function Merge-ControlData {
    param (
        [Parameter(Mandatory=$true)]
        [object]$SecureScore,
        
        [Parameter(Mandatory=$true)]
        [array]$ControlProfiles
    )
    
    Write-Host "Merging control scores with control profiles..." -ForegroundColor Yellow
    
    # Create lookup table for control profiles
    $profileLookup = @{}
    foreach ($profile in $ControlProfiles) {
        $profileLookup[$profile.id] = $profile
    }
    
    Write-Host "  Profile lookup table created with $($profileLookup.Count) entries" -ForegroundColor Gray
    
    $mergedControls = @()
    $matchedCount = 0
    $unmatchedCount = 0
    
    # Process each control score from the secure score API
    foreach ($controlScore in $SecureScore.controlScores) {
        $controlId = $controlScore.controlName
        $profile = $profileLookup[$controlId]
        
        # Get values from controlScore - use actual properties that exist
        $currentScore = if ($controlScore.score -ne $null) { [double]$controlScore.score } else { 0 }
        $scoreInPercentage = if ($controlScore.scoreInPercentage -ne $null) { [double]$controlScore.scoreInPercentage } else { 0 }
        
        # Try to get implementation status from controlScore first
        $implementationStatus = "Unknown"
        if ($controlScore.implementationStatus) {
            # Parse the implementation status string
            $statusText = $controlScore.implementationStatus
            if ($statusText -match "On|Implemented|Completed") {
                $implementationStatus = "Implemented"
            }
            elseif ($statusText -match "Off|Not") {
                $implementationStatus = "Not Implemented"
            }
            else {
                $implementationStatus = "Partial"
            }
        }
        
        if ($profile) {
            $matchedCount++
            
            # Get maxScore from profile
            $maxScore = if ($profile.maxScore) { [double]$profile.maxScore } else { 0 }
            
            # Calculate percentage if not provided or to verify
            if ($maxScore -gt 0 -and $scoreInPercentage -eq 0) {
                $calculatedPercentage = [math]::Round(($currentScore / $maxScore) * 100, 2)
            }
            else {
                $calculatedPercentage = $scoreInPercentage
            }
            
            # Determine implementation status from percentage if needed
            if ($implementationStatus -eq "Unknown") {
                if ($calculatedPercentage -eq 100) {
                    $implementationStatus = "Implemented"
                }
                elseif ($calculatedPercentage -eq 0) {
                    $implementationStatus = "Not Implemented"
                }
                else {
                    $implementationStatus = "Partial"
                }
            }
            
            $mergedControl = [PSCustomObject]@{
                # Basic identification
                Id = $controlId
                Title = $profile.title
                Description = if ($profile.remediation) { $profile.remediation } else { $controlScore.description }
                
                # Scoring - from BOTH APIs
                MaxScore = $maxScore
                CurrentScore = $currentScore
                PercentageComplete = $calculatedPercentage
                ImplementationStatus = $implementationStatus
                
                # Categorization
                ControlCategory = if ($profile.controlCategory) { $profile.controlCategory } else { $controlScore.controlCategory }
                Service = $profile.service
                
                # Detailed recommendation fields from control profile
                Remediation = $profile.remediation
                RemediationImpact = $profile.remediationImpact
                ImplementationCost = if ($profile.implementationCost -and $profile.implementationCost -ne "Unknown") { $profile.implementationCost } else { "Not Specified" }
                UserImpact = if ($profile.userImpact -and $profile.userImpact -ne "Unknown") { $profile.userImpact } else { "Not Specified" }
                ActionType = $profile.actionType
                ActionUrl = $profile.actionUrl
                Rank = if ($profile.rank) { $profile.rank } else { 999 }
                Threats = if ($profile.threats) { ($profile.threats -join "; ") } else { "" }
                Tier = $profile.tier
                Deprecated = $profile.deprecated
                
                # Compliance info
                ComplianceFrameworks = if ($profile.complianceInformation) {
                    ($profile.complianceInformation | ForEach-Object {
                        "$($_.certificationName):$($_.certificationControls -join ',')"
                    }) -join "; "
                } else { "" }
                
                # Additional metadata
                LastModified = $profile.lastModifiedDateTime
                LastSynced = $controlScore.lastSynced
                VendorInfo = if ($profile.vendorInformation) {
                    "$($profile.vendorInformation.provider) - $($profile.vendorInformation.vendor)"
                } else { "Microsoft" }
            }
            
            $mergedControls += $mergedControl
        }
        else {
            $unmatchedCount++
            Write-Verbose "No profile found for control: $controlId"
            
            # Control score exists but no profile - use what we have from controlScore
            # Calculate implementation status from percentage if available
            if ($implementationStatus -eq "Unknown" -and $scoreInPercentage -gt 0) {
                if ($scoreInPercentage -eq 100) {
                    $implementationStatus = "Implemented"
                }
                elseif ($scoreInPercentage -eq 0) {
                    $implementationStatus = "Not Implemented"
                }
                else {
                    $implementationStatus = "Partial"
                }
            }
            
            $mergedControl = [PSCustomObject]@{
                Id = $controlId
                Title = $controlId
                Description = $controlScore.description
                MaxScore = 0
                CurrentScore = $currentScore
                PercentageComplete = $scoreInPercentage
                ImplementationStatus = $implementationStatus
                ControlCategory = $controlScore.controlCategory
                Service = "Unknown"
                Remediation = $controlScore.description
                RemediationImpact = ""
                ImplementationCost = "Not Specified"
                UserImpact = "Not Specified"
                ActionType = ""
                ActionUrl = ""
                Rank = 999
                Threats = ""
                Tier = ""
                Deprecated = $false
                ComplianceFrameworks = ""
                LastModified = ""
                LastSynced = $controlScore.lastSynced
                VendorInfo = "Microsoft"
            }
            
            $mergedControls += $mergedControl
        }
    }
    
    Write-Host "  Matched $matchedCount controls with profiles, $unmatchedCount without profiles" -ForegroundColor $(if ($unmatchedCount -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Total merged controls: $($mergedControls.Count)" -ForegroundColor Green
    
    return $mergedControls
}

function Format-SecureScoreReport {
    param (
        [Parameter(Mandatory=$true)]
        [object]$SecureScore,
        
        [Parameter(Mandatory=$true)]
        [array]$ControlDetails,
        
        [Parameter(Mandatory=$false)]
        [array]$ScoreHistory = @()
    )
    
    # Calculate metrics
    $averageScore = if ($ScoreHistory.Count -gt 0) { 
        [math]::Round(($ScoreHistory | Measure-Object -Property currentScore -Average).Average, 2)
    } else { 0 }
    
    $maxPossibleScore = if ($SecureScore.maxScore) { $SecureScore.maxScore } else { 0 }
    $currentScore = if ($SecureScore.currentScore) { $SecureScore.currentScore } else { 0 }
    $percentComplete = if ($maxPossibleScore -gt 0) { [math]::Round(($currentScore / $maxPossibleScore) * 100, 2) } else { 0 }
    
    # Count implementation statuses
    $implementedControls = ($ControlDetails | Where-Object { $_.ImplementationStatus -eq "Implemented" }).Count
    $notImplementedControls = ($ControlDetails | Where-Object { $_.ImplementationStatus -eq "Not Implemented" }).Count
    $partialControls = ($ControlDetails | Where-Object { $_.ImplementationStatus -eq "Partial" }).Count
    $unknownControls = ($ControlDetails | Where-Object { $_.ImplementationStatus -eq "Unknown" }).Count
    
    # Group controls by category
    $controlsByCategory = if ($ControlDetails.Count -gt 0) { 
        $ControlDetails | Group-Object -Property ControlCategory 
    } else { 
        @() 
    }
    
    # Top improvement opportunities - not implemented or partial, has maxScore, sorted by max score
    $improvementOpportunities = $ControlDetails | 
        Where-Object { 
            $_.ImplementationStatus -ne "Implemented" -and 
            -not $_.Deprecated -and
            $_.MaxScore -gt 0
        } | 
        Sort-Object -Property @{Expression="MaxScore"; Descending=$true}, @{Expression="Rank"; Descending=$false} | 
        Select-Object -First 25
    
    # Quick wins - high impact, low/moderate cost, not implemented
    $quickWins = $ControlDetails |
        Where-Object {
            $_.ImplementationStatus -ne "Implemented" -and
            -not $_.Deprecated -and
            $_.MaxScore -gt 0 -and
            ($_.ImplementationCost -eq "Low" -or $_.ImplementationCost -eq "Moderate")
        } |
        Sort-Object -Property @{Expression="MaxScore"; Descending=$true} |
        Select-Object -First 15
    
    # High priority - high rank (low rank number = high priority), high max score
    $highPriority = $ControlDetails |
        Where-Object {
            $_.ImplementationStatus -ne "Implemented" -and
            -not $_.Deprecated -and
            $_.MaxScore -gt 5 -and
            $_.Rank -gt 0 -and
            $_.Rank -le 30
        } |
        Sort-Object -Property Rank |
        Select-Object -First 15
    
    $reportInfo = [PSCustomObject]@{
        CurrentScore = $currentScore
        MaxPossibleScore = $maxPossibleScore
        PercentComplete = $percentComplete
        AverageScore = $averageScore
        ScoreTrend = if ($ScoreHistory.Count -gt 1) {
            $firstScore = $ScoreHistory[0].currentScore
            $lastScore = $ScoreHistory[-1].currentScore
            [math]::Round(($lastScore - $firstScore), 2)
        } else { 0 }
        ImplementedControls = $implementedControls
        NotImplementedControls = $notImplementedControls
        PartialControls = $partialControls
        UnknownControls = $unknownControls
        ControlsByCategory = $controlsByCategory
        ImprovementOpportunities = $improvementOpportunities
        QuickWins = $quickWins
        HighPriority = $highPriority
        LastUpdated = if ($SecureScore.createdDateTime) { $SecureScore.createdDateTime } else { (Get-Date).ToString() }
        AllControls = $ControlDetails
    }
    
    Write-Host "`nReport Summary:" -ForegroundColor Cyan
    Write-Host "  Current Score: $currentScore / $maxPossibleScore ($percentComplete%)" -ForegroundColor White
    Write-Host "  Implemented: $implementedControls | Not Implemented: $notImplementedControls | Partial: $partialControls | Unknown: $unknownControls" -ForegroundColor White
    Write-Host "  Total Controls: $($ControlDetails.Count)" -ForegroundColor White
    Write-Host "  Improvement Opportunities: $($improvementOpportunities.Count)" -ForegroundColor Yellow
    Write-Host "  Quick Wins Available: $($quickWins.Count)" -ForegroundColor Green
    Write-Host "  High Priority Items: $($highPriority.Count)" -ForegroundColor Magenta
    
    return $reportInfo
}

function Get-SecureScoreHtml {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantName,
        
        [Parameter(Mandatory=$true)]
        [string]$TenantDomain,
        
        [Parameter(Mandatory=$true)]
        [object]$ReportInfo
    )
    
    # Helper function to escape HTML and remove HTML tags from remediation
    function ConvertTo-HtmlSafe {
        param([string]$Text)
        if ([string]::IsNullOrEmpty($Text)) { return "" }
        return [System.Net.WebUtility]::HtmlEncode($Text)
    }
    
    function Strip-HtmlTags {
        param([string]$Html)
        if ([string]::IsNullOrEmpty($Html)) { return "" }
        # Remove HTML tags but keep line breaks
        $text = $Html -replace '<br\s*/?>',"`n" -replace '<[^>]+>','' -replace '&nbsp;',' '
        return $text.Trim()
    }
    
    # Generate Quick Wins section
    $quickWinsHtml = ""
    if ($ReportInfo.QuickWins.Count -gt 0) {
        $quickWinsRows = ($ReportInfo.QuickWins | ForEach-Object {
            $safeTitle = ConvertTo-HtmlSafe $_.Title
            $cleanRemediation = Strip-HtmlTags $_.Remediation
            $safeRemediation = ConvertTo-HtmlSafe $cleanRemediation
            $actionUrl = if ($_.ActionUrl) { ConvertTo-HtmlSafe $_.ActionUrl } else { "#" }
            $costClass = switch ($_.ImplementationCost) {
                "Low" { "success" }
                "Moderate" { "warning" }
                "High" { "failure" }
                default { "" }
            }
            @"
                    <tr>
                        <td><strong>$safeTitle</strong><br><small style="color: #666;">$($safeRemediation.Substring(0, [Math]::Min(300, $safeRemediation.Length)))$(if ($safeRemediation.Length -gt 300) { "..." })</small></td>
                        <td style="text-align: center; font-weight: bold;">$($_.MaxScore)</td>
                        <td style="text-align: center;" class="$costClass">$($_.ImplementationCost)</td>
                        <td style="text-align: center;">$($_.ControlCategory)</td>
                        <td style="text-align: center;"><a href="$actionUrl" target="_blank" style="padding: 4px 12px; background: #0078D4; color: white; text-decoration: none; border-radius: 4px; font-size: 0.85em;">Configure</a></td>
                    </tr>
"@
        }) -join ""
        
        $quickWinsHtml = @"
        <div class="card">
            <h2>⚡ Quick Wins (Low-Moderate Cost, High Impact)</h2>
            <p style="color: #666;">These controls offer significant security improvements with reasonable effort. Start here for maximum ROI.</p>
            <div class="table-container">
                <table>
                    <tr>
                        <th>Control & Remediation Steps</th>
                        <th style="text-align: center; width: 80px;">Points</th>
                        <th style="text-align: center; width: 120px;">Cost</th>
                        <th style="text-align: center; width: 100px;">Category</th>
                        <th style="text-align: center; width: 100px;">Action</th>
                    </tr>
                    $quickWinsRows
                </table>
            </div>
        </div>
"@
    }
    
    # Generate High Priority section
    $highPriorityHtml = ""
    if ($ReportInfo.HighPriority.Count -gt 0) {
        $highPriorityRows = ($ReportInfo.HighPriority | ForEach-Object {
            $safeTitle = ConvertTo-HtmlSafe $_.Title
            $cleanRemediation = Strip-HtmlTags $_.Remediation
            $safeRemediation = ConvertTo-HtmlSafe $cleanRemediation
            $safeThreats = ConvertTo-HtmlSafe $_.Threats
            $actionUrl = if ($_.ActionUrl) { ConvertTo-HtmlSafe $_.ActionUrl } else { "#" }
            @"
                    <tr>
                        <td style="text-align: center; font-weight: bold;">$($_.Rank)</td>
                        <td><strong>$safeTitle</strong><br><small style="color: #666;">$($safeRemediation.Substring(0, [Math]::Min(300, $safeRemediation.Length)))$(if ($safeRemediation.Length -gt 300) { "..." })</small></td>
                        <td style="text-align: center; font-weight: bold;">$($_.MaxScore)</td>
                        <td><small style="color: #666;">$safeThreats</small></td>
                        <td style="text-align: center;">$($_.ImplementationCost)</td>
                        <td style="text-align: center;"><a href="$actionUrl" target="_blank" style="padding: 4px 12px; background: #0078D4; color: white; text-decoration: none; border-radius: 4px; font-size: 0.85em;">Configure</a></td>
                    </tr>
"@
        }) -join ""
        
        $highPriorityHtml = @"
        <div class="card">
            <h2>🎯 High Priority Recommendations</h2>
            <p style="color: #666;">Microsoft's top-ranked security controls based on threat intelligence and security best practices.</p>
            <div class="table-container">
                <table>
                    <tr>
                        <th style="text-align: center; width: 60px;">Rank</th>
                        <th>Control & Remediation Steps</th>
                        <th style="text-align: center; width: 80px;">Points</th>
                        <th style="width: 200px;">Threats Mitigated</th>
                        <th style="text-align: center; width: 120px;">Cost</th>
                        <th style="text-align: center; width: 100px;">Action</th>
                    </tr>
                    $highPriorityRows
                </table>
            </div>
        </div>
"@
    }
    
    # Generate Top Opportunities section
    $opportunitiesHtml = ""
    if ($ReportInfo.ImprovementOpportunities.Count -gt 0) {
        $opportunitiesRows = ($ReportInfo.ImprovementOpportunities | Select-Object -First 20 | ForEach-Object {
            $safeTitle = ConvertTo-HtmlSafe $_.Title
            $cleanRemediation = Strip-HtmlTags $_.Remediation
            $safeRemediation = ConvertTo-HtmlSafe $cleanRemediation
            $safeUserImpact = ConvertTo-HtmlSafe $_.UserImpact
            $actionUrl = if ($_.ActionUrl) { ConvertTo-HtmlSafe $_.ActionUrl } else { "#" }
            $costClass = switch ($_.ImplementationCost) {
                "Low" { "success" }
                "Moderate" { "warning" }
                "High" { "failure" }
                default { "" }
            }
            $statusClass = switch ($_.ImplementationStatus) {
                "Implemented" { "success" }
                "Not Implemented" { "failure" }
                "Partial" { "warning" }
                default { "" }
            }
            @"
                    <tr>
                        <td><strong>$safeTitle</strong><br><small style="color: #666;">$($safeRemediation.Substring(0, [Math]::Min(250, $safeRemediation.Length)))$(if ($safeRemediation.Length -gt 250) { "..." })</small></td>
                        <td style="text-align: center; font-weight: bold;">$($_.MaxScore)</td>
                        <td style="text-align: center;">$($_.CurrentScore)</td>
                        <td style="text-align: center;" class="$statusClass">$($_.PercentageComplete)%</td>
                        <td style="text-align: center;" class="$costClass">$($_.ImplementationCost)</td>
                        <td><small style="color: #666;">$safeUserImpact</small></td>
                        <td style="text-align: center;">$($_.ControlCategory)</td>
                        <td style="text-align: center;"><a href="$actionUrl" target="_blank" style="padding: 4px 12px; background: #0078D4; color: white; text-decoration: none; border-radius: 4px; font-size: 0.85em;">Configure</a></td>
                    </tr>
"@
        }) -join ""
        
        $opportunitiesHtml = @"
        <div class="card">
            <h2>📊 All Improvement Opportunities (Top 20 by Points)</h2>
            <p style="color: #666;">Complete list of available security improvements sorted by potential score gain.</p>
            <div class="table-container">
                <table>
                    <tr>
                        <th>Control & Remediation Steps</th>
                        <th style="text-align: center; width: 70px;">Max<br>Points</th>
                        <th style="text-align: center; width: 70px;">Current</th>
                        <th style="text-align: center; width: 90px;">Progress</th>
                        <th style="text-align: center; width: 100px;">Cost</th>
                        <th style="width: 150px;">User Impact</th>
                        <th style="text-align: center; width: 90px;">Category</th>
                        <th style="text-align: center; width: 90px;">Action</th>
                    </tr>
                    $opportunitiesRows
                </table>
            </div>
            <p style="margin-top: 10px; color: #666;"><em>Showing top 20 by maximum score. See CSV export for complete list.</em></p>
        </div>
"@
    }
    
    # Generate Category Summary
    $categorySummaryRows = ($ReportInfo.ControlsByCategory | ForEach-Object {
        $categoryName = $_.Name
        $totalControls = $_.Count
        $implemented = ($_.Group | Where-Object { $_.ImplementationStatus -eq "Implemented" }).Count
        $notImplemented = ($_.Group | Where-Object { $_.ImplementationStatus -eq "Not Implemented" }).Count
        $partial = ($_.Group | Where-Object { $_.ImplementationStatus -eq "Partial" }).Count
        $unknown = $totalControls - $implemented - $notImplemented - $partial
        $avgCompletion = [math]::Round(($_.Group | Measure-Object -Property PercentageComplete -Average).Average, 1)
        $totalPoints = [math]::Round(($_.Group | Measure-Object -Property CurrentScore -Sum).Sum, 0)
        $maxPoints = [math]::Round(($_.Group | Measure-Object -Property MaxScore -Sum).Sum, 0)
        @"
                    <tr>
                        <td>$categoryName</td>
                        <td style="text-align: center;">$totalControls</td>
                        <td style="text-align: center;" class="success">$implemented</td>
                        <td style="text-align: center;" class="failure">$notImplemented</td>
                        <td style="text-align: center;" class="warning">$partial</td>
                        <td style="text-align: center;">$unknown</td>
                        <td style="text-align: center; font-weight: bold;">$avgCompletion%</td>
                        <td style="text-align: center;">$totalPoints / $maxPoints</td>
                    </tr>
"@
    }) -join ""
    
    # HTML Template
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Microsoft 365 Secure Score Report - $TenantName</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
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
            padding: 20px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .header-card {
            background: linear-gradient(135deg, #0078D4, #005a9e);
            color: white;
        }
        .header-card h1 {
            color: white;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .dashboard-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .dashboard-number {
            font-size: 2.2em;
            font-weight: bold;
            margin-bottom: 10px;
        }
        .dashboard-label {
            font-size: 1em;
            opacity: 0.9;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 10px;
            font-size: 0.85rem;
        }
        th, td { 
            padding: 10px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
            vertical-align: top;
        }
        th { 
            background-color: #0078D4; 
            color: white;
            position: sticky;
            top: 0;
            font-weight: 600;
            z-index: 10;
        }
        tr:hover { 
            background-color: #f5f5f5; 
        }
        .success { color: #107C10; font-weight: bold; }
        .warning { color: #FF8C00; font-weight: bold; }
        .failure { color: #E81123; font-weight: bold; }
        .table-container {
            max-height: 700px;
            overflow-y: auto;
            margin-bottom: 10px;
        }
        .trend-up { color: #107C10; }
        .trend-down { color: #E81123; }
        .trend-neutral { color: #666; }
        .info-section {
            background-color: #E5F1FA;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }
        a {
            color: #0078D4;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card header-card">
            <h1>Microsoft 365 Secure Score Report</h1>
            <div class="info-section" style="background-color: rgba(255,255,255,0.1);">
                <strong>Tenant:</strong> $TenantName<br>
                <strong>Domain:</strong> $TenantDomain<br>
                <strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")<br>
                <strong>Last Score Update:</strong> $([DateTime]::Parse($ReportInfo.LastUpdated).ToString("yyyy-MM-dd HH:mm:ss"))
            </div>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card">
                <div class="dashboard-number">$($ReportInfo.CurrentScore) / $($ReportInfo.MaxPossibleScore)</div>
                <div class="dashboard-label">Current Score</div>
                <div style="font-size: 1.3em; margin-top: 5px; font-weight: bold;">$($ReportInfo.PercentComplete)%</div>
            </div>
            
            <div class="dashboard-card">
                <div class="dashboard-number $(if ($ReportInfo.ScoreTrend -gt 0) { "trend-up" } elseif ($ReportInfo.ScoreTrend -lt 0) { "trend-down" } else { "trend-neutral" })">
                    $(if ($ReportInfo.ScoreTrend -gt 0) { "+$($ReportInfo.ScoreTrend)" } else { "$($ReportInfo.ScoreTrend)" })
                </div>
                <div class="dashboard-label">Trend (90 days)</div>
                <div style="font-size: 0.9em; margin-top: 5px;">Avg: $($ReportInfo.AverageScore)</div>
            </div>
            
            <div class="dashboard-card">
                <div class="dashboard-number">$($ReportInfo.ImplementedControls)</div>
                <div class="dashboard-label">Implemented</div>
                <div style="font-size: 0.9em; margin-top: 5px;">of $($ReportInfo.AllControls.Count) total</div>
            </div>
            
            <div class="dashboard-card">
                <div class="dashboard-number">$($ReportInfo.NotImplementedControls)</div>
                <div class="dashboard-label">Not Implemented</div>
                <div style="font-size: 0.9em; margin-top: 5px;">$($ReportInfo.PartialControls) partial</div>
            </div>
            
            <div class="dashboard-card">
                <div class="dashboard-number">$($ReportInfo.QuickWins.Count)</div>
                <div class="dashboard-label">Quick Wins</div>
                <div style="font-size: 0.9em; margin-top: 5px;">Low effort, high value</div>
            </div>
        </div>
        
        $quickWinsHtml
        
        $highPriorityHtml
        
        $opportunitiesHtml
        
        <div class="card">
            <h2>📈 Summary by Category</h2>
            <div class="table-container">
                <table>
                    <tr>
                        <th>Category</th>
                        <th style="text-align: center; width: 80px;">Total</th>
                        <th style="text-align: center; width: 100px;">Implemented</th>
                        <th style="text-align: center; width: 120px;">Not Implemented</th>
                        <th style="text-align: center; width: 80px;">Partial</th>
                        <th style="text-align: center; width: 90px;">Unknown</th>
                        <th style="text-align: center; width: 110px;">Avg Complete</th>
                        <th style="text-align: center; width: 120px;">Points</th>
                    </tr>
                    $categorySummaryRows
                </table>
            </div>
        </div>
        
        <div class="card">
            <h3>📝 Understanding This Report</h3>
            <ul>
                <li><strong>Secure Score:</strong> Microsoft 365 Secure Score measures your organization's security posture. Higher scores indicate better security.</li>
                <li><strong>Quick Wins:</strong> Low-to-moderate effort security improvements that provide significant value. These are your best ROI opportunities.</li>
                <li><strong>High Priority:</strong> Microsoft's top-ranked recommendations based on current threat intelligence and industry best practices.</li>
                <li><strong>Implementation Cost:</strong> Estimated effort - <span class="success">Low</span> (minimal), <span class="warning">Moderate</span> (some effort), <span class="failure">High</span> (significant resources).</li>
                <li><strong>User Impact:</strong> How implementing each control affects end users.</li>
                <li><strong>Action Links:</strong> Click "Configure" to go directly to the relevant admin console.</li>
                <li><strong>Complete Details:</strong> See the exported CSV file for full control details including compliance mappings.</li>
            </ul>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Get-ConsolidatedSecureScoreHtml {
    param (
        [Parameter(Mandatory=$true)]
        [array]$TenantScores
    )
    
    $tableRows = ($TenantScores | ForEach-Object {
        $scoreClass = if ($_.PercentComplete -ge 70) { "success" } elseif ($_.PercentComplete -ge 40) { "warning" } else { "failure" }
        $trendClass = if ($_.ScoreTrend -gt 0) { "trend-up" } elseif ($_.ScoreTrend -lt 0) { "trend-down" } else { "trend-neutral" }
        $trendIndicator = if ($_.ScoreTrend -gt 0) { "↑" } elseif ($_.ScoreTrend -lt 0) { "↓" } else { "=" }
        @"
        <tr>
            <td>$($_.ClientName)</td>
            <td>$($_.TenantDomain)</td>
            <td style="text-align: center;">$($_.CurrentScore) / $($_.MaxScore)</td>
            <td style="text-align: center;" class="$scoreClass">$($_.PercentComplete)%</td>
            <td style="text-align: center;" class="$trendClass">$trendIndicator $([Math]::Abs($_.ScoreTrend))</td>
            <td style="text-align: center;">$($_.ImplementedControls)</td>
            <td style="text-align: center;">$($_.NotImplementedControls)</td>
            <td style="text-align: center;">$($_.PartialControls)</td>
            <td style="text-align: center;">$([DateTime]::Parse($_.LastUpdated).ToString("yyyy-MM-dd"))</td>
        </tr>
"@
    }) -join ""
    
    $averageScore = [math]::Round(($TenantScores | Measure-Object -Property PercentComplete -Average).Average, 2)
    $minScore = ($TenantScores | Measure-Object -Property PercentComplete -Minimum).Minimum
    $maxScore = ($TenantScores | Measure-Object -Property PercentComplete -Maximum).Maximum
    $tenantsAbove70 = ($TenantScores | Where-Object { $_.PercentComplete -ge 70 }).Count
    $tenantsBetween40And70 = ($TenantScores | Where-Object { $_.PercentComplete -ge 40 -and $_.PercentComplete -lt 70 }).Count
    $tenantsBelow40 = ($TenantScores | Where-Object { $_.PercentComplete -lt 40 }).Count
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Consolidated Microsoft 365 Secure Score Report</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; color: #333; }
        h1, h2, h3 { color: #0078D4; }
        .container { max-width: 1600px; margin: 0 auto; }
        .card { background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }
        .dashboard { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 20px; }
        .dashboard-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 8px; padding: 20px; flex: 1; min-width: 200px; text-align: center; }
        .dashboard-number { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .dashboard-label { font-size: 14px; opacity: 0.9; }
        table { border-collapse: collapse; width: 100%; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #0078D4; color: white; position: sticky; top: 0; }
        tr:hover { background-color: #f5f5f5; }
        .success { color: #107C10; font-weight: bold; }
        .warning { color: #FF8C00; font-weight: bold; }
        .failure { color: #E81123; font-weight: bold; }
        .trend-up { color: #107C10; font-weight: bold; }
        .trend-down { color: #E81123; font-weight: bold; }
        .trend-neutral { color: #666; }
        .summary { background-color: #E5F1FA; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Consolidated Microsoft 365 Secure Score Report</h1>
        <div class="summary card">
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p><strong>Total Tenants:</strong> $($TenantScores.Count)</p>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card">
                <div class="dashboard-number">$averageScore%</div>
                <div class="dashboard-label">Average Score</div>
                <p style="font-size: 0.9em; margin-top: 5px;">Min: $minScore% | Max: $maxScore%</p>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsAbove70</div>
                <div class="dashboard-label">Good (≥70%)</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsBetween40And70</div>
                <div class="dashboard-label">Fair (40-69%)</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$tenantsBelow40</div>
                <div class="dashboard-label">At Risk (<40%)</div>
            </div>
        </div>
        
        <div class="card">
            <h2>Tenant Overview</h2>
            <table>
                <tr>
                    <th>Tenant</th>
                    <th>Domain</th>
                    <th style="text-align: center;">Score</th>
                    <th style="text-align: center;">% Complete</th>
                    <th style="text-align: center;">Trend</th>
                    <th style="text-align: center;">Implemented</th>
                    <th style="text-align: center;">Not Impl.</th>
                    <th style="text-align: center;">Partial</th>
                    <th style="text-align: center;">Updated</th>
                </tr>
                $tableRows
            </table>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

# Main script execution
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"

if ($OutputPath) {
    $outputFolder = $OutputPath
} else {
    $outputFolder = "SecureScore-Report-$timestamp"
}

New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
Write-Host "Output folder: $outputFolder`n" -ForegroundColor Cyan

$allTenantsScoreInfo = @()

if ($CsvPath) {
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }
    
    try {
        $tenants = Import-Csv -Path $CsvPath
        
        if ($ClientName) {
            $tenants = $tenants | Where-Object { $_.Client -eq $ClientName }
            if ($tenants.Count -eq 0) {
                Write-Error "Client '$ClientName' not found in CSV"
                return
            }
        }
        
        $totalTenants = $tenants.Count
        $currentTenant = 0
        
        foreach ($tenant in $tenants) {
            $currentTenant++
            
            if ([string]::IsNullOrWhiteSpace($tenant.'Tenant ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Client ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Key Value')) {
                Write-Warning "Skipping tenant '$($tenant.Client)' - Missing credentials"
                continue
            }
            
            $clientName = $tenant.Client.Trim()
            $tenantId = $tenant.'Tenant ID'.Trim()
            $clientId = $tenant.'Client ID'.Trim()
            $clientSecret = $tenant.'Key Value'.Trim()
            
            Write-Host "`n$('='*70)" -ForegroundColor Cyan
            Write-Host "Processing $currentTenant of $totalTenants`: $clientName" -ForegroundColor Cyan
            Write-Host "$('='*70)" -ForegroundColor Cyan
            
            try {
                Write-Progress -Activity "Processing Tenants" -Status "$currentTenant of $totalTenants`: $clientName" -PercentComplete (($currentTenant / $totalTenants) * 100)
                
                Write-Host "Authenticating..." -ForegroundColor Yellow
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                
                Write-Host "Getting tenant information..." -ForegroundColor Yellow
                $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $tenantId
                
                Write-Host "Retrieving secure score..." -ForegroundColor Yellow
                $secureScore = Get-SecureScore -AccessToken $accessToken
                
                if ($secureScore) {
                    $controlProfiles = Get-SecureScoreControlProfiles -AccessToken $accessToken
                    $controlDetails = Merge-ControlData -SecureScore $secureScore -ControlProfiles $controlProfiles
                    
                    Write-Host "Retrieving score history..." -ForegroundColor Yellow
                    $scoreHistory = Get-SecureScoreHistory -AccessToken $accessToken -Months 3
                    
                    $reportInfo = Format-SecureScoreReport -SecureScore $secureScore -ControlDetails $controlDetails -ScoreHistory $scoreHistory
                    
                    $tenantReport = [PSCustomObject]@{
                        ClientName = $clientName
                        TenantId = $tenantId
                        DisplayName = $tenantInfo.DisplayName
                        TenantDomain = $tenantInfo.InitialDomain
                        CurrentScore = $reportInfo.CurrentScore
                        MaxScore = $reportInfo.MaxPossibleScore
                        PercentComplete = $reportInfo.PercentComplete
                        ScoreTrend = $reportInfo.ScoreTrend
                        ImplementedControls = $reportInfo.ImplementedControls
                        NotImplementedControls = $reportInfo.NotImplementedControls
                        PartialControls = $reportInfo.PartialControls
                        LastUpdated = $secureScore.createdDateTime
                    }
                    
                    $allTenantsScoreInfo += $tenantReport
                    
                    # Generate reports
                    $safeClientName = $clientName -replace '[^a-zA-Z0-9\-_]', '_'
                    $tenantHtmlFile = Join-Path -Path $outputFolder -ChildPath "SecureScore-$safeClientName-$timestamp.html"
                    $tenantHtmlContent = Get-SecureScoreHtml -TenantName $clientName -TenantDomain $tenantInfo.InitialDomain -ReportInfo $reportInfo
                    $tenantHtmlContent | Out-File -FilePath $tenantHtmlFile -Encoding utf8
                    
                    $controlsCsvFile = Join-Path -Path $outputFolder -ChildPath "SecureControls-$safeClientName-$timestamp.csv"
                    $controlDetails | Export-Csv -Path $controlsCsvFile -NoTypeInformation
                    
                    Write-Host "`nReports saved:" -ForegroundColor Green
                    Write-Host "  HTML: $tenantHtmlFile" -ForegroundColor White
                    Write-Host "  CSV:  $controlsCsvFile" -ForegroundColor White
                }
                else {
                    Write-Host "No Secure Score data available" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Error "Error processing tenant: $($_.Exception.Message)"
            }
        }
        
        Write-Progress -Activity "Processing Tenants" -Completed
        
        if ($allTenantsScoreInfo.Count -gt 0) {
            $summaryFile = Join-Path -Path $outputFolder -ChildPath "SecureScore-AllTenants-$timestamp.csv"
            $allTenantsScoreInfo | Export-Csv -Path $summaryFile -NoTypeInformation
            
            $consolidatedHtmlFile = Join-Path -Path $outputFolder -ChildPath "SecureScore-Consolidated-$timestamp.html"
            $consolidatedHtmlContent = Get-ConsolidatedSecureScoreHtml -TenantScores $allTenantsScoreInfo
            $consolidatedHtmlContent | Out-File -FilePath $consolidatedHtmlFile -Encoding utf8
            
            Write-Host "`n$('='*70)" -ForegroundColor Green
            Write-Host "SUMMARY" -ForegroundColor Green
            Write-Host "$('='*70)" -ForegroundColor Green
            Write-Host "Tenants Processed: $($allTenantsScoreInfo.Count)"
            Write-Host "Average Score: $([math]::Round(($allTenantsScoreInfo | Measure-Object -Property PercentComplete -Average).Average, 2))%"
            Write-Host "Consolidated HTML: $consolidatedHtmlFile"
            Write-Host "Summary CSV: $summaryFile"
        }
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
}
else {
    if ([string]::IsNullOrWhiteSpace($TenantId) -or [string]::IsNullOrWhiteSpace($ClientId) -or [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "You must provide TenantId, ClientId, and ClientSecret (or use -CsvPath)"
        return
    }
    
    try {
        Write-Host "Authenticating..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        
        Write-Host "Getting tenant information..." -ForegroundColor Yellow
        $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $TenantId
        
        Write-Host "Retrieving secure score..." -ForegroundColor Yellow
        $secureScore = Get-SecureScore -AccessToken $accessToken
        
        if ($secureScore) {
            $controlProfiles = Get-SecureScoreControlProfiles -AccessToken $accessToken
            $controlDetails = Merge-ControlData -SecureScore $secureScore -ControlProfiles $controlProfiles
            
            Write-Host "Retrieving score history..." -ForegroundColor Yellow
            $scoreHistory = Get-SecureScoreHistory -AccessToken $accessToken -Months 3
            
            $reportInfo = Format-SecureScoreReport -SecureScore $secureScore -ControlDetails $controlDetails -ScoreHistory $scoreHistory
            
            $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "SecureScore-$($tenantInfo.InitialDomain)-$timestamp.html"
            $htmlContent = Get-SecureScoreHtml -TenantName $tenantInfo.DisplayName -TenantDomain $tenantInfo.InitialDomain -ReportInfo $reportInfo
            $htmlContent | Out-File -FilePath $htmlReportPath -Encoding utf8
            
            $controlsCsvFile = Join-Path -Path $outputFolder -ChildPath "SecureControls-$($tenantInfo.InitialDomain)-$timestamp.csv"
            $controlDetails | Export-Csv -Path $controlsCsvFile -NoTypeInformation
            
            Write-Host "`nReports saved:" -ForegroundColor Green
            Write-Host "  HTML: $htmlReportPath"
            Write-Host "  CSV:  $controlsCsvFile"
        }
        else {
            Write-Host "No Secure Score data available" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error: $($_.Exception.Message)"
    }
}

Write-Host "`nCompleted at $(Get-Date)" -ForegroundColor Green
