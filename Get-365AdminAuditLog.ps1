<#
.SYNOPSIS
    Enhanced Admin Audit Logs Analyzer for Microsoft 365 tenants with SOC-focused security reporting.

.DESCRIPTION
    This PowerShell script retrieves and analyzes Microsoft 365 admin audit logs using the Microsoft Graph API.
    It provides comprehensive security analysis with risk scoring, suspicious activity detection, and generates
    both CSV exports and interactive HTML reports optimized for Security Operations Center (SOC) analysts.
    
    The script supports three modes of operation:
    1. Single tenant analysis with direct credentials
    2. Multiple tenant analysis from CSV file
    3. Specific client analysis from CSV file
    
    Key Features:
    - Risk-based scoring (1-10 scale) for all activities
    - High-risk activity detection and alerting
    - Suspicious actor identification through failed attempt patterns
    - IP address analysis for user-initiated activities
    - SOC-focused timeline view with critical event categorization
    - Interactive filtering and search capabilities
    - Support for both Security API and DirectoryAudits fallback methods

.PARAMETER TenantId
    The Azure AD Tenant ID (GUID format) for single tenant analysis.
    Example: "12345678-1234-1234-1234-123456789012"
    
.PARAMETER ClientId
    The Application (Client) ID of the registered Azure AD application.
    Requires appropriate Microsoft Graph permissions for audit log access.
    Example: "87654321-4321-4321-4321-210987654321"
    
.PARAMETER ClientSecret
    The client secret value for the registered Azure AD application.
    Keep this secure and consider using Azure Key Vault in production.
    
.PARAMETER CsvPath
    Path to CSV file containing multiple tenant credentials.
    CSV must contain columns: Client, Tenant ID, Client ID, Key Value
    Example: "C:\Tenants\TenantCredentials.csv"
    
.PARAMETER ClientName
    Specific client name to process from the CSV file.
    Performs partial matching, so "Building" will match "Building Blocks Inc."
    Use with -CsvPath parameter for single client processing.
    
.PARAMETER DaysToReport
    Number of days of audit logs to retrieve (1-90 days).
    Default: 90 days
    Note: Older logs may have limited availability depending on license type.
    
.PARAMETER AdminUpn
    Filter audit logs for specific admin user principal name.
    Example: "admin@company.com"
    Useful for investigating specific administrator activities.

.EXAMPLE
    .\Get-365AdminAuditLogs.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your_secret_here"
    
    Analyzes a single tenant using direct credential parameters with default 90-day lookback.

.EXAMPLE
    .\Get-365AdminAuditLogs.ps1 -CsvPath "C:\Tenants\Credentials.csv"
    
    Processes all tenants listed in the CSV file and generates individual reports plus a consolidated dashboard.

.EXAMPLE
    .\Get-365AdminAuditLogs.ps1 -CsvPath "C:\Tenants\Credentials.csv" -ClientName "Contoso"
    
    Processes only the tenant matching "Contoso" from the CSV file.

.EXAMPLE
    .\Get-365AdminAuditLogs.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your_secret_here" -DaysToReport 30 -AdminUpn "admin@company.com"
    
    Analyzes the last 30 days of audit logs for a specific administrator.

.NOTES
    File Name      : Get-365AdminAuditLogs.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1 or higher
    
    Required Azure AD App Permissions:
    - AuditLog.Read.All (Application Permission) - For DirectoryAudits API
    - AuditLogsQuery.Read.All (Application Permission) - For Security Audit Log Query API (preferred)
    
    The script automatically falls back to DirectoryAudits API if Security API is unavailable.
    
    Security Considerations:
    - Store client secrets securely (Azure Key Vault recommended)
    - Limit script access to authorized SOC personnel
    - Review generated reports for sensitive information before sharing
    - Client secrets are automatically cleared from memory after execution
    
    Performance Notes:
    - Security API provides better performance and more comprehensive data
    - DirectoryAudits fallback is limited to 1000 recent records with client-side filtering
    - Multi-tenant processing includes progress indicators and error handling
    
    Risk Scoring Algorithm:
    - Critical Activities (8-10): Role changes, password resets, user creation/deletion
    - High Risk Activities (6-7): Permission grants, service principal changes
    - Medium Risk Activities (4-5): License changes, device updates
    - Additional factors: Success/failure, initiator type, target sensitivity
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
    [int]$DaysToReport = 90,
    
    [Parameter(Mandatory=$false)]
    [string]$AdminUpn
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
        # Try to get domain information first (requires fewer permissions)
        $domainUri = "https://graph.microsoft.com/v1.0/domains"
        $domainsResponse = Invoke-RestMethod -Uri $domainUri -Method Get -Headers $headers
        
        $initialDomain = ($domainsResponse.value | Where-Object { $_.isInitial -eq $true }).id
        
        # If we can't find the initial domain, set a placeholder
        if (-not $initialDomain) {
            $initialDomain = "unknown.onmicrosoft.com"
        }
        
        # Try to get org display name, but continue if it fails
        $displayName = "Unknown"
        try {
            $orgUri = "https://graph.microsoft.com/v1.0/organization"
            $orgResponse = Invoke-RestMethod -Uri $orgUri -Method Get -Headers $headers
            $displayName = $orgResponse.value[0].displayName
        }
        catch {
            Write-Verbose "Could not retrieve organization display name: $_"
            # If we know the tenant ID from parameters, use it
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
        # Return minimal info to allow the script to continue
        return [PSCustomObject]@{
            TenantId = $TenantId
            DisplayName = "Unknown"
            InitialDomain = "unknown.onmicrosoft.com"
            VerifiedDomains = ""
        }
    }
}

function Get-AdminAuditLogs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToReport,
        
        [Parameter(Mandatory=$false)]
        [string]$AdminUpn
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        # Use the same approach as Microsoft-Extractor-Suite: Security Audit Log Query API
        Write-Host "Using Microsoft Graph Security Audit Log Query API (same as Microsoft-Extractor-Suite)..." -ForegroundColor Yellow
        
        # Calculate date range in proper ISO format
        $startDateTime = (Get-Date).AddDays(-$DaysToReport).ToUniversalTime()
        $endDateTime = (Get-Date).ToUniversalTime()
        $startDateString = $startDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $endDateString = $endDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        
        Write-Host "Creating audit log query for date range: $startDateString to $endDateString" -ForegroundColor Cyan
        
        # Create audit log query (step 1)
        $queryBody = @{
            displayName = "PowerShell-AuditQuery-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
            filterStartDateTime = $startDateString
            filterEndDateTime = $endDateString
        }
        
        # Add user filter if specified
        if (-not [string]::IsNullOrWhiteSpace($AdminUpn)) {
            $queryBody.userPrincipalNames = @($AdminUpn)
            Write-Host "Filtering for user: $AdminUpn" -ForegroundColor Cyan
        }
        
        $queryJson = $queryBody | ConvertTo-Json -Depth 3
        Write-Host "Query body: $queryJson" -ForegroundColor Gray
        
        # Create the audit log query
        $createUri = "https://graph.microsoft.com/beta/security/auditLog/queries"
        Write-Host "Creating audit log query..." -ForegroundColor Yellow
        
        try {
            $queryResponse = Invoke-RestMethod -Uri $createUri -Method Post -Headers $headers -Body $queryJson
            $queryId = $queryResponse.id
            Write-Host "Created query with ID: $queryId" -ForegroundColor Green
            
            # Wait for query to complete (step 2)
            Write-Host "Waiting for query to complete..." -ForegroundColor Yellow
            $maxWaitMinutes = 10
            $checkIntervalSeconds = 15
            $maxChecks = ($maxWaitMinutes * 60) / $checkIntervalSeconds
            $checkCount = 0
            
            do {
                Start-Sleep -Seconds $checkIntervalSeconds
                $checkCount++
                
                $statusUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId"
                $statusResponse = Invoke-RestMethod -Uri $statusUri -Method Get -Headers $headers
                $status = $statusResponse.status
                
                Write-Progress -Activity "Waiting for Audit Query" -Status "Status: $status" -PercentComplete (($checkCount / $maxChecks) * 100)
                Write-Host "Query status: $status (check $checkCount/$maxChecks)" -ForegroundColor Cyan
                
                if ($status -eq "succeeded") {
                    Write-Host "Query completed successfully!" -ForegroundColor Green
                    break
                }
                elseif ($status -eq "failed") {
                    Write-Error "Query failed. Check permissions and try again."
                    return @()
                }
                
            } while ($checkCount -lt $maxChecks -and $status -eq "running")
            
            Write-Progress -Activity "Waiting for Audit Query" -Completed
            
            if ($status -ne "succeeded") {
                Write-Warning "Query did not complete within $maxWaitMinutes minutes. Status: $status"
                return @()
            }
            
            # Get query results (step 3)
            Write-Host "Retrieving audit log results..." -ForegroundColor Yellow
            $resultsUri = "https://graph.microsoft.com/beta/security/auditLog/queries/$queryId/records"
            
            $allRecords = @()
            $nextLink = $resultsUri
            $batchCount = 0
            
            do {
                $batchCount++
                Write-Host "Retrieving batch $batchCount..." -ForegroundColor Cyan
                
                $resultsResponse = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
                $allRecords += $resultsResponse.value
                $nextLink = $resultsResponse.'@odata.nextLink'
                
                Write-Host "Retrieved $($resultsResponse.value.Count) records (Total: $($allRecords.Count))" -ForegroundColor Cyan
                
                # Small delay to avoid throttling
                if ($nextLink) {
                    Start-Sleep -Milliseconds 200
                }
                
            } while ($nextLink)
            
            Write-Host "Retrieved $($allRecords.Count) total audit records using Security API" -ForegroundColor Green
            return $allRecords
            
        }
        catch {
            $errorDetails = $_.Exception.Message
            if ($_.Exception.Response) {
                $statusCode = $_.Exception.Response.StatusCode.value__
                Write-Warning "Security Audit API failed (Status: $statusCode): $errorDetails"
                
                if ($statusCode -eq 403) {
                    Write-Host "Required permission: AuditLogsQuery.Read.All" -ForegroundColor Yellow
                    Write-Host "This is different from AuditLog.Read.All used for directoryAudits" -ForegroundColor Cyan
                }
            }
            else {
                Write-Warning "Security Audit API failed: $errorDetails"
            }
            
            # Fallback to original directoryAudits approach with client-side filtering
            Write-Host "Falling back to directoryAudits with client-side filtering..." -ForegroundColor Yellow
            return Get-DirectoryAuditsWithClientSideFiltering -AccessToken $AccessToken -DaysToReport $DaysToReport -AdminUpn $AdminUpn
        }
    }
    catch {
        Write-Error "Error in audit log retrieval: $_"
        return @()
    }
}

function Get-DirectoryAuditsWithClientSideFiltering {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToReport,
        
        [Parameter(Mandatory=$false)]
        [string]$AdminUpn
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    Write-Host "Using directoryAudits with client-side filtering (fallback method)..." -ForegroundColor Yellow
    
    # Calculate start date for filtering
    $startDateTime = (Get-Date).AddDays(-$DaysToReport).ToUniversalTime()
    
    # Retrieve recent logs without date filter and filter client-side
    $auditLogs = @()
    $maxRecords = 1000
    $recordsPerBatch = 250
    $nextLink = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=$recordsPerBatch&`$orderby=activityDateTime desc"
    $batchCounter = 0
    $maxBatches = [Math]::Ceiling($maxRecords / $recordsPerBatch)
    
    Write-Host "Retrieving up to $maxRecords recent audit logs for client-side filtering..." -ForegroundColor Cyan
    
    do {
        $batchCounter++
        Write-Progress -Activity "Retrieving Directory Audits" -Status "Batch $batchCounter of $maxBatches" -PercentComplete (($batchCounter / $maxBatches) * 100)
        
        try {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            $auditLogs += $response.value
            $nextLink = $response.'@odata.nextLink'
            
            Write-Host "Retrieved batch $batchCounter - Added $($response.value.Count) records (Total: $($auditLogs.Count))" -ForegroundColor Cyan
            
            # Check if we have enough data or reached max batches
            if ($batchCounter -ge $maxBatches) {
                Write-Host "Reached maximum batches for client-side filtering. Processing $($auditLogs.Count) total records..." -ForegroundColor Yellow
                break
            }
            
            # Add a small delay to avoid throttling
            if ($nextLink) {
                Start-Sleep -Milliseconds 100
            }
        }
        catch {
            Write-Warning "Error retrieving directory audits batch $batchCounter`: $_"
            break
        }
    } while ($nextLink)
    
    Write-Progress -Activity "Retrieving Directory Audits" -Completed
    
    # Filter results client-side by date
    if ($auditLogs.Count -gt 0) {
        Write-Host "Retrieved $($auditLogs.Count) total audit log records" -ForegroundColor Green
        
        $originalCount = $auditLogs.Count
        Write-Host "Filtering logs client-side for activities since $($startDateTime.ToString('yyyy-MM-dd HH:mm:ss')) UTC..." -ForegroundColor Yellow
        
        # Filter logs by date
        $filteredLogs = $auditLogs | Where-Object { 
            $logDate = [DateTime]::Parse($_.activityDateTime)
            $logDate -ge $startDateTime 
        }
        
        # Filter by user if specified
        if (-not [string]::IsNullOrWhiteSpace($AdminUpn)) {
            Write-Host "Filtering for user: $AdminUpn" -ForegroundColor Cyan
            $filteredLogs = $filteredLogs | Where-Object {
                ($_.initiatedBy.user.userPrincipalName -eq $AdminUpn) -or
                ($_.initiatedBy.user.displayName -eq $AdminUpn)
            }
        }
        
        Write-Host "After filtering: $($filteredLogs.Count) records (filtered out $($originalCount - $filteredLogs.Count) records)" -ForegroundColor Cyan
        return $filteredLogs
    }
    else {
        Write-Warning "No audit logs retrieved from directoryAudits"
        return @()
    }
}

function Format-AuditLogs {
    param (
        [Parameter(Mandatory=$true)]
        [array]$AuditLogs
    )
    
    $formattedLogs = @()
    
    foreach ($log in $AuditLogs) {
        # Extract initiator information with enhanced details
        $initiator = "Unknown"
        $initiatorId = ""
        $initiatorType = "Unknown"
        $initiatorIpAddress = ""
        $initiatorUserAgent = ""
        
        if ($log.initiatedBy.user) {
            $initiator = $log.initiatedBy.user.userPrincipalName
            if (-not $initiator) { $initiator = $log.initiatedBy.user.displayName }
            if (-not $initiator) { $initiator = $log.initiatedBy.user.id }
            $initiatorId = $log.initiatedBy.user.id
            $initiatorType = "User"
            $initiatorIpAddress = $log.initiatedBy.user.ipAddress
            $initiatorUserAgent = $log.initiatedBy.user.userAgent
        }
        elseif ($log.initiatedBy.app) {
            $initiator = $log.initiatedBy.app.displayName
            if (-not $initiator) { $initiator = $log.initiatedBy.app.servicePrincipalId }
            $initiatorId = $log.initiatedBy.app.servicePrincipalId
            $initiatorType = "Application"
        }
        
        # Extract target information with enhanced details
        $targetResources = @()
        foreach ($target in $log.targetResources) {
            $targetName = $target.displayName
            if (-not $targetName) { $targetName = $target.userPrincipalName }
            if (-not $targetName) { $targetName = $target.id }
            
            $modifications = @()
            $criticalChanges = @()
            
            if ($target.modifiedProperties) {
                foreach ($mod in $target.modifiedProperties) {
                    # Truncate very long values for readability
                    $oldValue = if ($mod.oldValue -and $mod.oldValue.Length -gt 150) { 
                        "$($mod.oldValue.Substring(0, 150))..." 
                    } else { 
                        $mod.oldValue 
                    }
                    $newValue = if ($mod.newValue -and $mod.newValue.Length -gt 150) { 
                        "$($mod.newValue.Substring(0, 150))..." 
                    } else { 
                        $mod.newValue 
                    }
                    
                    $change = "$($mod.displayName): $oldValue -> $newValue"
                    $modifications += $change
                    
                    # Track critical security-related changes
                    $criticalProperties = @("Role", "Permission", "Password", "Enabled", "License", "MembershipType")
                    if ($criticalProperties | Where-Object { $mod.displayName -like "*$_*" }) {
                        $criticalChanges += $change
                    }
                }
            }
            
            $targetResources += [PSCustomObject]@{
                DisplayName = $targetName
                Id = $target.id
                Type = $target.type
                UserPrincipalName = $target.userPrincipalName
                Modifications = ($modifications -join " | ")
                CriticalChanges = ($criticalChanges -join " | ")
                ModificationCount = $modifications.Count
                HasCriticalChanges = $criticalChanges.Count -gt 0
            }
        }
        
        # Enhanced risk assessment
        $riskScore = Get-ActivityRiskScore -ActivityType $log.activityDisplayName -Category $log.category -Result $log.result -InitiatorType $initiatorType -TargetResources $targetResources
        
        # Create formatted log entry with enhanced security context
        $formattedLog = [PSCustomObject]@{
            Timestamp = $log.activityDateTime
            Category = $log.category
            ActivityType = $log.activityDisplayName
            OperationType = $log.operationType
            Result = $log.result
            ResultReason = $log.resultReason
            Initiator = $initiator
            InitiatorId = $initiatorId
            InitiatorType = $initiatorType
            InitiatorIpAddress = $initiatorIpAddress
            InitiatorUserAgent = $initiatorUserAgent
            TargetResources = $targetResources
            TargetCount = $targetResources.Count
            HasCriticalTargetChanges = ($targetResources | Where-Object { $_.HasCriticalChanges }).Count -gt 0
            AdditionalDetails = $log.additionalDetails
            CorrelationId = $log.correlationId
            LogId = $log.id
            RiskScore = $riskScore
            IsHighRisk = $riskScore -ge 7
            IsFailedHighRisk = ($log.result -eq "failure" -and $riskScore -ge 6)
        }
        
        $formattedLogs += $formattedLog
    }
    
    return $formattedLogs
}

function Get-ActivityRiskScore {
    param (
        [string]$ActivityType,
        [string]$Category,
        [string]$Result,
        [string]$InitiatorType,
        [array]$TargetResources
    )
    
    $riskScore = 1
    
    # Critical risk activities (score 8-10)
    $criticalActivities = @(
        "Add member to role",
        "Remove member from role", 
        "Add service principal",
        "Delete service principal",
        "Add user",
        "Delete user",
        "Reset user password",
        "Add owner to service principal",
        "Add owner to application",
        "Add app role assignment to service principal",
        "Remove app role assignment from service principal"
    )
    
    # High risk activities (score 6-7)
    $highRiskActivities = @(
        "Add delegated permission grant",
        "Remove delegated permission grant",
        "Add password",
        "Update service principal",
        "Update application",
        "Consent to application",
        "Update user"
    )
    
    # Medium risk activities (score 4-5)
    $mediumRiskActivities = @(
        "Change user license",
        "Update device",
        "Add device",
        "Set Company Information"
    )
    
    # Assign base risk score based on activity type
    if ($criticalActivities -contains $ActivityType) {
        $riskScore = 8
    }
    elseif ($highRiskActivities -contains $ActivityType) {
        $riskScore = 6
    }
    elseif ($mediumRiskActivities -contains $ActivityType) {
        $riskScore = 4
    }
    else {
        $riskScore = 2
    }
    
    # Category-based risk adjustment
    switch ($Category) {
        "RoleManagement" { $riskScore += 2 }
        "ApplicationManagement" { $riskScore += 1 }
        "DirectoryManagement" { $riskScore += 1 }
        "UserManagement" { 
            if ($ActivityType -like "*password*" -or $ActivityType -like "*role*") {
                $riskScore += 2
            } else {
                $riskScore += 0.5
            }
        }
    }
    
    # Result-based adjustment
    if ($Result -eq "failure") {
        $riskScore += 1  # Failed attempts can indicate attack attempts
    }
    
    # Initiator type adjustment
    if ($InitiatorType -eq "Application") {
        $riskScore += 0.5  # Service principal actions need scrutiny
    }
    
    # Target-based risk adjustment
    if ($TargetResources) {
        $hasCriticalTargets = ($TargetResources | Where-Object { $_.HasCriticalChanges }).Count -gt 0
        if ($hasCriticalTargets) {
            $riskScore += 1
        }
        
        # Multiple targets increase risk
        if ($TargetResources.Count -gt 3) {
            $riskScore += 0.5
        }
    }
    
    return [Math]::Min([Math]::Round($riskScore, 1), 10)  # Cap at 10, allow decimals
}

function Get-AuditLogSummary {
    param (
        [Parameter(Mandatory=$true)]
        [array]$FormattedLogs
    )
    
    # Initialize summary object
    $summary = [PSCustomObject]@{
        TotalActivities = $FormattedLogs.Count
        TimeRange = [PSCustomObject]@{
            OldestActivity = if ($FormattedLogs.Count -gt 0) { ($FormattedLogs | Sort-Object -Property Timestamp | Select-Object -First 1).Timestamp } else { $null }
            NewestActivity = if ($FormattedLogs.Count -gt 0) { ($FormattedLogs | Sort-Object -Property Timestamp -Descending | Select-Object -First 1).Timestamp } else { $null }
        }
    }
    
    # Basic activity analysis
    $activityTypes = $FormattedLogs | Group-Object -Property ActivityType | Sort-Object -Property Count -Descending | Select-Object Name, Count
    $summary | Add-Member -NotePropertyName "ActivityTypes" -NotePropertyValue $activityTypes
    
    $categories = $FormattedLogs | Group-Object -Property Category | Sort-Object -Property Count -Descending | Select-Object Name, Count
    $summary | Add-Member -NotePropertyName "Categories" -NotePropertyValue $categories
    
    $resultCounts = $FormattedLogs | Group-Object -Property Result | Select-Object Name, Count
    $summary | Add-Member -NotePropertyName "ResultCounts" -NotePropertyValue $resultCounts
    
    $topInitiators = $FormattedLogs | Group-Object -Property Initiator | Sort-Object -Property Count -Descending | Select-Object -First 10 Name, Count
    $summary | Add-Member -NotePropertyName "TopInitiators" -NotePropertyValue $topInitiators
    
    $initiatorTypes = $FormattedLogs | Group-Object -Property InitiatorType | Select-Object Name, Count
    $summary | Add-Member -NotePropertyName "InitiatorTypes" -NotePropertyValue $initiatorTypes
    
    # Enhanced high-risk activities analysis with detailed breakdown
    $highRiskActivities = $FormattedLogs | Where-Object { $_.IsHighRisk -eq $true }
    $highRiskSummary = @()
    
    if ($highRiskActivities.Count -gt 0) {
        $highRiskSummary = $highRiskActivities | Group-Object -Property ActivityType | Sort-Object -Property Count -Descending | ForEach-Object {
            $activityLogs = $_.Group
            [PSCustomObject]@{
                Name = $_.Name
                Count = $_.Count
                SuccessfulCount = ($activityLogs | Where-Object { $_.Result -eq "success" }).Count
                FailedCount = ($activityLogs | Where-Object { $_.Result -eq "failure" }).Count
                UniqueInitiators = ($activityLogs | Group-Object -Property Initiator).Count
                TopInitiator = ($activityLogs | Group-Object -Property Initiator | Sort-Object -Property Count -Descending | Select-Object -First 1).Name
                MostRecentActivity = ($activityLogs | Sort-Object -Property Timestamp -Descending | Select-Object -First 1).Timestamp
                AverageRiskScore = [Math]::Round(($activityLogs | Measure-Object -Property RiskScore -Average).Average, 1)
                Details = $activityLogs | Sort-Object -Property Timestamp -Descending | Select-Object -First 5  # Get top 5 most recent examples
            }
        }
    }
    
    $summary | Add-Member -NotePropertyName "HighRiskActivities" -NotePropertyValue $highRiskSummary
    
    # Enhanced activity timeline analysis
    $dailyActivity = @()
    if ($FormattedLogs.Count -gt 0) {
        $dailyActivity = $FormattedLogs | ForEach-Object {
            [PSCustomObject]@{
                Date = [DateTime]::Parse($_.Timestamp).ToString("yyyy-MM-dd")
                Category = $_.Category
                ActivityType = $_.ActivityType
                Result = $_.Result
                IsHighRisk = $_.IsHighRisk
                RiskScore = $_.RiskScore
            }
        } | Group-Object -Property Date | Sort-Object -Property Name | ForEach-Object {
            $dayLogs = $_.Group
            [PSCustomObject]@{
                Name = $_.Name
                Count = $_.Count
                HighRiskCount = ($dayLogs | Where-Object { $_.IsHighRisk }).Count
                SuccessCount = ($dayLogs | Where-Object { $_.Result -eq "success" }).Count
                FailureCount = ($dayLogs | Where-Object { $_.Result -eq "failure" }).Count
                AverageRiskScore = if ($dayLogs.Count -gt 0) { [Math]::Round(($dayLogs | Measure-Object -Property RiskScore -Average).Average, 1) } else { 0 }
            }
        }
    }
    
    $summary | Add-Member -NotePropertyName "DailyActivity" -NotePropertyValue $dailyActivity
    
    # IP address analysis for user-initiated activities
    $ipAnalysis = @()
    $userActivities = $FormattedLogs | Where-Object { 
        $_.InitiatorType -eq "User" -and 
        -not [string]::IsNullOrEmpty($_.InitiatorIpAddress) 
    }
    
    if ($userActivities.Count -gt 0) {
        $ipAnalysis = $userActivities | Group-Object -Property InitiatorIpAddress | Sort-Object -Property Count -Descending | Select-Object -First 10 @{
            Name = "IPAddress"; Expression = { $_.Name }
        }, @{
            Name = "ActivityCount"; Expression = { $_.Count }
        }, @{
            Name = "UniqueUsers"; Expression = { ($_.Group | Group-Object -Property Initiator).Count }
        }, @{
            Name = "HighRiskActivities"; Expression = { ($_.Group | Where-Object { $_.IsHighRisk }).Count }
        }
    }
    
    $summary | Add-Member -NotePropertyName "TopSourceIPs" -NotePropertyValue $ipAnalysis
    
    # Failed authentication and suspicious activity analysis
    $failedHighRiskActivities = $FormattedLogs | Where-Object { $_.IsFailedHighRisk -eq $true }
    $suspiciousActivitySummary = @()
    
    if ($failedHighRiskActivities.Count -gt 0) {
        $suspiciousActivitySummary = $failedHighRiskActivities | Group-Object -Property Initiator | Sort-Object -Property Count -Descending | Select-Object -First 10 @{
            Name = "Initiator"; Expression = { $_.Name }
        }, @{
            Name = "FailedAttempts"; Expression = { $_.Count }
        }, @{
            Name = "ActivityTypes"; Expression = { ($_.Group | Group-Object -Property ActivityType | Sort-Object -Property Count -Descending | Select-Object -First 3 -ExpandProperty Name) -join ", " }
        }, @{
            Name = "LastAttempt"; Expression = { ($_.Group | Sort-Object -Property Timestamp -Descending | Select-Object -First 1).Timestamp }
        }
    }
    
    $summary | Add-Member -NotePropertyName "SuspiciousActivities" -NotePropertyValue $suspiciousActivitySummary
    
    return $summary
}

function Find-ClientInCsv {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CsvPath,
        
        [Parameter(Mandatory=$true)]
        [string]$ClientName
    )
    
    try {
        if (-not (Test-Path -Path $CsvPath)) {
            Write-Error "CSV file not found: $CsvPath"
            return $null
        }
        
        $tenants = Import-Csv -Path $CsvPath
        
        # Search for the client name (case-insensitive)
        $matchingClient = $tenants | Where-Object { $_.Client -like "*$ClientName*" }
        
        if ($matchingClient.Count -eq 0) {
            Write-Warning "No client found matching '$ClientName' in the CSV file."
            Write-Host "Available clients:" -ForegroundColor Yellow
            $tenants | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Cyan }
            return $null
        }
        elseif ($matchingClient.Count -gt 1) {
            Write-Warning "Multiple clients found matching '$ClientName':"
            $matchingClient | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Cyan }
            Write-Host "Please be more specific or use the exact client name." -ForegroundColor Yellow
            return $null
        }
        else {
            Write-Host "Found matching client: $($matchingClient.Client)" -ForegroundColor Green
            return $matchingClient
        }
    }
    catch {
        Write-Error "Error reading CSV file: $_"
        return $null
    }
}

function Get-TenantAuditLogHtml {
    param (
        [Parameter(Mandatory=$true)]
        [string]$TenantName,
        
        [Parameter(Mandatory=$true)]
        [string]$TenantDomain,
        
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$AuditSummary,
        
        [Parameter(Mandatory=$true)]
        [array]$FormattedLogs
    )
    
    # Prepare data for charts with null checks
    $activityTypeData = if ($AuditSummary.ActivityTypes -and $AuditSummary.ActivityTypes.Count -gt 0) { 
        $AuditSummary.ActivityTypes | Select-Object -First 10 | ConvertTo-Json -Compress
    } else { "[]" }
    
    $categoryData = if ($AuditSummary.Categories -and $AuditSummary.Categories.Count -gt 0) { 
        $AuditSummary.Categories | ConvertTo-Json -Compress
    } else { "[]" }
    
    $resultData = if ($AuditSummary.ResultCounts -and $AuditSummary.ResultCounts.Count -gt 0) { 
        $AuditSummary.ResultCounts | ConvertTo-Json -Compress
    } else { "[]" }
    
    $dailyActivityData = if ($AuditSummary.DailyActivity -and $AuditSummary.DailyActivity.Count -gt 0) { 
        $AuditSummary.DailyActivity | ConvertTo-Json -Compress
    } else { "[]" }
    
    # Create SOC-focused timeline with critical events
    $criticalEvents = @()
    $sortedLogs = $FormattedLogs | Sort-Object -Property Timestamp -Descending
    
    foreach ($log in $sortedLogs) {
        $eventType = "INFO"
        $riskLevel = "LOW"
        $description = ""
        
        # Categorize events for SOC analysts
        if ($log.IsHighRisk) {
            $eventType = "ALERT"
            $riskLevel = "HIGH"
        } elseif ($log.Result -eq "failure") {
            $eventType = "WARNING"
            $riskLevel = "MEDIUM"
        }
        
        # Create detailed description based on activity type
        switch ($log.ActivityType) {
            "Reset user password" {
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "PASSWORD RESET: $($log.Initiator) reset password for $targetUser"
                $eventType = "CRITICAL"
                $riskLevel = "CRITICAL"
            }
            "Add member to role" {
                $roleName = ""
                if ($log.TargetResources -and $log.TargetResources.Count -gt 0 -and $log.TargetResources[0].CriticalChanges) {
                    if ($log.TargetResources[0].CriticalChanges -match 'Role\.DisplayName.*?"([^"]*)"') {
                        $roleName = $matches[1]
                    }
                }
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "ROLE ASSIGNMENT: $($log.Initiator) added $targetUser to role: $roleName"
                $eventType = "CRITICAL"
                $riskLevel = "CRITICAL"
            }
            "Remove member from role" {
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "ROLE REMOVAL: $($log.Initiator) removed $targetUser from role"
                $eventType = "CRITICAL"
                $riskLevel = "CRITICAL"
            }
            "Add user" {
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "USER CREATION: $($log.Initiator) created new user: $targetUser"
                $eventType = "ALERT"
                $riskLevel = "HIGH"
            }
            "Delete user" {
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "USER DELETION: $($log.Initiator) deleted user: $targetUser"
                $eventType = "CRITICAL"
                $riskLevel = "CRITICAL"
            }
            "Disable account" {
                $targetUser = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "ACCOUNT DISABLED: $($log.Initiator) disabled account: $targetUser"
                $eventType = "ALERT"
                $riskLevel = "HIGH"
            }
            "Add service principal" {
                $appName = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $description = "APP REGISTRATION: $($log.Initiator) created service principal: $appName"
                $eventType = "ALERT"
                $riskLevel = "HIGH"
            }
            "Add delegated permission grant" {
                $appName = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { $log.TargetResources[0].DisplayName } else { "Unknown" }
                $result = if ($log.Result -eq "failure") { " (FAILED)" } else { "" }
                $description = "PERMISSION GRANT: $($log.Initiator) granted permissions to $appName$result"
                if ($log.Result -eq "failure") {
                    $eventType = "WARNING"
                    $riskLevel = "MEDIUM"
                } else {
                    $eventType = "ALERT"
                    $riskLevel = "HIGH"
                }
            }
            default {
                $targetInfo = if ($log.TargetResources -and $log.TargetResources.Count -gt 0) { 
                    "affecting $($log.TargetResources[0].DisplayName)" 
                } else { "" }
                $description = "$($log.ActivityType): $($log.Initiator) $targetInfo"
            }
        }
        
        $criticalEvents += [PSCustomObject]@{
            Timestamp = $log.Timestamp
            EventType = $eventType
            RiskLevel = $riskLevel
            Description = $description
            Initiator = $log.Initiator
            InitiatorType = $log.InitiatorType
            InitiatorIP = $log.InitiatorIpAddress
            Result = $log.Result
            ActivityType = $log.ActivityType
            CorrelationId = $log.CorrelationId
            RiskScore = $log.RiskScore
        }
    }
    
    # Create timeline rows for critical events (top 50)
    $timelineRows = ""
    $topEvents = $criticalEvents | Select-Object -First 50
    
    foreach ($event in $topEvents) {
        $timestamp = [DateTime]::Parse($event.Timestamp).ToString("yyyy-MM-dd HH:mm:ss")
        $riskClass = switch ($event.RiskLevel) {
            "CRITICAL" { "risk-critical" }
            "HIGH" { "risk-high" }
            "MEDIUM" { "risk-medium" }
            default { "risk-low" }
        }
        
        $resultClass = if ($event.Result -eq "success") { "success" } else { "failure" }
        $ipInfo = if ($event.InitiatorIP) { "<br><small>IP: $($event.InitiatorIP)</small>" } else { "" }
        
        $timelineRows += @"
        <tr class="$riskClass">
            <td class="timeline-time">$timestamp</td>
            <td class="event-type-$($event.EventType.ToLower())">$($event.EventType)</td>
            <td class="$resultClass">$($event.Result.ToUpper())</td>
            <td class="event-description">$($event.Description)</td>
            <td>$($event.Initiator)$ipInfo</td>
            <td class="risk-score-$($event.RiskLevel.ToLower())">$($event.RiskScore)/10</td>
        </tr>
"@
    }
    
    # Calculate dashboard metrics
    $totalHighRisk = if ($AuditSummary.HighRiskActivities) { 
        ($AuditSummary.HighRiskActivities | Measure-Object -Property Count -Sum).Sum 
    } else { 0 }
    
    $successfulActivities = if ($AuditSummary.ResultCounts) { 
        ($AuditSummary.ResultCounts | Where-Object { $_.Name -eq "success" }).Count 
    } else { 0 }
    
    $failedActivities = if ($AuditSummary.ResultCounts) { 
        ($AuditSummary.ResultCounts | Where-Object { $_.Name -eq "failure" }).Count 
    } else { 0 }
    
    $suspiciousCount = if ($AuditSummary.SuspiciousActivities) { 
        $AuditSummary.SuspiciousActivities.Count 
    } else { 0 }
    
    # Count critical events by type
    $criticalCount = ($criticalEvents | Where-Object { $_.EventType -eq "CRITICAL" }).Count
    $alertCount = ($criticalEvents | Where-Object { $_.EventType -eq "ALERT" }).Count
    $warningCount = ($criticalEvents | Where-Object { $_.EventType -eq "WARNING" }).Count

    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>SOC Security Audit Report - $TenantName</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0;
            padding: 20px;
            background-color: #0f1419;
            color: #e6e6e6;
            line-height: 1.4;
        }
        
        .container {
            max-width: 1800px;
            margin: 0 auto;
        }
        
        h1 { 
            color: #00ff41;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        
        h2, h3 { 
            color: #00bfff;
            margin-top: 30px;
        }
        
        .header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            border: 1px solid #333;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .dashboard-card {
            background: linear-gradient(135deg, #2d1b69 0%, #11998e 100%);
            color: white;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            border: 1px solid #444;
        }
        
        .dashboard-card.critical {
            background: linear-gradient(135deg, #c2185b 0%, #ad1457 100%);
        }
        
        .dashboard-card.alert {
            background: linear-gradient(135deg, #ff6f00 0%, #e65100 100%);
        }
        
        .dashboard-card.warning {
            background: linear-gradient(135deg, #fbc02d 0%, #f57f17 100%);
            color: #000;
        }
        
        .dashboard-number {
            font-size: 36px;
            font-weight: bold;
            margin: 10px 0;
        }
        
        .dashboard-label {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .chart-section {
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid #333;
        }
        
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
        }
        
        .chart {
            background: #16213e;
            border-radius: 10px;
            padding: 20px;
            height: 300px;
            border: 1px solid #444;
        }
        
        .timeline {
            background: #1a1a2e;
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 30px;
            border: 1px solid #333;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background: #16213e;
            border-radius: 10px;
            overflow: hidden;
        }
        
        th {
            background: #2d1b69;
            color: white;
            padding: 15px 10px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #00ff41;
        }
        
        td {
            padding: 12px 10px;
            border-bottom: 1px solid #333;
            vertical-align: top;
        }
        
        tr:hover {
            background: rgba(0, 255, 65, 0.1);
        }
        
        .timeline-time {
            font-family: 'Courier New', monospace;
            color: #00bfff;
            min-width: 150px;
        }
        
        .event-description {
            font-weight: 500;
            max-width: 400px;
        }
        
        .event-type-critical {
            background: #c2185b;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }
        
        .event-type-alert {
            background: #ff6f00;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }
        
        .event-type-warning {
            background: #fbc02d;
            color: #000;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }
        
        .event-type-info {
            background: #2196f3;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 12px;
        }
        
        .success {
            color: #4caf50;
            font-weight: bold;
        }
        
        .failure {
            color: #f44336;
            font-weight: bold;
        }
        
        .risk-critical {
            border-left: 4px solid #c2185b;
            background: rgba(194, 24, 91, 0.1);
        }
        
        .risk-high {
            border-left: 4px solid #ff6f00;
            background: rgba(255, 111, 0, 0.1);
        }
        
        .risk-medium {
            border-left: 4px solid #fbc02d;
            background: rgba(251, 192, 45, 0.1);
        }
        
        .risk-low {
            border-left: 4px solid #4caf50;
        }
        
        .risk-score-critical {
            background: #c2185b;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .risk-score-high {
            background: #ff6f00;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .risk-score-medium {
            background: #fbc02d;
            color: #000;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .risk-score-low {
            background: #4caf50;
            color: white;
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .filter-controls {
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .btn {
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            transition: all 0.3s ease;
        }
        
        .btn-critical {
            background: #c2185b;
            color: white;
        }
        
        .btn-alert {
            background: #ff6f00;
            color: white;
        }
        
        .btn-warning {
            background: #fbc02d;
            color: #000;
        }
        
        .btn-all {
            background: #2196f3;
            color: white;
        }
        
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.3);
        }
        
        .search-input {
            padding: 10px 15px;
            border: 1px solid #444;
            border-radius: 5px;
            background: #16213e;
            color: #e6e6e6;
            font-size: 14px;
            flex-grow: 1;
            min-width: 250px;
        }
        
        .search-input:focus {
            outline: none;
            border-color: #00ff41;
            box-shadow: 0 0 10px rgba(0, 255, 65, 0.3);
        }
        
        .legend {
            display: flex;
            gap: 20px;
            margin-bottom: 20px;
            font-size: 12px;
        }
        
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .legend-color {
            width: 20px;
            height: 20px;
            border-radius: 3px;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="container">
        <h1>SOC Security Audit Report - $TenantName</h1>
        
        <div class="header">
            <h3>Report Summary</h3>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC</p>
            <p><strong>Tenant:</strong> $TenantName</p>
            <p><strong>Domain:</strong> $TenantDomain</p>
            <p><strong>Analysis Period:</strong> $($AuditSummary.TimeRange.OldestActivity) to $($AuditSummary.TimeRange.NewestActivity)</p>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card critical">
                <div class="dashboard-number">$criticalCount</div>
                <div class="dashboard-label">Critical Events</div>
            </div>
            <div class="dashboard-card alert">
                <div class="dashboard-number">$alertCount</div>
                <div class="dashboard-label">High Risk Alerts</div>
            </div>
            <div class="dashboard-card warning">
                <div class="dashboard-number">$warningCount</div>
                <div class="dashboard-label">Warnings</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$failedActivities</div>
                <div class="dashboard-label">Failed Attempts</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$suspiciousCount</div>
                <div class="dashboard-label">Suspicious Actors</div>
            </div>
            <div class="dashboard-card">
                <div class="dashboard-number">$($AuditSummary.TotalActivities)</div>
                <div class="dashboard-label">Total Activities</div>
            </div>
        </div>
        
        <div class="chart-section">
            <h2>Activity Analysis</h2>
            <div class="chart-container">
                <div class="chart">
                    <h3>Top Activity Types</h3>
                    <canvas id="activityTypeChart"></canvas>
                </div>
                <div class="chart">
                    <h3>Daily Activity Timeline</h3>
                    <canvas id="dailyActivityChart"></canvas>
                </div>
            </div>
        </div>
        
        <div class="timeline">
            <h2>Security Event Timeline</h2>
            <p>Critical security events sorted by most recent. Focus on CRITICAL and ALERT events for immediate investigation.</p>
            
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #c2185b;"></div>
                    <span>CRITICAL - Immediate Investigation Required</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff6f00;"></div>
                    <span>ALERT - High Risk Activity</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #fbc02d;"></div>
                    <span>WARNING - Failed Attempts</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4caf50;"></div>
                    <span>INFO - Normal Activity</span>
                </div>
            </div>
            
            <div class="filter-controls">
                <button class="btn btn-all" onclick="filterByEventType('all')">Show All</button>
                <button class="btn btn-critical" onclick="filterByEventType('CRITICAL')">Critical Only</button>
                <button class="btn btn-alert" onclick="filterByEventType('ALERT')">Alerts Only</button>
                <button class="btn btn-warning" onclick="filterByEventType('WARNING')">Warnings Only</button>
                <input type="text" id="searchInput" onkeyup="filterTable()" placeholder="Search events, users, IPs..." class="search-input">
            </div>
            
            <table id="timelineTable">
                <thead>
                    <tr>
                        <th>Timestamp</th>
                        <th>Event Type</th>
                        <th>Result</th>
                        <th>Event Description</th>
                        <th>Initiator</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    $timelineRows
                </tbody>
            </table>
        </div>
    </div>
    
    <script>
        // Activity Type Chart
        var activityTypeData = $activityTypeData;
        if (activityTypeData && activityTypeData.length > 0) {
            var activityTypeCtx = document.getElementById('activityTypeChart').getContext('2d');
            var activityTypeChart = new Chart(activityTypeCtx, {
                type: 'bar',
                data: {
                    labels: activityTypeData.map(item => item.Name),
                    datasets: [{
                        label: 'Count',
                        data: activityTypeData.map(item => item.Count),
                        backgroundColor: '#00bfff',
                        borderColor: '#00ff41',
                        borderWidth: 1
                    }]
                },
                options: {
                    indexAxis: 'y',
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        x: { 
                            beginAtZero: true,
                            grid: { color: '#333' },
                            ticks: { color: '#e6e6e6' }
                        },
                        y: {
                            grid: { color: '#333' },
                            ticks: { color: '#e6e6e6' }
                        }
                    }
                }
            });
        }
        
        // Daily Activity Chart
        var dailyActivityData = $dailyActivityData;
        if (dailyActivityData && dailyActivityData.length > 0) {
            var dailyActivityCtx = document.getElementById('dailyActivityChart').getContext('2d');
            var dailyActivityChart = new Chart(dailyActivityCtx, {
                type: 'line',
                data: {
                    labels: dailyActivityData.map(item => item.Name),
                    datasets: [{
                        label: 'Total Activities',
                        data: dailyActivityData.map(item => item.Count),
                        backgroundColor: 'rgba(0, 191, 255, 0.2)',
                        borderColor: '#00bfff',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3
                    }, {
                        label: 'High Risk Activities',
                        data: dailyActivityData.map(item => item.HighRiskCount || 0),
                        backgroundColor: 'rgba(255, 111, 0, 0.2)',
                        borderColor: '#ff6f00',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.3
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        x: {
                            grid: { color: '#333' },
                            ticks: { color: '#e6e6e6' }
                        },
                        y: { 
                            beginAtZero: true,
                            grid: { color: '#333' },
                            ticks: { color: '#e6e6e6' }
                        }
                    },
                    plugins: {
                        legend: { 
                            position: 'top',
                            labels: { color: '#e6e6e6' }
                        }
                    }
                }
            });
        }
        
        function filterByEventType(eventType) {
            var table = document.getElementById('timelineTable');
            var rows = table.getElementsByTagName('tr');
            
            for (var i = 1; i < rows.length; i++) {
                var cells = rows[i].getElementsByTagName('td');
                if (cells.length > 1) {
                    var cellEventType = cells[1].textContent || cells[1].innerText;
                    
                    if (eventType === 'all' || cellEventType === eventType) {
                        rows[i].style.display = '';
                    } else {
                        rows[i].style.display = 'none';
                    }
                }
            }
        }
        
        function filterTable() {
            var input = document.getElementById('searchInput');
            var filter = input.value.toUpperCase();
            var table = document.getElementById('timelineTable');
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
</body>
</html>
"@
    
    return $html
}

function Get-ConsolidatedAuditLogHtml {
    param (
        [Parameter(Mandatory=$true)]
        [array]$TenantSummaries
    )
    
    # Prepare table rows
    $tableRows = ""
    foreach ($tenant in $TenantSummaries) {
        $riskClass = if ($tenant.HighRiskActivityCount -gt 50) { "high-risk" } elseif ($tenant.HighRiskActivityCount -gt 10) { "warning" } else { "" }
        
        $tableRows += @"
        <tr class="$riskClass">
            <td><strong>$($tenant.ClientName)</strong></td>
            <td>$($tenant.InitialDomain)</td>
            <td>$($tenant.TotalAuditActivities)</td>
            <td class="success">$($tenant.SuccessfulActivities)</td>
            <td class="failure">$($tenant.FailedActivities)</td>
            <td class="$(if($tenant.HighRiskActivityCount -gt 10) { 'failure' } elseif($tenant.HighRiskActivityCount -gt 0) { 'warning' } else { 'success' })">$($tenant.HighRiskActivityCount)</td>
            <td>$($tenant.TopActivityType)</td>
            <td>$($tenant.TopInitiator)</td>
            <td>$($tenant.OldestActivityDate) to $($tenant.NewestActivityDate)</td>
        </tr>
"@
    }
    
    # Prepare data for charts
    $tenantNames = ($TenantSummaries | ForEach-Object { "`"$($_.ClientName)`"" }) -join ", "
    $totalActivities = ($TenantSummaries | ForEach-Object { $_.TotalAuditActivities }) -join ", "
    $highRiskActivities = ($TenantSummaries | ForEach-Object { $_.HighRiskActivityCount }) -join ", "
    $successfulActivities = ($TenantSummaries | ForEach-Object { $_.SuccessfulActivities }) -join ", "
    $failedActivities = ($TenantSummaries | ForEach-Object { $_.FailedActivities }) -join ", "
    
    # Calculate dashboard metrics
    $totalTenants = $TenantSummaries.Count
    $totalAllActivities = ($TenantSummaries | Measure-Object -Property TotalAuditActivities -Sum).Sum
    $totalSuccess = ($TenantSummaries | Measure-Object -Property SuccessfulActivities -Sum).Sum
    $totalFailures = ($TenantSummaries | Measure-Object -Property FailedActivities -Sum).Sum
    $totalHighRisk = ($TenantSummaries | Measure-Object -Property HighRiskActivityCount -Sum).Sum
    $tenantsWithHighRisk = ($TenantSummaries | Where-Object { $_.HighRiskActivityCount -gt 0 }).Count

    # HTML Template for consolidated dashboard
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title> Multi-Tenant Security Audit Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        h1, h2, h3 { 
            color: #2c3e50; 
        }
        h1 { border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        .container {
            max-width: 1800px;
            margin: 0 auto;
        }
        .card {
            background-color: white;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            padding: 25px;
            margin-bottom: 25px;
            border-left: 4px solid #3498db;
        }
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .dashboard-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
            transition: transform 0.3s ease;
        }
        .dashboard-card:hover {
            transform: translateY(-5px);
        }
        .dashboard-card.alert {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
        }
        .dashboard-card.warning {
            background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
        }
        .dashboard-card.success {
            background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
        }
        .dashboard-number {
            font-size: 42px;
            font-weight: bold;
            margin: 15px 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .dashboard-label {
            font-size: 16px;
            opacity: 0.9;
            font-weight: 500;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        th, td { 
            padding: 15px 12px; 
            text-align: left; 
            border-bottom: 1px solid #ecf0f1; 
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            font-weight: 600;
            position: sticky;
            top: 0;
            z-index: 10;
        }
        tr:nth-child(even) { 
            background-color: #f8f9fa; 
        }
        tr:hover { 
            background-color: #e8f4f8 !important;
            transition: background-color 0.3s ease;
        }
        .success { 
            color: #27ae60; 
            font-weight: 600;
        }
        .failure { 
            color: #e74c3c; 
            font-weight: 600;
        }
        .warning {
            color: #f39c12;
            font-weight: 600;
        }
        .high-risk {
            background: linear-gradient(90deg, #fff3cd 0%, #ffffff 100%) !important;
            border-left: 4px solid #ff6b35;
        }
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 25px;
            margin-bottom: 30px;
        }
        .chart {
            background-color: white;
            border-radius: 15px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            padding: 25px;
            height: 350px;
        }
        .filter-controls {
            margin-bottom: 25px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        .search-input {
            padding: 12px 15px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            flex-grow: 1;
            min-width: 250px;
            transition: border-color 0.3s ease;
        }
        .search-input:focus {
            outline: none;
            border-color: #3498db;
            box-shadow: 0 0 10px rgba(52, 152, 219, 0.3);
        }
        .section-header {
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
        }
        .security-icon {
            font-size: 24px;
        }
        .summary { 
            background: linear-gradient(135deg, #e3f2fd 0%, #ffffff 100%);
            padding: 20px; 
            border-radius: 10px; 
            margin-bottom: 25px;
            border-left: 4px solid #2196f3;
        }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
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
        <h1> Multi-Tenant Security Audit Dashboard</h1>
        
        <div class="summary card">
            <div class="section-header">
                <span class="security-icon"></span>
                <h3>Executive Summary</h3>
            </div>
            <p><strong>Generated:</strong> $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") UTC</p>
            <p><strong>Analysis Scope:</strong> $totalTenants tenant(s) analyzed</p>
            <p><strong>Key Findings:</strong> $totalAllActivities total activities across all tenants, with $totalHighRisk high-risk activities requiring attention</p>
        </div>
        
        <div class="dashboard">
            <div class="dashboard-card">
                <div class="dashboard-number">$totalTenants</div>
                <div class="dashboard-label">Total Tenants</div>
            </div>
            <div class="dashboard-card success">
                <div class="dashboard-number">$totalAllActivities</div>
                <div class="dashboard-label">Total Activities</div>
            </div>
            <div class="dashboard-card success">
                <div class="dashboard-number">$totalSuccess</div>
                <div class="dashboard-label">Successful Activities</div>
            </div>
            <div class="dashboard-card alert">
                <div class="dashboard-number">$totalFailures</div>
                <div class="dashboard-label">Failed Activities</div>
            </div>
            <div class="dashboard-card alert">
                <div class="dashboard-number">$totalHighRisk</div>
                <div class="dashboard-label">High-Risk Activities</div>
            </div>
            <div class="dashboard-card warning">
                <div class="dashboard-number">$tenantsWithHighRisk</div>
                <div class="dashboard-label">Tenants w/ High Risk</div>
            </div>
        </div>
        
        <div class="chart-container">
            <div class="chart">
                <h3> Activities by Tenant</h3>
                <canvas id="tenantActivityChart"></canvas>
            </div>
            <div class="chart">
                <h3> High-Risk Activities by Tenant</h3>
                <canvas id="highRiskChart"></canvas>
            </div>
        </div>
        
        <div class="card">
            <h2> Activity Results Comparison</h2>
            <canvas id="resultsByTenantChart" style="height: 400px;"></canvas>
        </div>
        
        <div class="card">
            <div class="section-header">
                <span class="security-icon">🏢</span>
                <h2>Tenant Security Overview</h2>
            </div>
            
            <div class="filter-controls">
                <input type="text" id="searchInput" onkeyup="filterTable()" placeholder=" Search tenants..." class="search-input">
            </div>
            
            <table id="tenantsTable">
                <tr>
                    <th> Tenant Name</th>
                    <th> Domain</th>
                    <th> Total Activities</th>
                    <th> Successful</th>
                    <th> Failed</th>
                    <th> High-Risk</th>
                    <th> Top Activity</th>
                    <th> Top Initiator</th>
                    <th> Date Range</th>
                </tr>
                $tableRows
            </table>
        </div>
        
        <div class="card">
            <div class="section-header">
                <span class="security-icon">ℹ️</span>
                <h3>Multi-Tenant Security Analysis Notes</h3>
            </div>
            <ul style="line-height: 1.8;">
                <li><strong> High-Risk Activities:</strong> Activities that can significantly impact security or compliance across your tenant portfolio.</li>
                <li><strong> Cross-Tenant Analysis:</strong> Compare security posture and activity patterns across all managed tenants.</li>
                <li><strong> Risk Prioritization:</strong> Tenants with high failure rates or numerous high-risk activities require immediate attention.</li>
                <li><strong> Trend Monitoring:</strong> Regular analysis helps identify tenants with increasing security concerns.</li>
                <li><strong> Detailed Reports:</strong> Individual tenant reports provide forensic-level detail for security investigations.</li>
                <li><strong> Compliance:</strong> Use this dashboard to demonstrate security monitoring and incident response capabilities.</li>
            </ul>
        </div>
    </div>
    
    <script>
        // Tenant Activity Chart
        var tenantActivityCtx = document.getElementById('tenantActivityChart').getContext('2d');
        var tenantActivityChart = new Chart(tenantActivityCtx, {
            type: 'bar',
            data: {
                labels: [$tenantNames],
                datasets: [{
                    label: 'Total Activities',
                    data: [$totalActivities],
                    backgroundColor: 'rgba(102, 126, 234, 0.8)',
                    borderColor: 'rgba(102, 126, 234, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
        
        // High-Risk Activities Chart
        var highRiskCtx = document.getElementById('highRiskChart').getContext('2d');
        var highRiskChart = new Chart(highRiskCtx, {
            type: 'bar',
            data: {
                labels: [$tenantNames],
                datasets: [{
                    label: 'High-Risk Activities',
                    data: [$highRiskActivities],
                    backgroundColor: 'rgba(231, 76, 60, 0.8)',
                    borderColor: 'rgba(231, 76, 60, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: { beginAtZero: true }
                },
                plugins: {
                    legend: { display: false }
                }
            }
        });
        
        // Results by Tenant Chart
        var resultsByTenantCtx = document.getElementById('resultsByTenantChart').getContext('2d');
        var resultsByTenantChart = new Chart(resultsByTenantCtx, {
            type: 'bar',
            data: {
                labels: [$tenantNames],
                datasets: [
                    {
                        label: 'Successful',
                        data: [$successfulActivities],
                        backgroundColor: 'rgba(39, 174, 96, 0.8)',
                        borderColor: 'rgba(39, 174, 96, 1)',
                        borderWidth: 2
                    },
                    {
                        label: 'Failed',
                        data: [$failedActivities],
                        backgroundColor: 'rgba(231, 76, 60, 0.8)',
                        borderColor: 'rgba(231, 76, 60, 1)',
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { stacked: true },
                    y: { stacked: true, beginAtZero: true }
                }
            }
        });
    </script>
</body>
</html>
"@
    
    return $html
}

# Main script execution
$ErrorActionPreference = "Continue"  # Don't stop on errors
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "Admin-Audit-Logs-Report-$timestamp"
New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

# Create arrays to hold all reports
$allTenantsAuditInfo = @()

# Determine which parameter set is being used
if ($ClientName -and $CsvPath) {
    # Process specific client from CSV
    Write-Host "Searching for client '$ClientName' in CSV file '$CsvPath'..." -ForegroundColor Yellow
    
    $matchingClient = Find-ClientInCsv -CsvPath $CsvPath -ClientName $ClientName
    
    if ($null -eq $matchingClient) {
        Write-Error "Cannot proceed without valid client information."
        return
    }
    
    # Extract credentials for the matching client
    $clientNameValue = $matchingClient.Client.Trim()
    $tenantId = $matchingClient.'Tenant ID'.Trim()
    $clientId = $matchingClient.'Client ID'.Trim()
    $clientSecret = $matchingClient.'Key Value'.Trim()
    
    # Validate required fields
    if ([string]::IsNullOrWhiteSpace($tenantId) -or 
        [string]::IsNullOrWhiteSpace($clientId) -or 
        [string]::IsNullOrWhiteSpace($clientSecret)) {
        Write-Error "Missing required credential information for client '$clientNameValue'"
        return
    }
   
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "Processing client: $clientNameValue ($tenantId)" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    try {
        # Get authentication token
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
        
        # Get basic tenant information
        Write-Host "Retrieving tenant information..." -ForegroundColor Yellow
        $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $tenantId
        
        # Get admin audit logs
        Write-Host "Retrieving admin audit logs for the past $DaysToReport days..." -ForegroundColor Yellow
        $auditLogs = Get-AdminAuditLogs -AccessToken $accessToken -DaysToReport $DaysToReport -AdminUpn $AdminUpn
        
        if ($auditLogs.Count -gt 0) {
            # Format audit logs for easier analysis
            Write-Host "Formatting audit logs..." -ForegroundColor Yellow
            $formattedLogs = Format-AuditLogs -AuditLogs $auditLogs
            
            # Get summary statistics
            $auditSummary = Get-AuditLogSummary -FormattedLogs $formattedLogs
            
            # Export audit logs to CSV
            $csvFile = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($clientNameValue.Replace(' ', ''))-$timestamp.csv"
            $flattenedLogs = @()

            foreach ($log in $formattedLogs) {
                foreach ($target in $log.TargetResources) {
                    $flattenedLog = [PSCustomObject]@{
                        ClientName = $clientNameValue
                        TenantDomain = $tenantInfo.InitialDomain
                        Timestamp = $log.Timestamp
                        Category = $log.Category
                        ActivityType = $log.ActivityType
                        OperationType = $log.OperationType
                        Result = $log.Result
                        ResultReason = $log.ResultReason
                        Initiator = $log.Initiator
                        InitiatorId = $log.InitiatorId
                        InitiatorType = $log.InitiatorType
                        InitiatorIpAddress = $log.InitiatorIpAddress
                        InitiatorUserAgent = $log.InitiatorUserAgent
                        TargetName = $target.DisplayName
                        TargetId = $target.Id
                        TargetType = $target.Type
                        TargetUPN = $target.UserPrincipalName
                        Modifications = $target.Modifications
                        CriticalChanges = $target.CriticalChanges
                        CorrelationId = $log.CorrelationId
                        LogId = $log.LogId
                        RiskScore = $log.RiskScore
                        IsHighRisk = $log.IsHighRisk
                        IsFailedHighRisk = $log.IsFailedHighRisk
                    }
                    $flattenedLogs += $flattenedLog
                }
            }
            
            $flattenedLogs | Export-Csv -Path $csvFile -NoTypeInformation
            
            Write-Host "Retrieved $($auditLogs.Count) audit log activities for client $clientNameValue" -ForegroundColor Green
            Write-Host "Exported to: $csvFile" -ForegroundColor Green
            
            # Generate HTML report
            $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($clientNameValue.Replace(' ', ''))-$timestamp.html"
            $htmlContent = Get-TenantAuditLogHtml -TenantName $clientNameValue -TenantDomain $tenantInfo.InitialDomain -AuditSummary $auditSummary -FormattedLogs $formattedLogs
            $htmlContent | Out-File -FilePath $htmlReportPath -Encoding utf8
            
            Write-Host "HTML report saved to: $htmlReportPath" -ForegroundColor Green

            # Display a summary
            Write-Host "`nAudit Log Summary for $clientNameValue ($($tenantInfo.InitialDomain)):" -ForegroundColor Cyan
            Write-Host "  Total Activities: $($auditSummary.TotalActivities)" -ForegroundColor White
            Write-Host "  Date Range: $($auditSummary.TimeRange.OldestActivity) to $($auditSummary.TimeRange.NewestActivity)" -ForegroundColor White
            
            Write-Host "`nTop Activity Types:" -ForegroundColor Yellow
            $auditSummary.ActivityTypes | Select-Object -First 5 | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
            }
            
            Write-Host "`nTop Initiators:" -ForegroundColor Yellow
            $auditSummary.TopInitiators | Select-Object -First 5 | ForEach-Object {
                Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
            }
            
            Write-Host "`nHigh-Risk Activities:" -ForegroundColor Yellow
            if ($auditSummary.HighRiskActivities -and $auditSummary.HighRiskActivities.Count -gt 0) {
                $auditSummary.HighRiskActivities | ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
                }
            } else {
                Write-Host "  No high-risk activities detected" -ForegroundColor Green
            }
            
            # Optional: Open the HTML report
            if ($PSVersionTable.Platform -ne 'Unix') {
                Write-Host "Opening HTML report..."
                Start-Process $htmlReportPath
            }
        }
        else {
            Write-Host "No audit logs found for client $clientNameValue in the specified time period" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error processing client $clientNameValue ($tenantId): $_"
    }
}

elseif ($CsvPath -and -not $ClientName) {
    # Process multiple tenants from CSV (original behavior)
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
            Write-Host "Processing tenant $currentTenant of $totalTenants`: $($clientName) ($tenantId)" -ForegroundColor Cyan
            Write-Host "=======================================================" -ForegroundColor Cyan
            
            try {
                Write-Progress -Activity "Processing Tenants" -Status "Tenant $currentTenant of $totalTenants`: $clientName" -PercentComplete (($currentTenant / $totalTenants) * 100)
                
                # Get authentication token
                Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                
                # Get basic tenant information
                Write-Host "Retrieving tenant information..." -ForegroundColor Yellow
                $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $tenantId
                
                # Get admin audit logs
                Write-Host "Retrieving admin audit logs for the past $DaysToReport days..." -ForegroundColor Yellow
                $auditLogs = Get-AdminAuditLogs -AccessToken $accessToken -DaysToReport $DaysToReport -AdminUpn $AdminUpn
                if ($auditLogs.Count -gt 0) {
                    # Format audit logs for easier analysis
                    Write-Host "Formatting audit logs..." -ForegroundColor Yellow
                    $formattedLogs = Format-AuditLogs -AuditLogs $auditLogs
                    
                    # Get summary statistics
                    $auditSummary = Get-AuditLogSummary -FormattedLogs $formattedLogs
                    
                    # Add tenant info to audit summary
                    $tenantReport = [PSCustomObject]@{
                        ClientName = $clientName
                        TenantId = $tenantId
                        DisplayName = $tenantInfo.DisplayName
                        InitialDomain = $tenantInfo.InitialDomain
                        TotalAuditActivities = $auditSummary.TotalActivities
                        OldestActivityDate = $auditSummary.TimeRange.OldestActivity
                        NewestActivityDate = $auditSummary.TimeRange.NewestActivity
                        ActivityTypes = $auditSummary.ActivityTypes
                        Categories = $auditSummary.Categories
                        ResultCounts = $auditSummary.ResultCounts
                        TopInitiators = $auditSummary.TopInitiators
                        InitiatorTypes = $auditSummary.InitiatorTypes
                        HighRiskActivities = $auditSummary.HighRiskActivities
                        DailyActivity = $auditSummary.DailyActivity
                        SuspiciousActivities = $auditSummary.SuspiciousActivities
                        TopSourceIPs = $auditSummary.TopSourceIPs
                        FormattedLogs = $formattedLogs
                    }
                    
                    $allTenantsAuditInfo += $tenantReport
                    
                    # Export tenant-specific audit logs to CSV
                    $tenantCsvFile = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($clientName.Replace(' ', ''))-$timestamp.csv"
                    $flattenedLogs = @()
                    foreach ($log in $formattedLogs) {
                        if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                            foreach ($target in $log.TargetResources) {
                                $flattenedLog = [PSCustomObject]@{
                                    ClientName = $clientName
                                    TenantDomain = $tenantInfo.InitialDomain
                                    Timestamp = $log.Timestamp
                                    Category = $log.Category
                                    ActivityType = $log.ActivityType
                                    OperationType = $log.OperationType
                                    Result = $log.Result
                                    ResultReason = $log.ResultReason
                                    Initiator = $log.Initiator
                                    InitiatorId = $log.InitiatorId
                                    InitiatorType = $log.InitiatorType
                                    InitiatorIpAddress = $log.InitiatorIpAddress
                                    InitiatorUserAgent = $log.InitiatorUserAgent
                                    TargetName = $target.DisplayName
                                    TargetId = $target.Id
                                    TargetType = $target.Type
                                    TargetUPN = $target.UserPrincipalName
                                    Modifications = $target.Modifications
                                    CriticalChanges = $target.CriticalChanges
                                    CorrelationId = $log.CorrelationId
                                    LogId = $log.LogId
                                    RiskScore = $log.RiskScore
                                    IsHighRisk = $log.IsHighRisk
                                    IsFailedHighRisk = $log.IsFailedHighRisk
                                }
                                $flattenedLogs += $flattenedLog
                            }
                        } else {
                            # Handle logs with no target resources
                            $flattenedLog = [PSCustomObject]@{
                                ClientName = $clientName
                                TenantDomain = $tenantInfo.InitialDomain
                                Timestamp = $log.Timestamp
                                Category = $log.Category
                                ActivityType = $log.ActivityType
                                OperationType = $log.OperationType
                                Result = $log.Result
                                ResultReason = $log.ResultReason
                                Initiator = $log.Initiator
                                InitiatorId = $log.InitiatorId
                                InitiatorType = $log.InitiatorType
                                InitiatorIpAddress = $log.InitiatorIpAddress
                                InitiatorUserAgent = $log.InitiatorUserAgent
                                TargetName = "No targets"
                                TargetId = ""
                                TargetType = ""
                                TargetUPN = ""
                                Modifications = ""
                                CriticalChanges = ""
                                CorrelationId = $log.CorrelationId
                                LogId = $log.LogId
                                RiskScore = $log.RiskScore
                                IsHighRisk = $log.IsHighRisk
                                IsFailedHighRisk = $log.IsFailedHighRisk
                            }
                            $flattenedLogs += $flattenedLog
                        }
                    }
                    
                    $flattenedLogs | Export-Csv -Path $tenantCsvFile -NoTypeInformation
                    
                    Write-Host "Retrieved $($auditLogs.Count) audit log activities for tenant $clientName" -ForegroundColor Green
                    Write-Host "Exported to: $tenantCsvFile" -ForegroundColor Green
                    
                    # Generate tenant-specific HTML report
                    $tenantHtmlFile = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($clientName.Replace(' ', ''))-$timestamp.html"
                    $tenantHtmlContent = Get-TenantAuditLogHtml -TenantName $clientName -TenantDomain $tenantInfo.InitialDomain -AuditSummary $auditSummary -FormattedLogs $formattedLogs
                    $tenantHtmlContent | Out-File -FilePath $tenantHtmlFile -Encoding utf8
                    
                    Write-Host "HTML Report saved to: $tenantHtmlFile" -ForegroundColor Green
                }
                else {
                    Write-Host "No audit logs found for tenant $clientName in the specified time period" -ForegroundColor Yellow
                }
            }
            catch {
                Write-Error "Error processing tenant $clientName ($tenantId): $_"
            }
        }
        
        Write-Progress -Activity "Processing Tenants" -Completed

        if ($allTenantsAuditInfo.Count -gt 0) {
            # Export consolidated CSV report with audit summary for all tenants
            $summaryFile = Join-Path -Path $outputFolder -ChildPath "AuditSummary-AllTenants-$timestamp.csv"
            $tenantSummaries = @()
            
            foreach ($tenant in $allTenantsAuditInfo) {
                $successfulCount = if ($tenant.ResultCounts) { 
                    ($tenant.ResultCounts | Where-Object { $_.Name -eq "success" }).Count 
                } else { 0 }
                if (-not $successfulCount) { $successfulCount = 0 }
                
                $failedCount = if ($tenant.ResultCounts) { 
                    ($tenant.ResultCounts | Where-Object { $_.Name -eq "failure" }).Count 
                } else { 0 }
                if (-not $failedCount) { $failedCount = 0 }
                
                $highRiskCount = if ($tenant.HighRiskActivities) { 
                    ($tenant.HighRiskActivities | Measure-Object -Property Count -Sum).Sum 
                } else { 0 }
                if (-not $highRiskCount) { $highRiskCount = 0 }
                
                $summaryEntry = [PSCustomObject]@{
                    ClientName = $tenant.ClientName
                    TenantId = $tenant.TenantId
                    DisplayName = $tenant.DisplayName
                    InitialDomain = $tenant.InitialDomain
                    TotalAuditActivities = $tenant.TotalAuditActivities
                    OldestActivityDate = $tenant.OldestActivityDate
                    NewestActivityDate = $tenant.NewestActivityDate
                    SuccessfulActivities = $successfulCount
                    FailedActivities = $failedCount
                    HighRiskActivityCount = $highRiskCount
                    TopInitiator = if ($tenant.TopInitiators -and $tenant.TopInitiators.Count -gt 0) { $tenant.TopInitiators[0].Name } else { "None" }
                    TopInitiatorCount = if ($tenant.TopInitiators -and $tenant.TopInitiators.Count -gt 0) { $tenant.TopInitiators[0].Count } else { 0 }
                    TopActivityType = if ($tenant.ActivityTypes -and $tenant.ActivityTypes.Count -gt 0) { $tenant.ActivityTypes[0].Name } else { "None" }
                    TopActivityTypeCount = if ($tenant.ActivityTypes -and $tenant.ActivityTypes.Count -gt 0) { $tenant.ActivityTypes[0].Count } else { 0 }
                }
                
                $tenantSummaries += $summaryEntry
            }
            
            $tenantSummaries | Export-Csv -Path $summaryFile -NoTypeInformation
            
            # Generate consolidated HTML report
            $consolidatedHtmlFile = Join-Path -Path $outputFolder -ChildPath "AuditLogs-AllTenants-$timestamp.html"
            $consolidatedHtmlContent = Get-ConsolidatedAuditLogHtml -TenantSummaries $tenantSummaries
            $consolidatedHtmlContent | Out-File -FilePath $consolidatedHtmlFile -Encoding utf8
            
            Write-Host "`nAll processing complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
            Write-Host "Summary CSV: $summaryFile" -ForegroundColor Green
            Write-Host "Consolidated HTML Report: $consolidatedHtmlFile" -ForegroundColor Green
            
            # Display consolidated summary
            Write-Host "`n" + "="*60 -ForegroundColor Cyan
            Write-Host "CONSOLIDATED AUDIT SUMMARY" -ForegroundColor Cyan
            Write-Host "="*60 -ForegroundColor Cyan
            
            $totalActivitiesAll = ($tenantSummaries | Measure-Object -Property TotalAuditActivities -Sum).Sum
            $totalSuccessAll = ($tenantSummaries | Measure-Object -Property SuccessfulActivities -Sum).Sum
            $totalFailedAll = ($tenantSummaries | Measure-Object -Property FailedActivities -Sum).Sum
            $totalHighRiskAll = ($tenantSummaries | Measure-Object -Property HighRiskActivityCount -Sum).Sum
            
            Write-Host "Total Tenants Processed: $($tenantSummaries.Count)" -ForegroundColor White
            Write-Host "Total Activities Across All Tenants: $totalActivitiesAll" -ForegroundColor White
            Write-Host "Total Successful Activities: $totalSuccessAll" -ForegroundColor Green
            Write-Host "Total Failed Activities: $totalFailedAll" -ForegroundColor Red
            Write-Host "Total High-Risk Activities: $totalHighRiskAll" -ForegroundColor Yellow
            
            Write-Host "`nTenants with High-Risk Activities:" -ForegroundColor Yellow
            $tenantsWithHighRisk = $tenantSummaries | Where-Object { $_.HighRiskActivityCount -gt 0 } | Sort-Object -Property HighRiskActivityCount -Descending
            if ($tenantsWithHighRisk.Count -gt 0) {
                $tenantsWithHighRisk | ForEach-Object {
                    Write-Host "  $($_.ClientName): $($_.HighRiskActivityCount) high-risk activities" -ForegroundColor White
                }
            } else {
                Write-Host "  No tenants with high-risk activities detected" -ForegroundColor Green
            }
            
            # Optional: Open the HTML report
            if ($PSVersionTable.Platform -ne 'Unix') {
                Write-Host "`nOpening consolidated HTML report..."
                Start-Process $consolidatedHtmlFile
            }
        }
        else {
            Write-Host "`nNo audit logs found for any tenant in the specified time period" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Error "Error processing CSV file: $_"
    }
}

else {
    # Process single tenant with parameters (original behavior)
    if ([string]::IsNullOrWhiteSpace($TenantId) -or 
        [string]::IsNullOrWhiteSpace($ClientId) -or 
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "When not using a CSV file, you must provide TenantId, ClientId, and ClientSecret parameters."
        Write-Host "`nUsage examples:" -ForegroundColor Yellow
        Write-Host "  # Process specific client from CSV:" -ForegroundColor Cyan
        Write-Host "  .\script.ps1 -CsvPath 'path\to\file.csv' -ClientName 'ClientName'" -ForegroundColor White
        Write-Host "`n  # Process all clients from CSV:" -ForegroundColor Cyan
        Write-Host "  .\script.ps1 -CsvPath 'path\to\file.csv'" -ForegroundColor White
        Write-Host "`n  # Process single tenant with direct parameters:" -ForegroundColor Cyan
        Write-Host "  .\script.ps1 -TenantId 'xxx' -ClientId 'xxx' -ClientSecret 'xxx'" -ForegroundColor White
        Write-Host "`n  # Add optional parameters:" -ForegroundColor Cyan
        Write-Host "  .\script.ps1 -TenantId 'xxx' -ClientId 'xxx' -ClientSecret 'xxx' -DaysToReport 30 -AdminUpn 'admin@domain.com'" -ForegroundColor White
        return
    }
    
    try {
        Write-Host "`n=======================================================" -ForegroundColor Cyan
        Write-Host "Processing single tenant: $TenantId" -ForegroundColor Cyan
        Write-Host "=======================================================" -ForegroundColor Cyan
        
        # Get authentication token
        Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
        $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        
        # Get basic tenant information
        Write-Host "Retrieving tenant information..." -ForegroundColor Yellow
        $tenantInfo = Get-TenantBasicInfo -AccessToken $accessToken -TenantId $TenantId
        
        # Get admin audit logs
        Write-Host "Retrieving admin audit logs for the past $DaysToReport days..." -ForegroundColor Yellow
        $auditLogs = Get-AdminAuditLogs -AccessToken $accessToken -DaysToReport $DaysToReport -AdminUpn $AdminUpn
        
        if ($auditLogs.Count -gt 0) {
            # Format audit logs for easier analysis
            Write-Host "Formatting audit logs..." -ForegroundColor Yellow
            $formattedLogs = Format-AuditLogs -AuditLogs $auditLogs
            
            # Get summary statistics
            $auditSummary = Get-AuditLogSummary -FormattedLogs $formattedLogs
            
            # Export audit logs to CSV
            $csvFile = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($tenantInfo.InitialDomain)-$timestamp.csv"
            $flattenedLogs = @()
            foreach ($log in $formattedLogs) {
                if ($log.TargetResources -and $log.TargetResources.Count -gt 0) {
                    foreach ($target in $log.TargetResources) {
                        $flattenedLog = [PSCustomObject]@{
                            TenantDomain = $tenantInfo.InitialDomain
                            Timestamp = $log.Timestamp
                            Category = $log.Category
                            ActivityType = $log.ActivityType
                            OperationType = $log.OperationType
                            Result = $log.Result
                            ResultReason = $log.ResultReason
                            Initiator = $log.Initiator
                            InitiatorId = $log.InitiatorId
                            InitiatorType = $log.InitiatorType
                            InitiatorIpAddress = $log.InitiatorIpAddress
                            InitiatorUserAgent = $log.InitiatorUserAgent
                            TargetName = $target.DisplayName
                            TargetId = $target.Id
                            TargetType = $target.Type
                            TargetUPN = $target.UserPrincipalName
                            Modifications = $target.Modifications
                            CriticalChanges = $target.CriticalChanges
                            CorrelationId = $log.CorrelationId
                            LogId = $log.LogId
                            RiskScore = $log.RiskScore
                            IsHighRisk = $log.IsHighRisk
                            IsFailedHighRisk = $log.IsFailedHighRisk
                        }
                        $flattenedLogs += $flattenedLog
                    }
                } else {
                    # Handle logs with no target resources
                    $flattenedLog = [PSCustomObject]@{
                        TenantDomain = $tenantInfo.InitialDomain
                        Timestamp = $log.Timestamp
                        Category = $log.Category
                        ActivityType = $log.ActivityType
                        OperationType = $log.OperationType
                        Result = $log.Result
                        ResultReason = $log.ResultReason
                        Initiator = $log.Initiator
                        InitiatorId = $log.InitiatorId
                        InitiatorType = $log.InitiatorType
                        InitiatorIpAddress = $log.InitiatorIpAddress
                        InitiatorUserAgent = $log.InitiatorUserAgent
                        TargetName = "No targets"
                        TargetId = ""
                        TargetType = ""
                        TargetUPN = ""
                        Modifications = ""
                        CriticalChanges = ""
                        CorrelationId = $log.CorrelationId
                        LogId = $log.LogId
                        RiskScore = $log.RiskScore
                        IsHighRisk = $log.IsHighRisk
                        IsFailedHighRisk = $log.IsFailedHighRisk
                    }
                    $flattenedLogs += $flattenedLog
                }
            }
            
            $flattenedLogs | Export-Csv -Path $csvFile -NoTypeInformation
            
            Write-Host "Retrieved $($auditLogs.Count) audit log activities" -ForegroundColor Green
            Write-Host "Exported to: $csvFile" -ForegroundColor Green
            
            # Generate HTML report
            $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "AuditLogs-$($tenantInfo.InitialDomain)-$timestamp.html"
            $htmlContent = Get-TenantAuditLogHtml -TenantName $tenantInfo.DisplayName -TenantDomain $tenantInfo.InitialDomain -AuditSummary $auditSummary -FormattedLogs $formattedLogs
            $htmlContent | Out-File -FilePath $htmlReportPath -Encoding utf8
            
            Write-Host "HTML report saved to: $htmlReportPath" -ForegroundColor Green

            # Display a summary
            Write-Host "`nAudit Log Summary for $($tenantInfo.DisplayName) ($($tenantInfo.InitialDomain)):" -ForegroundColor Cyan
            Write-Host "  Total Activities: $($auditSummary.TotalActivities)" -ForegroundColor White
            Write-Host "  Date Range: $($auditSummary.TimeRange.OldestActivity) to $($auditSummary.TimeRange.NewestActivity)" -ForegroundColor White
            
            Write-Host "`nTop Activity Types:" -ForegroundColor Yellow
            if ($auditSummary.ActivityTypes -and $auditSummary.ActivityTypes.Count -gt 0) {
                $auditSummary.ActivityTypes | Select-Object -First 5 | ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
                }
            } else {
                Write-Host "  No activity types found" -ForegroundColor Gray
            }
            
            Write-Host "`nTop Initiators:" -ForegroundColor Yellow
            if ($auditSummary.TopInitiators -and $auditSummary.TopInitiators.Count -gt 0) {
                $auditSummary.TopInitiators | Select-Object -First 5 | ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
                }
            } else {
                Write-Host "  No initiators found" -ForegroundColor Gray
            }
            
            Write-Host "`nHigh-Risk Activities:" -ForegroundColor Yellow
            if ($auditSummary.HighRiskActivities -and $auditSummary.HighRiskActivities.Count -gt 0) {
                $auditSummary.HighRiskActivities | ForEach-Object {
                    Write-Host "  $($_.Name): $($_.Count)" -ForegroundColor White
                }
            } else {
                Write-Host "  No high-risk activities detected" -ForegroundColor Green
            }
            
            Write-Host "`nSecurity Analysis:" -ForegroundColor Yellow
            $totalHighRisk = if ($auditSummary.HighRiskActivities) { 
                ($auditSummary.HighRiskActivities | Measure-Object -Property Count -Sum).Sum 
            } else { 0 }
            $totalFailures = if ($auditSummary.ResultCounts) { 
                ($auditSummary.ResultCounts | Where-Object { $_.Name -eq "failure" }).Count 
            } else { 0 }
            $suspiciousCount = if ($auditSummary.SuspiciousActivities) { 
                $auditSummary.SuspiciousActivities.Count 
            } else { 0 }
            
            Write-Host "  High-Risk Activities: $totalHighRisk" -ForegroundColor White
            Write-Host "  Failed Activities: $totalFailures" -ForegroundColor White
            Write-Host "  Suspicious Actors: $suspiciousCount" -ForegroundColor White
            
            if ($totalHighRisk -gt 0 -or $totalFailures -gt 10 -or $suspiciousCount -gt 0) {
                Write-Host "`n  SECURITY ALERT: This tenant has activities requiring attention!" -ForegroundColor Red
                Write-Host "   Review the HTML report for detailed forensic analysis." -ForegroundColor Red
            } else {
                Write-Host "`n SECURITY STATUS: No immediate security concerns detected." -ForegroundColor Green
            }
            
            # Optional: Open the HTML report
            if ($PSVersionTable.Platform -ne 'Unix') {
                Write-Host "`nOpening HTML report..."
                Start-Process $htmlReportPath
            }
        }
        else {
            Write-Host "No audit logs found for the specified time period" -ForegroundColor Yellow
            Write-Host "This could indicate:" -ForegroundColor Cyan
            Write-Host "  - No administrative activities occurred in the past $DaysToReport days" -ForegroundColor White
            Write-Host "  - Insufficient permissions to read audit logs" -ForegroundColor White
            Write-Host "  - Audit logging is not enabled for this tenant" -ForegroundColor White
        }
    }
    catch {
        Write-Error "Error processing tenant: $_"
        Write-Host "`nTroubleshooting tips:" -ForegroundColor Cyan
        Write-Host "  - Verify the TenantId, ClientId, and ClientSecret are correct" -ForegroundColor White
        Write-Host "  - Ensure the app registration has the required permissions:" -ForegroundColor White
        Write-Host "    • AuditLog.Read.All (preferred)" -ForegroundColor White
        Write-Host "    • AuditLogsQuery.Read.All (for Security API)" -ForegroundColor White
        Write-Host "  - Check that admin consent has been granted" -ForegroundColor White
        Write-Host "  - Verify network connectivity to Microsoft Graph" -ForegroundColor White
    }
}

# Final script completion message
Write-Host "`n" + "="*60 -ForegroundColor Green
Write-Host "SCRIPT EXECUTION COMPLETED" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Green

Write-Host "Execution completed at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Output folder: $outputFolder" -ForegroundColor White

# Summary of what was processed
if ($ClientName -and $CsvPath) {
    Write-Host "Mode: Single client from CSV ($ClientName)" -ForegroundColor Cyan
} elseif ($CsvPath -and -not $ClientName) {
    Write-Host "Mode: Multiple tenants from CSV" -ForegroundColor Cyan
    if ($allTenantsAuditInfo.Count -gt 0) {
        Write-Host "Tenants processed: $($allTenantsAuditInfo.Count)" -ForegroundColor White
    }
} else {
    Write-Host "Mode: Single tenant with direct parameters" -ForegroundColor Cyan
}

Write-Host "Days of audit logs analyzed: $DaysToReport" -ForegroundColor White
if ($AdminUpn) {
    Write-Host "Filtered for admin: $AdminUpn" -ForegroundColor White
}

Write-Host "`nGenerated files:" -ForegroundColor Yellow
if (Test-Path $outputFolder) {
    $generatedFiles = Get-ChildItem -Path $outputFolder | Sort-Object Name
    foreach ($file in $generatedFiles) {
        $fileSize = [math]::Round($file.Length / 1KB, 2)
        Write-Host "   $($file.Name) ($fileSize KB)" -ForegroundColor White
    }
} else {
    Write-Host "  No files generated" -ForegroundColor Gray
}

Write-Host "`nFor support or issues with this script:" -ForegroundColor Cyan
Write-Host "  - Ensure you have the latest version" -ForegroundColor White
Write-Host "  - Check Microsoft Graph API status" -ForegroundColor White
Write-Host "  - Verify app registration permissions" -ForegroundColor White

Write-Host "`n Security Audit Analysis Complete! " -ForegroundColor Green

# Optional: Display folder in explorer (Windows only)
if ($PSVersionTable.Platform -ne 'Unix' -and (Test-Path $outputFolder)) {
    Write-Host "`nOpening output folder..." -ForegroundColor Yellow
    Start-Process "explorer.exe" -ArgumentList $outputFolder
}

# Clean up variables for security
if ($ClientSecret) { 
    Remove-Variable -Name ClientSecret -ErrorAction SilentlyContinue 
}
if ($accessToken) { 
    Remove-Variable -Name accessToken -ErrorAction SilentlyContinue 
}

Write-Host "`n Thank you for using the Enhanced Admin Audit Logs Analyzer!" -ForegroundColor Magenta
