<#
.SYNOPSIS
    Extracts and analyzes Azure AD/Entra ID sign-in logs from single or multiple tenants with advanced security anomaly detection.

.DESCRIPTION
    This script connects to Microsoft Graph API to retrieve sign-in logs from Azure AD/Entra ID tenants and provides 
    comprehensive analysis including user activity patterns, geographic distribution, and security anomalies. It generates 
    both structured data exports (JSON, CSV) and an interactive HTML dashboard for security operations teams.

    The script supports three operational modes:
    1. Single tenant with direct credential parameters
    2. Single tenant using CSV lookup by client name  
    3. Multi-tenant processing from CSV file

    Key security analysis features include detection of impossible travel, brute force attacks, off-hours authentication,
    risky sign-ins flagged by Microsoft's risk detection, and sign-ins from unusual locations or client applications.
    
    The script enriches sign-in data with user details from Azure AD and can filter by specific users or include 
    different event types (interactive, non-interactive, service principal, managed identity).

.PARAMETER TenantId
    The Azure AD/Entra ID tenant ID in GUID format. Required when using direct parameter authentication.

.PARAMETER ClientId
    The client/application ID of the registered Azure AD application used for authentication.

.PARAMETER ClientSecret
    The client secret for the registered Azure AD application used for authentication.

.PARAMETER CsvPath
    Optional. Path to CSV file containing tenant credentials for multi-tenant scenarios. 
    Default is ".\AzureAppKeys.csv" when using -ClientName parameter. The CSV should have columns for 
    "Client", "Tenant ID", "Client ID", and "Key Value".

.PARAMETER ClientName
    Optional. The name of the specific client/tenant to process from the CSV file. Used for single tenant 
    processing with CSV lookup. Must match the "Client" column value in the CSV file exactly.

.PARAMETER DaysToReport
    Optional. Number of days to look back for sign-in logs. Default is 90 days. Valid range is 1-90 days.

.PARAMETER UserPrincipalNames
    Optional. Array of specific user principal names to analyze instead of all users. Useful for targeted 
    investigations or high-privilege account monitoring.

.PARAMETER UserListPath
    Optional. Path to text file containing user principal names (one per line). Alternative to -UserPrincipalNames 
    for large user lists.

.PARAMETER SkipAnomalyDetection
    Optional switch. If specified, disables security anomaly detection and only performs data extraction.

.PARAMETER IncludeNonInteractive
    Optional switch. If specified, includes non-interactive sign-in events in addition to interactive sign-ins.

.PARAMETER IncludeServicePrincipal
    Optional switch. If specified, includes service principal sign-in events for application authentication analysis.

.PARAMETER IncludeManagedIdentity
    Optional switch. If specified, includes managed identity sign-in events for Azure resource authentication.

.PARAMETER OutputFormat
    Optional. Format for data export. Valid values are "JSON", "CSV", or "Both". Default is "Both". 
    HTML report is always generated regardless of this setting.

.PARAMETER BatchSize
    Optional. Number of records to retrieve per Microsoft Graph API call. Default is 100. Valid range is 1-999.

.PARAMETER ThrottleLimit
    Optional. Number of concurrent operations for API calls. Default is 5. Reduce if encountering rate limiting.

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-client-secret"

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-client-secret" -DaysToReport 30 -OutputFormat "CSV"

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -CsvPath "C:\TenantCredentials\clients.csv" -DaysToReport 7

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -ClientName "Contoso Corp" -CsvPath ".\tenants.csv" -IncludeNonInteractive -IncludeServicePrincipal

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -TenantId "tenant-guid" -ClientId "client-guid" -ClientSecret "secret" -UserPrincipalNames @("admin@company.com", "ceo@company.com") -DaysToReport 14

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -CsvPath ".\all_tenants.csv" -DaysToReport 30 -IncludeNonInteractive -IncludeServicePrincipal -IncludeManagedIdentity -SkipAnomalyDetection

.EXAMPLE
    .\Get-TenantUserLogins.ps1 -TenantId "guid" -ClientId "guid" -ClientSecret "secret" -UserListPath ".\vip_users.txt" -BatchSize 50 -ThrottleLimit 2

.NOTES
    Required Microsoft Graph API Permissions:
    - AuditLog.Read.All (to read audit log data including sign-ins)
    - User.Read.All (to read user profile information for enrichment)  
    - Directory.Read.All (to read directory data)
    
    Version:        2.0
    Author:         Geoff Tankersley
    Last Modified:  2025-08-11
#>

param(
    [Parameter(Mandatory=$false, ParameterSetName='SingleTenant')]
    [string]$TenantId,
    
    [Parameter(Mandatory=$false, ParameterSetName='SingleTenant')]
    [string]$ClientId,
    
    [Parameter(Mandatory=$false, ParameterSetName='SingleTenant')]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$false, ParameterSetName='MultiTenant')]
    [Parameter(Mandatory=$false, ParameterSetName='ClientLookup')]
    [string]$CsvPath,
    
    [Parameter(Mandatory=$false, ParameterSetName='ClientLookup')]
    [string]$ClientName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysToReport,
    
    [Parameter(Mandatory=$false)]
    [string[]]$UserPrincipalNames,
    
    [Parameter(Mandatory=$false)]
    [string]$UserListPath,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAnomalyDetection,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeNonInteractive,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeServicePrincipal,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeManagedIdentity,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "CSV", "Both")]
    [string]$OutputFormat,
    
    [Parameter(Mandatory=$false)]
    [int]$BatchSize,
    
    [Parameter(Mandatory=$false)]
    [int]$ThrottleLimit
)

#Requires -Version 5.1

Add-Type -AssemblyName System.Web

if (-not $DaysToReport) { $DaysToReport = 90 }
if (-not $OutputFormat) { $OutputFormat = "Both" }
if (-not $BatchSize) { $BatchSize = 100 }
if (-not $ThrottleLimit) { $ThrottleLimit = 5 }
if (-not $CsvPath -and $ClientName) { $CsvPath = ".\AzureAppKeys.csv" }

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "SignInLogs-$timestamp"
$logFile = Join-Path -Path $outputFolder -ChildPath "extraction-log-$timestamp.txt"

# Create output directory
try {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    Write-Host "Created output directory: $outputFolder" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create output directory: $_"
    exit 1
}

function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
    Add-Content -Path $logFile -Value $logMessage -Force
    
    switch ($Level) {
        "INFO"  { Write-Host $Message -ForegroundColor Green }
        "WARN"  { Write-Warning $Message }
        "ERROR" { Write-Error $Message }
        "DEBUG" { Write-Verbose $Message -Verbose }
    }
}

function Get-ClientCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClientName,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvPath
    )
    
    Write-Log "Looking up credentials for client: $ClientName" -Level "INFO"
    
    if (-not (Test-Path -Path $CsvPath)) {
        throw "CSV file not found: $CsvPath"
    }
    
    try {
        $keys = Import-Csv -Path $CsvPath
        $clientCreds = $keys | Where-Object { $_.Client -eq $ClientName }
        
        if (-not $clientCreds) {
            throw "Client '$ClientName' not found in CSV file"
        }
        
        if ($clientCreds.Count -gt 1) {
            Write-Log "Multiple entries found for client '$ClientName', using first match" -Level "WARN"
            $clientCreds = $clientCreds[0]
        }
        
        return @{
            TenantId = $clientCreds.'Tenant ID'.Trim()
            ClientId = $clientCreds.'Client ID'.Trim()
            ClientSecret = $clientCreds.'Key Value'.Trim()
            ClientName = $clientCreds.Client.Trim()
        }
    }
    catch {
        throw "Error reading CSV file: $_"
    }
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
        [int]$MaxRetries = 3
    )
    
    $tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }
    
    $retryCount = 0
    while ($retryCount -lt $MaxRetries) {
        try {
            Write-Log "Attempting to acquire access token (attempt $($retryCount + 1)/$MaxRetries)" -Level "INFO"
            $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
            Write-Log "Successfully acquired access token" -Level "INFO"
            return $response.access_token
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Write-Log "Failed to obtain access token after $MaxRetries attempts: $_" -Level "ERROR"
                throw $_
            }
            Write-Log "Token acquisition failed, retrying in 5 seconds... (attempt $retryCount/$MaxRetries)" -Level "WARN"
            Start-Sleep -Seconds 5
        }
    }
}

function Get-AllSignInLogs {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [int]$DaysToReport,
        
        [Parameter(Mandatory=$false)]
        [string[]]$TargetUsers,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeNonInteractive,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeServicePrincipal,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeManagedIdentity
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
        "ConsistencyLevel" = "eventual"
    }
    
    try {
        $startDate = (Get-Date).AddDays(-$DaysToReport).ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        $allSignInLogs = @()
        
        # Define sign-in event types to collect
        $eventTypes = @("interactiveUser")
        if ($IncludeNonInteractive) { $eventTypes += "nonInteractiveUser" }
        if ($IncludeServicePrincipal) { $eventTypes += "servicePrincipal" }
        if ($IncludeManagedIdentity) { $eventTypes += "managedIdentity" }
        
        Write-Log "Collecting sign-in events for types: $($eventTypes -join ', ')" -Level "INFO"
        
        foreach ($eventType in $eventTypes) {
            Write-Log "Retrieving $eventType sign-in logs..." -Level "INFO"
            
            $dateFilter = "createdDateTime ge $startDate"
            
            $userFilter = ""
            if ($TargetUsers -and $TargetUsers.Count -gt 0) {
                if ($TargetUsers.Count -eq 1) {
                    $userFilter = " and userPrincipalName eq '$($TargetUsers[0])'"
                } else {
                    $userFilterParts = $TargetUsers | ForEach-Object { "userPrincipalName eq '$_'" }
                    $userFilter = " and (" + ($userFilterParts -join " or ") + ")"
                }
            }
            
            # Use v1 endpoint for interactive users
            if ($eventType -eq "interactiveUser") {
                $filterQuery = $dateFilter + $userFilter
                $baseUrl = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
            } else {
                # Use beta endpoint for non-interactive, service principal, and managed identity
                $eventTypeFilter = " and signInEventTypes/any(t: t eq '$eventType')"
                $filterQuery = $dateFilter + $eventTypeFilter + $userFilter
                $baseUrl = "https://graph.microsoft.com/beta/auditLogs/signIns"
            }
            
            Write-Log "Filter query for $eventType`: $filterQuery" -Level "DEBUG"
            
            # Retrieve logs with pagination
            $eventTypeLogs = @()
            $encodedFilter = [System.Web.HttpUtility]::UrlEncode($filterQuery)
            $nextLink = "$baseUrl`?`$filter=$encodedFilter&`$top=$BatchSize"
            $batchCounter = 0
            
            do {
                $batchCounter++
                Write-Progress -Activity "Retrieving $eventType Sign-in Logs" -Status "Batch $batchCounter" -Id 1
                
                try {
                    $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
                    $eventTypeLogs += $response.value
                    $nextLink = $response.'@odata.nextLink'
                    
                    Write-Log "Retrieved batch $batchCounter for $eventType - Added $($response.value.Count) records (Total: $($eventTypeLogs.Count))" -Level "INFO"
                    
                    # Throttling
                    if ($nextLink) {
                        Start-Sleep -Milliseconds 200
                    }
                }
                catch {
                    Write-Log "Error retrieving batch $batchCounter for $eventType`: $_" -Level "ERROR"
                    if ($_.Exception.Response.StatusCode -eq 429) {
                        Write-Log "Rate limit hit, waiting 60 seconds..." -Level "WARN"
                        Start-Sleep -Seconds 60
                    } else {
                        throw $_
                    }
                }
            } while ($nextLink)
            
            Write-Progress -Activity "Retrieving $eventType Sign-in Logs" -Id 1 -Completed
            Write-Log "Completed retrieval of $eventType logs: $($eventTypeLogs.Count) records" -Level "INFO"
            $allSignInLogs += $eventTypeLogs
        }
        
        Write-Log "Total sign-in logs retrieved: $($allSignInLogs.Count)" -Level "INFO"
        return $allSignInLogs
    }
    catch {
        Write-Log "Error retrieving sign-in logs: $_" -Level "ERROR"
        throw $_
    }
}

function Get-UserDetailsForSignIns {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [array]$SignInLogs
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        # Extract unique user IDs from sign-ins
        $userIds = $SignInLogs | ForEach-Object { $_.userId } | Sort-Object -Unique | Where-Object { $_ }
        
        Write-Log "Retrieving details for $($userIds.Count) unique users..." -Level "INFO"
        
        $userDetailsMap = @{}
        $userBatches = @()
        $currentBatch = @()
        
        # Process in batches
        foreach ($userId in $userIds) {
            $currentBatch += $userId
            
            if ($currentBatch.Count -ge 20) {
                $userBatches += ,$currentBatch
                $currentBatch = @()
            }
        }
        
        if ($currentBatch.Count -gt 0) {
            $userBatches += ,$currentBatch
        }
        
        $batchCount = $userBatches.Count
        $currentBatchNum = 0
        
        foreach ($batch in $userBatches) {
            $currentBatchNum++
            Write-Progress -Activity "Retrieving User Details" -Status "Batch $currentBatchNum of $batchCount" -PercentComplete (($currentBatchNum / $batchCount) * 100) -Id 2
            
            foreach ($userId in $batch) {
                try {
                    $userUri = "https://graph.microsoft.com/v1.0/users/$userId`?`$select=id,userPrincipalName,displayName,mail,department,jobTitle"
                    $userResponse = Invoke-RestMethod -Uri $userUri -Method Get -Headers $headers
                    
                    $userDetailsMap[$userId] = @{
                        userPrincipalName = $userResponse.userPrincipalName
                        displayName = $userResponse.displayName
                        mail = $userResponse.mail
                        department = $userResponse.department
                        jobTitle = $userResponse.jobTitle
                    }
                }
                catch {
                    Write-Log "Could not retrieve details for user ID $userId`: $_" -Level "WARN"
                    $userDetailsMap[$userId] = @{
                        userPrincipalName = "Unknown"
                        displayName = "Unknown User"
                        mail = "Unknown"
                        department = "Unknown"
                        jobTitle = "Unknown"
                    }
                }
            }
            
            Start-Sleep -Milliseconds 100
        }
        
        Write-Progress -Activity "Retrieving User Details" -Id 2 -Completed
        return $userDetailsMap
    }
    catch {
        Write-Log "Error retrieving user details: $_" -Level "ERROR"
        return @{}
    }
}

function Format-SignInLogs {
    param (
        [Parameter(Mandatory=$true)]
        [array]$SignInLogs,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$UserDetailsMap = @{}
    )
    
    Write-Log "Formatting $($SignInLogs.Count) sign-in logs..." -Level "INFO"
    $formattedLogs = @()
    
    foreach ($log in $SignInLogs) {
        # Get user details from map or use defaults
        $userDetails = $UserDetailsMap[$log.userId]
        if (-not $userDetails) {
            $userDetails = @{
                userPrincipalName = $log.userPrincipalName
                displayName = "Unknown User"
                mail = "Unknown"
                department = "Unknown"
                jobTitle = "Unknown"
            }
        }
        
        $formattedLog = [PSCustomObject]@{
            UserPrincipalName = $userDetails.userPrincipalName
            DisplayName = $userDetails.displayName
            Email = $userDetails.mail
            Department = $userDetails.department
            JobTitle = $userDetails.jobTitle
            UserId = $log.userId
            SignInTime = $log.createdDateTime
            IPAddress = $log.ipAddress
            Location = if ($log.location) { "$($log.location.city), $($log.location.countryOrRegion)" } else { "Unknown" }
            Country = $log.location.countryOrRegion
            State = $log.location.state
            City = $log.location.city
            AppDisplayName = $log.appDisplayName
            AppId = $log.appId
            ClientAppUsed = $log.clientAppUsed
            DeviceId = $log.deviceDetail.deviceId
            DeviceName = $log.deviceDetail.displayName
            DeviceOS = $log.deviceDetail.operatingSystem
            DeviceBrowser = $log.deviceDetail.browser
            DeviceTrustType = $log.deviceDetail.trustType
            Status = if ($log.status.errorCode -eq 0) { "Success" } else { "Failure" }
            ErrorCode = $log.status.errorCode
            FailureReason = $log.status.failureReason
            IsInteractive = $log.isInteractive
            SignInEventType = ($log.signInEventTypes -join "; ")
            RiskState = $log.riskState
            RiskLevelAggregated = $log.riskLevelAggregated
            RiskLevelDuringSignIn = $log.riskLevelDuringSignIn
            RiskDetail = $log.riskDetail
            RiskEventTypes = ($log.riskEventTypes -join "; ")
            CorrelationId = $log.correlationId
            ConditionalAccessStatus = $log.conditionalAccessStatus
            AuthenticationRequirement = $log.authenticationRequirement
            AuthenticationMethods = ($log.authenticationDetails | ForEach-Object { "$($_.authenticationMethod):$($_.succeeded)" }) -join "; "
            AppliedConditionalAccessPolicies = ($log.appliedConditionalAccessPolicies | ForEach-Object { "$($_.displayName):$($_.result)" }) -join "; "
            UserAgent = $log.userAgent
            NetworkLocationDetails = if ($log.networkLocationDetails) { ($log.networkLocationDetails | ConvertTo-Json -Compress) } else { $null }
            TokenIssuerType = $log.tokenIssuerType
            ProcessingTimeInMs = $log.processingTimeInMs
        }
        
        $formattedLogs += $formattedLog
    }
    
    Write-Log "Completed formatting of sign-in logs" -Level "INFO"
    return $formattedLogs
}

function Find-SignInAnomalies {
    param (
        [Parameter(Mandatory=$true)]
        [array]$SignInLogs
    )
    
    Write-Log "Starting anomaly detection on $($SignInLogs.Count) sign-in logs..." -Level "INFO"
    $anomalies = @()
    
    # Group sign-ins by user
    $userSignIns = $SignInLogs | Group-Object -Property UserPrincipalName
    $totalUsers = $userSignIns.Count
    $currentUser = 0
    
    foreach ($userGroup in $userSignIns) {
        $currentUser++
        Write-Progress -Activity "Analyzing Sign-in Anomalies" -Status "User $currentUser of $totalUsers" -PercentComplete (($currentUser / $totalUsers) * 100)
        
        $user = $userGroup.Name
        $userLogs = $userGroup.Group
        
        # 1. Impossible travel detection (enhanced)
        $userLocations = $userLogs | Group-Object -Property Country
        if ($userLocations.Count -gt 1) {
            $signInsByDate = $userLogs | Sort-Object -Property SignInTime
            $previousSignIn = $null
            
            foreach ($signIn in $signInsByDate) {
                if ($previousSignIn -ne $null) {
                    if ($signIn.Country -ne $previousSignIn.Country -and 
                        $signIn.Country -ne "Unknown" -and $previousSignIn.Country -ne "Unknown") {
                        $timeDifference = [DateTime]::Parse($signIn.SignInTime) - [DateTime]::Parse($previousSignIn.SignInTime)
                        
                        # Flag if less than 4 hours between different countries
                        if ($timeDifference.TotalHours -lt 4) {
                            $anomalies += [PSCustomObject]@{
                                Type = "Impossible Travel"
                                User = $user
                                Details = "Sign-ins from different countries within $([Math]::Round($timeDifference.TotalHours, 2)) hours: $($previousSignIn.Country) at $($previousSignIn.SignInTime) and $($signIn.Country) at $($signIn.SignInTime)"
                                Severity = "High"
                                FirstSignIn = $previousSignIn
                                SecondSignIn = $signIn
                                TimeDifferenceHours = [Math]::Round($timeDifference.TotalHours, 2)
                            }
                        }
                    }
                }
                $previousSignIn = $signIn
            }
        }
        
        # 2. Multiple failed attempts followed by success
        $chronologicalSignIns = $userLogs | Sort-Object -Property SignInTime
        $failedAttempts = 0
        $lastFailedTime = $null
        $failureIPs = @()
        
        foreach ($signIn in $chronologicalSignIns) {
            if ($signIn.Status -ne "Success") {
                $failedAttempts++
                $lastFailedTime = [DateTime]::Parse($signIn.SignInTime)
                $failureIPs += $signIn.IPAddress
            } else {
                if ($failedAttempts -ge 3 -and $lastFailedTime -ne $null) {
                    $timeSinceLastFailed = [DateTime]::Parse($signIn.SignInTime) - $lastFailedTime
                    
                    if ($timeSinceLastFailed.TotalMinutes -lt 60) {
                        $uniqueIPs = $failureIPs | Sort-Object -Unique
                        $anomalies += [PSCustomObject]@{
                            Type = "Brute Force Success"
                            User = $user
                            Details = "$failedAttempts failed attempts from $($uniqueIPs.Count) unique IPs followed by successful sign-in within $([Math]::Round($timeSinceLastFailed.TotalMinutes, 2)) minutes"
                            Severity = if ($uniqueIPs.Count -gt 1) { "High" } else { "Medium" }
                            SuccessfulSignIn = $signIn
                            FailedAttempts = $failedAttempts
                            UniqueFailureIPs = $uniqueIPs -join "; "
                        }
                    }
                }
                $failedAttempts = 0
                $failureIPs = @()
            }
        }
        
        # 3. Off-hours sign-ins (business hours 7 AM to 7 PM)
        foreach ($signIn in $userLogs) {
            $signInTime = [DateTime]::Parse($signIn.SignInTime)
            $hour = $signInTime.Hour
            
            if ($hour -lt 7 -or $hour -gt 19) {
                $anomalies += [PSCustomObject]@{
                    Type = "Off-hours Sign-in"
                    User = $user
                    Details = "Sign-in detected at $($signInTime.ToString("HH:mm")) from $($signIn.IPAddress) in $($signIn.Location)"
                    Severity = "Low"
                    SignIn = $signIn
                    SignInHour = $hour
                }
            }
        }
        
        # 4. High-risk sign-ins
        foreach ($signIn in $userLogs) {
            if ($signIn.RiskState -ne "none" -and $signIn.RiskState -ne "" -and $signIn.RiskState -ne $null) {
                $riskSeverity = switch ($signIn.RiskLevelAggregated) {
                    "high" { "High" }
                    "medium" { "Medium" }
                    default { "Low" }
                }
                
                $anomalies += [PSCustomObject]@{
                    Type = "Risky Sign-in"
                    User = $user
                    Details = "Risk state: $($signIn.RiskState), Risk level: $($signIn.RiskLevelAggregated), Risk detail: $($signIn.RiskDetail), Risk events: $($signIn.RiskEventTypes)"
                    Severity = $riskSeverity
                    SignIn = $signIn
                    RiskLevel = $signIn.RiskLevelAggregated
                }
            }
        }
        
        # 5. Sign-ins from new/unusual locations
        $userCountries = $userLogs | Group-Object -Property Country | Where-Object { $_.Name -ne "Unknown" }
        if ($userCountries.Count -gt 3) {
            $rareLogs = $userCountries | Where-Object { $_.Count -eq 1 }
            foreach ($rareCountry in $rareLogs) {
                $signIn = $rareCountry.Group[0]
                $anomalies += [PSCustomObject]@{
                    Type = "Unusual Location"
                    User = $user
                    Details = "Single sign-in from unusual location: $($signIn.Location) at $($signIn.SignInTime)"
                    Severity = "Medium"
                    SignIn = $signIn
                    UnusualCountry = $rareCountry.Name
                }
            }
        }
        
        # 6. Sign-ins with unusual user agents or client apps
        $userAgents = $userLogs | Group-Object -Property ClientAppUsed
        $rareUserAgents = $userAgents | Where-Object { $_.Count -eq 1 -and $_.Name -ne "Browser" -and $_.Name -ne "Mobile Apps and Desktop clients" }
        foreach ($rareAgent in $rareUserAgents) {
            $signIn = $rareAgent.Group[0]
            $anomalies += [PSCustomObject]@{
                Type = "Unusual Client App"
                User = $user
                Details = "Sign-in using unusual client app: $($signIn.ClientAppUsed) from $($signIn.IPAddress)"
                Severity = "Low"
                SignIn = $signIn
                UnusualClientApp = $signIn.ClientAppUsed
            }
        }
    }
    
    Write-Progress -Activity "Analyzing Sign-in Anomalies" -Completed
    Write-Log "Anomaly detection completed. Found $($anomalies.Count) potential anomalies" -Level "INFO"
    return $anomalies
}

function Export-SignInData {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$BasePath,
        
        [Parameter(Mandatory=$true)]
        [string]$FilePrefix,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("JSON", "CSV", "Both")]
        [string]$Format = "Both"
    )
    
    $exports = @()
    
    if ($Format -eq "CSV" -or $Format -eq "Both") {
        $csvPath = "${BasePath}\${FilePrefix}.csv"
        $Data | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        $exports += $csvPath
        Write-Log "Exported CSV: $csvPath" -Level "INFO"
    }
    
    if ($Format -eq "JSON" -or $Format -eq "Both") {
        $jsonPath = "${BasePath}\${FilePrefix}.json"
        $Data | ConvertTo-Json -Depth 10 -Compress | Out-File -FilePath $jsonPath -Encoding UTF8
        $exports += $jsonPath
        Write-Log "Exported JSON: $jsonPath" -Level "INFO"
    }
}

function New-HTMLReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$TenantResults,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$true)]
        [hashtable]$Summary
    )
    
    Write-Log "Generating HTML report..." -Level "INFO"
    
    $validResults = $TenantResults | Where-Object { $_ -ne $null }
    
    $allSignInLogs = @()
    $allAnomalies = @()
    
    foreach ($result in $validResults) {
        if ($result.SignInLogs) { $allSignInLogs += $result.SignInLogs }
        if ($result.Anomalies) { $allAnomalies += $result.Anomalies }
    }
    
    $successfulLogins = ($allSignInLogs | Where-Object { $_.Status -eq "Success" }).Count
    $failedLogins = $allSignInLogs.Count - $successfulLogins
    $uniqueUsers = ($allSignInLogs | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
    $uniqueCountries = ($allSignInLogs | Select-Object -ExpandProperty Country -Unique | Where-Object { $_ -ne "Unknown" }).Count
    $riskyLogins = ($allSignInLogs | Where-Object { $_.RiskState -ne "none" -and $_.RiskState -ne "" -and $_.RiskState -ne $null }).Count
    
    $topUsers = $allSignInLogs | Group-Object -Property UserPrincipalName | Sort-Object Count -Descending | Select-Object -First 10
    $topCountries = $allSignInLogs | Where-Object { $_.Country -ne "Unknown" } | Group-Object -Property Country | Sort-Object Count -Descending | Select-Object -First 10
    $topApps = $allSignInLogs | Group-Object -Property AppDisplayName | Sort-Object Count -Descending | Select-Object -First 10
    $topIPs = $allSignInLogs | Group-Object -Property IPAddress | Sort-Object Count -Descending | Select-Object -First 10
    
    $recentAnomalies = $allAnomalies | Sort-Object { 
        if ($_.SignIn.SignInTime) { [DateTime]::Parse($_.SignIn.SignInTime) }
        elseif ($_.FirstSignIn.SignInTime) { [DateTime]::Parse($_.FirstSignIn.SignInTime) }
        elseif ($_.SuccessfulSignIn.SignInTime) { [DateTime]::Parse($_.SuccessfulSignIn.SignInTime) }
        else { Get-Date "1900-01-01" }
    } -Descending | Select-Object -First 20
    $anomalyTypes = $allAnomalies | Group-Object -Property Type | Sort-Object Count -Descending
    $highSeverityAnomalies = ($allAnomalies | Where-Object { $_.Severity -eq "High" })
    $mediumSeverityAnomalies = ($allAnomalies | Where-Object { $_.Severity -eq "Medium" })
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign-In Logs Analysis Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f7fa; color: #333; line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 20px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; font-weight: 300; }
        .header p { font-size: 1.1em; opacity: 0.9; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 4px 20px rgba(0,0,0,0.08); transition: transform 0.3s ease; }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #666; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; }
        .success { color: #28a745; }
        .danger { color: #dc3545; }
        .warning { color: #ffc107; }
        .info { color: #17a2b8; }
        .primary { color: #007bff; }
        .section { background: white; margin-bottom: 30px; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        .section-header { background: #f8f9fa; padding: 20px; border-bottom: 1px solid #e9ecef; }
        .section-header h2 { color: #495057; font-size: 1.4em; font-weight: 600; }
        .section-content { padding: 20px; }
        .alert { padding: 15px; margin-bottom: 20px; border-radius: 8px; border-left: 4px solid; }
        .alert-danger { background: #f8d7da; border-color: #dc3545; color: #721c24; }
        .alert-warning { background: #fff3cd; border-color: #ffc107; color: #856404; }
        .alert-info { background: #d1ecf1; border-color: #17a2b8; color: #0c5460; }
        .table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        .table th, .table td { padding: 12px; text-align: left; border-bottom: 1px solid #e9ecef; }
        .table th { background: #f8f9fa; font-weight: 600; color: #495057; }
        .table tbody tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.75em; font-weight: bold; text-transform: uppercase; }
        .badge-danger { background: #dc3545; color: white; }
        .badge-warning { background: #ffc107; color: #212529; }
        .badge-info { background: #17a2b8; color: white; }
        .badge-success { background: #28a745; color: white; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .grid-3 { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 20px; }
        @media (max-width: 768px) { .grid-2, .grid-3 { grid-template-columns: 1fr; } }
        .anomaly-item { background: #f8f9fa; padding: 15px; margin-bottom: 10px; border-radius: 8px; border-left: 4px solid; }
        .anomaly-high { border-color: #dc3545; }
        .anomaly-medium { border-color: #ffc107; }
        .anomaly-low { border-color: #17a2b8; }
        .progress { background: #e9ecef; border-radius: 10px; overflow: hidden; height: 20px; margin-top: 5px; }
        .progress-bar { height: 100%; transition: width 0.3s ease; }
        .bg-success { background: #28a745; }
        .bg-danger { background: #dc3545; }
        .bg-warning { background: #ffc107; }
        .bg-info { background: #17a2b8; }
        .text-small { font-size: 0.85em; color: #666; }
        .mt-10 { margin-top: 10px; }
        .mb-10 { margin-bottom: 10px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>&#x1F50D; Sign-In Logs Analysis Report</h1>
            <p>Generated on $(Get-Date -Format 'MMMM dd, yyyy at HH:mm') | Analysis Period: $DaysToReport days</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number primary">$($Summary.TotalSignIns.ToString('N0'))</div>
                <div class="stat-label">Total Sign-ins</div>
            </div>
            <div class="stat-card">
                <div class="stat-number success">$($successfulLogins.ToString('N0'))</div>
                <div class="stat-label">Successful</div>
            </div>
            <div class="stat-card">
                <div class="stat-number danger">$($failedLogins.ToString('N0'))</div>
                <div class="stat-label">Failed</div>
            </div>
            <div class="stat-card">
                <div class="stat-number info">$($uniqueUsers.ToString('N0'))</div>
                <div class="stat-label">Unique Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-number warning">$($Summary.TotalAnomalies.ToString('N0'))</div>
                <div class="stat-label">Anomalies</div>
            </div>
        </div>

        $(if ($Summary.TotalAnomalies -gt 0) {
            $highCount = ($allAnomalies | Where-Object { $_.Severity -eq "High" }).Count
            $mediumCount = ($allAnomalies | Where-Object { $_.Severity -eq "Medium" }).Count
            $lowCount = ($allAnomalies | Where-Object { $_.Severity -eq "Low" }).Count
            
            $alertClass = if ($highCount -gt 0) { "alert-danger" } elseif ($mediumCount -gt 0) { "alert-warning" } else { "alert-info" }
            $alertIcon = if ($highCount -gt 0) { "&#x1F6A8;" } elseif ($mediumCount -gt 0) { "&#x26A0;" } else { "&#x2139;" }
            
            "<div class='alert $alertClass'>
                <strong>$alertIcon Security Alert:</strong> $($Summary.TotalAnomalies) potential security anomalies detected.
                High Priority: $highCount | Medium Priority: $mediumCount | Low Priority: $lowCount
            </div>"
        })

        <div class="grid-2">
            <div class="section">
                <div class="section-header">
                    <h2>&#x1F4CA; Top Users by Sign-in Activity</h2>
                </div>
                <div class="section-content">
                    <table class="table">
                        <thead>
                            <tr><th>User</th><th>Sign-ins</th><th>Activity</th></tr>
                        </thead>
                        <tbody>
                            $(foreach ($user in $topUsers) {
                                $percentage = [math]::Round(($user.Count / $allSignInLogs.Count) * 100, 1)
                                "<tr>
                                    <td>$($user.Name)</td>
                                    <td>$($user.Count.ToString('N0'))</td>
                                    <td>
                                        <div class='progress'>
                                            <div class='progress-bar bg-info' style='width: $percentage%'></div>
                                        </div>
                                        <div class='text-small mt-10'>$percentage% of total</div>
                                    </td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>&#x1F30D; Geographic Distribution</h2>
                </div>
                <div class="section-content">
                    <table class="table">
                        <thead>
                            <tr><th>Country</th><th>Sign-ins</th><th>Distribution</th></tr>
                        </thead>
                        <tbody>
                            $(foreach ($country in $topCountries) {
                                $percentage = [math]::Round(($country.Count / $allSignInLogs.Count) * 100, 1)
                                "<tr>
                                    <td>$($country.Name)</td>
                                    <td>$($country.Count.ToString('N0'))</td>
                                    <td>
                                        <div class='progress'>
                                            <div class='progress-bar bg-success' style='width: $percentage%'></div>
                                        </div>
                                        <div class='text-small mt-10'>$percentage% of total</div>
                                    </td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>&#x1F6A8; Security Anomalies Breakdown</h2>
            </div>
            <div class="section-content">
                <div class="grid-3">
                    $(foreach ($anomalyType in $anomalyTypes) {
                        $badgeClass = switch ($anomalyType.Name) {
                            "Impossible Travel" { "badge-danger" }
                            "Brute Force Success" { "badge-danger" }
                            "Risky Sign-in" { "badge-warning" }
                            "Unusual Location" { "badge-warning" }
                            default { "badge-info" }
                        }
                        "<div class='stat-card'>
                            <div class='stat-number'>$($anomalyType.Count)</div>
                            <div class='stat-label'>$($anomalyType.Name)</div>
                            <span class='badge $badgeClass'>$(switch ($anomalyType.Name) {
                                "Impossible Travel" { "High Risk" }
                                "Brute Force Success" { "High Risk" }
                                "Risky Sign-in" { "Medium Risk" }
                                default { "Low Risk" }
                            })</span>
                        </div>"
                    })
                </div>
            </div>
        </div>

        $(if ($highSeverityAnomalies.Count -gt 0) {
            "<div class='section'>
                <div class='section-header'>
                    <h2>&#x1F525; High Priority Security Alerts</h2>
                </div>
                <div class='section-content'>
                    $(foreach ($anomaly in ($highSeverityAnomalies | Select-Object -First 10)) {
                        $signInTime = if ($anomaly.SignIn.SignInTime) { $anomaly.SignIn.SignInTime }
                                     elseif ($anomaly.FirstSignIn.SignInTime) { $anomaly.FirstSignIn.SignInTime }
                                     elseif ($anomaly.SuccessfulSignIn.SignInTime) { $anomaly.SuccessfulSignIn.SignInTime }
                                     else { "Unknown" }
                        
                        "<div class='anomaly-item anomaly-high'>
                            <div style='display: flex; justify-content: between; align-items: center;'>
                                <div>
                                    <strong>$($anomaly.Type)</strong> - $($anomaly.User)
                                    <div class='text-small mt-10'>$($anomaly.Details)</div>
                                    <div class='text-small'>Time: $signInTime</div>
                                </div>
                                <span class='badge badge-danger'>$($anomaly.Severity)</span>
                            </div>
                        </div>"
                    })
                </div>
            </div>"
        })

        <div class="grid-2">
            <div class="section">
                <div class="section-header">
                    <h2>&#x1F4F1; Top Applications</h2>
                </div>
                <div class="section-content">
                    <table class="table">
                        <thead>
                            <tr><th>Application</th><th>Sign-ins</th></tr>
                        </thead>
                        <tbody>
                            $(foreach ($app in $topApps) {
                                "<tr>
                                    <td>$($app.Name)</td>
                                    <td>$($app.Count.ToString('N0'))</td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="section">
                <div class="section-header">
                    <h2>&#x1F310; Top IP Addresses</h2>
                </div>
                <div class="section-content">
                    <table class="table">
                        <thead>
                            <tr><th>IP Address</th><th>Sign-ins</th></tr>
                        </thead>
                        <tbody>
                            $(foreach ($ip in $topIPs) {
                                "<tr>
                                    <td>$($ip.Name)</td>
                                    <td>$($ip.Count.ToString('N0'))</td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        $(if ($Summary.TotalTenants -gt 1) {
            "<div class='section'>
                <div class='section-header'>
                    <h2>&#x1F3E2; Tenant Summary</h2>
                </div>
                <div class='section-content'>
                    <table class='table'>
                        <thead>
                            <tr><th>Tenant</th><th>Sign-ins</th><th>Users</th><th>Anomalies</th><th>Risk Level</th></tr>
                        </thead>
                        <tbody>
                            $(foreach ($tenant in $Summary.TenantSummary) {
                                $riskBadge = if ($tenant.HighSeverityAnomalies -gt 0) { "badge-danger" }
                                           elseif ($tenant.MediumSeverityAnomalies -gt 0) { "badge-warning" }
                                           else { "badge-success" }
                                $riskText = if ($tenant.HighSeverityAnomalies -gt 0) { "High" }
                                          elseif ($tenant.MediumSeverityAnomalies -gt 0) { "Medium" }
                                          else { "Low" }
                                "<tr>
                                    <td>$($tenant.TenantName)</td>
                                    <td>$($tenant.SignInCount.ToString('N0'))</td>
                                    <td>$($tenant.UniqueUsers.ToString('N0'))</td>
                                    <td>$($tenant.AnomaliesFound.ToString('N0'))</td>
                                    <td><span class='badge $riskBadge'>$riskText</span></td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
            </div>"
        })

        <div class="section">
            <div class="section-header">
                <h2>&#x1F4CB; Report Details</h2>
            </div>
            <div class="section-content">
                <div class="grid-2">
                    <div>
                        <h4>Analysis Parameters</h4>
                        <ul>
                            <li><strong>Time Range:</strong> $DaysToReport days</li>
                            <li><strong>Tenants Analyzed:</strong> $($Summary.TotalTenants)</li>
                            <li><strong>Output Format:</strong> $OutputFormat</li>
                            <li><strong>Anomaly Detection:</strong> $(if ($SkipAnomalyDetection) { "Disabled" } else { "Enabled" })</li>
                        </ul>
                    </div>
                    <div>
                        <h4>Risk Summary</h4>
                        <ul>
                            <li><strong>Countries Accessed:</strong> $uniqueCountries</li>
                            <li><strong>Risky Sign-ins:</strong> $riskyLogins</li>
                            <li><strong>Success Rate:</strong> $([math]::Round(($successfulLogins / $allSignInLogs.Count) * 100, 1))%</li>
                            <li><strong>Generated:</strong> $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>&#x1F550; Complete Sign-In Timeline</h2>
                <p style="color: #666; font-size: 0.9em; margin-top: 5px;">Chronological view of all sign-in events (newest first)</p>
            </div>
            <div class="section-content">
                <div style="margin-bottom: 15px;">
                    <button onclick="filterTimeline('all')" class="filter-btn active" id="filter-all">All ($($allSignInLogs.Count))</button>
                    <button onclick="filterTimeline('success')" class="filter-btn" id="filter-success">Successful ($successfulLogins)</button>
                    <button onclick="filterTimeline('failed')" class="filter-btn" id="filter-failed">Failed ($failedLogins)</button>
                    $(if ($riskyLogins -gt 0) { "<button onclick=`"filterTimeline('risky')`" class='filter-btn' id='filter-risky'>Risky ($riskyLogins)</button>" })
                </div>
                
                <div class="timeline-container">
                    <table class="table timeline-table" id="timelineTable">
                        <thead>
                            <tr>
                                <th style="width: 140px;">Time</th>
                                <th style="width: 200px;">User</th>
                                <th style="width: 120px;">Status</th>
                                <th style="width: 120px;">IP Address</th>
                                <th style="width: 150px;">Location</th>
                                <th style="width: 200px;">Application</th>
                                <th style="width: 120px;">Client</th>
                                <th style="width: 150px;">Device</th>
                                <th style="width: 100px;">Risk</th>
                            </tr>
                        </thead>
                        <tbody>
                            $(foreach ($logEntry in ($allSignInLogs | Sort-Object { [DateTime]::Parse($_.SignInTime) } -Descending)) {
                                $statusClass = if ($logEntry.Status -eq "Success") { "success" } else { "danger" }
                                $riskClass = switch ($logEntry.RiskLevelAggregated) {
                                    "high" { "danger" }
                                    "medium" { "warning" }
                                    "low" { "info" }
                                    default { "" }
                                }
                                $riskLabel = if ($logEntry.RiskLevelAggregated -and $logEntry.RiskLevelAggregated -ne "none") { $logEntry.RiskLevelAggregated } else { "-" }
                                
                                $timeFormatted = try { 
                                    [DateTime]::Parse($logEntry.SignInTime).ToString("MM/dd HH:mm:ss") 
                                } catch { 
                                    $logEntry.SignInTime 
                                }
                                
                                $deviceInfo = if ($logEntry.DeviceName) { 
                                    "$($logEntry.DeviceName) ($($logEntry.DeviceOS))" 
                                } elseif ($logEntry.DeviceOS) { 
                                    $logEntry.DeviceOS 
                                } else { 
                                    "Unknown" 
                                }
                                
                                $filterClasses = @("timeline-row")
                                if ($logEntry.Status -eq "Success") { $filterClasses += "filter-success" }
                                if ($logEntry.Status -ne "Success") { $filterClasses += "filter-failed" }
                                if ($logEntry.RiskState -ne "none" -and $logEntry.RiskState -ne "" -and $logEntry.RiskState -ne $null) { $filterClasses += "filter-risky" }
                                $filterClassString = $filterClasses -join " "
                                
                                "<tr class='$filterClassString' onclick=`"showSignInDetails('$($logEntry.CorrelationId)')`">
                                    <td class='timeline-time'>$timeFormatted</td>
                                    <td class='timeline-user'>$($logEntry.UserPrincipalName)</td>
                                    <td><span class='badge badge-$statusClass'>$($logEntry.Status)</span></td>
                                    <td class='timeline-ip'>$($logEntry.IPAddress)</td>
                                    <td class='timeline-location'>$($logEntry.Location)</td>
                                    <td class='timeline-app'>$($logEntry.AppDisplayName)</td>
                                    <td class='timeline-client'>$($logEntry.ClientAppUsed)</td>
                                    <td class='timeline-device'>$deviceInfo</td>
                                    <td>$(if ($riskLabel -ne "-") { "<span class='badge badge-$riskClass'>$riskLabel</span>" } else { "-" })</td>
                                </tr>"
                            })
                        </tbody>
                    </table>
                </div>
                
                <div class="timeline-summary" style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                    <h4>Timeline Summary</h4>
                    <div class="grid-3" style="margin-top: 10px;">
                        <div>
                            <strong>First Sign-in:</strong><br>
                            <span class="text-small">$(try { ($allSignInLogs | Sort-Object { [DateTime]::Parse($_.SignInTime) } | Select-Object -First 1).SignInTime } catch { "Unknown" })</span>
                        </div>
                        <div>
                            <strong>Last Sign-in:</strong><br>
                            <span class="text-small">$(try { ($allSignInLogs | Sort-Object { [DateTime]::Parse($_.SignInTime) } -Descending | Select-Object -First 1).SignInTime } catch { "Unknown" })</span>
                        </div>
                        <div>
                            <strong>Total Duration:</strong><br>
                            <span class="text-small">$(try { 
                                $first = [DateTime]::Parse(($allSignInLogs | Sort-Object { [DateTime]::Parse($_.SignInTime) } | Select-Object -First 1).SignInTime)
                                $last = [DateTime]::Parse(($allSignInLogs | Sort-Object { [DateTime]::Parse($_.SignInTime) } -Descending | Select-Object -First 1).SignInTime)
                                $duration = $last - $first
                                if ($duration.TotalHours -gt 24) { "$([Math]::Round($duration.TotalDays, 1)) days" }
                                elseif ($duration.TotalMinutes -gt 60) { "$([Math]::Round($duration.TotalHours, 1)) hours" }
                                else { "$([Math]::Round($duration.TotalMinutes, 1)) minutes" }
                            } catch { "Unknown" })</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Modal for detailed information -->
    <div id="detailModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <span class="close">&times;</span>
                <h2 id="modalTitle" class="modal-title"></h2>
            </div>
            <div id="modalBody"></div>
        </div>
    </div>

    <script>
        // All sign-in logs data (embedded for JavaScript access)
        var signInLogs = [];
        var anomalies = [];
        
        try {
            signInLogs = $($allSignInLogs | ConvertTo-Json -Depth 3);
            if (!signInLogs) signInLogs = [];
        } catch (e) {
            console.error('Error with sign-in logs data:', e);
            signInLogs = [];
        }
        
        try {
            anomalies = $($allAnomalies | ConvertTo-Json -Depth 3);
            if (!anomalies) anomalies = [];
        } catch (e) {
            console.error('Error with anomalies data:', e);
            anomalies = [];
        }
        
        // Modal functionality
        const modal = document.getElementById('detailModal');
        const span = document.getElementsByClassName('close')[0];
        
        span.onclick = function() {
            modal.style.display = 'none';
        }
        
        window.onclick = function(event) {
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
        
        function showModal(title, content) {
            document.getElementById('modalTitle').innerText = title;
            document.getElementById('modalBody').innerHTML = content;
            modal.style.display = 'block';
        }
        
        function showCountryDetails(countryCode) {
            if (!signInLogs || signInLogs.length === 0) {
                showModal('No Data', '<p>No sign-in data available.</p>');
                return;
            }
            
            const countryLogs = signInLogs.filter(log => 
                log.Country === countryCode && log.Status === 'Success'
            );
            
            const countryName = countryCode || 'Unknown';
            let content = '<p>Successful sign-ins from ' + countryName + ':</p>';
            
            if (countryLogs.length > 0) {
                content += '<table class="detail-table">';
                content += '<thead><tr><th>User</th><th>Time</th><th>IP Address</th><th>Location</th><th>Application</th></tr></thead>';
                content += '<tbody>';
                
                countryLogs.forEach(log => {
                    content += '<tr>';
                    content += '<td>' + (log.UserPrincipalName || 'Unknown') + '</td>';
                    content += '<td>' + (log.SignInTime || 'Unknown') + '</td>';
                    content += '<td>' + (log.IPAddress || 'Unknown') + '</td>';
                    content += '<td>' + (log.Location || 'Unknown') + '</td>';
                    content += '<td>' + (log.AppDisplayName || 'Unknown') + '</td>';
                    content += '</tr>';
                });
                
                content += '</tbody></table>';
            } else {
                content += '<p>No successful sign-ins found for this country.</p>';
            }
            
            showModal('Sign-ins from ' + countryName, content);
        }
        
        function showAnomalyDetails(anomalyType) {
            if (!anomalies || anomalies.length === 0) {
                showModal('No Data', '<p>No anomaly data available.</p>');
                return;
            }
            
            const typeAnomalies = anomalies.filter(a => a.Type === anomalyType);
            
            let content = '<p>Details for ' + anomalyType + ' anomalies:</p>';
            
            if (typeAnomalies.length > 0) {
                content += '<table class="detail-table">';
                content += '<thead><tr><th>User</th><th>Details</th><th>Severity</th><th>Time</th></tr></thead>';
                content += '<tbody>';
                
                typeAnomalies.forEach(anomaly => {
                    content += '<tr>';
                    content += '<td>' + (anomaly.User || 'Unknown') + '</td>';
                    content += '<td style="max-width: 300px; word-wrap: break-word;">' + (anomaly.Details || 'No details') + '</td>';
                    content += '<td><span class="badge badge-' + (anomaly.Severity === 'High' ? 'danger' : anomaly.Severity === 'Medium' ? 'warning' : 'info') + '">' + (anomaly.Severity || 'Unknown') + '</span></td>';
                    
                    let timeField = 'Unknown';
                    if (anomaly.SignIn && anomaly.SignIn.SignInTime) {
                        timeField = anomaly.SignIn.SignInTime;
                    } else if (anomaly.FirstSignIn && anomaly.FirstSignIn.SignInTime) {
                        timeField = anomaly.FirstSignIn.SignInTime;
                    } else if (anomaly.SuccessfulSignIn && anomaly.SuccessfulSignIn.SignInTime) {
                        timeField = anomaly.SuccessfulSignIn.SignInTime;
                    }
                    content += '<td>' + timeField + '</td>';
                    content += '</tr>';
                });
                
                content += '</tbody></table>';
                
                // Add specific details for certain anomaly types
                if (anomalyType === 'Unusual Client App') {
                    const clientApps = [...new Set(typeAnomalies.map(a => 
                        a.SignIn ? a.SignIn.ClientAppUsed : 'Unknown'
                    ).filter(app => app && app !== 'Unknown'))];
                    if (clientApps.length > 0) {
                        content += '<h4 style="margin-top: 20px;">Unusual Client Applications:</h4>';
                        content += '<ul>';
                        clientApps.forEach(app => {
                            content += '<li>' + app + '</li>';
                        });
                        content += '</ul>';
                    }
                }
                
                if (anomalyType === 'Brute Force Success') {
                    content += '<h4 style="margin-top: 20px;">Brute Force Details:</h4>';
                    typeAnomalies.forEach(anomaly => {
                        if (anomaly.FailedAttempts) {
                            content += '<p><strong>' + (anomaly.User || 'Unknown') + ':</strong> ' + 
                                     anomaly.FailedAttempts + ' failed attempts from IPs: ' + 
                                     (anomaly.UniqueFailureIPs || 'Unknown') + '</p>';
                        }
                    });
                }
                
                if (anomalyType === 'Impossible Travel') {
                    content += '<h4 style="margin-top: 20px;">Travel Details:</h4>';
                    typeAnomalies.forEach(anomaly => {
                        if (anomaly.TimeDifferenceHours) {
                            const firstCountry = (anomaly.FirstSignIn && anomaly.FirstSignIn.Country) ? anomaly.FirstSignIn.Country : 'Unknown';
                            const secondCountry = (anomaly.SecondSignIn && anomaly.SecondSignIn.Country) ? anomaly.SecondSignIn.Country : 'Unknown';
                            content += '<p><strong>' + (anomaly.User || 'Unknown') + ':</strong> ' + 
                                     firstCountry + ' → ' + secondCountry + ' in ' + 
                                     anomaly.TimeDifferenceHours + ' hours</p>';
                        }
                    });
                }
                
            } else {
                content += '<p>No anomalies found for this type.</p>';
            }
            
            showModal(anomalyType + ' (' + typeAnomalies.length + ')', content);
        }
        
        function filterTimeline(filterType) {
            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            document.getElementById('filter-' + filterType).classList.add('active');
            
            // Show/hide rows based on filter
            const rows = document.querySelectorAll('.timeline-row');
            rows.forEach(row => {
                if (filterType === 'all') {
                    row.classList.remove('hidden');
                } else {
                    if (row.classList.contains('filter-' + filterType)) {
                        row.classList.remove('hidden');
                    } else {
                        row.classList.add('hidden');
                    }
                }
            });
        }
        
        function showSignInDetails(correlationId) {
            if (!signInLogs || signInLogs.length === 0) {
                showModal('No Data', '<p>No sign-in data available.</p>');
                return;
            }
            
            const signIn = signInLogs.find(log => log.CorrelationId === correlationId);
            if (!signIn) {
                showModal('Sign-In Not Found', '<p>Could not find sign-in details for this event.</p>');
                return;
            }
            
            let content = '<div style="margin-bottom: 20px;">';
            content += '<div class="grid-2">';
            
            // Left column - Basic Info
            content += '<div>';
            content += '<h4>Basic Information</h4>';
            content += '<table class="detail-table">';
            content += '<tr><td><strong>User:</strong></td><td>' + (signIn.UserPrincipalName || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Display Name:</strong></td><td>' + (signIn.DisplayName || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Department:</strong></td><td>' + (signIn.Department || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Job Title:</strong></td><td>' + (signIn.JobTitle || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Sign-in Time:</strong></td><td>' + (signIn.SignInTime || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Status:</strong></td><td><span class="badge badge-' + (signIn.Status === 'Success' ? 'success' : 'danger') + '">' + (signIn.Status || 'Unknown') + '</span></td></tr>';
            content += '</table>';
            content += '</div>';
            
            // Right column - Location & Network
            content += '<div>';
            content += '<h4>Location & Network</h4>';
            content += '<table class="detail-table">';
            content += '<tr><td><strong>IP Address:</strong></td><td>' + (signIn.IPAddress || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Location:</strong></td><td>' + (signIn.Location || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Country:</strong></td><td>' + (signIn.Country || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>State:</strong></td><td>' + (signIn.State || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>City:</strong></td><td>' + (signIn.City || 'Unknown') + '</td></tr>';
            content += '</table>';
            content += '</div>';
            
            content += '</div>';
            
            // Application & Device Info
            content += '<h4 style="margin-top: 20px;">Application & Device</h4>';
            content += '<table class="detail-table">';
            content += '<tr><td><strong>Application:</strong></td><td>' + (signIn.AppDisplayName || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>App ID:</strong></td><td style="font-family: monospace; font-size: 0.85em;">' + (signIn.AppId || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Client App:</strong></td><td>' + (signIn.ClientAppUsed || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Device Name:</strong></td><td>' + (signIn.DeviceName || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Device OS:</strong></td><td>' + (signIn.DeviceOS || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Browser:</strong></td><td>' + (signIn.DeviceBrowser || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Device Trust:</strong></td><td>' + (signIn.DeviceTrustType || 'Unknown') + '</td></tr>';
            content += '</table>';
            
            // Security & Risk Info
            if (signIn.RiskState !== 'none' && signIn.RiskState !== '' && signIn.RiskState !== null) {
                content += '<h4 style="margin-top: 20px;">Security & Risk</h4>';
                content += '<table class="detail-table">';
                content += '<tr><td><strong>Risk State:</strong></td><td>' + (signIn.RiskState || 'Unknown') + '</td></tr>';
                content += '<tr><td><strong>Risk Level:</strong></td><td>' + (signIn.RiskLevelAggregated || 'Unknown') + '</td></tr>';
                content += '<tr><td><strong>Risk Detail:</strong></td><td>' + (signIn.RiskDetail || 'Unknown') + '</td></tr>';
                content += '<tr><td><strong>Risk Events:</strong></td><td>' + (signIn.RiskEventTypes || 'None') + '</td></tr>';
                content += '</table>';
            }
            
            // Authentication Details
            content += '<h4 style="margin-top: 20px;">Authentication Details</h4>';
            content += '<table class="detail-table">';
            content += '<tr><td><strong>Auth Methods:</strong></td><td>' + (signIn.AuthenticationMethods || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Conditional Access:</strong></td><td>' + (signIn.ConditionalAccessStatus || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>CA Policies:</strong></td><td>' + (signIn.AppliedConditionalAccessPolicies || 'None') + '</td></tr>';
            content += '<tr><td><strong>Interactive:</strong></td><td>' + (signIn.IsInteractive ? 'Yes' : 'No') + '</td></tr>';
            content += '</table>';
            
            // Technical Details
            content += '<h4 style="margin-top: 20px;">Technical Details</h4>';
            content += '<table class="detail-table">';
            content += '<tr><td><strong>Correlation ID:</strong></td><td style="font-family: monospace; font-size: 0.85em;">' + (signIn.CorrelationId || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>User ID:</strong></td><td style="font-family: monospace; font-size: 0.85em;">' + (signIn.UserId || 'Unknown') + '</td></tr>';
            content += '<tr><td><strong>Error Code:</strong></td><td>' + (signIn.ErrorCode || 'None') + '</td></tr>';
            if (signIn.FailureReason && signIn.FailureReason !== 'Other.') {
                content += '<tr><td><strong>Failure Reason:</strong></td><td>' + signIn.FailureReason + '</td></tr>';
            }
            content += '</table>';
            
            content += '</div>';
            
            const title = 'Sign-In Details - ' + (signIn.UserPrincipalName || 'Unknown User');
            showModal(title, content);
        }
    </script>
</body>
</html>
"@

    # Write HTML to file
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Log "HTML report generated: $OutputPath" -Level "INFO"
    
    return $OutputPath
}

function Process-Tenant {
    param(
        [Parameter(Mandatory=$true)]
        [hashtable]$Credentials,
        
        [Parameter(Mandatory=$false)]
        [string[]]$TargetUsers
    )
    
    $clientName = $Credentials.ClientName
    Write-Log "Processing tenant: $clientName ($($Credentials.TenantId))" -Level "INFO"
    
    try {
        $accessToken = Get-MsGraphToken -TenantId $Credentials.TenantId -ClientId $Credentials.ClientId -ClientSecret $Credentials.ClientSecret
        
        $filterMsg = if ($TargetUsers) { "for $($TargetUsers.Count) specific users" } else { "for all users" }
        Write-Log "Retrieving sign-in logs $filterMsg in the past $DaysToReport days..." -Level "INFO"
        
        $signInLogs = Get-AllSignInLogs -AccessToken $accessToken -DaysToReport $DaysToReport -TargetUsers $TargetUsers -IncludeNonInteractive:$IncludeNonInteractive -IncludeServicePrincipal:$IncludeServicePrincipal -IncludeManagedIdentity:$IncludeManagedIdentity
        
        if ($signInLogs.Count -gt 0) {
            $userDetailsMap = Get-UserDetailsForSignIns -AccessToken $accessToken -SignInLogs $signInLogs
            
            $formattedLogs = Format-SignInLogs -SignInLogs $signInLogs -UserDetailsMap $userDetailsMap
            
            foreach ($log in $formattedLogs) {
                $log | Add-Member -NotePropertyName "TenantName" -NotePropertyValue $clientName -Force
                $log | Add-Member -NotePropertyName "TenantId" -NotePropertyValue $Credentials.TenantId -Force
            }
            
            $tenantPrefix = "SignInLogs-$($clientName.Replace(' ', '').Replace('/', '-'))-$timestamp"
            $exportedFiles = Export-SignInData -Data $formattedLogs -BasePath $outputFolder -FilePrefix $tenantPrefix -Format $OutputFormat
            
            Write-Log "Retrieved $($signInLogs.Count) sign-in logs for tenant $clientName" -Level "INFO"
            
            if (-not $SkipAnomalyDetection) {
                Write-Log "Analyzing sign-in logs for security anomalies..." -Level "INFO"
                $anomalies = Find-SignInAnomalies -SignInLogs $formattedLogs
                
                if ($anomalies.Count -gt 0) {
                    $anomaliesPrefix = "SignInAnomalies-$($clientName.Replace(' ', '').Replace('/', '-'))-$timestamp"
                    Export-SignInData -Data $anomalies -BasePath $outputFolder -FilePrefix $anomaliesPrefix -Format $OutputFormat
                    
                    $highSeverity = ($anomalies | Where-Object { $_.Severity -eq "High" }).Count
                    $mediumSeverity = ($anomalies | Where-Object { $_.Severity -eq "Medium" }).Count
                    $lowSeverity = ($anomalies | Where-Object { $_.Severity -eq "Low" }).Count
                    
                    Write-Log "Found $($anomalies.Count) potential security anomalies for tenant $clientName" -Level "WARN"
                    Write-Log "Anomalies by severity - High: $highSeverity, Medium: $mediumSeverity, Low: $lowSeverity" -Level "INFO"
                }
                else {
                    Write-Log "No security anomalies detected for tenant $clientName" -Level "INFO"
                    $anomalies = @()  # Ensure it's an empty array
                }
            }
            else {
                $anomalies = @()  # Ensure it's an empty array when skipped
            }
            
            return @{
                TenantName = $clientName
                TenantId = $Credentials.TenantId
                SignInLogs = $formattedLogs
                Anomalies = if ($anomalies) { $anomalies } else { @() }
                ExportedFiles = $exportedFiles
            }
        }
        else {
            Write-Log "No sign-in logs found for tenant $clientName in the specified time period" -Level "WARN"
            return $null
        }
    }
    catch {
        Write-Log "Error processing tenant $clientName`: $_" -Level "ERROR"
        throw $_
    }
}

function New-SummaryReport {
    param(
        [Parameter(Mandatory=$true)]
        [array]$TenantResults
    )
    
    Write-Log "Generating summary report..." -Level "INFO"
    
    $validResults = $TenantResults | Where-Object { $_ -ne $null }
    
    $summary = @{
        ExecutionTime = Get-Date
        TotalTenants = $validResults.Count
        TotalSignIns = ($validResults | ForEach-Object { if ($_.SignInLogs) { $_.SignInLogs.Count } else { 0 } } | Measure-Object -Sum).Sum
        TotalAnomalies = ($validResults | ForEach-Object { if ($_.Anomalies) { $_.Anomalies.Count } else { 0 } } | Measure-Object -Sum).Sum
        TenantSummary = @()
    }
    
    foreach ($result in $validResults) {
        if ($result) {
            $signInLogs = if ($result.SignInLogs) { $result.SignInLogs } else { @() }
            $anomalies = if ($result.Anomalies) { $result.Anomalies } else { @() }
            
            $tenantSummary = [PSCustomObject]@{
                TenantName = $result.TenantName
                TenantId = $result.TenantId
                SignInCount = $signInLogs.Count
                SuccessfulSignIns = ($signInLogs | Where-Object { $_.Status -eq "Success" }).Count
                FailedSignIns = ($signInLogs | Where-Object { $_.Status -ne "Success" }).Count
                RiskySignIns = ($signInLogs | Where-Object { $_.RiskState -ne "none" -and $_.RiskState -ne "" -and $_.RiskState -ne $null }).Count
                UniqueUsers = ($signInLogs | Select-Object -ExpandProperty UserPrincipalName -Unique).Count
                UniqueCountries = ($signInLogs | Select-Object -ExpandProperty Country -Unique | Where-Object { $_ -ne "Unknown" }).Count
                AnomaliesFound = $anomalies.Count
                HighSeverityAnomalies = ($anomalies | Where-Object { $_.Severity -eq "High" }).Count
                MediumSeverityAnomalies = ($anomalies | Where-Object { $_.Severity -eq "Medium" }).Count
                LowSeverityAnomalies = ($anomalies | Where-Object { $_.Severity -eq "Low" }).Count
            }
            $summary.TenantSummary += $tenantSummary
        }
    }
    
    $summaryPath = Join-Path -Path $outputFolder -ChildPath "ExecutionSummary-$timestamp.json"
    $summary | ConvertTo-Json -Depth 5 | Out-File -FilePath $summaryPath -Encoding UTF8
    
    $tenantSummaryPath = Join-Path -Path $outputFolder -ChildPath "TenantSummary-$timestamp.csv"
    $summary.TenantSummary | Export-Csv -Path $tenantSummaryPath -NoTypeInformation -Encoding UTF8
    
    Write-Log "Summary reports exported to: $summaryPath and $tenantSummaryPath" -Level "INFO"
    
    return $summary
}

# Main
Write-Log "Starting Enhanced Sign-In Log Extractor" -Level "INFO"
Write-Log "Parameters: DaysToReport=$DaysToReport, OutputFormat=$OutputFormat, SkipAnomalyDetection=$SkipAnomalyDetection" -Level "INFO"

$targetUsers = @()
if ($UserPrincipalNames) {
    $targetUsers = $UserPrincipalNames
    Write-Log "Processing specific users: $($UserPrincipalNames -join ', ')" -Level "INFO"
}
elseif ($UserListPath -and (Test-Path -Path $UserListPath)) {
    $targetUsers = Get-Content -Path $UserListPath | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    Write-Log "Loaded $($targetUsers.Count) users from file: $UserListPath" -Level "INFO"
}

$allResults = @()

try {
    if ($ClientName) {
        # Single tenant
        Write-Log "Single tenant mode using client name: $ClientName" -Level "INFO"
        
        $credentials = Get-ClientCredentials -ClientName $ClientName -CsvPath $CsvPath
        $result = Process-Tenant -Credentials $credentials -TargetUsers $targetUsers
        if ($result) { $allResults += $result }
        
    }
    elseif ($CsvPath) {
        # Multiple tenants
        Write-Log "Multi-tenant mode using CSV: $CsvPath" -Level "INFO"
        
        if (-not (Test-Path -Path $CsvPath)) {
            throw "CSV file not found: $CsvPath"
        }
        
        $tenants = Import-Csv -Path $CsvPath
        $totalTenants = $tenants.Count
        $currentTenant = 0
        
        foreach ($tenant in $tenants) {
            $currentTenant++
            
            if ([string]::IsNullOrWhiteSpace($tenant.'Tenant ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Client ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Key Value')) {
                Write-Log "Skipping tenant '$($tenant.Client)' - Missing required credential information" -Level "WARN"
                continue
            }
            
            $credentials = @{
                TenantId = $tenant.'Tenant ID'.Trim()
                ClientId = $tenant.'Client ID'.Trim()
                ClientSecret = $tenant.'Key Value'.Trim()
                ClientName = $tenant.Client.Trim()
            }
            
            Write-Progress -Activity "Processing Tenants" -Status "Tenant $currentTenant of $totalTenants`: $($credentials.ClientName)" -PercentComplete (($currentTenant / $totalTenants) * 100)
            
            try {
                $result = Process-Tenant -Credentials $credentials -TargetUsers $targetUsers
                if ($result) { $allResults += $result }
            }
            catch {
                Write-Log "Failed to process tenant $($credentials.ClientName): $_" -Level "ERROR"
            }
        }
        
        Write-Progress -Activity "Processing Tenants" -Completed
        
    }
    else {
        Write-Log "Single tenant mode using direct parameters" -Level "INFO"
        
        if ([string]::IsNullOrWhiteSpace($TenantId) -or 
            [string]::IsNullOrWhiteSpace($ClientId) -or 
            [string]::IsNullOrWhiteSpace($ClientSecret)) {
            throw "When not using a CSV file or client name, you must provide TenantId, ClientId, and ClientSecret parameters."
        }
        
        $credentials = @{
            TenantId = $TenantId
            ClientId = $ClientId
            ClientSecret = $ClientSecret
            ClientName = "Direct-$TenantId"
        }
        
        $result = Process-Tenant -Credentials $credentials -TargetUsers $targetUsers
        if ($result) { $allResults += $result }
    }
    
    # Generate reports
    if ($allResults.Count -gt 1) {
        Write-Log "Generating consolidated reports for $($allResults.Count) tenants..." -Level "INFO"
        
        $allSignInLogs = @()
        $allAnomalies = @()
        
        foreach ($result in $allResults) {
            if ($result -and $result.SignInLogs) {
                $allSignInLogs += $result.SignInLogs
            }
            if ($result -and $result.Anomalies) {
                $allAnomalies += $result.Anomalies
            }
        }
        
        if ($allSignInLogs.Count -gt 0) {
            $consolidatedPrefix = "AllTenants-SignInLogs-$timestamp"
            Export-SignInData -Data $allSignInLogs -BasePath $outputFolder -FilePrefix $consolidatedPrefix -Format $OutputFormat
            Write-Log "Consolidated sign-in logs exported: $($allSignInLogs.Count) total records" -Level "INFO"
        }
        
        if ($allAnomalies.Count -gt 0) {
            $consolidatedAnomaliesPrefix = "AllTenants-Anomalies-$timestamp"
            Export-SignInData -Data $allAnomalies -BasePath $outputFolder -FilePrefix $consolidatedAnomaliesPrefix -Format $OutputFormat
            Write-Log "Consolidated anomalies exported: $($allAnomalies.Count) total anomalies" -Level "INFO"
        }
    }
    
    # Generate summary report
    if ($allResults.Count -gt 0) {
        Write-Log "Processing summary for $($allResults.Count) tenant result(s)..." -Level "INFO"
        $summary = New-SummaryReport -TenantResults $allResults
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "SignInAnalysisReport-$timestamp.html"
        New-HTMLReport -TenantResults $allResults -OutputPath $htmlReportPath -Summary $summary
        
        Write-Log "=== EXECUTION SUMMARY ===" -Level "INFO"
        Write-Log "Total tenants processed: $($summary.TotalTenants)" -Level "INFO"
        Write-Log "Total sign-in logs collected: $($summary.TotalSignIns)" -Level "INFO"
        Write-Log "Total anomalies detected: $($summary.TotalAnomalies)" -Level "INFO"
        Write-Log "Reports saved to: $outputFolder" -Level "INFO"
        Write-Log "HTML Report: $htmlReportPath" -Level "INFO"
    }
    else {
        Write-Log "No data was collected from any tenant" -Level "WARN"
    }
}
catch {
    Write-Log "Script execution failed: $_" -Level "ERROR"
    exit 1
}
finally {
    Write-Log "Script execution completed at $(Get-Date)" -Level "INFO"
}

# Display final summary
Write-Host "`n=== Enhanced Sign-In Log Extractor Completed ===" -ForegroundColor Cyan
Write-Host "Output Directory: $outputFolder" -ForegroundColor Green
Write-Host "Log File: $logFile" -ForegroundColor Green

if ($allResults.Count -gt 0) {
    $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "SignInAnalysisReport-$timestamp.html"
    Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Yellow
    Write-Host "`nProcessed Tenants:" -ForegroundColor Yellow
    foreach ($result in $allResults) {
        if ($result) {
            $signInCount = if ($result.SignInLogs) { $result.SignInLogs.Count } else { 0 }
            $anomalyCount = if ($result.Anomalies) { $result.Anomalies.Count } else { 0 }
            Write-Host "  - $($result.TenantName): $signInCount sign-ins, $anomalyCount anomalies" -ForegroundColor Cyan
        }
    }
    
    if ($PSVersionTable.Platform -ne 'Unix') {
        try {
            Write-Host "`nOpening HTML report in default browser..." -ForegroundColor Green
            Start-Process $htmlReportPath
        }
        catch {
            Write-Host "Could not automatically open HTML report. Please open manually: $htmlReportPath" -ForegroundColor Yellow
        }
    }
}

Write-Host "`nFor detailed analysis, review the HTML report and exported files in the output directory." -ForegroundColor Green
