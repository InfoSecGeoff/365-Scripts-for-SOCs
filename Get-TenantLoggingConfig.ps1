<#
.SYNOPSIS
    Extracts and analyzes Office 365 tenant logging configurations from single or multiple tenants with comprehensive audit and security logging analysis.

.DESCRIPTION
    This script connects to Microsoft Graph API and Exchange Online to retrieve comprehensive logging configuration information
    from Office 365 tenants. It provides detailed analysis of audit logging settings, security configurations, compliance
    settings, and generates both structured data exports (JSON, CSV) and an interactive HTML dashboard for security operations teams.

    The script supports three operational modes:
    1. Single tenant with direct credential parameters
    2. Single tenant using CSV lookup by client name  
    3. Multi-tenant processing from CSV file

    Key logging analysis features include:
    - Mailbox audit logging configuration
    - Organization-wide audit settings
    - Security & Compliance Center configuration
    - Azure AD audit log settings
    - Conditional Access logging
    - Sign-in log retention policies
    - Unified Audit Log status
    
    The script provides recommendations for improving logging coverage and identifies potential security gaps.

.PARAMETER TenantId
    The Azure AD/Entra ID tenant ID in GUID format. Required when using direct parameter authentication.

.PARAMETER ClientId
    The client/application ID of the registered Azure AD application used for authentication.

.PARAMETER ClientSecret
    The client secret for the registered Azure AD application used for authentication.

.PARAMETER CsvPath
    Optional. Path to CSV file containing tenant credentials for multi-tenant scenarios. 

.PARAMETER ClientName
    Optional. The name of the specific client/tenant to process from the CSV file.

.PARAMETER IncludeMailboxAudit
    Optional switch. If specified, includes detailed mailbox audit configuration analysis.

.PARAMETER IncludeComplianceCenter
    Optional switch. If specified, includes Security & Compliance Center logging configuration.

.PARAMETER IncludeAzureADAudit
    Optional switch. If specified, includes Azure AD audit log configuration and retention settings.

.PARAMETER SkipAnomalyDetection
    Optional switch. If specified, disables logging configuration anomaly detection.

.PARAMETER OutputFormat
    Optional. Format for data export. Valid values are "JSON", "CSV", or "Both". Default is "Both".

.PARAMETER LogLevel
    Specifies the level of logging: None, Minimal, Standard, Debug. Default: Standard

.EXAMPLE
    .\Get-TenantLoggingConfig.ps1 -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "87654321-4321-4321-4321-210987654321" -ClientSecret "your-client-secret"

.EXAMPLE
    .\Get-TenantLoggingConfig.ps1 -ClientName "Contoso Corp" -CsvPath ".\tenants.csv" -IncludeMailboxAudit -IncludeComplianceCenter

.EXAMPLE
    .\Get-TenantLoggingConfig.ps1 -CsvPath ".\all_tenants.csv" -IncludeMailboxAudit -IncludeAzureADAudit -IncludeComplianceCenter

.NOTES
    Required Microsoft Graph API Permissions:
    - AuditLog.Read.All (to read audit log configuration)
    - Directory.Read.All (to read directory and tenant configuration)
    - Policy.Read.All (to read conditional access and security policies)
    - SecurityEvents.Read.All (to read security configuration)
    
    Required Exchange Online Permissions:
    - Exchange Administrator or Global Administrator role
    
    Version:        1.0
    Author:         Geoff Tankersley
    Last Modified:  2025-08-12
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
    [switch]$IncludeMailboxAudit,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeComplianceCenter,
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeAzureADAudit,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipAnomalyDetection,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("JSON", "CSV", "Both")]
    [string]$OutputFormat = "Both",
    
    [Parameter(Mandatory=$false)]
    [ValidateSet('None', 'Minimal', 'Standard', 'Debug')]
    [string]$LogLevel = 'Standard'
)

#Requires -Version 5.1

$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "TenantLoggingConfig-$timestamp"
$logFile = Join-Path -Path $outputFolder -ChildPath "logging-config-$timestamp.txt"

try {
    New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null
    Write-Host "Created output directory: $outputFolder" -ForegroundColor Green
}
catch {
    Write-Error "Failed to create output directory: $_"
    exit 1
}


enum LogLevel {
    None = 0
    Minimal = 1
    Standard = 2
    Debug = 3
}

$script:LogLevel = [LogLevel]::$LogLevel

function Set-LogLevel {
    param([LogLevel]$Level)
    $script:LogLevel = $Level
}

function Write-LogFile {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("None", "Minimal", "Standard", "Debug")]
        [string]$Level = "Standard",
        
        [Parameter(Mandatory=$false)]
        [string]$Color = "White"
    )
    
    $logLevelEnum = [LogLevel]::$Level
    if ($script:LogLevel -ge $logLevelEnum) {
        $logMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [$Level] $Message"
        Add-Content -Path $logFile -Value $logMessage -Force
        
        if ($Color -ne "White") {
            Write-Host $Message -ForegroundColor $Color
        } else {
            Write-Host $Message
        }
    }
}

function Get-ClientCredentials {
    param(
        [Parameter(Mandatory=$true)]
        [string]$ClientName,
        
        [Parameter(Mandatory=$true)]
        [string]$CsvPath
    )
    
    Write-LogFile "Looking up credentials for client: $ClientName" -Level "Standard"
    
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
            Write-LogFile "Multiple entries found for client '$ClientName', using first match" -Level "Minimal" -Color "Yellow"
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
            Write-LogFile "Attempting to acquire access token (attempt $($retryCount + 1)/$MaxRetries)" -Level "Standard"
            $response = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
            Write-LogFile "Successfully acquired access token" -Level "Standard"
            return $response.access_token
        }
        catch {
            $retryCount++
            if ($retryCount -ge $MaxRetries) {
                Write-LogFile "Failed to obtain access token after $MaxRetries attempts: $_" -Level "Minimal" -Color "Red"
                throw $_
            }
            Write-LogFile "Token acquisition failed, retrying in 5 seconds... (attempt $retryCount/$MaxRetries)" -Level "Minimal" -Color "Yellow"
            Start-Sleep -Seconds 5
        }
    }
}

function Get-AzureADAuditConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        Write-LogFile "Retrieving Azure AD audit log configuration..." -Level "Standard"
        
        # Directory audit settings
        $auditConfigUri = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$top=1"
        $auditResponse = Invoke-RestMethod -Uri $auditConfigUri -Method Get -Headers $headers
        
        # Sign-in log settings
        $signInConfigUri = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$top=1"
        $signInResponse = Invoke-RestMethod -Uri $signInConfigUri -Method Get -Headers $headers
        
        # Tenant information
        $tenantUri = "https://graph.microsoft.com/v1.0/organization"
        $tenantResponse = Invoke-RestMethod -Uri $tenantUri -Method Get -Headers $headers
        $tenant = $tenantResponse.value[0]
        
        return @{
            DirectoryAuditEnabled = ($auditResponse.value.Count -gt 0)
            SignInAuditEnabled = ($signInResponse.value.Count -gt 0)
            TenantDisplayName = $tenant.displayName
            TenantId = $tenant.id
            TenantDomain = ($tenant.verifiedDomains | Where-Object { $_.isDefault }).name
            SecurityDefaults = $tenant.securityComplianceNotificationMails
            DirectorySync = $tenant.onPremisesSyncEnabled
        }
    }
    catch {
        Write-LogFile "Error retrieving Azure AD audit configuration: $_" -Level "Minimal" -Color "Red"
        return @{
            DirectoryAuditEnabled = $false
            SignInAuditEnabled = $false
            TenantDisplayName = "Unknown"
            TenantId = "Unknown"
            TenantDomain = "Unknown"
            SecurityDefaults = $null
            DirectorySync = $null
        }
    }
}

function Get-ConditionalAccessConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        Write-LogFile "Retrieving Conditional Access configuration..." -Level "Standard"
        
        $caPoliciesUri = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
        $caResponse = Invoke-RestMethod -Uri $caPoliciesUri -Method Get -Headers $headers
        
        $policies = $caResponse.value
        $enabledPolicies = $policies | Where-Object { $_.state -eq "enabled" }
        $reportOnlyPolicies = $policies | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" }
        $disabledPolicies = $policies | Where-Object { $_.state -eq "disabled" }
        
        return @{
            TotalPolicies = $policies.Count
            EnabledPolicies = $enabledPolicies.Count
            ReportOnlyPolicies = $reportOnlyPolicies.Count
            DisabledPolicies = $disabledPolicies.Count
            PoliciesWithLogging = ($policies | Where-Object { $_.sessionControls }).Count
            BlockLegacyAuth = ($enabledPolicies | Where-Object { 
                $_.conditions.clientAppTypes -contains "exchangeActiveSync" -or 
                $_.conditions.clientAppTypes -contains "other" 
            }).Count
            RequireMFA = ($enabledPolicies | Where-Object { 
                $_.grantControls.builtInControls -contains "mfa" 
            }).Count
            Policies = $policies
        }
    }
    catch {
        $errorDetails = $_.Exception.Message
        if ($_.Exception.Message -like "*403*" -or $_.Exception.Message -like "*Forbidden*") {
            Write-LogFile "Insufficient permissions for Conditional Access configuration (403 Forbidden). This requires Policy.Read.All permission." -Level "Minimal" -Color "Yellow"
        } else {
            Write-LogFile "Error retrieving Conditional Access configuration: $errorDetails" -Level "Minimal" -Color "Red"
        }
        
        return @{
            TotalPolicies = 0
            EnabledPolicies = 0
            ReportOnlyPolicies = 0
            DisabledPolicies = 0
            PoliciesWithLogging = 0
            BlockLegacyAuth = 0
            RequireMFA = 0
            Policies = @()
            Error = "Access Denied - Insufficient Permissions"
        }
    }
}

function Get-ComplianceCenterConfig {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        Write-LogFile "Retrieving Security & Compliance Center configuration..." -Level "Standard"
        
        # Compliance policies
        $complianceUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"
        $complianceResponse = Invoke-RestMethod -Uri $complianceUri -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        # DLP policies  
        $dlpUri = "https://graph.microsoft.com/beta/informationProtection/policy/labels"
        $dlpResponse = Invoke-RestMethod -Uri $dlpUri -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        # Retention policies
        $retentionUri = "https://graph.microsoft.com/beta/security/labels/retentionLabels"
        $retentionResponse = Invoke-RestMethod -Uri $retentionUri -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        return @{
            CompliancePolicies = if ($complianceResponse.value) { $complianceResponse.value.Count } else { 0 }
            DLPPolicies = if ($dlpResponse.value) { $dlpResponse.value.Count } else { 0 }
            RetentionPolicies = if ($retentionResponse.value) { $retentionResponse.value.Count } else { 0 }
            HasComplianceConfig = ($complianceResponse.value.Count -gt 0) -or ($dlpResponse.value.Count -gt 0) -or ($retentionResponse.value.Count -gt 0)
        }
    }
    catch {
        Write-LogFile "Error retrieving Compliance Center configuration: $_" -Level "Minimal" -Color "Red"
        return @{
            CompliancePolicies = 0
            DLPPolicies = 0
            RetentionPolicies = 0
            HasComplianceConfig = $false
        }
    }
}

function Get-ExchangeOnlineAuditConfig {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Credentials
    )
    
    try {
        Write-LogFile "Connecting to Exchange Online for comprehensive audit configuration..." -Level "Standard"
        
        if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
            Write-LogFile "ExchangeOnlineManagement module not found. Installing..." -Level "Standard" -Color "Yellow"
            try {
                Install-Module -Name ExchangeOnlineManagement -Force -AllowClobber -Scope CurrentUser
                Write-LogFile "ExchangeOnlineManagement module installed successfully" -Level "Standard" -Color "Green"
            }
            catch {
                Write-LogFile "Failed to install ExchangeOnlineManagement module: $_" -Level "Minimal" -Color "Red"
                return @{
                    Error = "ExchangeOnlineManagement module not available and installation failed"
                }
            }
        }
        
        Import-Module ExchangeOnlineManagement -Force
        
    try {
    # Get Exchange Online specific access token
    $tokenBody = @{
        client_id     = $Credentials.ClientId
        client_secret = $Credentials.ClientSecret
        scope         = "https://outlook.office365.com/.default"
        grant_type    = "client_credentials"
    }
    
    $tokenUrl = "https://login.microsoftonline.com/$($Credentials.TenantId)/oauth2/v2.0/token"
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ContentType "application/x-www-form-urlencoded"
    $accessToken = $tokenResponse.access_token
    
    # Connect with the Exchange-specific access token
    $Organization = "$($Credentials.TenantId).onmicrosoft.com"
    Connect-ExchangeOnline -AccessToken $accessToken -Organization $Organization -ShowBanner:$false -WarningAction SilentlyContinue
    Write-LogFile "Successfully connected to Exchange Online using access token" -Level "Standard" -Color "Green"
}
catch {
    Write-LogFile "Exchange Online connection failed: $_" -Level "Minimal" -Color "Red"
    throw "Exchange Online authentication failed. Ensure Exchange Administrator role is assigned to the service principal."
}
        
        $auditResults = @{}
        
        # 1. Organization-wide audit configuration
        Write-LogFile "Retrieving organization audit configuration..." -Level "Debug"
        try {
            $orgConfig = Get-OrganizationConfig | Select-Object AuditDisabled, IsDehydrated
            $auditResults.OrganizationAuditDisabled = $orgConfig.AuditDisabled
            $auditResults.OrganizationAuditEnabled = -not $orgConfig.AuditDisabled
            $auditResults.TenantIsDehydrated = $orgConfig.IsDehydrated
        }
        catch {
            Write-LogFile "Error retrieving organization config: $_" -Level "Debug"
            $auditResults.OrganizationAuditDisabled = $null
            $auditResults.OrganizationAuditEnabled = $false
        }
        
        # 2. Admin audit log configuration
        Write-LogFile "Retrieving admin audit log configuration..." -Level "Debug"
        try {
            $adminAuditConfig = Get-AdminAuditLogConfig
            $auditResults.AdminAuditLogEnabled = $adminAuditConfig.AdminAuditLogEnabled
            $auditResults.AdminAuditLogAgeLimit = $adminAuditConfig.LogLevel
            $auditResults.AdminAuditLogCmdlets = $adminAuditConfig.AdminAuditLogCmdlets.Count
            $auditResults.AdminAuditLogParameters = $adminAuditConfig.AdminAuditLogParameters.Count
        }
        catch {
            Write-LogFile "Error retrieving admin audit config: $_" -Level "Debug"
            $auditResults.AdminAuditLogEnabled = $false
            $auditResults.AdminAuditLogAgeLimit = "Unknown"
            $auditResults.AdminAuditLogCmdlets = 0
            $auditResults.AdminAuditLogParameters = 0
        }
        # 3. Mailbox audit configuration (comprehensive)
        Write-LogFile "Retrieving mailbox audit configuration..." -Level "Debug"
        try {
            # Get all mailboxes with audit settings
            $mailboxes = Get-EXOMailbox -ResultSize 1000 -PropertySets Audit
            
            $auditEnabledCount = ($mailboxes | Where-Object { $_.AuditEnabled }).Count
            $auditDisabledCount = ($mailboxes | Where-Object { -not $_.AuditEnabled }).Count
            
            # Get default mailbox audit configuration
            $defaultAuditConfig = Get-MailboxAuditBypassAssociation | Where-Object { $_.AuditBypassEnabled }
            $bypassCount = $defaultAuditConfig.Count
            
            $auditResults.TotalMailboxes = $mailboxes.Count
            $auditResults.MailboxAuditEnabledCount = $auditEnabledCount
            $auditResults.MailboxAuditDisabledCount = $auditDisabledCount
            $auditResults.MailboxAuditBypassCount = $bypassCount
            $auditResults.MailboxAuditCoveragePercentage = if ($mailboxes.Count -gt 0) { 
                [math]::Round(($auditEnabledCount / $mailboxes.Count) * 100, 1) 
            } else { 0 }
            
            # Sample of mailbox audit settings
            $auditResults.SampleMailboxAuditSettings = $mailboxes | Select-Object -First 10 | ForEach-Object {
                @{
                    UserPrincipalName = $_.UserPrincipalName
                    DisplayName = $_.DisplayName
                    AuditEnabled = $_.AuditEnabled
                    RecipientTypeDetails = $_.RecipientTypeDetails
                    AuditLogAgeLimit = $_.AuditLogAgeLimit
                    AuditOwner = $_.AuditOwner -join ","
                    AuditDelegate = $_.AuditDelegate -join ","
                    AuditAdmin = $_.AuditAdmin -join ","
                }
            }
        }
        catch {
            Write-LogFile "Error retrieving mailbox audit config: $_" -Level "Debug"
            $auditResults.TotalMailboxes = 0
            $auditResults.MailboxAuditEnabledCount = 0
            $auditResults.MailboxAuditDisabledCount = 0
            $auditResults.MailboxAuditBypassCount = 0
            $auditResults.MailboxAuditCoveragePercentage = 0
            $auditResults.SampleMailboxAuditSettings = @()
        }
        
        # 4. Transport and message tracking configuration
        Write-LogFile "Retrieving transport and message tracking configuration..." -Level "Debug"
        try {
            $transportConfig = Get-TransportConfig | Select-Object MessageTrackingLogEnabled, MessageTrackingLogMaxAge, MessageTrackingLogMaxDirectorySize
            $auditResults.MessageTrackingEnabled = $transportConfig.MessageTrackingLogEnabled
            $auditResults.MessageTrackingMaxAge = $transportConfig.MessageTrackingLogMaxAge
            $auditResults.MessageTrackingMaxSize = $transportConfig.MessageTrackingLogMaxDirectorySize
        }
        catch {
            Write-LogFile "Error retrieving transport config: $_" -Level "Debug"
            $auditResults.MessageTrackingEnabled = $false
            $auditResults.MessageTrackingMaxAge = "Unknown"
            $auditResults.MessageTrackingMaxSize = "Unknown"
        }
        
        # 5. Role group and management role assignments
        Write-LogFile "Retrieving role group configuration..." -Level "Debug"
        try {
            $roleGroups = Get-RoleGroup | Select-Object Name, Members
            $auditResults.TotalRoleGroups = $roleGroups.Count
            $auditResults.PopulatedRoleGroups = ($roleGroups | Where-Object { $_.Members.Count -gt 0 }).Count
            
            # Get management role assignments for audit-related roles
            $managementRoles = Get-ManagementRoleAssignment | Where-Object { 
                $_.Role -like "*Audit*" -or $_.Role -like "*Compliance*" -or $_.Role -like "*eDiscovery*" 
            }
            $auditResults.AuditRelatedRoleAssignments = $managementRoles.Count
            
            # Sample role group data
            $auditResults.SampleRoleGroups = $roleGroups | Select-Object -First 10 | ForEach-Object {
                @{
                    Name = $_.Name
                    MemberCount = $_.Members.Count
                    Members = ($_.Members | Select-Object -First 5) -join ", "
                }
            }
        }
        catch {
            Write-LogFile "Error retrieving role configuration: $_" -Level "Debug"
            $auditResults.TotalRoleGroups = 0
            $auditResults.PopulatedRoleGroups = 0
            $auditResults.AuditRelatedRoleAssignments = 0
            $auditResults.SampleRoleGroups = @()
        }
        # 6. Litigation hold and retention policy information
    Write-LogFile "Retrieving litigation hold and retention configuration..." -Level "Debug"
    try {
        $litigationHoldMailboxes = Get-EXOMailbox -Properties LitigationHoldEnabled -ResultSize 1000 | Where-Object { $_.LitigationHoldEnabled -eq $true }
        $auditResults.LitigationHoldMailboxes = $litigationHoldMailboxes.Count
        
        # Retention policy count
        $retentionPolicies = Get-RetentionPolicy
        $auditResults.RetentionPoliciesCount = $retentionPolicies.Count
        
        # Retention tag count
        $retentionTags = Get-RetentionPolicyTag
        $auditResults.RetentionTagsCount = $retentionTags.Count
    }
    catch {
        Write-LogFile "Error retrieving retention config: $_" -Level "Debug"
        $auditResults.LitigationHoldMailboxes = 0
        $auditResults.RetentionPoliciesCount = 0
        $auditResults.RetentionTagsCount = 0
    }
        
        # 7. Data Loss Prevention (DLP) policy information
        Write-LogFile "Retrieving DLP policy configuration..." -Level "Debug"
        try {
            $dlpPolicies = Get-DlpPolicy
            $auditResults.DLPPoliciesCount = $dlpPolicies.Count
            $auditResults.DLPPoliciesEnabled = ($dlpPolicies | Where-Object { $_.State -eq "Enabled" }).Count
            
            # Sample DLP policies
            $auditResults.SampleDLPPolicies = $dlpPolicies | Select-Object -First 5 | ForEach-Object {
                @{
                    Name = $_.Name
                    State = $_.State
                    Mode = $_.Mode
                }
            }
        }
        catch {
            Write-LogFile "Error retrieving DLP config: $_" -Level "Debug"
            $auditResults.DLPPoliciesCount = 0
            $auditResults.DLPPoliciesEnabled = 0
            $auditResults.SampleDLPPolicies = @()
        }
        
        # 8. Anti-malware and anti-spam configuration
        Write-LogFile "Retrieving anti-malware and anti-spam configuration..." -Level "Debug"
        try {
            $malwarePolicies = Get-MalwareFilterPolicy
            $auditResults.MalwarePoliciesCount = $malwarePolicies.Count
            
            $spamPolicies = Get-HostedContentFilterPolicy
            $auditResults.SpamPoliciesCount = $spamPolicies.Count
        }
        catch {
            Write-LogFile "Error retrieving anti-malware/spam config: $_" -Level "Debug"
            $auditResults.MalwarePoliciesCount = 0
            $auditResults.SpamPoliciesCount = 0
        }
        
        # 9. Safe Attachments and Safe Links (if available)
        Write-LogFile "Retrieving Defender for Office 365 configuration..." -Level "Debug"
        try {
            $safeAttachmentPolicies = Get-SafeAttachmentPolicy -ErrorAction SilentlyContinue
            $auditResults.SafeAttachmentPoliciesCount = if ($safeAttachmentPolicies) { $safeAttachmentPolicies.Count } else { 0 }
            
            $safeLinkPolicies = Get-SafeLinksPolicy -ErrorAction SilentlyContinue
            $auditResults.SafeLinkPoliciesCount = if ($safeLinkPolicies) { $safeLinkPolicies.Count } else { 0 }
        }
        catch {
            Write-LogFile "Defender for Office 365 not available or no permissions: $_" -Level "Debug"
            $auditResults.SafeAttachmentPoliciesCount = 0
            $auditResults.SafeLinkPoliciesCount = 0
        }
        
        # 10. Calculate overall Exchange audit score
        $exchangeAuditScore = 0
        $maxExchangeScore = 100
        
        # Scoring criteria
        if ($auditResults.OrganizationAuditEnabled) { $exchangeAuditScore += 20 }
        if ($auditResults.AdminAuditLogEnabled) { $exchangeAuditScore += 15 }
        if ($auditResults.MailboxAuditCoveragePercentage -gt 90) { $exchangeAuditScore += 20 }
        elseif ($auditResults.MailboxAuditCoveragePercentage -gt 75) { $exchangeAuditScore += 15 }
        elseif ($auditResults.MailboxAuditCoveragePercentage -gt 50) { $exchangeAuditScore += 10 }
        if ($auditResults.MessageTrackingEnabled) { $exchangeAuditScore += 10 }
        if ($auditResults.DLPPoliciesEnabled -gt 0) { $exchangeAuditScore += 10 }
        if ($auditResults.RetentionPoliciesCount -gt 0) { $exchangeAuditScore += 10 }
        if ($auditResults.SafeAttachmentPoliciesCount -gt 0) { $exchangeAuditScore += 5 }
        if ($auditResults.SafeLinkPoliciesCount -gt 0) { $exchangeAuditScore += 5 }
        if ($auditResults.MailboxAuditBypassCount -eq 0) { $exchangeAuditScore += 5 }
        
        $auditResults.ExchangeAuditScore = $exchangeAuditScore
        $auditResults.ExchangeAuditScorePercentage = [math]::Round(($exchangeAuditScore / $maxExchangeScore) * 100, 1)
        
        Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Write-LogFile "Exchange Online audit configuration retrieval completed" -Level "Standard" -Color "Green"
        
        return $auditResults
    }
    catch {
        Write-LogFile "Error during Exchange Online audit configuration retrieval: $_" -Level "Minimal" -Color "Red"
        try {
            Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        }
        catch {
            
        }
        
        return @{
            Error = $_.Exception.Message
            OrganizationAuditEnabled = $false
            TotalMailboxes = 0
            MailboxAuditEnabledCount = 0
            MailboxAuditDisabledCount = 0
            MailboxAuditBypassCount = 0
            MailboxAuditCoveragePercentage = 0
            ExchangeAuditScore = 0
            ExchangeAuditScorePercentage = 0
        }
    }
}

function Find-LoggingAnomalies {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$LoggingConfig
    )
    
    Write-LogFile "Analyzing logging configuration for potential issues..." -Level "Standard"
    $anomalies = @()
    
    # 1. Organization-wide audit disabled
    if (-not $LoggingConfig.AzureAD.DirectoryAuditEnabled) {
        $anomalies += @{
            Type = "Directory Audit Disabled"
            Severity = "High"
            Details = "Azure AD directory audit logging is not enabled"
            Recommendation = "Enable directory audit logging in Azure AD to track administrative changes"
        }
    }
    
    # 2. Sign-in audit disabled
    if (-not $LoggingConfig.AzureAD.SignInAuditEnabled) {
        $anomalies += @{
            Type = "Sign-in Audit Disabled"
            Severity = "High"
            Details = "Azure AD sign-in audit logging is not enabled"
            Recommendation = "Enable sign-in audit logging to track user authentication events"
        }
    }
    
    # 3. Exchange Online audit issues
    if ($LoggingConfig.ExchangeOnlineAudit) {
        if (-not $LoggingConfig.ExchangeOnlineAudit.OrganizationAuditEnabled) {
            $anomalies += @{
                Type = "Exchange Organization Audit Disabled"
                Severity = "High"
                Details = "Exchange Online organization-wide auditing is disabled"
                Recommendation = "Enable organization-wide auditing with Set-OrganizationConfig -AuditDisabled `$false"
            }
        }
        
        if (-not $LoggingConfig.ExchangeOnlineAudit.AdminAuditLogEnabled) {
            $anomalies += @{
                Type = "Exchange Admin Audit Disabled"
                Severity = "High"
                Details = "Exchange Online administrator audit logging is disabled"
                Recommendation = "Enable admin audit logging to track administrative changes"
            }
        }
        
        if ($LoggingConfig.ExchangeOnlineAudit.MailboxAuditBypassCount -gt 0) {
            $anomalies += @{
                Type = "Mailbox Audit Bypass"
                Severity = "Medium"
                Details = "$($LoggingConfig.ExchangeOnlineAudit.MailboxAuditBypassCount) mailboxes have audit bypass enabled"
                Recommendation = "Review and minimize audit bypass exceptions for security accounts"
            }
        }
        
        $nonAuditedPercentage = if ($LoggingConfig.ExchangeOnlineAudit.TotalMailboxes -gt 0) {
            [math]::Round(($LoggingConfig.ExchangeOnlineAudit.MailboxAuditDisabledCount / $LoggingConfig.ExchangeOnlineAudit.TotalMailboxes) * 100, 1)
        } else { 0 }
        
        if ($nonAuditedPercentage -gt 10) {
            $anomalies += @{
                Type = "High Non-Audited Mailbox Percentage"
                Severity = "Medium"
                Details = "$nonAuditedPercentage% of mailboxes ($($LoggingConfig.ExchangeOnlineAudit.MailboxAuditDisabledCount)/$($LoggingConfig.ExchangeOnlineAudit.TotalMailboxes)) have audit disabled"
                Recommendation = "Review mailbox audit settings and enable auditing for critical mailboxes"
            }
        }
        
        if (-not $LoggingConfig.ExchangeOnlineAudit.MessageTrackingEnabled) {
            $anomalies += @{
                Type = "Message Tracking Disabled"
                Severity = "Medium"
                Details = "Exchange Online message tracking is disabled"
                Recommendation = "Enable message tracking for email flow monitoring and troubleshooting"
            }
        }
        
        if ($LoggingConfig.ExchangeOnlineAudit.DLPPoliciesCount -eq 0) {
            $anomalies += @{
                Type = "No DLP Policies"
                Severity = "Medium"
                Details = "No Data Loss Prevention policies are configured in Exchange Online"
                Recommendation = "Implement DLP policies to protect sensitive data and generate audit trails"
            }
        }
    }
    
    # 4. Conditional Access logging gaps
    if ($LoggingConfig.ConditionalAccess.TotalPolicies -eq 0) {
        $anomalies += @{
            Type = "No Conditional Access Policies"
            Severity = "Medium"
            Details = "No Conditional Access policies are configured"
            Recommendation = "Implement Conditional Access policies to improve security and generate audit logs"
        }
    }
    
    # 5. Missing compliance configuration
    if (-not $LoggingConfig.ComplianceCenter.HasComplianceConfig) {
        $anomalies += @{
            Type = "No Compliance Configuration"
            Severity = "Medium"
            Details = "No compliance policies, DLP policies, or retention policies are configured"
            Recommendation = "Implement compliance policies to generate audit trails for data protection"
        }
    }
    
    Write-LogFile "Logging anomaly detection completed. Found $($anomalies.Count) potential issues" -Level "Standard"
    return $anomalies
}

function Format-LoggingData {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$AzureADConfig,
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ConditionalAccessConfig = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ComplianceCenterConfig = @{},
        
        [Parameter(Mandatory=$false)]
        [hashtable]$ExchangeOnlineAuditConfig = @{}
    )
    
    Write-LogFile "Formatting logging configuration data..." -Level "Standard"
    
    # Calculate overall logging score (0-100)
    $scoringCriteria = @{
        AzureADDirectoryAudit = if ($AzureADConfig.DirectoryAuditEnabled) { 12 } else { 0 }
        AzureADSignInAudit = if ($AzureADConfig.SignInAuditEnabled) { 12 } else { 0 }
        ExchangeOrgAudit = if ($ExchangeOnlineAuditConfig.OrganizationAuditEnabled) { 15 } else { 0 }
        ExchangeAdminAudit = if ($ExchangeOnlineAuditConfig.AdminAuditLogEnabled) { 10 } else { 0 }
        MailboxAuditCoverage = if ($ExchangeOnlineAuditConfig.MailboxAuditCoveragePercentage -gt 90) { 12 } elseif ($ExchangeOnlineAuditConfig.MailboxAuditCoveragePercentage -gt 75) { 8 } elseif ($ExchangeOnlineAuditConfig.MailboxAuditCoveragePercentage -gt 50) { 4 } else { 0 }
        ConditionalAccessPolicies = if ($ConditionalAccessConfig.EnabledPolicies -gt 0) { 8 } else { 0 }
        ComplianceConfig = if ($ComplianceCenterConfig.HasComplianceConfig) { 6 } else { 0 }
        LegacyAuthBlocking = if ($ConditionalAccessConfig.BlockLegacyAuth -gt 0) { 6 } else { 0 }
        MFAEnforcement = if ($ConditionalAccessConfig.RequireMFA -gt 0) { 6 } else { 0 }
        MessageTracking = if ($ExchangeOnlineAuditConfig.MessageTrackingEnabled) { 4 } else { 0 }
        DLPPolicies = if ($ExchangeOnlineAuditConfig.DLPPoliciesEnabled -gt 0) { 4 } else { 0 }
    }
    
    $overallScore = ($scoringCriteria.Values | Measure-Object -Sum).Sum
    $securityPosture = switch ($overallScore) {
        { $_ -ge 90 } { "Excellent" }
        { $_ -ge 75 } { "Good" }
        { $_ -ge 60 } { "Fair" }
        { $_ -ge 40 } { "Poor" }
        default { "Critical" }
    }
    
    $formattedConfig = [PSCustomObject]@{
        TenantName = $AzureADConfig.TenantDisplayName
        TenantId = $AzureADConfig.TenantId
        TenantDomain = $AzureADConfig.TenantDomain
        DirectorySyncEnabled = $AzureADConfig.DirectorySync
        
        # Azure AD Audit Configuration
        DirectoryAuditEnabled = $AzureADConfig.DirectoryAuditEnabled
        SignInAuditEnabled = $AzureADConfig.SignInAuditEnabled
        
        # Exchange Online Audit Configuration (Comprehensive)
        ExchangeOrganizationAuditEnabled = if ($ExchangeOnlineAuditConfig.OrganizationAuditEnabled -ne $null) { $ExchangeOnlineAuditConfig.OrganizationAuditEnabled } else { $false }
        ExchangeAdminAuditEnabled = if ($ExchangeOnlineAuditConfig.AdminAuditLogEnabled) { $ExchangeOnlineAuditConfig.AdminAuditLogEnabled } else { $false }
        TotalMailboxes = if ($ExchangeOnlineAuditConfig.TotalMailboxes) { $ExchangeOnlineAuditConfig.TotalMailboxes } else { 0 }
        MailboxAuditEnabledCount = if ($ExchangeOnlineAuditConfig.MailboxAuditEnabledCount) { $ExchangeOnlineAuditConfig.MailboxAuditEnabledCount } else { 0 }
        MailboxAuditDisabledCount = if ($ExchangeOnlineAuditConfig.MailboxAuditDisabledCount) { $ExchangeOnlineAuditConfig.MailboxAuditDisabledCount } else { 0 }
        MailboxAuditBypassCount = if ($ExchangeOnlineAuditConfig.MailboxAuditBypassCount) { $ExchangeOnlineAuditConfig.MailboxAuditBypassCount } else { 0 }
        MessageTrackingEnabled = if ($ExchangeOnlineAuditConfig.MessageTrackingEnabled) { $ExchangeOnlineAuditConfig.MessageTrackingEnabled } else { $false }
        LitigationHoldMailboxes = if ($ExchangeOnlineAuditConfig.LitigationHoldMailboxes) { $ExchangeOnlineAuditConfig.LitigationHoldMailboxes } else { 0 }
        
        # Exchange Online Security Policies
        ExchangeDLPPoliciesCount = if ($ExchangeOnlineAuditConfig.DLPPoliciesCount) { $ExchangeOnlineAuditConfig.DLPPoliciesCount } else { 0 }
        ExchangeDLPPoliciesEnabled = if ($ExchangeOnlineAuditConfig.DLPPoliciesEnabled) { $ExchangeOnlineAuditConfig.DLPPoliciesEnabled } else { 0 }
        ExchangeRetentionPoliciesCount = if ($ExchangeOnlineAuditConfig.RetentionPoliciesCount) { $ExchangeOnlineAuditConfig.RetentionPoliciesCount } else { 0 }
        ExchangeRetentionTagsCount = if ($ExchangeOnlineAuditConfig.RetentionTagsCount) { $ExchangeOnlineAuditConfig.RetentionTagsCount } else { 0 }
        MalwarePoliciesCount = if ($ExchangeOnlineAuditConfig.MalwarePoliciesCount) { $ExchangeOnlineAuditConfig.MalwarePoliciesCount } else { 0 }
        SpamPoliciesCount = if ($ExchangeOnlineAuditConfig.SpamPoliciesCount) { $ExchangeOnlineAuditConfig.SpamPoliciesCount } else { 0 }
        SafeAttachmentPoliciesCount = if ($ExchangeOnlineAuditConfig.SafeAttachmentPoliciesCount) { $ExchangeOnlineAuditConfig.SafeAttachmentPoliciesCount } else { 0 }
        SafeLinkPoliciesCount = if ($ExchangeOnlineAuditConfig.SafeLinkPoliciesCount) { $ExchangeOnlineAuditConfig.SafeLinkPoliciesCount } else { 0 }
        
        # Exchange Audit Scoring
        ExchangeAuditScore = if ($ExchangeOnlineAuditConfig.ExchangeAuditScore) { $ExchangeOnlineAuditConfig.ExchangeAuditScore } else { 0 }
        ExchangeAuditScorePercentage = if ($ExchangeOnlineAuditConfig.ExchangeAuditScorePercentage) { $ExchangeOnlineAuditConfig.ExchangeAuditScorePercentage } else { 0 }
        
        # Conditional Access Configuration
        ConditionalAccessPoliciesTotal = $ConditionalAccessConfig.TotalPolicies
        ConditionalAccessPoliciesEnabled = $ConditionalAccessConfig.EnabledPolicies
        ConditionalAccessReportOnly = $ConditionalAccessConfig.ReportOnlyPolicies
        ConditionalAccessDisabled = $ConditionalAccessConfig.DisabledPolicies
        LegacyAuthBlockingPolicies = $ConditionalAccessConfig.BlockLegacyAuth
        MFARequirementPolicies = $ConditionalAccessConfig.RequireMFA
        
        # Compliance & Security Configuration
        CompliancePoliciesCount = $ComplianceCenterConfig.CompliancePolicies
        DLPPoliciesCount = $ComplianceCenterConfig.DLPPolicies
        RetentionPoliciesCount = $ComplianceCenterConfig.RetentionPolicies
        HasComplianceConfiguration = $ComplianceCenterConfig.HasComplianceConfig
        
        # Calculated Metrics
        MailboxAuditCoveragePercentage = if ($ExchangeOnlineAuditConfig.MailboxAuditCoveragePercentage) { 
            $ExchangeOnlineAuditConfig.MailboxAuditCoveragePercentage
        } else { 0 }
        ConditionalAccessCoverage = if ($ConditionalAccessConfig.TotalPolicies -gt 0) { 
            [math]::Round(($ConditionalAccessConfig.EnabledPolicies / $ConditionalAccessConfig.TotalPolicies) * 100, 1) 
        } else { 0 }
        
        # Overall Assessment
        OverallLoggingScore = $overallScore
        SecurityPosture = $securityPosture
        LoggingMaturityLevel = switch ($overallScore) {
            { $_ -ge 85 } { "Advanced" }
            { $_ -ge 70 } { "Intermediate" }
            { $_ -ge 50 } { "Basic" }
            default { "Minimal" }
        }
        
        # Timestamps
        AssessmentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        LastUpdated = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    return $formattedConfig
}

function Export-ToJson {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath,
        
        [Parameter(Mandatory=$false)]
        [array]$Anomalies = @(),
        
        [Parameter(Mandatory=$false)]
        [hashtable]$RawData = @{}
    )
    
    $exportData = @{
        Summary = $Data
        Anomalies = $Anomalies
        RawData = $RawData
        ExportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        ScriptVersion = "1.0"
    }
    
    $jsonOutput = $exportData | ConvertTo-Json -Depth 10
    $jsonFile = Join-Path -Path $OutputPath -ChildPath "tenant-logging-config-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    
    try {
        $jsonOutput | Out-File -FilePath $jsonFile -Encoding UTF8
        Write-LogFile "JSON export completed: $jsonFile" -Level "Standard" -Color "Green"
        return $jsonFile
    }
    catch {
        Write-LogFile "Failed to export JSON: $_" -Level "Minimal" -Color "Red"
        return $null
    }
}

function Export-ToCsv {
    param (
        [Parameter(Mandatory=$true)]
        [PSCustomObject]$Data,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $csvFile = Join-Path -Path $OutputPath -ChildPath "tenant-logging-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    
    try {
        $Data | Export-Csv -Path $csvFile -NoTypeInformation -Encoding UTF8
        Write-LogFile "CSV export completed: $csvFile" -Level "Standard" -Color "Green"
        return $csvFile
    }
    catch {
        Write-LogFile "Failed to export CSV: $_" -Level "Minimal" -Color "Red"
        return $null
    }
}

function New-HtmlDashboard {
   param (
       [Parameter(Mandatory=$true)]
       [PSCustomObject]$Data,
       
       [Parameter(Mandatory=$true)]
       [string]$OutputPath,
       
       [Parameter(Mandatory=$false)]
       [array]$Anomalies = @()
   )
   
   $htmlFile = Join-Path -Path $OutputPath -ChildPath "tenant-logging-dashboard-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
   
   $scoreColor = switch ($Data.OverallLoggingScore) {
       { $_ -ge 90 } { "#28a745" }  # Green
       { $_ -ge 75 } { "#ffc107" }  # Yellow
       { $_ -ge 60 } { "#fd7e14" }  # Orange
       default { "#dc3545" }       # Red
   }
   
   $htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
   <meta charset="UTF-8">
   <meta name="viewport" content="width=device-width, initial-scale=1.0">
   <title>Office 365 Logging Configuration Dashboard - $($Data.TenantName)</title>
   <style>
       body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
       .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
       .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }
       .header h1 { margin: 0; font-size: 2.5em; }
       .header .subtitle { opacity: 0.9; font-size: 1.1em; margin-top: 10px; }
       .dashboard { padding: 30px; }
       .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
       .metric-card { background: #f8f9fa; border-left: 4px solid #667eea; padding: 20px; border-radius: 6px; }
       .metric-card h3 { margin: 0 0 10px 0; color: #333; font-size: 1.1em; }
       .metric-value { font-size: 2em; font-weight: bold; color: #667eea; }
       .metric-subtitle { color: #666; font-size: 0.9em; margin-top: 5px; }
       .score-card { text-align: center; background: linear-gradient(135deg, $scoreColor 0%, rgba(0,0,0,0.1) 100%); color: white; }
       .score-card .metric-value { color: white; font-size: 3em; }
       .section { margin-bottom: 30px; }
       .section h2 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
       .anomaly { background: #fff3cd; border: 1px solid #ffeeba; border-radius: 6px; padding: 15px; margin-bottom: 10px; }
       .anomaly.high { background: #f8d7da; border-color: #f5c6cb; }
       .anomaly.medium { background: #fff3cd; border-color: #ffeeba; }
       .anomaly.low { background: #d1ecf1; border-color: #bee5eb; }
       .anomaly-type { font-weight: bold; margin-bottom: 5px; }
       .anomaly-details { margin-bottom: 10px; }
       .anomaly-recommendation { font-style: italic; color: #666; }
       .details-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }
       .details-section { background: #f8f9fa; padding: 20px; border-radius: 6px; }
       .details-section h3 { margin-top: 0; color: #667eea; }
       .status-enabled { color: #28a745; font-weight: bold; }
       .status-disabled { color: #dc3545; font-weight: bold; }
       .footer { text-align: center; padding: 20px; background: #f8f9fa; border-radius: 0 0 8px 8px; color: #666; }
       .progress-bar { background: #e9ecef; border-radius: 10px; height: 20px; margin: 10px 0; }
       .progress-fill { background: $scoreColor; height: 100%; border-radius: 10px; transition: width 0.3s ease; }
   </style>
</head>
<body>
   <div class="container">
       <div class="header">
           <h1>Office 365 Logging Configuration</h1>
           <div class="subtitle">Tenant: $($Data.TenantName) ($($Data.TenantDomain))</div>
           <div class="subtitle">Assessment Date: $($Data.AssessmentDate)</div>
       </div>
       
       <div class="dashboard">
           <div class="metric-grid">
               <div class="metric-card score-card">
                   <h3>Overall Logging Score</h3>
                   <div class="metric-value">$($Data.OverallLoggingScore)</div>
                   <div class="metric-subtitle">$($Data.SecurityPosture) - $($Data.LoggingMaturityLevel)</div>
                   <div class="progress-bar">
                       <div class="progress-fill" style="width: $($Data.OverallLoggingScore)%;"></div>
                   </div>
               </div>
               
               <div class="metric-card">
                   <h3>Directory Audit Logging</h3>
                   <div class="metric-value $(if ($Data.DirectoryAuditEnabled) { 'status-enabled' } else { 'status-disabled' })">
                       $(if ($Data.DirectoryAuditEnabled) { 'ENABLED' } else { 'DISABLED' })
                   </div>
                   <div class="metric-subtitle">Azure AD Directory Auditing</div>
               </div>
               
               <div class="metric-card">
                   <h3>Sign-in Audit Logging</h3>
                   <div class="metric-value $(if ($Data.SignInAuditEnabled) { 'status-enabled' } else { 'status-disabled' })">
                       $(if ($Data.SignInAuditEnabled) { 'ENABLED' } else { 'DISABLED' })
                   </div>
                   <div class="metric-subtitle">User Authentication Tracking</div>
               </div>
               
               <div class="metric-card">
                   <h3>Exchange Organization Audit</h3>
                   <div class="metric-value $(if ($Data.ExchangeOrganizationAuditEnabled) { 'status-enabled' } else { 'status-disabled' })">
                       $(if ($Data.ExchangeOrganizationAuditEnabled) { 'ENABLED' } else { 'DISABLED' })
                   </div>
                   <div class="metric-subtitle">Exchange Org-Wide Auditing</div>
               </div>
               
               <div class="metric-card">
                   <h3>Exchange Admin Audit</h3>
                   <div class="metric-value $(if ($Data.ExchangeAdminAuditEnabled) { 'status-enabled' } else { 'status-disabled' })">
                       $(if ($Data.ExchangeAdminAuditEnabled) { 'ENABLED' } else { 'DISABLED' })
                   </div>
                   <div class="metric-subtitle">Administrator Activity Logging</div>
               </div>
               
               <div class="metric-card">
                   <h3>Mailbox Audit Coverage</h3>
                   <div class="metric-value">$($Data.MailboxAuditCoveragePercentage)%</div>
                   <div class="metric-subtitle">$($Data.MailboxAuditEnabledCount) of $($Data.TotalMailboxes) mailboxes</div>
               </div>
               
               <div class="metric-card">
                   <h3>Exchange Audit Score</h3>
                   <div class="metric-value">$($Data.ExchangeAuditScore)/100</div>
                   <div class="metric-subtitle">$($Data.ExchangeAuditScorePercentage)% Exchange Coverage</div>
               </div>
               
               <div class="metric-card">
                   <h3>Conditional Access Policies</h3>
                   <div class="metric-value">$($Data.ConditionalAccessPoliciesEnabled)</div>
                   <div class="metric-subtitle">$($Data.ConditionalAccessCoverage)% coverage ($($Data.ConditionalAccessPoliciesTotal) total)</div>
               </div>
               
               <div class="metric-card">
                   <h3>Exchange DLP & Security</h3>
                   <div class="metric-value">$($Data.ExchangeDLPPoliciesEnabled + $Data.SafeAttachmentPoliciesCount + $Data.SafeLinkPoliciesCount)</div>
                   <div class="metric-subtitle">DLP + Defender for Office 365</div>
               </div>
           </div>
           
           $(if ($Anomalies.Count -gt 0) {
           @"
           <div class="section">
               <h2>Security & Logging Issues Found ($($Anomalies.Count))</h2>
               $(foreach ($anomaly in $Anomalies) {
                   $severityClass = $anomaly.Severity.ToLower()
                   @"
               <div class="anomaly $severityClass">
                   <div class="anomaly-type">[$($anomaly.Severity.ToUpper())] $($anomaly.Type)</div>
                   <div class="anomaly-details">$($anomaly.Details)</div>
                   <div class="anomaly-recommendation">Recommendation: $($anomaly.Recommendation)</div>
               </div>
"@
               })
           </div>
"@
           })
           
           <div class="details-grid">
               <div class="details-section">
                   <h3>Azure AD Configuration</h3>
                   <p><strong>Directory Sync:</strong> $(if ($Data.DirectorySyncEnabled) { 'Enabled' } else { 'Disabled' })</p>
                   <p><strong>Tenant ID:</strong> $($Data.TenantId)</p>
                   <p><strong>Primary Domain:</strong> $($Data.TenantDomain)</p>
               </div>
               
               <div class="details-section">
                   <h3>Exchange Online Audit</h3>
                   <p><strong>Organization Audit:</strong> $(if ($Data.ExchangeOrganizationAuditEnabled) { 'Enabled' } else { 'Disabled' })</p>
                   <p><strong>Admin Audit Log:</strong> $(if ($Data.ExchangeAdminAuditEnabled) { 'Enabled' } else { 'Disabled' })</p>
                   <p><strong>Message Tracking:</strong> $(if ($Data.MessageTrackingEnabled) { 'Enabled' } else { 'Disabled' })</p>
                   <p><strong>Bypass Count:</strong> $($Data.MailboxAuditBypassCount) accounts</p>
               </div>
               
               <div class="details-section">
                   <h3>Mailbox Audit Details</h3>
                   <p><strong>Total Mailboxes:</strong> $($Data.TotalMailboxes)</p>
                   <p><strong>Audit Enabled:</strong> $($Data.MailboxAuditEnabledCount) mailboxes</p>
                   <p><strong>Audit Disabled:</strong> $($Data.MailboxAuditDisabledCount) mailboxes</p>
                   <p><strong>Coverage:</strong> $($Data.MailboxAuditCoveragePercentage)%</p>
               </div>
               
               <div class="details-section">
                   <h3>Exchange Security Policies</h3>
                   <p><strong>DLP Policies:</strong> $($Data.ExchangeDLPPoliciesCount) total, $($Data.ExchangeDLPPoliciesEnabled) enabled</p>
                   <p><strong>Retention Policies:</strong> $($Data.ExchangeRetentionPoliciesCount)</p>
                   <p><strong>Safe Attachments:</strong> $($Data.SafeAttachmentPoliciesCount) policies</p>
                   <p><strong>Safe Links:</strong> $($Data.SafeLinkPoliciesCount) policies</p>
               </div>
               
               <div class="details-section">
                   <h3>Conditional Access</h3>
                   <p><strong>Total Policies:</strong> $($Data.ConditionalAccessPoliciesTotal)</p>
                   <p><strong>Enabled:</strong> $($Data.ConditionalAccessPoliciesEnabled)</p>
                   <p><strong>Report Only:</strong> $($Data.ConditionalAccessReportOnly)</p>
                   <p><strong>Legacy Auth Blocking:</strong> $($Data.LegacyAuthBlockingPolicies) policies</p>
                   <p><strong>MFA Requirements:</strong> $($Data.MFARequirementPolicies) policies</p>
               </div>
               
               <div class="details-section">
                   <h3>Compliance & Governance</h3>
                   <p><strong>Litigation Hold:</strong> $($Data.LitigationHoldMailboxes) mailboxes</p>
                   <p><strong>Retention Tags:</strong> $($Data.ExchangeRetentionTagsCount)</p>
                   <p><strong>Malware Policies:</strong> $($Data.MalwarePoliciesCount)</p>
                   <p><strong>Spam Policies:</strong> $($Data.SpamPoliciesCount)</p>
               </div>
           </div>
       </div>
       
       <div class="footer">
           <p>Generated by Office 365 Logging Configuration Analyzer v1.0 | Last Updated: $($Data.LastUpdated)</p>
       </div>
   </div>
</body>
</html>
"@
   
   try {
       $htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8
       Write-LogFile "HTML dashboard generated: $htmlFile" -Level "Standard" -Color "Green"
       return $htmlFile
   }
   catch {
       Write-LogFile "Failed to generate HTML dashboard: $_" -Level "Minimal" -Color "Red"
       return $null
   }
}


# Process a single tenant
function Invoke-TenantLoggingAnalysis {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$Credentials,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeMailboxAudit,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeComplianceCenter,
        
        [Parameter(Mandatory=$false)]
        [switch]$IncludeAzureADAudit,
        
        [Parameter(Mandatory=$false)]
        [switch]$SkipAnomalyDetection
    )
    
    Write-LogFile "Starting logging configuration analysis for tenant: $($Credentials.TenantId)" -Level "Standard" -Color "Green"
    
    try {
        $accessToken = Get-MsGraphToken -TenantId $Credentials.TenantId -ClientId $Credentials.ClientId -ClientSecret $Credentials.ClientSecret
        
        $results = @{
            AzureAD = @{}
            ConditionalAccess = @{}
            ComplianceCenter = @{}
            ExchangeOnlineAudit = @{}
        }
        
        Write-LogFile "Retrieving Azure AD audit configuration..." -Level "Standard"
        $results.AzureAD = Get-AzureADAuditConfig -AccessToken $accessToken
        
        Write-LogFile "Retrieving Conditional Access configuration..." -Level "Standard"
        $results.ConditionalAccess = Get-ConditionalAccessConfig -AccessToken $accessToken
        
        if ($IncludeComplianceCenter) {
            Write-LogFile "Retrieving Compliance Center configuration..." -Level "Standard"
            $results.ComplianceCenter = Get-ComplianceCenterConfig -AccessToken $accessToken
        } else {
            $results.ComplianceCenter = @{
                CompliancePolicies = 0
                DLPPolicies = 0
                RetentionPolicies = 0
                HasComplianceConfig = $false
            }
        }
        
        # Optional: Exchange Online comprehensive audit configuration
        if ($IncludeMailboxAudit) {
            Write-LogFile "Retrieving comprehensive Exchange Online audit configuration..." -Level "Standard"
            $results.ExchangeOnlineAudit = Get-ExchangeOnlineAuditConfig -Credentials $Credentials
        } else {
            $results.ExchangeOnlineAudit = @{
                OrganizationAuditEnabled = $null
                TotalMailboxes = 0
                MailboxAuditEnabledCount = 0
                MailboxAuditDisabledCount = 0
                MailboxAuditBypassCount = 0
                MailboxAuditCoveragePercentage = 0
                ExchangeAuditScore = 0
                ExchangeAuditScorePercentage = 0
                AdminAuditLogEnabled = $false
                MessageTrackingEnabled = $false
                DLPPoliciesCount = 0
                RetentionPoliciesCount = 0
            }
        }
        
        $formattedData = Format-LoggingData -AzureADConfig $results.AzureAD -ConditionalAccessConfig $results.ConditionalAccess -ComplianceCenterConfig $results.ComplianceCenter -ExchangeOnlineAuditConfig $results.ExchangeOnlineAudit
        
        $anomalies = @()
        if (-not $SkipAnomalyDetection) {
            $anomalies = Find-LoggingAnomalies -LoggingConfig $results
        }
        
        Write-LogFile "Logging configuration analysis completed successfully" -Level "Standard" -Color "Green"
        
        return @{
            FormattedData = $formattedData
            Anomalies = $anomalies
            RawData = $results
        }
    }
    catch {
        Write-LogFile "Error during tenant logging analysis: $_" -Level "Minimal" -Color "Red"
        throw $_
    }
}

# Main
try {
    Write-LogFile "Starting Office 365 Logging Configuration Analysis" -Level "Standard" -Color "Cyan"
    Write-LogFile "Script Version: 1.0" -Level "Standard"
    Write-LogFile "Output Directory: $outputFolder" -Level "Standard"
    
    $tenantsToProcess = @()
    
    if ($PSCmdlet.ParameterSetName -eq 'SingleTenant') {
        # Single tenant with direct parameters
        if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
            throw "TenantId, ClientId, and ClientSecret are required for single tenant mode"
        }
        
        $tenantsToProcess += @{
            TenantId = $TenantId
            ClientId = $ClientId
            ClientSecret = $ClientSecret
            ClientName = "Direct-$TenantId"
        }
        
        Write-LogFile "Processing single tenant: $TenantId" -Level "Standard"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'ClientLookup') {
        # Single tenant lookup from CSV
        if (-not $CsvPath) {
            $CsvPath = ".\AzureAppKeys.csv"
        }
        
        $credentials = Get-ClientCredentials -ClientName $ClientName -CsvPath $CsvPath
        $tenantsToProcess += $credentials
        
        Write-LogFile "Processing tenant lookup for client: $ClientName" -Level "Standard"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'MultiTenant') {
        # Multi-tenant processing from CSV
        if (-not $CsvPath) {
            throw "CsvPath is required for multi-tenant mode"
        }
        
        Write-LogFile "Processing multiple tenants from CSV: $CsvPath" -Level "Standard"
        
        $allKeys = Import-Csv -Path $CsvPath
        foreach ($key in $allKeys) {
            $tenantsToProcess += @{
                TenantId = $key.'Tenant ID'.Trim()
                ClientId = $key.'Client ID'.Trim()
                ClientSecret = $key.'Key Value'.Trim()
                ClientName = $key.Client.Trim()
            }
        }
        
        Write-LogFile "Found $($tenantsToProcess.Count) tenants to process" -Level "Standard"
    }
    else {
        throw "Invalid parameter set. Please specify either single tenant parameters, client lookup, or multi-tenant CSV path."
    }

    $allResults = @()
    $tenantCount = 0
    
    foreach ($tenant in $tenantsToProcess) {
        $tenantCount++
        Write-LogFile "Processing tenant $tenantCount of $($tenantsToProcess.Count): $($tenant.ClientName)" -Level "Standard" -Color "Yellow"
        
        try {
            $tenantResult = Invoke-TenantLoggingAnalysis -Credentials $tenant -IncludeMailboxAudit:$IncludeMailboxAudit -IncludeComplianceCenter:$IncludeComplianceCenter -IncludeAzureADAudit:$IncludeAzureADAudit -SkipAnomalyDetection:$SkipAnomalyDetection
            
            $allResults += @{
                TenantName = $tenant.ClientName
                Data = $tenantResult.FormattedData
                Anomalies = $tenantResult.Anomalies
                RawData = $tenantResult.RawData
            }
            
            Write-LogFile "Successfully processed tenant: $($tenant.ClientName)" -Level "Standard" -Color "Green"
            
            if ($OutputFormat -eq "JSON" -or $OutputFormat -eq "Both") {
                $null = Export-ToJson -Data $tenantResult.FormattedData -OutputPath $outputFolder -Anomalies $tenantResult.Anomalies -RawData $tenantResult.RawData
            }
            
            if ($OutputFormat -eq "CSV" -or $OutputFormat -eq "Both") {
                $null = Export-ToCsv -Data $tenantResult.FormattedData -OutputPath $outputFolder
            }
            
            $null = New-HtmlDashboard -Data $tenantResult.FormattedData -OutputPath $outputFolder -Anomalies $tenantResult.Anomalies
        }
        catch {
            Write-LogFile "Failed to process tenant $($tenant.ClientName): $_" -Level "Minimal" -Color "Red"
            continue
        }
    }
    
    if ($tenantsToProcess.Count -gt 1) {
        Write-LogFile "Generating multi-tenant summary report..." -Level "Standard"
        
        $summaryData = $allResults | ForEach-Object { $_.Data }
        $summaryFile = Join-Path -Path $outputFolder -ChildPath "multi-tenant-summary-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
        $summaryData | Export-Csv -Path $summaryFile -NoTypeInformation -Encoding UTF8
        
        Write-LogFile "Multi-tenant summary exported: $summaryFile" -Level "Standard" -Color "Green"
    }
    
    Write-LogFile "Office 365 Logging Configuration Analysis completed successfully!" -Level "Standard" -Color "Green"
    Write-LogFile "Total tenants processed: $($allResults.Count)" -Level "Standard"
    Write-LogFile "Results available in: $outputFolder" -Level "Standard"
    
    # Summary statistics
    if ($allResults.Count -gt 0) {
        $avgScore = [math]::Round(($allResults.Data.OverallLoggingScore | Measure-Object -Average).Average, 1)
        $highRiskTenants = ($allResults.Data | Where-Object { $_.OverallLoggingScore -lt 60 }).Count
        
        Write-Host "`nSUMMARY STATISTICS:" -ForegroundColor Cyan
        Write-Host "Average Logging Score: $avgScore" -ForegroundColor White
        Write-Host "High Risk Tenants (Score < 60): $highRiskTenants" -ForegroundColor $(if ($highRiskTenants -gt 0) { "Red" } else { "Green" })
        Write-Host "Analysis Complete!" -ForegroundColor Green
    }
}
catch {
    Write-LogFile "Critical error in main execution: $_" -Level "Minimal" -Color "Red"
    Write-Error "Script execution failed: $_"
    exit 1
}
finally {
    Write-LogFile "Script execution completed" -Level "Standard"
}
