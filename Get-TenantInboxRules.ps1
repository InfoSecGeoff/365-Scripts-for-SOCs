<#
.SYNOPSIS
    Scans Microsoft 365 tenants for ALL inbox rules using Microsoft Graph API

.DESCRIPTION
    This script retrieves all inbox rules across one or more Microsoft 365 tenants.
    It can process a single tenant directly or multiple tenants from a CSV file with client name lookup.

.PARAMETER TenantId
    The tenant ID for direct single-tenant processing

.PARAMETER ClientId  
    The client ID of the Azure app registration for direct single-tenant processing

.PARAMETER ClientSecret
    The client secret for direct single-tenant processing

.PARAMETER CsvPath
    Path to CSV file containing tenant credentials (columns: Client, Tenant ID, Client ID, Key Value, Expiry)

.PARAMETER ClientName
    Filter to process only a specific client from the CSV file (supports partial matching)

.NOTES
    - Author: Geoff Tankersley
    - Version: 1.0
    - Requires appropriate Microsoft Graph permissions (Mail.Read, MailboxSettings.Read)
    - Generates both CSV and HTML reports
    - Filters for enabled users with active licenses only
    - Reports ALL inbox rules, not just suspicious ones

.EXAMPLE
    .\Get-AllInboxRules.ps1 -CsvPath "TestAzureAppKeys.csv"
    
.EXAMPLE  
    .\Get-AllInboxRules.ps1 -CsvPath "TestAzureAppKeys.csv" -ClientName "Contoso"
    
.EXAMPLE
    .\Get-AllInboxRules.ps1 -TenantId "xxx" -ClientId "xxx" -ClientSecret "xxx"
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

function Get-EnabledLicensedUsers {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }

    $users = @()
    $baseUrl = "https://graph.microsoft.com/v1.0/users"
    $nextLink = $baseUrl + "?`$select=id,displayName,userPrincipalName,mail,accountEnabled,assignedLicenses&`$filter=userType eq 'Member'&`$top=100"

    try {
        # Paginate through all users
        do {
            $response = Invoke-RestMethod -Uri $nextLink -Method Get -Headers $headers
            
            # Filter for enabled users with licenses
            $enabledLicensedUsers = $response.value | Where-Object { 
                $_.accountEnabled -eq $true -and 
                $_.assignedLicenses -ne $null -and 
                $_.assignedLicenses.Count -gt 0 
            }
            
            $users += $enabledLicensedUsers
            $nextLink = $response.'@odata.nextLink'
        } while ($nextLink)

        return $users
    }
    catch {
        Write-Error "Error retrieving users: $_"
        throw $_
    }
}

function Get-UserInboxRules {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId
    )
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/inbox/messageRules" -Method Get -Headers $headers
        return $response.value
    }
    catch {
        Write-Warning "Could not retrieve inbox rules for user ID $UserId : $($_.Exception.Message)"
        return @()
    }
}

function Format-RuleConditions {
    param (
        [Parameter(Mandatory=$false)]
        $Conditions
    )
    
    if ($null -eq $Conditions) {
        return "No conditions specified"
    }
    
    $conditionDetails = @()
    
    if ($Conditions.bodyContains) {
        $conditionDetails += "Body contains: $($Conditions.bodyContains -join ', ')"
    }
    
    if ($Conditions.bodyOrSubjectContains) {
        $conditionDetails += "Body or subject contains: $($Conditions.bodyOrSubjectContains -join ', ')"
    }
    
    if ($Conditions.categories) {
        $conditionDetails += "Categories include: $($Conditions.categories -join ', ')"
    }
    
    if ($Conditions.fromAddresses) {
        $senders = $Conditions.fromAddresses | ForEach-Object { 
            if ($_.emailAddress) {
                "$($_.emailAddress.name) <$($_.emailAddress.address)>"
            } else {
                "Unknown sender"
            }
        }
        $conditionDetails += "From: $($senders -join ', ')"
    }
    
    if ($Conditions.headerContains) {
        $conditionDetails += "Header contains: $($Conditions.headerContains -join ', ')"
    }
    
    if ($Conditions.importance) {
        $conditionDetails += "Importance: $($Conditions.importance)"
    }
    
    # Boolean conditions
    $booleanConditions = @{
        'isApprovalRequest' = 'Is approval request'
        'isAutomaticForward' = 'Is automatic forward'
        'isAutomaticReply' = 'Is automatic reply'
        'isEncrypted' = 'Is encrypted'
        'isMeetingRequest' = 'Is meeting request'
        'isMeetingResponse' = 'Is meeting response'
        'isNonDeliveryReport' = 'Is non-delivery report'
        'isPermissionControlled' = 'Is permission controlled'
        'isReadReceipt' = 'Is read receipt'
        'isSigned' = 'Is signed'
        'isVoicemail' = 'Is voicemail'
        'notSentToMe' = 'Not sent to me'
        'sentCcMe' = 'Sent with me on CC'
        'sentOnlyToMe' = 'Sent only to me'
        'sentToMe' = 'Sent to me'
        'sentToOrCcMe' = 'Sent to or CC''d to me'
    }
    
    foreach ($condition in $booleanConditions.Keys) {
        if ($Conditions.$condition -eq $true) {
            $conditionDetails += $booleanConditions[$condition]
        }
    }
    
    if ($Conditions.messageActionFlag) {
        $conditionDetails += "Message action flag: $($Conditions.messageActionFlag)"
    }
    
    if ($Conditions.recipientContains) {
        $conditionDetails += "Recipient contains: $($Conditions.recipientContains -join ', ')"
    }
    
    if ($Conditions.senderContains) {
        $conditionDetails += "Sender contains: $($Conditions.senderContains -join ', ')"
    }
    
    if ($Conditions.sensitivity) {
        $conditionDetails += "Sensitivity: $($Conditions.sensitivity)"
    }
    
    if ($Conditions.sentToAddresses) {
        $recipients = $Conditions.sentToAddresses | ForEach-Object { 
            if ($_.emailAddress) {
                "$($_.emailAddress.name) <$($_.emailAddress.address)>"
            } else {
                "Unknown recipient"
            }
        }
        $conditionDetails += "Sent to: $($recipients -join ', ')"
    }
    
    if ($Conditions.subjectContains) {
        $conditionDetails += "Subject contains: $($Conditions.subjectContains -join ', ')"
    }
    
    if ($Conditions.withinSizeRange) {
        $minSize = if ($Conditions.withinSizeRange.minimumSize) { [math]::Round($Conditions.withinSizeRange.minimumSize / 1KB, 2) } else { 0 }
        $maxSize = if ($Conditions.withinSizeRange.maximumSize) { [math]::Round($Conditions.withinSizeRange.maximumSize / 1KB, 2) } else { "unlimited" }
        $conditionDetails += "Size between: $minSize KB and $maxSize KB"
    }
    
    if ($conditionDetails.Count -eq 0) {
        return "No conditions specified"
    } else {
        return $conditionDetails -join "; "
    }
}

function Format-RuleActions {
    param (
        [Parameter(Mandatory=$false)]
        $Actions,
        
        [Parameter(Mandatory=$false)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$false)]
        [string]$UserId
    )
    
    if ($null -eq $Actions) {
        return "No actions specified"
    }
    
    $actionDetails = @()
    
    if ($Actions.assignCategories) {
        $actionDetails += "Assign categories: $($Actions.assignCategories -join ', ')"
    }
    
    if ($Actions.copyToFolder) {
        $folderName = "Unknown Folder"
        if (![string]::IsNullOrEmpty($AccessToken) -and ![string]::IsNullOrEmpty($UserId)) {
            $folderName = Get-FolderPathById -AccessToken $AccessToken -UserId $UserId -FolderId $Actions.copyToFolder
        }
        $actionDetails += "Copy to folder: $folderName"
    }
    
    if ($Actions.delete -eq $true) {
        $actionDetails += "Delete message"
    }
    
    if ($Actions.forwardAsAttachmentTo) {
        $forwardTo = $Actions.forwardAsAttachmentTo | ForEach-Object { 
            if ($_.emailAddress -and $_.emailAddress.address) {
                if ($_.emailAddress.name) {
                    "$($_.emailAddress.name) <$($_.emailAddress.address)>"
                } else {
                    $_.emailAddress.address
                }
            } else {
                "Unknown recipient"
            }
        }
        $actionDetails += "Forward as attachment to: $($forwardTo -join ', ')"
    }
    
    if ($Actions.forwardTo) {
        $forwardTo = $Actions.forwardTo | ForEach-Object { 
            if ($_.emailAddress -and $_.emailAddress.address) {
                if ($_.emailAddress.name) {
                    "$($_.emailAddress.name) <$($_.emailAddress.address)>"
                } else {
                    $_.emailAddress.address
                }
            } else {
                "Unknown recipient"
            }
        }
        $actionDetails += "Forward to: $($forwardTo -join ', ')"
    }
    
    if ($Actions.markAsRead -eq $true) {
        $actionDetails += "Mark as read"
    }
    
    if ($Actions.markImportance) {
        $actionDetails += "Mark importance: $($Actions.markImportance)"
    }
    
    if ($Actions.moveToFolder) {
        $folderName = "Unknown Folder"
        if (![string]::IsNullOrEmpty($AccessToken) -and ![string]::IsNullOrEmpty($UserId)) {
            $folderName = Get-FolderPathById -AccessToken $AccessToken -UserId $UserId -FolderId $Actions.moveToFolder
        }
        $actionDetails += "Move to folder: $folderName"
    }
    
    if ($Actions.permanentDelete -eq $true) {
        $actionDetails += "Permanently delete"
    }
    
    if ($Actions.redirectTo) {
        $redirectTo = $Actions.redirectTo | ForEach-Object { 
            if ($_.emailAddress -and $_.emailAddress.address) {
                if ($_.emailAddress.name) {
                    "$($_.emailAddress.name) <$($_.emailAddress.address)>"
                } else {
                    $_.emailAddress.address
                }
            } else {
                "Unknown recipient"
            }
        }
        $actionDetails += "Redirect to: $($redirectTo -join ', ')"
    }
    
    if ($Actions.stopProcessingRules -eq $true) {
        $actionDetails += "Stop processing rules"
    }
    
    if ($actionDetails.Count -eq 0) {
        return "No actions specified"
    } else {
        return $actionDetails -join "; "
    }
}

function Get-FolderPathById {
    param (
        [Parameter(Mandatory=$true)]
        [string]$AccessToken,
        
        [Parameter(Mandatory=$true)]
        [string]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$FolderId
    )
    
    if ($FolderId -eq "inbox") {
        return "Inbox"
    }
    
    # Handle special folder names first
    $wellKnownFolders = @{
        "deleteditems" = "Deleted Items"
        "drafts" = "Drafts"
        "sentitems" = "Sent Items"
        "junkemail" = "Junk Email"
        "outbox" = "Outbox"
        "archive" = "Archive"
        "conversationhistory" = "Conversation History"
        "rssfeeds" = "RSS Feeds"
    }
    
    if ($wellKnownFolders.ContainsKey($FolderId.ToLower())) {
        return $wellKnownFolders[$FolderId.ToLower()]
    }
    
    $headers = @{
        "Authorization" = "Bearer $AccessToken"
        "Content-Type"  = "application/json"
    }
    
    try {
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/$FolderId" -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        if ($response -and $response.displayName) {
            return $response.displayName
        }
    }
    catch {
        # Fallback to searching folder hierarchy
        try {
            $rootFoldersResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders?`$select=id,displayName&`$top=999" -Method Get -Headers $headers -ErrorAction SilentlyContinue
            
            if ($rootFoldersResponse -and $rootFoldersResponse.value) {
                $matchingFolder = $rootFoldersResponse.value | Where-Object { $_.id -eq $FolderId }
                if ($matchingFolder) {
                    return $matchingFolder.displayName
                }
            }
        }
        catch {
            # Final fallback
        }
    }
    
    return "Custom Folder (ID: $($FolderId.Substring(0, [Math]::Min(8, $FolderId.Length)))...)"
}

function New-HTMLReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$TenantSummaries,
        
        [Parameter(Mandatory=$true)]
        [array]$AllRules,
        
        [Parameter(Mandatory=$true)]
        [string]$OutputPath
    )
    
    $totalRules = ($AllRules | Where-Object { $_.RuleId -ne "N/A" }).Count
    $totalUsersWithRules = ($AllRules | Where-Object { $_.RuleId -ne "N/A" } | Select-Object -Property UserPrincipalName -Unique | Measure-Object).Count
    $totalUsers = ($AllRules | Select-Object -Property UserPrincipalName -Unique | Measure-Object).Count
    
    $htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Inbox Rules Report</title>
    <meta charset="UTF-8">
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #0066cc; 
            border-bottom: 3px solid #0066cc;
            padding-bottom: 10px;
        }
        h2 { 
            color: #0066cc; 
            margin-top: 30px;
        }
        table { 
            border-collapse: collapse; 
            width: 100%; 
            margin-bottom: 20px;
            font-size: 13px;
        }
        th, td { 
            padding: 10px 8px; 
            text-align: left; 
            border-bottom: 1px solid #ddd; 
            vertical-align: top;
        }
        th { 
            background-color: #f8f9fa; 
            font-weight: bold;
            color: #495057;
            position: sticky;
            top: 0;
        }
        tr:hover { 
            background-color: #f8f9fa; 
        }
        .summary { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px; 
            border-radius: 8px; 
            margin-bottom: 20px;
        }
        .summary h3 {
            margin-top: 0;
            color: white;
        }
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .summary-item {
            background-color: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 5px;
        }
        .summary-value {
            font-size: 24px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        .summary-label {
            font-size: 12px;
            opacity: 0.9;
        }
        .table-container {
            overflow-x: auto;
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid #dee2e6;
            border-radius: 5px;
        }
        .small-text {
            font-size: 11px;
            color: #6c757d;
        }
        .rule-name {
            font-weight: bold;
            color: #495057;
        }
        .user-info {
            font-weight: bold;
        }
        .badge {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 12px;
            font-size: 10px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .badge-enabled {
            background-color: #d4edda;
            color: #155724;
        }
        .badge-disabled {
            background-color: #f8d7da;
            color: #721c24;
        }
        .no-rules {
            color: #6c757d;
            font-style: italic;
        }
        .conditions, .actions {
            max-width: 300px;
            word-wrap: break-word;
        }
        .client-name {
            font-weight: bold;
            color: #0066cc;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Microsoft 365 Inbox Rules Report</h1>
        
        <div class="summary">
            <h3>Executive Summary</h3>
            <div class="summary-grid">
                <div class="summary-item">
                    <div class="summary-value">$(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</div>
                    <div class="summary-label">Generated On</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$($TenantSummaries.Count)</div>
                    <div class="summary-label">Tenants Scanned</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$totalUsers</div>
                    <div class="summary-label">Total Users</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$totalUsersWithRules</div>
                    <div class="summary-label">Users with Rules</div>
                </div>
                <div class="summary-item">
                    <div class="summary-value">$totalRules</div>
                    <div class="summary-label">Total Rules Found</div>
                </div>
            </div>
        </div>

        <h2>Tenant Summary</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Client Name</th>
                        <th>Tenant ID</th>
                        <th>Total Users</th>
                        <th>Users with Rules</th>
                        <th>Total Rules</th>
                        <th>% Users with Rules</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($summary in $TenantSummaries) {
        $htmlContent += @"
                    <tr>
                        <td class="client-name">$($summary.ClientName)</td>
                        <td class="small-text">$($summary.TenantId)</td>
                        <td>$($summary.TotalUsers)</td>
                        <td>$($summary.UsersWithRules)</td>
                        <td>$($summary.TotalRules)</td>
                        <td>$($summary.PercentageWithRules)%</td>
                    </tr>
"@
    }

    $htmlContent += @"
                </tbody>
            </table>
        </div>

        <h2>All Inbox Rules Details</h2>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Client</th>
                        <th>User</th>
                        <th>Rule Name</th>
                        <th>Status</th>
                        <th>Sequence</th>
                        <th>Conditions</th>
                        <th>Actions</th>
                        <th>Destination Folder</th>
                    </tr>
                </thead>
                <tbody>
"@

    foreach ($rule in $AllRules) {
        $enabledBadge = if ($rule.IsEnabled -eq $true) { 
            '<span class="badge badge-enabled">Enabled</span>' 
        } elseif ($rule.IsEnabled -eq $false) { 
            '<span class="badge badge-disabled">Disabled</span>' 
        } else { 
            '<span class="badge">Unknown</span>' 
        }
        
        $ruleNameDisplay = if ($rule.DisplayName -eq "No inbox rules") {
            '<span class="no-rules">No inbox rules</span>'
        } else {
            "<span class='rule-name'>$($rule.DisplayName)</span>"
        }
        
        $htmlContent += @"
                    <tr>
                        <td class="client-name">$($rule.ClientName)</td>
                        <td>
                            <div class="user-info">$($rule.UserDisplayName)</div>
                            <div class="small-text">$($rule.UserPrincipalName)</div>
                        </td>
                        <td>$ruleNameDisplay</td>
                        <td>$enabledBadge</td>
                        <td>$($rule.Sequence)</td>
                        <td class="conditions">$($rule.Conditions)</td>
                        <td class="actions">$($rule.Actions)</td>
                        <td>$($rule.DestinationFolder)</td>
                    </tr>
"@
    }

    $htmlContent += @"
                </tbody>
            </table>
        </div>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #dee2e6; color: #6c757d; font-size: 12px;">
            <p>Report generated by Complete Inbox Rules Scanner | Microsoft Graph API | PowerShell</p>
        </div>
    </div>
</body>
</html>
"@

    $htmlContent | Out-File -FilePath $OutputPath -Encoding utf8
}

# Main script execution
$ErrorActionPreference = "Continue"
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "InboxRules-Report-$timestamp"
New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

# Create arrays to hold all reports
$allInboxRules = @()
$tenantSummaries = @()

# Check which parameter set is being used
if ($CsvPath) {
    # Process tenants from CSV
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        return
    }
    
    try {
        $tenants = Import-Csv -Path $CsvPath
        
        # If ClientName is specified, filter for that specific client
        if (![string]::IsNullOrWhiteSpace($ClientName)) {
            $tenants = $tenants | Where-Object { $_.Client -like "*$ClientName*" }
            if ($tenants.Count -eq 0) {
                Write-Error "No tenants found matching client name: $ClientName"
                Write-Host "Available clients in CSV:" -ForegroundColor Yellow
                Import-Csv -Path $CsvPath | Select-Object -ExpandProperty Client | Sort-Object | ForEach-Object { Write-Host "  - $_" -ForegroundColor Yellow }
                return
            }
            Write-Host "Found $($tenants.Count) tenant(s) matching '$ClientName'" -ForegroundColor Green
        }
        
        foreach ($tenant in $tenants) {
            # Skip entries with missing required values
            if ([string]::IsNullOrWhiteSpace($tenant.'Tenant ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Client ID') -or 
                [string]::IsNullOrWhiteSpace($tenant.'Key Value')) {
                Write-Warning "Skipping tenant '$($tenant.Client)' - Missing required credential information"
                continue
            }
            
            $clientNameValue = $tenant.Client.Trim()
            $tenantId = $tenant.'Tenant ID'.Trim()
            $clientId = $tenant.'Client ID'.Trim()
            $clientSecret = $tenant.'Key Value'.Trim()
            
            Write-Host "`n=======================================================" -ForegroundColor Cyan
            Write-Host "Processing tenant: $clientNameValue ($tenantId)" -ForegroundColor Cyan
            Write-Host "=======================================================" -ForegroundColor Cyan
            
            try {
                # Get authentication token
                Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                
                # Get all enabled users with licenses
                Write-Host "Retrieving enabled users with licenses..." -ForegroundColor Yellow
                $users = Get-EnabledLicensedUsers -AccessToken $accessToken
                
                Write-Host "Found $($users.Count) enabled, licensed users. Gathering all inbox rules..." -ForegroundColor Yellow
                
                # Track statistics for this tenant
                $totalRulesCount = 0
                $usersWithRulesCount = 0
                $usersWithRules = @{}
                
                # Process each user
                $counter = 0
                
                foreach ($user in $users) {
                    $counter++
                    Write-Progress -Activity "Processing Users" -Status "Processing user $counter of $($users.Count): $($user.displayName)" -PercentComplete (($counter / $users.Count) * 100)
                    
                    # Get user's inbox rules
                    $rules = Get-UserInboxRules -AccessToken $accessToken -UserId $user.id
                    
                    if ($rules.Count -eq 0) {
                        # User has no rules, add a placeholder entry
                        $allInboxRules += [PSCustomObject]@{
                            ClientName          = $clientNameValue
                            TenantId            = $tenantId
                            UserDisplayName     = $user.displayName
                            UserPrincipalName   = $user.userPrincipalName
                            UserId              = $user.id
                            RuleId              = "N/A"
                            DisplayName         = "No inbox rules"
                            Sequence            = 0
                            IsEnabled           = $false
                            Conditions          = "N/A"
                            Actions             = "N/A"
                            DestinationFolder   = "N/A"
                        }
                    } else {
                        $usersWithRules[$user.id] = $true
                        $totalRulesCount += $rules.Count
                        
                        # Process each rule
                        foreach ($rule in $rules) {
                            # Format rule conditions and actions
                            $conditionsFormatted = Format-RuleConditions -Conditions $rule.conditions
                            $actionsFormatted = Format-RuleActions -Actions $rule.actions -AccessToken $accessToken -UserId $user.id
                            
                            # Get destination folder if applicable
                            $destinationFolder = "N/A"
                            if ($rule.actions -and $rule.actions.moveToFolder) {
                                $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.moveToFolder
                            } elseif ($rule.actions -and $rule.actions.copyToFolder) {
                                $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.copyToFolder
                            }
                            
                            $allInboxRules += [PSCustomObject]@{
                                ClientName          = $clientNameValue
                                TenantId            = $tenantId
                                UserDisplayName     = $user.displayName
                                UserPrincipalName   = $user.userPrincipalName
                                UserId              = $user.id
                                RuleId              = $rule.id
                                DisplayName         = $rule.displayName
                                Sequence            = $rule.sequence
                                IsEnabled           = $rule.isEnabled
                                Conditions          = $conditionsFormatted
                                Actions             = $actionsFormatted
                                DestinationFolder   = $destinationFolder
                            }
                        }
                    }
                }
                
                Write-Progress -Activity "Processing Users" -Completed
                
                $usersWithRulesCount = $usersWithRules.Count
                
                # Add tenant summary
                $tenantSummaries += [PSCustomObject]@{
                    ClientName           = $clientNameValue
                    TenantId             = $tenantId
                    TotalUsers           = $users.Count
                    UsersWithRules       = $usersWithRulesCount
                    TotalRules           = $totalRulesCount
                    PercentageWithRules  = if ($users.Count -gt 0) { [math]::Round(($usersWithRulesCount / $users.Count) * 100, 2) } else { 0 }
                }
                
                Write-Host "Found $totalRulesCount inbox rules across $usersWithRulesCount users (out of $($users.Count) total users) in $clientNameValue" -ForegroundColor Green
                
            } catch {
                Write-Error "Error processing tenant $clientNameValue ($tenantId): $_"
            }
        }
        
        # Export consolidated reports
        Write-Host "`n=======================================================" -ForegroundColor Green
        Write-Host "Generating Reports..." -ForegroundColor Green
        Write-Host "=======================================================" -ForegroundColor Green
        
        $summaryFile = Join-Path -Path $outputFolder -ChildPath "TenantSummary.csv"
        $tenantSummaries | Export-Csv -Path $summaryFile -NoTypeInformation
        
        $detailedFile = Join-Path -Path $outputFolder -ChildPath "AllInboxRules-Detailed.csv"
        $allInboxRules | Export-Csv -Path $detailedFile -NoTypeInformation
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "InboxRulesReport.html"
        New-HTMLReport -TenantSummaries $tenantSummaries -AllRules $allInboxRules -OutputPath $htmlReportPath
        
        Write-Host "`nAll processing complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
        Write-Host "Summary Report: $summaryFile" -ForegroundColor Green
        Write-Host "Detailed Report: $detailedFile" -ForegroundColor Green
        Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
    }
    catch {
        Write-Error "Error processing CSV file: $_"
    }
}
else {
    # Process single tenant with parameters
    if ([string]::IsNullOrWhiteSpace($TenantId) -or 
        [string]::IsNullOrWhiteSpace($ClientId) -or 
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "When not using a CSV file, you must provide TenantId, ClientId, and ClientSecret parameters."
        return
    }
    
    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host "Processing single tenant: $TenantId" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    # Get authentication token
    Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
    $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Get all enabled users with licenses
    Write-Host "Retrieving enabled users with licenses..." -ForegroundColor Yellow
    $users = Get-EnabledLicensedUsers -AccessToken $accessToken
    
    Write-Host "Found $($users.Count) enabled, licensed users. Gathering all inbox rules..." -ForegroundColor Yellow
    
    # Track statistics for this tenant
    $totalRulesCount = 0
    $usersWithRulesCount = 0
    $usersWithRules = @{}
    
    # Process each user
    $counter = 0
    
    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Processing Users" -Status "Processing user $counter of $($users.Count): $($user.displayName)" -PercentComplete (($counter / $users.Count) * 100)
        
        # Get user's inbox rules
        $rules = Get-UserInboxRules -AccessToken $accessToken -UserId $user.id
        
        if ($rules.Count -eq 0) {
            # User has no rules, add a placeholder entry
            $allInboxRules += [PSCustomObject]@{
                ClientName          = "Direct Access"
                TenantId            = $TenantId
                UserDisplayName     = $user.displayName
                UserPrincipalName   = $user.userPrincipalName
                UserId              = $user.id
                RuleId              = "N/A"
                DisplayName         = "No inbox rules"
                Sequence            = 0
                IsEnabled           = $false
                Conditions          = "N/A"
                Actions             = "N/A"
                DestinationFolder   = "N/A"
            }
        } else {
            $usersWithRules[$user.id] = $true
            $totalRulesCount += $rules.Count
            
            # Process each rule
            foreach ($rule in $rules) {
                # Format rule conditions and actions
                $conditionsFormatted = Format-RuleConditions -Conditions $rule.conditions
                $actionsFormatted = Format-RuleActions -Actions $rule.actions -AccessToken $accessToken -UserId $user.id
                
                # Get destination folder if applicable
                $destinationFolder = "N/A"
                if ($rule.actions -and $rule.actions.moveToFolder) {
                    $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.moveToFolder
                } elseif ($rule.actions -and $rule.actions.copyToFolder) {
                    $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.copyToFolder
                }
                
                $allInboxRules += [PSCustomObject]@{
                    ClientName          = "Direct Access"
                    TenantId            = $TenantId
                    UserDisplayName     = $user.displayName
                    UserPrincipalName   = $user.userPrincipalName
                    UserId              = $user.id
                    RuleId              = $rule.id
                    DisplayName         = $rule.displayName
                    Sequence            = $rule.sequence
                    IsEnabled           = $rule.isEnabled
                    Conditions          = $conditionsFormatted
                    Actions             = $actionsFormatted
                    DestinationFolder   = $destinationFolder
                }
            }
        }
    }
    
    Write-Progress -Activity "Processing Users" -Completed
    
    $usersWithRulesCount = $usersWithRules.Count
    
    # Create summary object
    $tenantSummary = [PSCustomObject]@{
        ClientName           = "Direct Access"
        TenantId             = $TenantId
        TotalUsers           = $users.Count
        UsersWithRules       = $usersWithRulesCount
        TotalRules           = $totalRulesCount
        PercentageWithRules  = if ($users.Count -gt 0) { [math]::Round(($usersWithRulesCount / $users.Count) * 100, 2) } else { 0 }
    }
    
    $tenantSummaries += $tenantSummary
    
    Write-Host "Found $totalRulesCount inbox rules across $usersWithRulesCount users (out of $($users.Count) total users)" -ForegroundColor Green
    
    # Export reports
    Write-Host "`n=======================================================" -ForegroundColor Green
    Write-Host "Generating Reports..." -ForegroundColor Green
    Write-Host "=======================================================" -ForegroundColor Green
    
    $summaryFile = Join-Path -Path $outputFolder -ChildPath "TenantSummary.csv"
    $tenantSummaries | Export-Csv -Path $summaryFile -NoTypeInformation
    
    $detailedFile = Join-Path -Path $outputFolder -ChildPath "AllInboxRules-Detailed.csv"
    $allInboxRules | Export-Csv -Path $detailedFile -NoTypeInformation
    
    # Generate HTML report
    $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "InboxRulesReport.html"
    New-HTMLReport -TenantSummaries $tenantSummaries -AllRules $allInboxRules -OutputPath $htmlReportPath
    
    Write-Host "`nScan complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
    Write-Host "Summary Report: $summaryFile" -ForegroundColor Green
    Write-Host "Detailed Report: $detailedFile" -ForegroundColor Green
    Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
    
    # Display summary information in the console
    Write-Host "`n=======================================================" -ForegroundColor Cyan
    Write-Host "Summary of Inbox Rules Found:" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan
    
    $allInboxRules | Where-Object { $_.RuleId -ne "N/A" } | Format-Table UserDisplayName, DisplayName, IsEnabled, DestinationFolder -AutoSize
    
    # Return the inbox rules information as objects for further processing if needed
    return $allInboxRules
}
