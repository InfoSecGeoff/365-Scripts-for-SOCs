<#
.SYNOPSIS
    Scans Microsoft 365 tenants for suspicious inbox rules using Microsoft Graph API

.DESCRIPTION
    This script identifies potentially malicious inbox rules across one or more Microsoft 365 tenants.
    It can process a single tenant directly or multiple tenants from a CSV file.

.PARAMETER TenantId
    The tenant ID for direct single-tenant processing

.PARAMETER ClientId  
    The client ID of the Azure app registration for direct single-tenant processing

.PARAMETER ClientSecret
    The client secret for direct single-tenant processing

.PARAMETER CsvPath
    Path to CSV file containing tenant credentials (columns: Client, Tenant ID, Client ID, Key Value)

.PARAMETER ClientName
    Filter to process only a specific client from the CSV file (supports partial matching)

.PARAMETER SuspiciousFolders
    Array of folder names considered suspicious for email rules (default includes RSS Feeds, Archive, Conversation History)

.PARAMETER SuspiciousNames
    Array of rule names considered suspicious - typically single characters, symbols, or keyboard patterns

.PARAMETER SuspiciousKeywords
    Array of keywords that when found in rule conditions or names are considered suspicious

.NOTES
    - MessageRule objects in Microsoft Graph API do not include createdDateTime or lastModifiedDateTime properties
    - This is an API limitation, not a script issue - these timestamps are not available for inbox rules
    - Folder name resolution may take time for complex folder structures
    - Requires appropriate Microsoft Graph permissions (Mail.Read, MailboxSettings.Read)
    - The script removes Created/Modified columns from output due to API limitations

.EXAMPLE
    .\Get-TenantSusInboxRules.ps1 -CsvPath "credentials.csv"
    
.EXAMPLE  
    .\Get-TenantSusInboxRules.ps1 -CsvPath "credentials.csv" -ClientName "CompanyName"
    
.EXAMPLE
    .\Get-TenantSusInboxRules.ps1 -TenantId "xxx" -ClientId "xxx" -ClientSecret "xxx"

.EXAMPLE
    .\Get-TenantSusInboxRules.ps1 -CsvPath "creds.csv" -SuspiciousKeywords @("malware", "phishing") -SuspiciousFolders @("Junk", "Spam")
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
    [string[]]$SuspiciousFolders = @("RSS Feeds", "Archive", "Conversation History"),
    
    [Parameter(Mandatory=$false)]
    [string[]]$SuspiciousNames = @(
        ".", "..", "...", "....", ".....", "-", "/", "//", "///", "_", 
        "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", "=", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+",
        "q", "w", "e", "r", "t", "y", "u", "i", "o", "p", "[", "]", "\", 
        "Q", "W", "E", "R", "T", "Y", "U", "I", "O", "P", "{", "}", "|",
        "a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'",
        "A", "S", "D", "F", "G", "H", "J", "K", "L", ":", """",
        "z", "x", "c", "v", "b", "n", "m", ",", ".", "/",
        "Z", "X", "C", "V", "B", "N", "M", "<", ">", "?"
    ),
    
    [Parameter(Mandatory=$false)]
    [string[]]$SuspiciousKeywords = @(
        "Dropbox", "Drop box", "dropbox", "password", "w2", "Box", "mfa", "MFA", 
        "docusign", "invoice", "payment", "fraud", "hack", "compromise"
    )
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
        [string]$UserId,
        
        [Parameter(Mandatory=$true)]
        [string]$UserDisplayName,
        
        [Parameter(Mandatory=$true)]
        [string]$UserPrincipalName
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
        # Some users might not allow rule listing with the current permissions
        $errorMessage = "Could not retrieve inbox rules for user $UserDisplayName ($UserPrincipalName): " + $_.Exception.Message
        Write-Warning $errorMessage
        return @()
    }
}

function Format-RuleConditions {
    param (
        [Parameter(Mandatory=$false)]
        $Conditions
    )
    
    # Check if Conditions is null
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
    
    if ($Conditions.isApprovalRequest -eq $true) {
        $conditionDetails += "Is approval request"
    }
    
    if ($Conditions.isAutomaticForward -eq $true) {
        $conditionDetails += "Is automatic forward"
    }
    
    if ($Conditions.isAutomaticReply -eq $true) {
        $conditionDetails += "Is automatic reply"
    }
    
    if ($Conditions.isEncrypted -eq $true) {
        $conditionDetails += "Is encrypted"
    }
    
    if ($Conditions.isMeetingRequest -eq $true) {
        $conditionDetails += "Is meeting request"
    }
    
    if ($Conditions.isMeetingResponse -eq $true) {
        $conditionDetails += "Is meeting response"
    }
    
    if ($Conditions.isNonDeliveryReport -eq $true) {
        $conditionDetails += "Is non-delivery report"
    }
    
    if ($Conditions.isPermissionControlled -eq $true) {
        $conditionDetails += "Is permission controlled"
    }
    
    if ($Conditions.isReadReceipt -eq $true) {
        $conditionDetails += "Is read receipt"
    }
    
    if ($Conditions.isSigned -eq $true) {
        $conditionDetails += "Is signed"
    }
    
    if ($Conditions.isVoicemail -eq $true) {
        $conditionDetails += "Is voicemail"
    }
    
    if ($Conditions.messageActionFlag) {
        $conditionDetails += "Message action flag: $($Conditions.messageActionFlag)"
    }
    
    if ($Conditions.notSentToMe -eq $true) {
        $conditionDetails += "Not sent to me"
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
    
    if ($Conditions.sentCcMe -eq $true) {
        $conditionDetails += "Sent with me on CC"
    }
    
    if ($Conditions.sentOnlyToMe -eq $true) {
        $conditionDetails += "Sent only to me"
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
    
    if ($Conditions.sentToMe -eq $true) {
        $conditionDetails += "Sent to me"
    }
    
    if ($Conditions.sentToOrCcMe -eq $true) {
        $conditionDetails += "Sent to or CC'd to me"
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
    
    # Check if Actions is null
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
            } elseif ($_.address) {
                if ($_.name) {
                    "$($_.name) <$($_.address)>"
                } else {
                    $_.address
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
            } elseif ($_.address) {
                if ($_.name) {
                    "$($_.name) <$($_.address)>"
                } else {
                    $_.address
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
            } elseif ($_.address) {
                if ($_.name) {
                    "$($_.name) <$($_.address)>"
                } else {
                    $_.address
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
        # Try the direct folder lookup first with error suppression
        $response = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/$FolderId" -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        if ($response -and $response.displayName) {
            return $response.displayName
        }
    }
    catch {
        # Continue to next method
    }
    
    # If direct lookup fails, try comprehensive folder search
    try {
        # Get all root folders first
        $rootFoldersResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders?`$select=id,displayName&`$top=999" -Method Get -Headers $headers -ErrorAction SilentlyContinue
        
        if ($rootFoldersResponse -and $rootFoldersResponse.value) {
            # Check if target folder is in root folders
            $matchingFolder = $rootFoldersResponse.value | Where-Object { $_.id -eq $FolderId }
            if ($matchingFolder) {
                return $matchingFolder.displayName
            }
            
            # Search in child folders with improved logic
            foreach ($folder in $rootFoldersResponse.value) {
                try {
                    $childFoldersResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/$($folder.id)/childFolders?`$select=id,displayName&`$top=999" -Method Get -Headers $headers -ErrorAction SilentlyContinue
                    
                    if ($childFoldersResponse -and $childFoldersResponse.value) {
                        $matchingChildFolder = $childFoldersResponse.value | Where-Object { $_.id -eq $FolderId }
                        if ($matchingChildFolder) {
                            return "$($folder.displayName)/$($matchingChildFolder.displayName)"
                        }
                        
                        # Check grandchild folders (one more level deep)
                        foreach ($childFolder in $childFoldersResponse.value) {
                            try {
                                $grandChildResponse = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$UserId/mailFolders/$($childFolder.id)/childFolders?`$select=id,displayName&`$top=999" -Method Get -Headers $headers -ErrorAction SilentlyContinue
                                
                                if ($grandChildResponse -and $grandChildResponse.value) {
                                    $matchingGrandChild = $grandChildResponse.value | Where-Object { $_.id -eq $FolderId }
                                    if ($matchingGrandChild) {
                                        return "$($folder.displayName)/$($childFolder.displayName)/$($matchingGrandChild.displayName)"
                                    }
                                }
                            } catch {
                                # Continue searching
                            }
                        }
                    }
                } catch {
                    # Continue searching other folders
                }
            }
        }
    }
    catch {
        # Final fallback
    }
    
    # If all searches fail, return a cleaner message
    return "Custom Folder (ID not resolved)"
}

function Is-SuspiciousRule {
    param (
        [Parameter(Mandatory=$true)]
        $Rule,
        
        [Parameter(Mandatory=$false)]
        [string]$DestinationFolder = "N/A",
        
        [Parameter(Mandatory=$false)]
        [string]$Conditions = "No conditions specified",
        
        [Parameter(Mandatory=$false)]
        [string]$Actions = "No actions specified"
    )
    
    $suspiciousReason = @()
    
    # Ensure we have valid string values to work with
    $safeDestinationFolder = if ([string]::IsNullOrEmpty($DestinationFolder)) { "N/A" } else { $DestinationFolder }
    $safeConditions = if ([string]::IsNullOrEmpty($Conditions)) { "No conditions specified" } else { $Conditions }
    $safeActions = if ([string]::IsNullOrEmpty($Actions)) { "No actions specified" } else { $Actions }
    $safeRuleName = if ($Rule -and $Rule.displayName) { $Rule.displayName } else { "" }
    
    # Check for suspicious destination folders using the parameterized list
    if ($SuspiciousFolders -contains $safeDestinationFolder) {
        $suspiciousReason += "Suspicious destination folder: $safeDestinationFolder"
    }
    
    # Check for suspicious rule names using the parameterized list
    if (![string]::IsNullOrEmpty($safeRuleName) -and $SuspiciousNames -contains $safeRuleName) {
        $suspiciousReason += "Suspicious rule name: '$safeRuleName'"
    }
    
    # Check for keyword matches in conditions and rule names using the parameterized list
    foreach ($keyword in $SuspiciousKeywords) {
        if ($safeConditions -match $keyword -or $safeRuleName -match $keyword) {
            $suspiciousReason += "Contains suspicious keyword: '$keyword'"
        }
    }
    
    # Check for forwarding actions, which could be suspicious
    if ($safeActions -match "Forward to:" -or $safeActions -match "Redirect to:" -or $safeActions -match "Forward as attachment to:") {
        $suspiciousReason += "Contains forwarding action"
    }
    
    if ($suspiciousReason.Count -gt 0) {
        return ($suspiciousReason -join "; ")
    } else {
        return $null
    }
}

# Main script execution
$ErrorActionPreference = "Continue"  # Don't stop on errors
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$outputFolder = "SuspiciousInboxRules-$timestamp"
New-Item -ItemType Directory -Path $outputFolder -Force | Out-Null

# Create arrays to hold all reports
$allSuspiciousRules = @()
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
            
            $clientName = $tenant.Client.Trim()
            $tenantId = $tenant.'Tenant ID'.Trim()
            $clientId = $tenant.'Client ID'.Trim()
            $clientSecret = $tenant.'Key Value'.Trim()
            
            Write-Host "`n=======================================================" -ForegroundColor Cyan
            Write-Host "Processing tenant: $clientName ($tenantId)" -ForegroundColor Cyan
            Write-Host "=======================================================" -ForegroundColor Cyan
            
            try {
                # Get authentication token
                Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
                $accessToken = Get-MsGraphToken -TenantId $tenantId -ClientId $clientId -ClientSecret $clientSecret
                
                # Get all enabled users with licenses
                Write-Host "Retrieving enabled users with licenses..." -ForegroundColor Yellow
                $users = Get-EnabledLicensedUsers -AccessToken $accessToken
                
                Write-Host "Found $($users.Count) enabled, licensed users. Scanning for suspicious inbox rules..." -ForegroundColor Yellow
                
                # Track suspicious rules for this tenant
                $suspiciousRulesCount = 0
                $affectedUsersCount = 0
                $uniqueAffectedUsers = @{}
                
                # Process each user
                $counter = 0
                
                foreach ($user in $users) {
                    $counter++
                    Write-Progress -Activity "Processing Users" -Status "Processing user $counter of $($users.Count): $($user.displayName)" -PercentComplete (($counter / $users.Count) * 100)
                    
                    # Validate user object has required properties
                    if (-not $user.id -or -not $user.displayName -or -not $user.userPrincipalName) {
                        Write-Warning "Skipping user with incomplete information: $($user | ConvertTo-Json -Compress)"
                        continue
                    }
                    
                    # Get user's inbox rules - pass display name and UPN for better error reporting
                    $rules = Get-UserInboxRules -AccessToken $accessToken -UserId $user.id -UserDisplayName $user.displayName -UserPrincipalName $user.userPrincipalName
                    $userHasSuspiciousRule = $false
                    
                    foreach ($rule in $rules) {
                        # Skip malformed rules
                        if ($null -eq $rule) { continue }
                        
                        # Format rule conditions and actions with null safety
                        $conditionsFormatted = Format-RuleConditions -Conditions $rule.conditions
                        $actionsFormatted = Format-RuleActions -Actions $rule.actions -AccessToken $accessToken -UserId $user.id
                        
                        # Get human-readable destination folder if applicable
                        $destinationFolder = "N/A"
                        if ($rule.actions -and $rule.actions.moveToFolder) {
                            $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.moveToFolder
                        } elseif ($rule.actions -and $rule.actions.copyToFolder) {
                            $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.copyToFolder
                        }
                        
                        # Check if this rule matches any suspicious criteria with safe parameters
                        $suspiciousReason = Is-SuspiciousRule -Rule $rule -DestinationFolder $destinationFolder -Conditions $conditionsFormatted -Actions $actionsFormatted
                        
                        if ($suspiciousReason) {
                            $suspiciousRulesCount++
                            $userHasSuspiciousRule = $true
                            
                            $allSuspiciousRules += [PSCustomObject]@{
                                ClientName          = $clientName
                                TenantId            = $tenantId
                                UserDisplayName     = $user.displayName
                                UserPrincipalName   = $user.userPrincipalName
                                RuleDisplayName     = $rule.displayName
                                IsEnabled           = $rule.isEnabled
                                Conditions          = $conditionsFormatted
                                Actions             = $actionsFormatted
                                DestinationFolder   = $destinationFolder
                                SuspiciousReason    = $suspiciousReason
                            }
                        }
                    }
                    
                    # Count unique affected users
                    if ($userHasSuspiciousRule) {
                        $uniqueAffectedUsers[$user.id] = $true
                    }
                }
                
                Write-Progress -Activity "Processing Users" -Completed
                
                $affectedUsersCount = $uniqueAffectedUsers.Count
                
                # Add tenant summary
                $tenantSummaries += [PSCustomObject]@{
                    ClientName           = $clientName
                    TenantId             = $tenantId
                    TotalUsers           = $users.Count
                    SuspiciousRulesCount = $suspiciousRulesCount
                    AffectedUsersCount   = $affectedUsersCount
                    PercentageAffected   = if ($users.Count -gt 0) { [math]::Round(($affectedUsersCount / $users.Count) * 100, 2) } else { 0 }
                }
                
                Write-Host "Found $suspiciousRulesCount suspicious rules across $affectedUsersCount users in $clientName" -ForegroundColor Yellow
                
            } catch {
                Write-Error "Error processing tenant $clientName ($tenantId): $_"
            }
        }
        
        # Export consolidated reports
        $summaryFile = Join-Path -Path $outputFolder -ChildPath "TenantSummary.csv"
        $tenantSummaries | Export-Csv -Path $summaryFile -NoTypeInformation
        
        $detailedFile = Join-Path -Path $outputFolder -ChildPath "SuspiciousRules-Detailed.csv"
        $allSuspiciousRules | Export-Csv -Path $detailedFile -NoTypeInformation
        
        # Generate HTML report
        $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "SuspiciousRulesReport.html"
        
        $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Suspicious Inbox Rules Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .summary { background-color: #e6f2ff; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .warning { color: #cc0000; }
    </style>
</head>
<body>
    <h1>Suspicious Inbox Rules Report</h1>
    <div class="summary">
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Total Tenants Scanned: $($tenantSummaries.Count)</p>
        <p>Total Suspicious Rules Found: $($allSuspiciousRules.Count)</p>
        <p>Total Affected Users: $($allSuspiciousRules | Select-Object -Property UserPrincipalName -Unique | Measure-Object | Select-Object -ExpandProperty Count)</p>
    </div>
"@
        
        $tenantSummaryHtml = @"
    <h2>Tenant Summary</h2>
    <table>
        <tr>
            <th>Client Name</th>
            <th>Total Users</th>
            <th>Suspicious Rules</th>
            <th>Affected Users</th>
            <th>% Affected</th>
        </tr>
"@
        
        foreach ($summary in $tenantSummaries) {
            $tenantSummaryHtml += @"
        <tr>
            <td>$($summary.ClientName)</td>
            <td>$($summary.TotalUsers)</td>
            <td>$($summary.SuspiciousRulesCount)</td>
            <td>$($summary.AffectedUsersCount)</td>
            <td>$($summary.PercentageAffected)%</td>
        </tr>
"@
        }
        
        $tenantSummaryHtml += "</table>"
        
        $detailedHtml = ""
        if ($allSuspiciousRules.Count -gt 0) {
            $detailedHtml = @"
    <h2>Detailed Suspicious Rules</h2>
    <table>
        <tr>
            <th>Client Name</th>
            <th>User</th>
            <th>Rule Name</th>
            <th>Enabled</th>
            <th>Suspicious Reason</th>
            <th>Conditions</th>
            <th>Actions</th>
            <th>Destination Folder</th>
        </tr>
"@
            
            foreach ($rule in $allSuspiciousRules) {
                $detailedHtml += @"
        <tr>
            <td>$($rule.ClientName)</td>
            <td>$($rule.UserDisplayName)<br><small>$($rule.UserPrincipalName)</small></td>
            <td>$($rule.RuleDisplayName)</td>
            <td>$($rule.IsEnabled)</td>
            <td class="warning">$($rule.SuspiciousReason)</td>
            <td>$($rule.Conditions)</td>
            <td>$($rule.Actions)</td>
            <td>$($rule.DestinationFolder)</td>
        </tr>
"@
            }
            
            $detailedHtml += "</table>"
        }
        
        $htmlFooter = @"
</body>
</html>
"@
        
        $htmlReport = $htmlHeader + $tenantSummaryHtml + $detailedHtml + $htmlFooter
        $htmlReport | Out-File -FilePath $htmlReportPath -Encoding utf8
        
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
    
    # Get authentication token
    Write-Host "Authenticating to Microsoft Graph..." -ForegroundColor Yellow
    $accessToken = Get-MsGraphToken -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
    
    # Get all enabled users with licenses
    Write-Host "Retrieving enabled users with licenses..." -ForegroundColor Yellow
    $users = Get-EnabledLicensedUsers -AccessToken $accessToken
    
    Write-Host "Found $($users.Count) enabled, licensed users. Scanning for suspicious inbox rules..." -ForegroundColor Yellow
    
    # Process each user
    $counter = 0
    $suspiciousRulesCount = 0
    $uniqueAffectedUsers = @{}
    
    foreach ($user in $users) {
        $counter++
        Write-Progress -Activity "Processing Users" -Status "Processing user $counter of $($users.Count): $($user.displayName)" -PercentComplete (($counter / $users.Count) * 100)
        
        # Validate user object has required properties
        if (-not $user.id -or -not $user.displayName -or -not $user.userPrincipalName) {
            Write-Warning "Skipping user with incomplete information: $($user | ConvertTo-Json -Compress)"
            continue
        }
        
        # Get user's inbox rules - pass display name and UPN for better error reporting
        $rules = Get-UserInboxRules -AccessToken $accessToken -UserId $user.id -UserDisplayName $user.displayName -UserPrincipalName $user.userPrincipalName
        $userHasSuspiciousRule = $false
        
        foreach ($rule in $rules) {
            # Skip malformed rules
            if ($null -eq $rule) { continue }
            
            # Format rule conditions and actions with null safety
            $conditionsFormatted = Format-RuleConditions -Conditions $rule.conditions
            $actionsFormatted = Format-RuleActions -Actions $rule.actions -AccessToken $accessToken -UserId $user.id
            
            # Get human-readable destination folder if applicable
            $destinationFolder = "N/A"
            if ($rule.actions -and $rule.actions.moveToFolder) {
                $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.moveToFolder
            } elseif ($rule.actions -and $rule.actions.copyToFolder) {
                $destinationFolder = Get-FolderPathById -AccessToken $accessToken -UserId $user.id -FolderId $rule.actions.copyToFolder
            }
            
            # Check if this rule matches any suspicious criteria with safe parameters
            $suspiciousReason = Is-SuspiciousRule -Rule $rule -DestinationFolder $destinationFolder -Conditions $conditionsFormatted -Actions $actionsFormatted
            
            if ($suspiciousReason) {
                $suspiciousRulesCount++
                $userHasSuspiciousRule = $true
                
                $allSuspiciousRules += [PSCustomObject]@{
                    ClientName          = "Direct Access"
                    TenantId            = $TenantId
                    UserDisplayName     = $user.displayName
                    UserPrincipalName   = $user.userPrincipalName
                    RuleDisplayName     = $rule.displayName
                    IsEnabled           = $rule.isEnabled
                    Conditions          = $conditionsFormatted
                    Actions             = $actionsFormatted
                    DestinationFolder   = $destinationFolder
                    SuspiciousReason    = $suspiciousReason
                }
            }
        }
        
        # Count unique affected users
        if ($userHasSuspiciousRule) {
            $uniqueAffectedUsers[$user.id] = $true
        }
    }
    
    Write-Progress -Activity "Processing Users" -Completed
    
    $affectedUsersCount = $uniqueAffectedUsers.Count
    
    # Create summary object
    $tenantSummary = [PSCustomObject]@{
        ClientName           = "Direct Access"
        TenantId             = $TenantId
        TotalUsers           = $users.Count
        SuspiciousRulesCount = $suspiciousRulesCount
        AffectedUsersCount   = $affectedUsersCount
        PercentageAffected   = if ($users.Count -gt 0) { [math]::Round(($affectedUsersCount / $users.Count) * 100, 2) } else { 0 }
    }
    
    $tenantSummaries += $tenantSummary
    
    # Export reports
    $summaryFile = Join-Path -Path $outputFolder -ChildPath "TenantSummary.csv"
    $tenantSummaries | Export-Csv -Path $summaryFile -NoTypeInformation
    
    $detailedFile = Join-Path -Path $outputFolder -ChildPath "SuspiciousRules-Detailed.csv"
    $allSuspiciousRules | Export-Csv -Path $detailedFile -NoTypeInformation
    
    # Generate HTML report
    $htmlReportPath = Join-Path -Path $outputFolder -ChildPath "SuspiciousRulesReport.html"
    
    $htmlHeader = @"
<!DOCTYPE html>
<html>
<head>
    <title>Suspicious Inbox Rules Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2 { color: #0066cc; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .summary { background-color: #e6f2ff; padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .warning { color: #cc0000; }
    </style>
</head>
<body>
    <h1>Suspicious Inbox Rules Report</h1>
    <div class="summary">
        <p>Generated on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Total Tenants Scanned: 1</p>
        <p>Total Suspicious Rules Found: $suspiciousRulesCount</p>
        <p>Total Affected Users: $affectedUsersCount</p>
    </div>
"@
    
    $tenantSummaryHtml = @"
    <h2>Tenant Summary</h2>
    <table>
        <tr>
            <th>Tenant ID</th>
            <th>Total Users</th>
            <th>Suspicious Rules</th>
            <th>Affected Users</th>
            <th>% Affected</th>
        </tr>
        <tr>
            <td>$TenantId</td>
            <td>$($users.Count)</td>
            <td>$suspiciousRulesCount</td>
            <td>$affectedUsersCount</td>
            <td>$($tenantSummary.PercentageAffected)%</td>
        </tr>
    </table>
"@
    
    $detailedHtml = ""
    if ($allSuspiciousRules.Count -gt 0) {
        $detailedHtml = @"
    <h2>Detailed Suspicious Rules</h2>
    <table>
        <tr>
            <th>User</th>
            <th>Rule Name</th>
            <th>Enabled</th>
            <th>Suspicious Reason</th>
            <th>Conditions</th>
            <th>Actions</th>
            <th>Destination Folder</th>
        </tr>
"@
        
        foreach ($rule in $allSuspiciousRules) {
            $detailedHtml += @"
        <tr>
            <td>$($rule.UserDisplayName)<br><small>$($rule.UserPrincipalName)</small></td>
            <td>$($rule.RuleDisplayName)</td>
            <td>$($rule.IsEnabled)</td>
            <td class="warning">$($rule.SuspiciousReason)</td>
            <td>$($rule.Conditions)</td>
            <td>$($rule.Actions)</td>
            <td>$($rule.DestinationFolder)</td>
        </tr>
"@
        }
        
        $detailedHtml += "</table>"
    }
    
    $htmlFooter = @"
</body>
</html>
"@
    
    $htmlReport = $htmlHeader + $tenantSummaryHtml + $detailedHtml + $htmlFooter
    $htmlReport | Out-File -FilePath $htmlReportPath -Encoding utf8
    
    Write-Host "`nScan complete. Reports saved to folder: $outputFolder" -ForegroundColor Green
    Write-Host "Summary Report: $summaryFile" -ForegroundColor Green
    Write-Host "Detailed Report: $detailedFile" -ForegroundColor Green
    Write-Host "HTML Report: $htmlReportPath" -ForegroundColor Green
}
