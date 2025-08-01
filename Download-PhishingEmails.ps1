<#
.SYNOPSIS
    Downloads phishing emails and malicious content from Microsoft 365 across multiple tenants using Graph API for incident response.

.DESCRIPTION
    This script searches Microsoft 365 mailboxes for emails matching specific criteria and downloads them as EML files
    with full headers and attachments for forensic analysis. Unlike most tools this one esschews the burdensome Microsoft Graph modules and makes direct API calls to Graph using established Azure App permissions. Designed for SOC analysts and incident responders to
    quickly collect evidence during phishing investigations with a lower chance of user error than traditional emails forwardings and eDiscovery. This tool accepts a CSV file containing client name, app ID, client ID, and app secret values to allow for searcing suspicious subject lines across multiple tenants.

.PARAMETER SubjectKeyword
    Keyword to search for in email subjects (partial match, case-insensitive).
    Example: "RE: testfiles" will match "RE: testfiles@company.com shared file"

.PARAMETER ClientName
    Name of the client/organization as defined in the AzureAppKeys.csv file.
    Must match exactly with the "Client" column in your CSV.

.PARAMETER AppKeysCSV
    Path to CSV file containing Azure app registration credentials.
    CSV format: Client,Tenant ID,Client ID,Key Value,Expiry

.PARAMETER UserPrincipalName
    Specific user's email address to search. Required unless -SearchAllMailboxes is used.
    Example: "user@company.com"

.PARAMETER SearchAllMailboxes
    Switch to search all mailboxes in the tenant instead of a specific user.
    Requires appropriate permissions in Azure app registration.

.PARAMETER OutputPath
    Directory where downloaded emails will be saved. Default: "C:\EmailDownloads"
    Creates subdirectories for each mailbox when searching all mailboxes.

.PARAMETER MaxResults
    Maximum number of emails to download per mailbox. Default: 50

.PARAMETER DaysBack
    Number of days to search backwards from today. Default: 30

.EXAMPLE
    .\Download-PhishingEmail.ps1 -AppKeysCSV ".\AzureAppKeys.csv" -SubjectKeyword "Invoice" -ClientName "Acme Corp" -UserPrincipalName "victim@acmecorp.com"
    
    Downloads emails containing "Invoice" in subject from victim@acmecorp.com for the last 30 days.

.EXAMPLE
    .\Download-PhishingEmail.ps1 -AppKeysCSV ".\AzureAppKeys.csv" -SubjectKeyword "shared" -ClientName "Acme Corp" -SearchAllMailboxes -DaysBack 7 -MaxResults 10
    
    Searches all mailboxes for emails with "shared" in subject from the last 7 days, max 10 results per mailbox.

.EXAMPLE
    .\Download-PhishingEmail.ps1 -AppKeysCSV "C:\SOC\Keys.csv" -SubjectKeyword "urgent payment" -ClientName "Acme Corp" -UserPrincipalName "cfo@acmecorp.com" -OutputPath "C:\Investigations\Case123"
    
    Downloads urgent payment phishing emails to a specific case folder.

.NOTES
    Author: Geoff Tankersley
    Version: 2.0
    Requirements:
    - Azure App Registration with Mail.Read.All and Mail.ReadWrite.All delegated permissions. Most SIEMs will already have an Azure App generated for Unified Audit Log monitoring.
    - PowerShell 5.1 or later

    
    Output Files:
    - *.eml: Raw email files that can be opened in Outlook or email forensic tools
    - *_Headers.txt: Extracted headers for quick analysis
    - EmailSummary_*.csv: Summary of all downloaded emails with metadata
    
    Permissions Required:
    - Mail.Read (minimum)
    - Mail.ReadWrite (for downloading of actual EML files and attachments)
    - User.Read.All (for SearchAllMailboxes)


#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SubjectKeyword,
    
    [Parameter(Mandatory=$true)]
    [string]$ClientName,
    
    [Parameter(Mandatory=$true)]
    [string]$AppKeysCSV,
    
    [Parameter(Mandatory=$false)]
    [string]$UserPrincipalName = $null,
    
    [Parameter(Mandatory=$false)]
    [switch]$SearchAllMailboxes,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\EmailDownloads",
    
    [Parameter(Mandatory=$false)]
    [int]$MaxResults = 50,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysBack = 30
)

# Load app credentials from CSV
function Get-AppCredentials {
    param([string]$CsvPath, [string]$Client)
    
    if (!(Test-Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"
        exit 1
    }
    
    try {
        $apps = Import-Csv -Path $CsvPath
        $app = $apps | Where-Object { $_.Client -eq $Client }
        
        if (!$app) {
            Write-Error "Client '$Client' not found in CSV. Available clients:"
            $apps | ForEach-Object { Write-Host "  - $($_.Client)" -ForegroundColor Cyan }
            exit 1
        }
        
        # Check if key is expired
        if ($app.Expiry) {
            try {
                $expiryDate = [DateTime]::Parse($app.Expiry)
                if ($expiryDate -lt (Get-Date)) {
                    Write-Warning "App secret for '$Client' expired on $($app.Expiry)"
                }
            }
            catch {
                Write-Warning "Could not parse expiry date: $($app.Expiry)"
            }
        }
        
        Write-Host "Using app registration: $Client" -ForegroundColor Green
        Write-Host "Tenant ID: $($app.'Tenant ID')" -ForegroundColor Cyan
        Write-Host "Client ID: $($app.'Client ID')" -ForegroundColor Cyan
        
        return @{
            TenantId = $app.'Tenant ID'
            ClientId = $app.'Client ID'
            ClientSecret = $app.'Key Value'
        }
    }
    catch {
        Write-Error "Error loading app credentials: $_"
        exit 1
    }
}

# Get access token using client credentials flow
function Get-AccessToken {
    param($Credentials)
    
    try {
        Write-Host "Getting access token..." -ForegroundColor Yellow
        
        $tokenUrl = "https://login.microsoftonline.com/$($Credentials.TenantId)/oauth2/v2.0/token"
        
        $body = @{
            client_id = $Credentials.ClientId
            client_secret = $Credentials.ClientSecret
            scope = "https://graph.microsoft.com/.default"
            grant_type = "client_credentials"
        }
        
        $response = Invoke-RestMethod -Uri $tokenUrl -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
        
        Write-Host "Access token obtained successfully" -ForegroundColor Green
        Write-Host "Token expires in: $($response.expires_in) seconds" -ForegroundColor Cyan
        
        return $response.access_token
    }
    catch {
        Write-Error "Failed to get access token: $_"
        if ($_.Exception.Response) {
            $errorResponse = $_.Exception.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $errorBody = $reader.ReadToEnd()
            Write-Host "Error details: $errorBody" -ForegroundColor Red
        }
        return $null
    }
}

# Make Graph API call
function Invoke-GraphAPI {
    param(
        [string]$AccessToken,
        [string]$Endpoint,
        [string]$Method = "GET",
        [hashtable]$Body = $null
    )
    
    try {
        $headers = @{
            "Authorization" = "Bearer $AccessToken"
            "Content-Type" = "application/json"
        }
        
        $params = @{
            Uri = "https://graph.microsoft.com/v1.0$Endpoint"
            Method = $Method
            Headers = $headers
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        $response = Invoke-RestMethod @params
        return $response
    }
    catch {
        Write-Error "Graph API call failed: $_"
        if ($_.Exception.Response) {
            $statusCode = $_.Exception.Response.StatusCode
            $statusDescription = $_.Exception.Response.StatusDescription
            Write-Host "HTTP Status: $statusCode - $statusDescription" -ForegroundColor Red
            
            try {
                $errorStream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($errorStream)
                $errorBody = $reader.ReadToEnd()
                Write-Host "Error body: $errorBody" -ForegroundColor Red
            }
            catch {
                Write-Host "Could not read error response body" -ForegroundColor Red
            }
        }
        return $null
    }
}

# Search for emails
function Search-Emails {
    param(
        [string]$AccessToken,
        [string]$UserEmail,
        [string]$Subject,
        [int]$Days,
        [int]$Limit
    )
    
    try {
        Write-Host "Searching mailbox: $UserEmail" -ForegroundColor Cyan
        Write-Host "Subject contains: '$Subject'" -ForegroundColor Cyan
        Write-Host "Looking back $Days days from today (since $(((Get-Date).AddDays(-$Days)).ToString('yyyy-MM-dd')))" -ForegroundColor Cyan
        
        # First, get recent messages without complex filtering
        $endpoint = "/users/$UserEmail/messages"
        $endpoint += "?`$top=1000"  # Get more messages to filter locally
        $endpoint += "&`$select=id,subject,sender,receivedDateTime,bodyPreview,hasAttachments,internetMessageId"
        $endpoint += "&`$orderby=receivedDateTime desc"
        
        Write-Host "Getting recent messages..." -ForegroundColor Yellow
        Write-Host "API Endpoint: $endpoint" -ForegroundColor Gray
        
        $response = Invoke-GraphAPI -AccessToken $AccessToken -Endpoint $endpoint
        
        if ($response -and $response.value) {
            Write-Host "Retrieved $($response.value.Count) recent messages, filtering locally..." -ForegroundColor Yellow
            
            # Filter locally by subject and date
            $cutoffDate = (Get-Date).AddDays(-$Days)
            $filteredMessages = @()
            
            foreach ($message in $response.value) {
                try {
                    $messageDate = [DateTime]::Parse($message.receivedDateTime)
                    
                    # Check if message is within date range and subject matches
                    if ($messageDate -ge $cutoffDate -and $message.subject -like "*$Subject*") {
                        $filteredMessages += $message
                    }
                    
                    # Stop if we have enough results
                    if ($filteredMessages.Count -ge $Limit) {
                        break
                    }
                }
                catch {
                    Write-Warning "Could not parse date for message: $($message.subject)"
                }
            }
            
            if ($filteredMessages.Count -gt 0) {
                Write-Host "Found $($filteredMessages.Count) matching messages" -ForegroundColor Green
                return $filteredMessages
            } else {
                Write-Host "No messages found matching criteria after filtering" -ForegroundColor Yellow
                return $null
            }
        } else {
            Write-Host "No messages retrieved from mailbox" -ForegroundColor Yellow
            return $null
        }
    }
    catch {
        Write-Error "Error searching emails: $_"
        return $null
    }
}

# Extract headers from EML file
function Extract-EmailHeaders {
    param(
        [string]$EmlFilePath
    )
    
    try {
        $content = Get-Content -Path $EmlFilePath -Raw -Encoding UTF8
        
        # Split headers from body (headers end at first blank line)
        $headerSection = $content -split "`r`n`r`n|`n`n" | Select-Object -First 1
        
        # Parse headers
        $headers = @{}
        $currentHeader = ""
        $currentValue = ""
        
        foreach ($line in ($headerSection -split "`r`n|`n")) {
            if ($line -match "^([^:]+):\s*(.*)$") {
                # Save previous header if exists
                if ($currentHeader) {
                    $headers[$currentHeader] = $currentValue.Trim()
                }
                
                # Start new header
                $currentHeader = $matches[1]
                $currentValue = $matches[2]
            }
            elseif ($line -match "^\s+(.*)$" -and $currentHeader) {
                # Continuation of previous header (folded header)
                $currentValue += " " + $matches[1]
            }
        }
        
        # Save last header
        if ($currentHeader) {
            $headers[$currentHeader] = $currentValue.Trim()
        }
        
        return $headers
    }
    catch {
        Write-Warning "Failed to extract headers from $EmlFilePath`: $_"
        return @{}
    }
}

# Get all mailboxes in the tenant
function Get-AllMailboxes {
    param([string]$AccessToken)
    
    try {
        Write-Host "Getting all mailboxes in tenant..." -ForegroundColor Yellow
        
        $allUsers = @()
        $endpoint = "/users?`$select=id,userPrincipalName,displayName,mail&`$filter=accountEnabled eq true and userType eq 'Member'"
        
        do {
            $response = Invoke-GraphAPI -AccessToken $AccessToken -Endpoint $endpoint
            if ($response -and $response.value) {
                $allUsers += $response.value | Where-Object { $_.mail -ne $null }
            }
            $endpoint = if ($response.'@odata.nextLink') { $response.'@odata.nextLink'.Replace('https://graph.microsoft.com/v1.0', '') } else { $null }
        } while ($endpoint)
        
        Write-Host "Found $($allUsers.Count) mailboxes" -ForegroundColor Green
        return $allUsers
    }
    catch {
        Write-Error "Failed to get mailboxes: $_"
        return @()
    }
}
function Get-EmailAttachments {
    param(
        [string]$AccessToken,
        [string]$UserEmail,
        [string]$MessageId
    )
    
    try {
        $endpoint = "/users/$UserEmail/messages/$MessageId/attachments"
        $response = Invoke-GraphAPI -AccessToken $AccessToken -Endpoint $endpoint
        
        if ($response -and $response.value) {
            return $response.value
        }
        return $null
    }
    catch {
        Write-Warning "Failed to get attachments for message $MessageId`: $_"
        return $null
    }
}

# Download attachment content
function Download-Attachment {
    param(
        [string]$AccessToken,
        [string]$UserEmail,
        [string]$MessageId,
        [string]$AttachmentId,
        [string]$AttachmentName,
        [string]$OutputPath
    )
    
    try {
        $endpoint = "/users/$UserEmail/messages/$MessageId/attachments/$AttachmentId"
        $attachment = Invoke-GraphAPI -AccessToken $AccessToken -Endpoint $endpoint
        
        if ($attachment -and $attachment.contentBytes) {
            # Decode base64 content
            $bytes = [System.Convert]::FromBase64String($attachment.contentBytes)
            
            # Save to file
            $filePath = Join-Path $OutputPath $AttachmentName
            [System.IO.File]::WriteAllBytes($filePath, $bytes)
            
            return @{
                Success = $true
                FilePath = $filePath
                Size = $bytes.Length
            }
        }
        return @{ Success = $false; Error = "No content bytes" }
    }
    catch {
        return @{ Success = $false; Error = $_.Exception.Message }
    }
}
function Get-EmailContent {
    param(
        [string]$AccessToken,
        [string]$UserEmail,
        [string]$MessageId,
        [switch]$GetRawMessage
    )
    
    try {
        if ($GetRawMessage) {
            # Get the raw MIME content
            $endpoint = "/users/$UserEmail/messages/$MessageId/`$value"
            $headers = @{
                "Authorization" = "Bearer $AccessToken"
            }
            
            $response = Invoke-WebRequest -Uri "https://graph.microsoft.com/v1.0$endpoint" -Headers $headers
            return $response.Content
        } else {
            # Get metadata
            $endpoint = "/users/$UserEmail/messages/$MessageId"
            $endpoint += "?`$select=id,subject,sender,receivedDateTime,body,hasAttachments,internetMessageId,toRecipients,ccRecipients,bccRecipients"
            
            $response = Invoke-GraphAPI -AccessToken $AccessToken -Endpoint $endpoint
            return $response
        }
    }
    catch {
        Write-Warning "Failed to get content for message $MessageId`: $_"
        return $null
    }
}

# Download and save emails
function Download-Emails {
    param(
        [string]$AccessToken,
        [array]$Messages,
        [string]$UserEmail,
        [string]$OutputDir
    )
    
    if (!$Messages -or $Messages.Count -eq 0) {
        Write-Host "No messages to download." -ForegroundColor Yellow
        return
    }
    
    # Ensure output directory exists
    if (!(Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
        Write-Host "Created directory: $OutputDir" -ForegroundColor Green
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $results = @()
    $counter = 0
    
    Write-Host "Downloading $($Messages.Count) emails as EML files..." -ForegroundColor Yellow
    
    foreach ($message in $Messages) {
        $counter++
        Write-Progress -Activity "Downloading Emails" -Status "Processing email $counter of $($Messages.Count)" -PercentComplete (($counter / $Messages.Count) * 100)
        
        try {
            # Get metadata first
            $fullMessage = Get-EmailContent -AccessToken $AccessToken -UserEmail $UserEmail -MessageId $message.id
            
            if ($fullMessage) {
                # Get raw MIME content
                Write-Host "  [$counter/$($Messages.Count)] Getting raw message: $($fullMessage.subject)" -ForegroundColor Gray
                $rawMessage = Get-EmailContent -AccessToken $AccessToken -UserEmail $UserEmail -MessageId $message.id -GetRawMessage
                
                if ($rawMessage) {
                    # Create email data object for CSV
                    $emailData = [PSCustomObject]@{
                        MessageId = $fullMessage.id
                        InternetMessageId = $fullMessage.internetMessageId
                        Subject = $fullMessage.subject
                        Sender = if ($fullMessage.sender.emailAddress) { $fullMessage.sender.emailAddress.address } else { "Unknown" }
                        SenderName = if ($fullMessage.sender.emailAddress) { $fullMessage.sender.emailAddress.name } else { "Unknown" }
                        ReceivedDateTime = $fullMessage.receivedDateTime
                        HasAttachments = $fullMessage.hasAttachments
                        ToRecipients = if ($fullMessage.toRecipients) { ($fullMessage.toRecipients | ForEach-Object { $_.emailAddress.address }) -join "; " } else { "" }
                        CcRecipients = if ($fullMessage.ccRecipients) { ($fullMessage.ccRecipients | ForEach-Object { $_.emailAddress.address }) -join "; " } else { "" }
                        BccRecipients = if ($fullMessage.bccRecipients) { ($fullMessage.bccRecipients | ForEach-Object { $_.emailAddress.address }) -join "; " } else { "" }
                        FileName = ""  # Will update this below
                    }
                    
                    $results += $emailData
                    
                    # Save raw email as EML file
                    $sanitizedSubject = $fullMessage.subject -replace '[<>:"/\\|?*]', '_'
                    $receivedDate = [DateTime]::Parse($fullMessage.receivedDateTime)
                    $emlFileName = "$($receivedDate.ToString('yyyyMMdd_HHmmss'))_$($sanitizedSubject.Substring(0, [Math]::Min(50, $sanitizedSubject.Length))).eml"
                    $emlPath = Join-Path $OutputDir $emlFileName
                    
                    # Convert MIME to EML
                    [System.Text.Encoding]::UTF8.GetBytes($rawMessage) | Set-Content -Path $emlPath -Encoding Byte
                    
                    # Update filename in results
                    $emailData.FileName = $emlFileName
                    
                    # Extract headers
                    Write-Host "    Extracting headers..." -ForegroundColor Yellow
                    $headers = Extract-EmailHeaders -EmlFilePath $emlPath
                    
                    if ($headers.Count -gt 0) {
                        # Save headers
                        $headersFileName = "$($receivedDate.ToString('yyyyMMdd_HHmmss'))_$($sanitizedSubject.Substring(0, [Math]::Min(30, $sanitizedSubject.Length)))_Headers.txt"
                        $headersPath = Join-Path $OutputDir $headersFileName
                        
                        $headerOutput = @()
                        $headerOutput += "=" * 60
                        $headerOutput += "EMAIL HEADERS ANALYSIS"
                        $headerOutput += "=" * 60
                        $headerOutput += "File: $emlFileName"
                        $headerOutput += "Extracted: $(Get-Date)"
                        $headerOutput += "=" * 60
                        $headerOutput += ""
                        
                        $keyHeaders = @(
                            "Return-Path", "Delivered-To", "Received", "Authentication-Results", 
                            "DKIM-Signature", "SPF", "DMARC", "Message-ID", "Date", "From", 
                            "To", "Cc", "Bcc", "Subject", "Reply-To", "Sender", "X-Originating-IP", 
                            "X-Mailer", "User-Agent", "X-Priority", "Importance", "X-MS-Exchange-Organization-AuthSource"
                        )
                        
                        $headerOutput += "KEY HEADERS FOR ANALYSIS:"
                        $headerOutput += "-" * 40
                        foreach ($key in $keyHeaders) {
                            if ($headers.ContainsKey($key)) {
                                $headerOutput += "$key`: $($headers[$key])"
                            }
                        }
                        
                        $headerOutput += ""
                        $headerOutput += "ALL HEADERS (ALPHABETICAL):"
                        $headerOutput += "-" * 40
                        foreach ($header in ($headers.Keys | Sort-Object)) {
                            $headerOutput += "$header`: $($headers[$header])"
                        }
                        
                        $headerOutput | Out-File -FilePath $headersPath -Encoding UTF8
                        Write-Host "      Saved headers: $headersFileName" -ForegroundColor Green
                        
                        # Add key forensic info to email data
                       $emailData | Add-Member -MemberType NoteProperty -Name "HeaderMessageID" -Value $headers["Message-ID"] -Force
                       $emailData | Add-Member -MemberType NoteProperty -Name "OriginatingIP" -Value $headers["X-Originating-IP"] -Force
                       $emailData | Add-Member -MemberType NoteProperty -Name "ReturnPath" -Value $headers["Return-Path"] -Force
                       $emailData | Add-Member -MemberType NoteProperty -Name "HeadersFile" -Value $headersFileName -Force
                    }
                    
                    # Download attachments if present
                    $attachmentInfo = ""
                    if ($fullMessage.hasAttachments) {
                        Write-Host "    Getting attachments..." -ForegroundColor Yellow
                        $attachments = Get-EmailAttachments -AccessToken $AccessToken -UserEmail $UserEmail -MessageId $message.id
                        
                        if ($attachments) {
                            # Create attachments subfolder
                            $attachmentDir = Join-Path $OutputDir "Attachments_$($receivedDate.ToString('yyyyMMdd_HHmmss'))"
                            if (!(Test-Path $attachmentDir)) {
                                New-Item -ItemType Directory -Path $attachmentDir -Force | Out-Null
                            }
                            
                            $attachmentNames = @()
                            foreach ($attachment in $attachments) {
                                Write-Host "      Downloading: $($attachment.name)" -ForegroundColor Gray
                                
                                # Sanitize filename
                                $safeFileName = $attachment.name -replace '[<>:"/\\|?*]', '_'
                                
                                $result = Download-Attachment -AccessToken $AccessToken -UserEmail $UserEmail -MessageId $message.id -AttachmentId $attachment.id -AttachmentName $safeFileName -OutputPath $attachmentDir
                                
                                if ($result.Success) {
                                    $attachmentNames += $safeFileName
                                    $sizeKB = [math]::Round($result.Size / 1024, 2)
                                    Write-Host "      Saved: $safeFileName ($sizeKB KB)" -ForegroundColor Green
                                } else {
                                    Write-Warning "      Failed to download $($attachment.name): $($result.Error)"
                                }
                            }
                            
                            $attachmentInfo = "Folder: $attachmentDir | Files: $($attachmentNames -join ', ')"
                        }
                    }
                    
                    # Add attachment info to email data
                    $emailData | Add-Member -MemberType NoteProperty -Name "AttachmentInfo" -Value $attachmentInfo
                } else {
                    Write-Warning "Failed to get raw message content for: $($fullMessage.subject)"
                }
            }
        }
        catch {
            Write-Warning "Failed to download message $($counter): $($message.subject) - $_"
        }
    }
    
    Write-Progress -Activity "Downloading Emails" -Completed
    
    # Create CSV summary
    $csvPath = Join-Path $OutputDir "EmailSummary_$timestamp.csv"
    $results | Export-Csv -Path $csvPath -NoTypeInformation
    
    Write-Host "`nDownload Summary:" -ForegroundColor Cyan
    Write-Host "Total emails downloaded: $($results.Count)" -ForegroundColor White
    Write-Host "CSV summary: $csvPath" -ForegroundColor White
    Write-Host "EML files saved to: $OutputDir" -ForegroundColor White
    
    # Display summary table
    Write-Host "`nEmail Summary:" -ForegroundColor Cyan
    $results | Format-Table @{Name="Subject";Expression={$_.Subject.Substring(0,[Math]::Min(40,$_.Subject.Length))}}, Sender, ReceivedDateTime, HasAttachments, FileName -AutoSize
    
    return $results
}

# Main 
try {
    Write-Host "=== Microsoft Graph Email Search (Raw REST API) ===" -ForegroundColor Cyan
    Write-Host "Client: $ClientName" -ForegroundColor White
    Write-Host "Subject keyword: '$SubjectKeyword'" -ForegroundColor White
    Write-Host "Search mode: $(if ($SearchAllMailboxes) { 'ALL MAILBOXES' } else { $UserPrincipalName })" -ForegroundColor White
    Write-Host "Days back: $DaysBack" -ForegroundColor White
    Write-Host "Max results: $MaxResults" -ForegroundColor White
    Write-Host ""
    
    # Load .NET assembly for URL encoding
    Add-Type -AssemblyName System.Web
    
    # Load app credentials
    $appCreds = Get-AppCredentials -CsvPath $AppKeysCSV -Client $ClientName
    
    # Get access token
    $accessToken = Get-AccessToken -Credentials $appCreds
    if (!$accessToken) {
        Write-Error "Failed to obtain access token. Exiting."
        exit 1
    }
    
    $allResults = @()
    
    if ($SearchAllMailboxes) {
        # Search all mailboxes
        $mailboxes = Get-AllMailboxes -AccessToken $accessToken
        
        if ($mailboxes.Count -eq 0) {
            Write-Error "No mailboxes found or insufficient permissions"
            exit 1
        }
        
        Write-Host "Searching $($mailboxes.Count) mailboxes for subject: '$SubjectKeyword'" -ForegroundColor Cyan
        
        $mailboxCounter = 0
        foreach ($mailbox in $mailboxes) {
            $mailboxCounter++
            Write-Progress -Activity "Searching Mailboxes" -Status "[$mailboxCounter/$($mailboxes.Count)] $($mailbox.userPrincipalName)" -PercentComplete (($mailboxCounter / $mailboxes.Count) * 100)
            
            try {
                $foundEmails = Search-Emails -AccessToken $accessToken -UserEmail $mailbox.userPrincipalName -Subject $SubjectKeyword -Days $DaysBack -Limit $MaxResults
                
                if ($foundEmails) {
                    Write-Host "  Found $($foundEmails.Count) emails in $($mailbox.userPrincipalName)" -ForegroundColor Green
                    
                    # Create mailbox-specific output folder
                    $mailboxOutputPath = Join-Path $OutputPath $mailbox.userPrincipalName.Replace('@', '_at_')
                    
                    $results = Download-Emails -AccessToken $accessToken -Messages $foundEmails -UserEmail $mailbox.userPrincipalName -OutputDir $mailboxOutputPath
                    $allResults += $results
                }
            }
            catch {
                Write-Warning "Failed to search mailbox $($mailbox.userPrincipalName): $_"
            }
        }
        
        Write-Progress -Activity "Searching Mailboxes" -Completed
        
        if ($allResults.Count -gt 0) {
            # Create consolidated summary
            $consolidatedCsv = Join-Path $OutputPath "ConsolidatedResults_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $allResults | Export-Csv -Path $consolidatedCsv -NoTypeInformation
            
            Write-Host "`nConsolidated Results:" -ForegroundColor Cyan
            Write-Host "Total emails found: $($allResults.Count)" -ForegroundColor Green
            Write-Host "Consolidated CSV: $consolidatedCsv" -ForegroundColor Green
            Write-Host "Individual mailbox folders created in: $OutputPath" -ForegroundColor Green
        }
    } else {
        # Search single mailbox
        if ([string]::IsNullOrEmpty($UserPrincipalName)) {
            Write-Error "UserPrincipalName is required when not searching all mailboxes"
            exit 1
        }
        
        $foundEmails = Search-Emails -AccessToken $accessToken -UserEmail $UserPrincipalName -Subject $SubjectKeyword -Days $DaysBack -Limit $MaxResults
        
        if ($foundEmails) {
            $allResults = Download-Emails -AccessToken $accessToken -Messages $foundEmails -UserEmail $UserPrincipalName -OutputDir $OutputPath
        }
    }
    
    if ($allResults.Count -gt 0) {
        Write-Host "`nOperation completed successfully!" -ForegroundColor Green
        Write-Host "Downloaded $($allResults.Count) email(s) with headers and attachments" -ForegroundColor Green
    } else {
        Write-Host "No emails found matching the search criteria." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}
