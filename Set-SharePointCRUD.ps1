<#
.SYNOPSIS
    Enhanced PowerShell SharePoint CSV Manager for Azure App Registration credentials management.

.DESCRIPTION
    This script manages Azure App Registration credentials stored in a CSV file on SharePoint.
    Supports CRUD operations (Create, Read, Update, Delete) with secure authentication via Microsoft Graph API.
    The script reads from and writes to a CSV file located at SOAR/TestAzureAppKeys.csv on the specified SharePoint site.

.PARAMETER SiteUrl
    The SharePoint site URL where the CSV file is located.
    Example: "https://contoso.sharepoint.com/sites/IT"

.PARAMETER TenantId
    Azure AD Tenant ID used for authentication to SharePoint and Graph API.

.PARAMETER ClientId
    Azure AD Application Client ID used for authentication.

.PARAMETER ClientSecret
    Azure AD Application Client Secret used for authentication.

.PARAMETER Operation
    The operation to perform on the CSV data.
    Valid values: "Read", "Add", "List", "Update", "Delete"

.PARAMETER ClientName
    [Add/Update operations] Name of the client entry. For Add: creates new entry. For Update: renames existing entry.

.PARAMETER NewTenantId
    [Add/Update operations] Tenant ID value for the client entry.

.PARAMETER NewClientId
    [Add/Update operations] Client ID value for the client entry.

.PARAMETER NewClientSecret
    [Add/Update operations] Client Secret value for the client entry.

.PARAMETER NewExpiry
    [Add/Update operations] Expiry date for the client entry (optional).

.PARAMETER ClientIndex
    [Update/Delete operations] 1-based index number of the client to modify or delete.
    Use -Operation List first to see available indices.

.PARAMETER SearchClientName
    [Update/Delete operations] Name of the client to search for and modify or delete.
    Alternative to using ClientIndex.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    Console output with operation results. No objects are returned to the pipeline.

.NOTES
    File Name      : Set-SharePointCRUD.ps1
    Author         : Geoff Tankersley
    Prerequisite   : PowerShell 5.1+, Azure AD App Registration with SharePoint permissions
    CSV File Path  : SOAR/TestAzureAppKeys.csv
    CSV Format     : Client,Tenant ID,Client ID,Key Value,Expiry

.EXAMPLE
    .\Set-SharePointCRUD.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/IT" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "abcdefgh-1234-1234-1234-abcdefghijkl" -ClientSecret "your-secret-here" -Operation "List"
    
    Lists all client entries in the CSV file with masked secrets for security.

.EXAMPLE
    .\Set-SharePointCRUD.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/IT" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "abcdefgh-1234-1234-1234-abcdefghijkl" -ClientSecret "your-secret-here" -Operation "Add" -ClientName "Test Client 1" -NewTenantId "tenant-123" -NewClientId "client-456" -NewClientSecret "secret-789" -NewExpiry "12/31/2025"
    
    Adds a new client entry with the specified credentials and expiry date.

.EXAMPLE
    .\Set-SharePointCRUD.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/IT" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "abcdefgh-1234-1234-1234-abcdefghijkl" -ClientSecret "your-secret-here" -Operation "Update" -ClientIndex 3 -NewClientSecret "updated-secret-123"
    
    Updates the client secret for the client at index 3 (3rd entry in the list).

.EXAMPLE
    .\Set-SharePointCRUD.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/IT" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "abcdefgh-1234-1234-1234-abcdefghijkl" -ClientSecret "your-secret-here" -Operation "Update" -SearchClientName "Test Client 1" -NewClientSecret "new-secret" -NewExpiry "06/30/2026"
    
    Updates the client secret and expiry date for the client named "Test Client 1".

.EXAMPLE
    .\Set-SharePointCRUD.ps1 -SiteUrl "https://contoso.sharepoint.com/sites/IT" -TenantId "12345678-1234-1234-1234-123456789012" -ClientId "abcdefgh-1234-1234-1234-abcdefghijkl" -ClientSecret "your-secret-here" -Operation "Delete" -SearchClientName "Test Client 1"
    
    Deletes the client entry named "Test Client 1" from the CSV file.
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SiteUrl,
    
    [Parameter(Mandatory=$true)]
    [string]$TenantId,
    
    [Parameter(Mandatory=$true)]
    [string]$ClientId,
    
    [Parameter(Mandatory=$true)]
    [string]$ClientSecret,
    
    [Parameter(Mandatory=$true)]
    [ValidateSet("Read", "Add", "List", "Update", "Delete")]
    [string]$Operation,
    
    # For Add and Update operations
    [Parameter(Mandatory=$false)]
    [string]$ClientName,
    
    [Parameter(Mandatory=$false)]
    [string]$NewTenantId,
    
    [Parameter(Mandatory=$false)]
    [string]$NewClientId,
    
    [Parameter(Mandatory=$false)]
    [string]$NewClientSecret,
    
    [Parameter(Mandatory=$false)]
    [string]$NewExpiry,
    
    # For Update operation - specify which client to update
    [Parameter(Mandatory=$false)]
    [int]$ClientIndex,  # Option 1: Update by index number (1-based)
    
    [Parameter(Mandatory=$false)]
    [string]$SearchClientName  # Option 2: Update by client name
)

# Force TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host "`n=== SharePoint CSV Manager ===" -ForegroundColor Cyan
Write-Host "Operation: $Operation" -ForegroundColor Yellow

# Validate Update parameters
if ($Operation -eq "Update") {
    if (-not $ClientIndex -and -not $SearchClientName) {
        Write-Error "For Update operation, you must specify either -ClientIndex or -SearchClientName"
        Write-Host "`nUsage examples:" -ForegroundColor Yellow
        Write-Host "  Update by index: -Operation Update -ClientIndex 5 -NewClientSecret 'newsecret'" -ForegroundColor Gray
        Write-Host "  Update by name: -Operation Update -SearchClientName 'Test Client 5' -NewClientSecret 'newsecret'" -ForegroundColor Gray
        exit 1
    }
}

# Get token
$tokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
$body = @{
    client_id     = $ClientId
    scope         = "https://graph.microsoft.com/.default"
    client_secret = $ClientSecret
    grant_type    = "client_credentials"
}

try {
    $authResponse = Invoke-RestMethod -Method Post -Uri $tokenUrl -Body $body -ContentType "application/x-www-form-urlencoded"
    $authToken = $authResponse.access_token
    Write-Host "✓ Authentication successful" -ForegroundColor Green
}
catch {
    Write-Error "Authentication failed: $_"
    exit 1
}

# Get site info
$uri = [System.Uri]$SiteUrl
$hostname = $uri.Host
$sitePath = $uri.AbsolutePath
$siteApiUrl = "https://graph.microsoft.com/v1.0/sites/$hostname`:$sitePath"

$headers = @{
    "Authorization" = "Bearer $authToken"
    "Content-Type"  = "application/json"
}

try {
    $site = Invoke-RestMethod -Method Get -Uri $siteApiUrl -Headers $headers
    $siteId = $site.id
    Write-Host "✓ Found site: $($site.displayName)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get site: $_"
    exit 1
}

# Get the drive ID
try {
    $drivesUrl = "https://graph.microsoft.com/v1.0/sites/$siteId/drives"
    $drives = Invoke-RestMethod -Method Get -Uri $drivesUrl -Headers $headers
    $driveId = $drives.value[0].id
    Write-Host "✓ Found drive: $($drives.value[0].name)" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get drive: $_"
    exit 1
}

# Read CSV
$csvPath = "SOAR/TestAzureAppKeys.csv"
$encodedPath = [System.Web.HttpUtility]::UrlEncode($csvPath)
$fileUrl = "https://graph.microsoft.com/v1.0/sites/$siteId/drive/root:/$encodedPath"

try {
    $file = Invoke-RestMethod -Method Get -Uri $fileUrl -Headers $headers
    $downloadUrl = $file.'@microsoft.graph.downloadUrl'
    $csvContent = Invoke-RestMethod -Method Get -Uri $downloadUrl
    $fileId = $file.id
    Write-Host "✓ CSV read successfully from SharePoint" -ForegroundColor Green
}
catch {
    Write-Error "Failed to read CSV: $_"
    exit 1
}

# Parse CSV
$csvData = @()
if ($csvContent.Trim() -ne "Client,Tenant ID,Client ID,Key Value,Expiry") {
    $csvData = $csvContent | ConvertFrom-Csv
}

# Function to upload CSV back to SharePoint
function Upload-CSVToSharePoint {
    param($UpdatedData)
    
    $updatedCsvContent = $UpdatedData | ConvertTo-Csv -NoTypeInformation | Out-String
    $fileBytes = [System.Text.Encoding]::UTF8.GetBytes($updatedCsvContent)
    $fileLength = $fileBytes.Length
    
    Write-Host "`nUploading updated CSV to SharePoint..." -ForegroundColor Yellow
    
    try {
        $uploadUrl = "https://graph.microsoft.com/v1.0/drives/$driveId/root:/SOAR/TestAzureAppKeys.csv:/content"
        
        $uploadHeaders = @{
            "Authorization" = "Bearer $authToken"
            "Content-Type" = "text/csv"
        }
        
        $response = Invoke-RestMethod -Method Put -Uri $uploadUrl -Headers $uploadHeaders -Body $fileBytes
        Write-Host "✓ Upload successful!" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Error "Upload failed: $_"
        return $false
    }
}

# Handle List operation
if ($Operation -eq "List") {
    Write-Host "`n=== Current Azure App Registrations ===" -ForegroundColor Cyan
    Write-Host "Total clients: $($csvData.Count)" -ForegroundColor Yellow
    
    $counter = 1
    foreach ($client in $csvData) {
        Write-Host "`n[$counter] Client: $($client.Client)" -ForegroundColor Yellow
        Write-Host "    Tenant ID: $($client.'Tenant ID')"
        Write-Host "    Client ID: $($client.'Client ID')"
        
        # Mask the secret for security
        $maskedSecret = if ($client.'Key Value'.Length -gt 8) {
            $client.'Key Value'.Substring(0, 8) + "..."
        } else {
            "***"
        }
        Write-Host "    Key Value: $maskedSecret"
        Write-Host "    Expiry: $($client.Expiry)"
        $counter++
    }
}

# Handle Update operation
elseif ($Operation -eq "Update") {
    Write-Host "`n=== Update Operation ===" -ForegroundColor Cyan
    
    # Find the client to update
    $clientToUpdate = $null
    $updateIndex = -1
    
    if ($ClientIndex) {
        # Update by index (1-based)
        if ($ClientIndex -gt 0 -and $ClientIndex -le $csvData.Count) {
            $updateIndex = $ClientIndex - 1
            $clientToUpdate = $csvData[$updateIndex]
            Write-Host "Found client at index $ClientIndex`: $($clientToUpdate.Client)" -ForegroundColor Green
        }
        else {
            Write-Error "Invalid index. Please specify a number between 1 and $($csvData.Count)"
            exit 1
        }
    }
    elseif ($SearchClientName) {
        # Update by name
        for ($i = 0; $i -lt $csvData.Count; $i++) {
            if ($csvData[$i].Client -eq $SearchClientName) {
                $updateIndex = $i
                $clientToUpdate = $csvData[$i]
                Write-Host "Found client: $SearchClientName (at index $($i + 1))" -ForegroundColor Green
                break
            }
        }
        
        if (-not $clientToUpdate) {
            Write-Error "Client '$SearchClientName' not found"
            Write-Host "`nAvailable clients:" -ForegroundColor Yellow
            $csvData | ForEach-Object { Write-Host "  - $($_.Client)" }
            exit 1
        }
    }
    
    # Display current values
    Write-Host "`nCurrent values:" -ForegroundColor Cyan
    Write-Host "  Client: $($clientToUpdate.Client)"
    Write-Host "  Tenant ID: $($clientToUpdate.'Tenant ID')"
    Write-Host "  Client ID: $($clientToUpdate.'Client ID')"
    $maskedSecret = if ($clientToUpdate.'Key Value'.Length -gt 8) {
        $clientToUpdate.'Key Value'.Substring(0, 8) + "..."
    } else {
        "***"
    }
    Write-Host "  Key Value: $maskedSecret"
    Write-Host "  Expiry: $($clientToUpdate.Expiry)"
    
    # Update fields
    $fieldsUpdated = @()
    
    if ($NewClientSecret) {
        $csvData[$updateIndex].'Key Value' = $NewClientSecret
        $fieldsUpdated += "Key Value"
    }
    
    if ($NewTenantId) {
        $csvData[$updateIndex].'Tenant ID' = $NewTenantId
        $fieldsUpdated += "Tenant ID"
    }
    
    if ($NewClientId) {
        $csvData[$updateIndex].'Client ID' = $NewClientId
        $fieldsUpdated += "Client ID"
    }
    
    if ($NewExpiry) {
        $csvData[$updateIndex].Expiry = $NewExpiry
        $fieldsUpdated += "Expiry"
    }
    
    if ($ClientName) {
        $csvData[$updateIndex].Client = $ClientName
        $fieldsUpdated += "Client Name"
    }
    
    if ($fieldsUpdated.Count -eq 0) {
        Write-Warning "No fields to update. Please specify at least one field to update."
        Write-Host "`nAvailable parameters:" -ForegroundColor Yellow
        Write-Host "  -ClientName 'New Name'" -ForegroundColor Gray
        Write-Host "  -NewTenantId 'tenant-id'" -ForegroundColor Gray
        Write-Host "  -NewClientId 'client-id'" -ForegroundColor Gray
        Write-Host "  -NewClientSecret 'secret'" -ForegroundColor Gray
        Write-Host "  -NewExpiry 'MM/DD/YY'" -ForegroundColor Gray
        exit 0
    }
    
    Write-Host "`nUpdating fields: $($fieldsUpdated -join ', ')" -ForegroundColor Yellow
    
    # Display new values
    Write-Host "`nNew values:" -ForegroundColor Green
    Write-Host "  Client: $($csvData[$updateIndex].Client)"
    Write-Host "  Tenant ID: $($csvData[$updateIndex].'Tenant ID')"
    Write-Host "  Client ID: $($csvData[$updateIndex].'Client ID')"
    $maskedNewSecret = if ($csvData[$updateIndex].'Key Value'.Length -gt 8) {
        $csvData[$updateIndex].'Key Value'.Substring(0, 8) + "..."
    } else {
        "***"
    }
    Write-Host "  Key Value: $maskedNewSecret"
    Write-Host "  Expiry: $($csvData[$updateIndex].Expiry)"
    
    # Upload updated CSV
    if (Upload-CSVToSharePoint -UpdatedData $csvData) {
        Write-Host "`n✓ Successfully updated $($clientToUpdate.Client)" -ForegroundColor Green
        Write-Host "Fields updated: $($fieldsUpdated -join ', ')" -ForegroundColor Cyan
    }
}

# Handle Add operation (existing code)
elseif ($Operation -eq "Add") {
    Write-Host "`nAdding: $ClientName" -ForegroundColor Yellow
    
    # Check if client already exists
    $existingClient = $csvData | Where-Object { $_.Client -eq $ClientName }
    if ($existingClient) {
        Write-Warning "Client '$ClientName' already exists. Use -Operation Update to modify it."
        exit 1
    }
    
    # Create new entry
    $newClient = New-Object PSObject -Property @{
        'Client' = $ClientName
        'Tenant ID' = $NewTenantId
        'Client ID' = $NewClientId
        'Key Value' = $NewClientSecret
        'Expiry' = if ($NewExpiry) { $NewExpiry } else { "" }
    }
    
    $csvData = $csvData + $newClient
    
    if (Upload-CSVToSharePoint -UpdatedData $csvData) {
        Write-Host "`n✓ Successfully added $ClientName" -ForegroundColor Green
        Write-Host "Total clients now: $($csvData.Count)" -ForegroundColor Cyan
    }
}

# Handle Delete operation
elseif ($Operation -eq "Delete") {
    Write-Host "`n=== Delete Operation ===" -ForegroundColor Cyan
    
    if (-not $ClientIndex -and -not $SearchClientName) {
        Write-Error "For Delete operation, specify either -ClientIndex or -SearchClientName"
        exit 1
    }
    
    $clientToDelete = $null
    $deleteIndex = -1
    
    if ($ClientIndex) {
        if ($ClientIndex -gt 0 -and $ClientIndex -le $csvData.Count) {
            $deleteIndex = $ClientIndex - 1
            $clientToDelete = $csvData[$deleteIndex]
        }
    }
    elseif ($SearchClientName) {
        for ($i = 0; $i -lt $csvData.Count; $i++) {
            if ($csvData[$i].Client -eq $SearchClientName) {
                $deleteIndex = $i
                $clientToDelete = $csvData[$i]
                break
            }
        }
    }
    
    if ($clientToDelete) {
        Write-Host "Deleting: $($clientToDelete.Client)" -ForegroundColor Yellow
        
        # Remove the client
        $newData = @()
        for ($i = 0; $i -lt $csvData.Count; $i++) {
            if ($i -ne $deleteIndex) {
                $newData += $csvData[$i]
            }
        }
        
        if (Upload-CSVToSharePoint -UpdatedData $newData) {
            Write-Host "✓ Successfully deleted $($clientToDelete.Client)" -ForegroundColor Green
            Write-Host "Total clients now: $($newData.Count)" -ForegroundColor Cyan
        }
    }
    else {
        Write-Error "Client not found"
    }
}

Write-Host "`n=== Operation Complete ===" -ForegroundColor Green
