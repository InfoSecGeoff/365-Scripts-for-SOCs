<#
.SYNOPSIS
    Reports Conditional Access policy configuration across one or more Entra ID tenants.

.DESCRIPTION
    Connects to Microsoft Graph via app-only credentials and retrieves all CA policies
    per tenant. Resolves user, group, and named-location IDs to display names. Flags
    policies that are enabled but not effectively applied — including policies with no
    user scope, no application scope, or no grant/session controls. Each policy row is
    expandable to show full condition and control details. Outputs a per-policy CSV and
    HTML report.

.PARAMETER TenantId
    Entra ID tenant ID. Required when not using -CsvPath.

.PARAMETER ClientId
    Application (client) ID. Required when not using -CsvPath.

.PARAMETER ClientSecret
    Client secret. Required when not using -CsvPath.

.PARAMETER CsvPath
    Path to CSV with columns: Client, Tenant ID, Client ID, Key Value.

.PARAMETER ClientName
    When used with -CsvPath, processes only the matching Client row.

.PARAMETER OutputFolder
    Output directory for CSV and HTML. Defaults to current directory.

.EXAMPLE
    .\Get-TenantConditionalAccess.ps1 `
        -TenantId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret "your-secret"

.EXAMPLE
    .\Get-TenantConditionalAccess.ps1 -CsvPath ".\AzureAppKeys.csv" -OutputFolder "C:\Reports"

.EXAMPLE
    .\Get-TenantConditionalAccess.ps1 -CsvPath ".\AzureAppKeys.csv" -ClientName "Contoso"

.NOTES
    Required Graph API permissions (application):
        Policy.Read.All     — Conditional Access policies
        Directory.Read.All  — user/group name resolution + named locations

    Author : Geoff Tankersley
    Version: 2.0
#>
#Requires -Version 7.0

param(
    [Parameter(Mandatory=$false)] [string]$TenantId,
    [Parameter(Mandatory=$false)] [string]$ClientId,
    [Parameter(Mandatory=$false)] [string]$ClientSecret,
    [Parameter(Mandatory=$false)] [string]$CsvPath,
    [Parameter(Mandatory=$false)] [string]$ClientName,
    [Parameter(Mandatory=$false)] [string]$OutputFolder
)

$ErrorActionPreference = "Continue"
$resolvedOutput = if ($OutputFolder) { $OutputFolder } else { ".\" }

$script:knownApps = @{
    "Office365"              = "Microsoft 365"
    "MicrosoftAdminPortals"  = "Microsoft Admin Portals"
    "00000002-0000-0ff1-ce00-000000000000" = "Exchange Online"
    "00000003-0000-0ff1-ce00-000000000000" = "SharePoint Online"
    "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
    "00000004-0000-ff01-ce00-000000000000" = "Skype for Business"
}

$script:roleMap = @{
    "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
    "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
    "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
    "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
    "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
    "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
    "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
    "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
    "0526716b-113d-4c15-b2c8-68e3c22b9f80" = "Authentication Policy Administrator"
    "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
    "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
    "4a5d8f65-41da-4de4-8968-e035b65339cf" = "Security Reader"
    "5d6b6bb7-de71-4623-b4af-96380a352509" = "Security Operator"
    "f023fd81-a637-4b56-95fd-791ac0226033" = "Service Support Administrator"
    "9f06204d-73c1-4d4c-880a-6edb90606fd8" = "Azure AD Joined Device Local Admin"
    "17315797-102d-40b4-93e0-432062caca18" = "Compliance Administrator"
    "74ef975b-6605-40af-a5d2-b9539d836353" = "Compliance Data Administrator"
    "d29b2b05-8046-44ba-8758-1e26182fcf32" = "Directory Synchronization Accounts"
    "69091246-20e8-4a56-aa4d-066075b2a7a8" = "Teams Administrator"
    "baf37b3a-610e-45da-9e62-d9d1e5e8914b" = "Teams Service Administrator"
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Groups Administrator"
    "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = "Power Platform Administrator"
    "a9ea8996-122f-4c74-9520-8edcd192826c" = "Reports Reader"
    "75941009-915a-4869-abe7-691bff18279e" = "Skype for Business Administrator"
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = "Global Reader"
    "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing Administrator"
    "31392ffb-586c-42d1-9346-e59415a2cc4e" = "Exchange Recipient Administrator"
    "38a96431-2bdf-4b4c-8b6e-5d3d8abac1a4" = "Desktop Analytics Administrator"
    "e3973bdf-4987-49ae-837a-ba8e231c7286" = "Azure DevOps Administrator"
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = "Directory Readers"
    "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
    "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = "External Identity Provider Administrator"
    "c430b396-e693-46cc-96f3-db01bf8bb62a" = "Attack Simulator Administrator"
    "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Azure Information Protection Administrator"
    "3edaf663-341e-4475-9f94-5c188be8b12a" = "Teams Communications Support Engineer"
    "f70938a0-fc10-4177-9e90-2178f8765737" = "Teams Communications Support Specialist"
    "2b745bdf-0803-4d80-aa65-822c4493daac" = "Office Apps Administrator"
    "44367163-eba1-44c3-98af-f5787879f96a" = "Commerce Administrator"
    "25a516ed-2fa0-40ea-a2d0-12923a21473a" = "Application Developer"
}

function Get-MsGraphTokenMain {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    $b = @{ client_id=$ClientId; client_secret=$ClientSecret
            scope="https://graph.microsoft.com/.default"; grant_type="client_credentials" }
    (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method Post -Body $b -ContentType "application/x-www-form-urlencoded").access_token
}

function Get-AllPagesMain {
    param([string]$Uri, [hashtable]$Headers)
    $out = @(); $next = $Uri
    do { $r = Invoke-RestMethod -Uri $next -Method Get -Headers $Headers
         $out += $r.value; $next = $r.'@odata.nextLink' } while ($next)
    return $out
}

function Resolve-UserScope {
    param($Users)
    $inc  = @($Users.includeUsers)
    $incG = @($Users.includeGroups)
    $incR = @($Users.includeRoles)
    if ($inc -contains "All") { return "All Users" }
    $parts = @()
    if ($inc -contains "GuestsOrExternalUsers") { $parts += "Guests/External" }
    $specific = $inc | Where-Object { $_ -ne "None" -and $_ -ne "GuestsOrExternalUsers" }
    if ($specific.Count -gt 0) { $parts += "$($specific.Count) user(s)" }
    if ($incG.Count -gt 0)     { $parts += "$($incG.Count) group(s)" }
    if ($incR.Count -gt 0)     { $parts += "$($incR.Count) role(s)" }
    if ($parts.Count -eq 0)    { return "None" }
    return $parts -join " + "
}

function Resolve-AppScope {
    param($Apps, [hashtable]$KnownApps)
    $inc = @($Apps.includeApplications)
    if ($inc -contains "All") { return "All Cloud Apps" }
    if ($inc.Count -eq 0 -or ($inc.Count -eq 1 -and $inc[0] -eq "None")) { return "None" }
    $names = foreach ($id in $inc) {
        if ($KnownApps.ContainsKey($id)) { $KnownApps[$id] } else { $id }
    }
    return $names -join "; "
}

function Format-GrantControls {
    param($GC)
    if (-not $GC) { return "" }
    $lMap = @{ "mfa"="MFA"; "compliantDevice"="Compliant Device"; "domainJoinedDevice"="Domain Joined";
               "approvedApplication"="Approved App"; "compliantApplication"="Compliant App";
               "passwordChange"="Password Change"; "block"="Block" }
    $parts = foreach ($ctrl in $GC.builtInControls) { if ($lMap[$ctrl]) { $lMap[$ctrl] } else { $ctrl } }
    if ($GC.authenticationStrength) {
        $parts += "Auth Strength: $(if ($GC.authenticationStrength.displayName) { $GC.authenticationStrength.displayName } else { 'Custom' })"
    }
    $sep = if (@($parts).Count -gt 1 -and $GC.operator) { " $($GC.operator) " } else { ", " }
    return (@($parts) -join $sep)
}

function Format-SessionControls {
    param($SC)
    if (-not $SC) { return "" }
    $parts = @()
    if ($SC.applicationEnforcedRestrictions -and $SC.applicationEnforcedRestrictions.isEnabled) { $parts += "App Restrictions" }
    if ($SC.cloudAppSecurity -and $SC.cloudAppSecurity.isEnabled) { $parts += "MCAS" }
    if ($SC.signInFrequency -and $SC.signInFrequency.isEnabled)   { $parts += "Sign-in Freq: $($SC.signInFrequency.value) $($SC.signInFrequency.type)" }
    if ($SC.persistentBrowser -and $SC.persistentBrowser.isEnabled) { $parts += "Browser: $($SC.persistentBrowser.mode)" }
    if ($SC.continuousAccessEvaluation -and $SC.continuousAccessEvaluation.mode -ne "disabled") { $parts += "CAE" }
    if ($SC.disableResilienceDefaults -eq $true) { $parts += "Resilience Disabled" }
    return ($parts -join "; ")
}

function Get-PolicyIssues {
    param($Policy)
    if ($Policy.state -eq "disabled") { return @("Disabled") }
    $issues = @()
    if ($Policy.state -eq "enabledForReportingButNotEnforced") { $issues += "Report-only" }
    $inc  = @($Policy.conditions.users.includeUsers)
    $incG = @($Policy.conditions.users.includeGroups)
    $incR = @($Policy.conditions.users.includeRoles)
    $incA = @($Policy.conditions.applications.includeApplications)
    $hasUsers = ($inc -contains "All") -or ($inc -contains "GuestsOrExternalUsers") -or
                ($inc | Where-Object { $_ -ne "None" }).Count -gt 0 -or
                $incG.Count -gt 0 -or $incR.Count -gt 0
    if (-not $hasUsers) { $issues += "No user scope" }
    $hasApps = ($incA -contains "All") -or ($incA -contains "Office365") -or
               ($incA -contains "MicrosoftAdminPortals") -or
               ($incA | Where-Object { $_ -ne "None" }).Count -gt 0
    if (-not $hasApps) { $issues += "No app scope" }
    if ($hasUsers -and $hasApps -and $Policy.state -eq "enabled") {
        $gc = $Policy.grantControls
        $sc = $Policy.sessionControls
        $hasGrant = $gc -and ($gc.builtInControls.Count -gt 0 -or $gc.authenticationStrength)
        $hasSession = $sc -and (
            ($sc.applicationEnforcedRestrictions -and $sc.applicationEnforcedRestrictions.isEnabled) -or
            ($sc.cloudAppSecurity -and $sc.cloudAppSecurity.isEnabled) -or
            ($sc.signInFrequency -and $sc.signInFrequency.isEnabled) -or
            ($sc.persistentBrowser -and $sc.persistentBrowser.isEnabled) -or
            ($sc.continuousAccessEvaluation -and $sc.continuousAccessEvaluation.mode -ne "disabled") -or
            $sc.disableResilienceDefaults -eq $true)
        if (-not $hasGrant -and -not $hasSession) { $issues += "No controls" }
    }
    return $issues
}

# HTML helper — used in main thread only
function New-HtmlList {
    param([string[]]$Items)
    $f = @($Items | Where-Object { $_ })
    if ($f.Count -eq 0) { return "<span style='color:#bbb'>—</span>" }
    return "<ul>" + (($f | ForEach-Object { "<li>$([System.Net.WebUtility]::HtmlEncode($_))</li>" }) -join "") + "</ul>"
}

if ($CsvPath) {
    if (-not (Test-Path -Path $CsvPath)) { Write-Error "CSV not found: $CsvPath"; return }
    $tenants = Import-Csv -Path $CsvPath
    if ($ClientName) {
        $tenants = @($tenants | Where-Object { $_.Client -eq $ClientName })
        if ($tenants.Count -eq 0) { Write-Error "Client '$ClientName' not found in CSV."; return }
    }

    Write-Host "Processing $($tenants.Count) tenant(s) in parallel (ThrottleLimit 20)..." -ForegroundColor Cyan
    $outFolder = $resolvedOutput

    $allData = $tenants | ForEach-Object -ThrottleLimit 20 -Parallel {

        function Get-Token {
            param([string]$Tid, [string]$Cid, [string]$Sec)
            $b = @{ client_id=$Cid; client_secret=$Sec
                    scope="https://graph.microsoft.com/.default"; grant_type="client_credentials" }
            (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tid/oauth2/v2.0/token" `
                -Method Post -Body $b -ContentType "application/x-www-form-urlencoded").access_token
        }
        function Get-Pages {
            param([string]$Uri, [hashtable]$H)
            $out = @(); $next = $Uri
            do { $r = Invoke-RestMethod -Uri $next -Method Get -Headers $H
                 $out += $r.value; $next = $r.'@odata.nextLink' } while ($next)
            return $out
        }

        $knownApps = @{
            "Office365"              = "Microsoft 365"
            "MicrosoftAdminPortals"  = "Microsoft Admin Portals"
            "00000002-0000-0ff1-ce00-000000000000" = "Exchange Online"
            "00000003-0000-0ff1-ce00-000000000000" = "SharePoint Online"
            "1fec8e78-bce4-4aaf-ab1b-5451cc387264" = "Microsoft Teams"
            "00000004-0000-ff01-ce00-000000000000" = "Skype for Business"
        }
        $roleMap = @{
            "62e90394-69f5-4237-9190-012177145e10" = "Global Administrator"
            "f28a1f50-f6e7-4571-818b-6a12f2af6b6c" = "SharePoint Administrator"
            "fe930be7-5e62-47db-91af-98c3a49a38b1" = "User Administrator"
            "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3" = "Application Administrator"
            "c4e39bd9-1100-46d3-8c65-fb160da0071f" = "Authentication Administrator"
            "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9" = "Conditional Access Administrator"
            "29232cdf-9323-42fd-ade2-1d097af3e4de" = "Exchange Administrator"
            "729827e3-9c14-49f7-bb1b-9608f156bbb8" = "Helpdesk Administrator"
            "966707d0-3269-4727-9be2-8c3a10f19b9d" = "Password Administrator"
            "194ae4cb-b126-40b2-bd5b-6091b380977d" = "Security Administrator"
            "e8611ab8-c189-46e8-94e1-60213ab1f814" = "Privileged Role Administrator"
            "7be44c8a-adaf-4e2a-84d6-ab2649e08a13" = "Privileged Authentication Administrator"
            "0526716b-113d-4c15-b2c8-68e3c22b9f80" = "Authentication Policy Administrator"
            "158c047a-c907-4556-b7ef-446551a6b5f7" = "Cloud Application Administrator"
            "3a2c62db-5318-420d-8d74-23affee5d9d5" = "Intune Administrator"
            "4a5d8f65-41da-4de4-8968-e035b65339cf" = "Security Reader"
            "5d6b6bb7-de71-4623-b4af-96380a352509" = "Security Operator"
            "f023fd81-a637-4b56-95fd-791ac0226033" = "Service Support Administrator"
            "17315797-102d-40b4-93e0-432062caca18" = "Compliance Administrator"
            "69091246-20e8-4a56-aa4d-066075b2a7a8" = "Teams Administrator"
            "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2" = "Groups Administrator"
            "11648597-926c-4cf3-9c36-bcebb0ba8dcc" = "Power Platform Administrator"
            "f2ef992c-3afb-46b9-b7cf-a126ee74c451" = "Global Reader"
            "b0f54661-2d74-4c50-afa3-1ec803f12efe" = "Billing Administrator"
            "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" = "Directory Readers"
            "9360feb5-f418-4baa-8175-e2a00bac4301" = "Directory Writers"
            "25a516ed-2fa0-40ea-a2d0-12923a21473a" = "Application Developer"
            "45d8d3c5-c802-45c6-b32a-1d70b5e1e86e" = "External Identity Provider Administrator"
            "2b745bdf-0803-4d80-aa65-822c4493daac" = "Office Apps Administrator"
            "c430b396-e693-46cc-96f3-db01bf8bb62a" = "Attack Simulator Administrator"
            "fdd7a751-b60b-444a-984c-02652fe8fa1c" = "Azure Information Protection Administrator"
            "e3973bdf-4987-49ae-837a-ba8e231c7286" = "Azure DevOps Administrator"
        }
        $lMap = @{ "mfa"="MFA"; "compliantDevice"="Compliant Device"; "domainJoinedDevice"="Domain Joined";
                   "approvedApplication"="Approved App"; "compliantApplication"="Compliant App";
                   "passwordChange"="Password Change"; "block"="Block" }
        $guidRx = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

        $t      = $_
        $name   = $t.Client.Trim()
        $tid    = $t.'Tenant ID'.Trim()
        $cid    = $t.'Client ID'.Trim()
        $secret = $t.'Key Value'.Trim()

        if ([string]::IsNullOrWhiteSpace($tid) -or [string]::IsNullOrWhiteSpace($cid) -or [string]::IsNullOrWhiteSpace($secret)) {
            return [PSCustomObject]@{ ClientName="$name"; TenantId="$tid"; PolicyCount=0
                EnabledCount=0; DisabledCount=0; ReportOnlyCount=0; MisconfigCount=0
                HasCaLicense=$false; CaLicenseSku="Unknown"
                Error="Missing credentials"; Policies=@() }
        }

        try {
            $token = Get-Token -Tid $tid -Cid $cid -Sec $secret
            $h = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }

            $rawPolicies = @()
            try { $rawPolicies = Get-Pages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -H $h }
            catch { throw "Cannot read CA policies: $_" }

            # Named locations map
            $locMap = @{}
            try {
                $locs = Get-Pages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/namedLocations" -H $h
                foreach ($l in $locs) { $locMap[$l.id] = $l.displayName }
            } catch {}

            # Collect unique user and group IDs across all policies for batch resolution
            $allUserIds  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $allGroupIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($p in $rawPolicies) {
                foreach ($id in @($p.conditions.users.includeUsers) + @($p.conditions.users.excludeUsers)) {
                    if ($id -match $guidRx) { $allUserIds.Add($id) | Out-Null }
                }
                foreach ($id in @($p.conditions.users.includeGroups) + @($p.conditions.users.excludeGroups)) {
                    if ($id -match $guidRx) { $allGroupIds.Add($id) | Out-Null }
                }
            }

            # Batch resolve user and group display names via directoryObjects/getByIds
            $nameMap    = @{}
            $userIdArr  = @([string[]]$allUserIds  | Where-Object { $_ })
            $groupIdArr = @([string[]]$allGroupIds | Where-Object { $_ })
            if ($userIdArr.Count -gt 0) {
                try {
                    $body = @{ ids = $userIdArr; types = @("user") } | ConvertTo-Json -Depth 3
                    $r = Invoke-RestMethod "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" `
                        -Method Post -Headers $h -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    foreach ($obj in $r.value) { $nameMap[$obj.id] = $obj.displayName }
                } catch {}
            }
            if ($groupIdArr.Count -gt 0) {
                try {
                    $body = @{ ids = $groupIdArr; types = @("group") } | ConvertTo-Json -Depth 3
                    $r = Invoke-RestMethod "https://graph.microsoft.com/v1.0/directoryObjects/getByIds" `
                        -Method Post -Headers $h -Body $body -ContentType "application/json" -ErrorAction SilentlyContinue
                    foreach ($obj in $r.value) { $nameMap[$obj.id] = $obj.displayName }
                } catch {}
            }

            # License check — AAD Premium P1/P2 required for Conditional Access
            $hasCALicense = $false; $caLicenseSku = "None"
            try {
                $skus = Get-Pages -Uri "https://graph.microsoft.com/v1.0/subscribedSkus?`$select=skuPartNumber,servicePlans,capabilityStatus" -H $h
                foreach ($sku in $skus) {
                    if ($sku.capabilityStatus -ne "Enabled") { continue }
                    $p2plan = $sku.servicePlans | Where-Object { $_.servicePlanName -eq "AAD_PREMIUM_P2" -and $_.provisioningStatus -eq "Success" }
                    $p1plan = $sku.servicePlans | Where-Object { $_.servicePlanName -eq "AAD_PREMIUM"    -and $_.provisioningStatus -eq "Success" }
                    if ($p2plan) { $hasCALicense = $true; $caLicenseSku = "$($sku.skuPartNumber) (AAD P2)"; break }
                    if ($p1plan) { $hasCALicense = $true; $caLicenseSku = "$($sku.skuPartNumber) (AAD P1)" }
                }
            } catch {}

            $policyObjects = foreach ($p in $rawPolicies) {
                $inc  = @($p.conditions.users.includeUsers)
                $incG = @($p.conditions.users.includeGroups)
                $incR = @($p.conditions.users.includeRoles)
                $excU = @($p.conditions.users.excludeUsers)
                $excG = @($p.conditions.users.excludeGroups)
                $excR = @($p.conditions.users.excludeRoles)
                $incA = @(if ($p.conditions.applications) { $p.conditions.applications.includeApplications | Where-Object { $_ } })
                $excA = @(if ($p.conditions.applications) { $p.conditions.applications.excludeApplications | Where-Object { $_ } })
                $incL = @(if ($p.conditions.locations)    { $p.conditions.locations.includeLocations        | Where-Object { $_ } })
                $excL = @(if ($p.conditions.locations)    { $p.conditions.locations.excludeLocations        | Where-Object { $_ } })

                # Summary user scope string
                $userScope = if ($inc -contains "All") { "All Users" } else {
                    $pts = @()
                    if ($inc -contains "GuestsOrExternalUsers") { $pts += "Guests/External" }
                    $su = $inc | Where-Object { $_ -ne "None" -and $_ -ne "GuestsOrExternalUsers" }
                    if ($su.Count -gt 0)   { $pts += "$($su.Count) user(s)" }
                    if ($incG.Count -gt 0) { $pts += "$($incG.Count) group(s)" }
                    if ($incR.Count -gt 0) { $pts += "$($incR.Count) role(s)" }
                    if ($pts.Count -eq 0)  { "None" } else { $pts -join " + " }
                }

                # Exclusion summary
                $excParts = @()
                if ($excU.Count -gt 0) { $excParts += "$($excU.Count) user(s)" }
                if ($excG.Count -gt 0) { $excParts += "$($excG.Count) group(s)" }
                if ($excR.Count -gt 0) { $excParts += "$($excR.Count) role(s)" }
                $excScope = $excParts -join " + "

                # App scope summary
                $appScope = if ($incA -contains "All") { "All Cloud Apps" }
                            elseif ($incA.Count -eq 0 -or ($incA.Count -eq 1 -and $incA[0] -eq "None")) { "None" }
                            else { ($incA | ForEach-Object { if ($knownApps.ContainsKey($_)) { $knownApps[$_] } else { $_ } }) -join "; " }

                # Resolved name lists (semicolon-delimited for CSV and HTML detail)
                $resolve = {
                    param([string[]]$Ids, [hashtable]$Map, [hashtable]$RoleM, [bool]$IsRole)
                    $Ids | ForEach-Object {
                        if ($IsRole) { if ($RoleM.ContainsKey($_)) { $RoleM[$_] } else { $_ } }
                        else         { if ($Map.ContainsKey($_))   { $Map[$_]   } else { $_ } }
                    }
                }

                $incUserNames  = ($inc  | Where-Object { $_ -match $guidRx } | ForEach-Object { if ($nameMap[$_]) { $nameMap[$_] } else { $_ } }) -join ";"
                $excUserNames  = ($excU | Where-Object { $_ -match $guidRx } | ForEach-Object { if ($nameMap[$_]) { $nameMap[$_] } else { $_ } }) -join ";"
                $incGroupNames = ($incG | Where-Object { $_ } | ForEach-Object { if ($nameMap[$_]) { $nameMap[$_] } else { $_ } }) -join ";"
                $excGroupNames = ($excG | Where-Object { $_ } | ForEach-Object { if ($nameMap[$_]) { $nameMap[$_] } else { $_ } }) -join ";"
                $incRoleNames  = ($incR | Where-Object { $_ } | ForEach-Object { if ($roleMap[$_]) { $roleMap[$_] } else { $_ } }) -join ";"
                $excRoleNames  = ($excR | Where-Object { $_ } | ForEach-Object { if ($roleMap[$_]) { $roleMap[$_] } else { $_ } }) -join ";"

                # Special user values
                $specialInc = $inc | Where-Object { $_ -eq "All" -or $_ -eq "GuestsOrExternalUsers" -or $_ -eq "None" }
                if ($specialInc) { $incUserNames = ((@($specialInc) + @($incUserNames -split ";" | Where-Object {$_})) -join ";") }

                # App names (resolved)
                $incAppNames = if ($incA -contains "All") { "All Cloud Apps" }
                               else { ($incA | Where-Object { $_ } | ForEach-Object { if ($knownApps.ContainsKey($_)) { $knownApps[$_] } else { $_ } }) -join ";" }
                $excAppNames = ($excA | Where-Object { $_ } | ForEach-Object { if ($knownApps.ContainsKey($_)) { $knownApps[$_] } else { $_ } }) -join ";"

                # Named locations
                $incLocNames = ($incL | Where-Object { $_ } | ForEach-Object {
                    switch ($_) {
                        "All"        { "All Locations" }
                        "AllTrusted" { "All Trusted Locations" }
                        default      { if ($locMap[$_]) { $locMap[$_] } else { $_ } }
                    }
                }) -join ";"
                $excLocNames = ($excL | Where-Object { $_ } | ForEach-Object {
                    switch ($_) {
                        "All"        { "All Locations" }
                        "AllTrusted" { "All Trusted Locations" }
                        default      { if ($locMap[$_]) { $locMap[$_] } else { $_ } }
                    }
                }) -join ";"

                # Conditions
                $platforms  = @(if ($p.conditions.platforms)    { $p.conditions.platforms.includePlatforms | Where-Object { $_ } }) -join ";"
                $signInRisk = (@($p.conditions.signInRiskLevels) | Where-Object { $_ }) -join ";"
                $userRisk   = (@($p.conditions.userRiskLevels)   | Where-Object { $_ }) -join ";"
                $clientApps = (@($p.conditions.clientAppTypes)   | Where-Object { $_ }) -join ";"

                # Grant controls
                $gc = $p.grantControls
                $grantStr = ""
                if ($gc) {
                    $gParts = foreach ($ctrl in $gc.builtInControls) { if ($lMap[$ctrl]) { $lMap[$ctrl] } else { $ctrl } }
                    if ($gc.authenticationStrength) {
                        $gParts = @($gParts) + "Auth Strength: $(if ($gc.authenticationStrength.displayName) { $gc.authenticationStrength.displayName } else { 'Custom' })"
                    }
                    $sep = if (@($gParts).Count -gt 1 -and $gc.operator) { " $($gc.operator) " } else { ", " }
                    $grantStr = @($gParts) -join $sep
                }

                # Session controls
                $sc = $p.sessionControls
                $sessionStr = ""
                if ($sc) {
                    $sParts = @()
                    if ($sc.applicationEnforcedRestrictions -and $sc.applicationEnforcedRestrictions.isEnabled) { $sParts += "App Restrictions" }
                    if ($sc.cloudAppSecurity -and $sc.cloudAppSecurity.isEnabled) { $sParts += "MCAS" }
                    if ($sc.signInFrequency -and $sc.signInFrequency.isEnabled)   { $sParts += "Sign-in Freq: $($sc.signInFrequency.value) $($sc.signInFrequency.type)" }
                    if ($sc.persistentBrowser -and $sc.persistentBrowser.isEnabled) { $sParts += "Browser: $($sc.persistentBrowser.mode)" }
                    if ($sc.continuousAccessEvaluation -and $sc.continuousAccessEvaluation.mode -ne "disabled") { $sParts += "CAE" }
                    if ($sc.disableResilienceDefaults -eq $true) { $sParts += "Resilience Disabled" }
                    $sessionStr = $sParts -join "; "
                }

                # Issue detection
                $issues = @()
                if ($p.state -eq "disabled") {
                    $issues = @("Disabled")
                } else {
                    if ($p.state -eq "enabledForReportingButNotEnforced") { $issues += "Report-only" }
                    $hasUsers = ($inc -contains "All") -or ($inc -contains "GuestsOrExternalUsers") -or
                                ($inc | Where-Object { $_ -ne "None" }).Count -gt 0 -or
                                $incG.Count -gt 0 -or $incR.Count -gt 0
                    $hasApps  = ($incA -contains "All") -or ($incA -contains "Office365") -or
                                ($incA -contains "MicrosoftAdminPortals") -or
                                ($incA | Where-Object { $_ -ne "None" }).Count -gt 0
                    if (-not $hasUsers) { $issues += "No user scope" }
                    if (-not $hasApps)  { $issues += "No app scope" }
                    if ($hasUsers -and $hasApps -and $p.state -eq "enabled") {
                        $hasGrant = $gc -and ($gc.builtInControls.Count -gt 0 -or $gc.authenticationStrength)
                        $hasSession = $sc -and (
                            ($sc.applicationEnforcedRestrictions -and $sc.applicationEnforcedRestrictions.isEnabled) -or
                            ($sc.cloudAppSecurity -and $sc.cloudAppSecurity.isEnabled) -or
                            ($sc.signInFrequency -and $sc.signInFrequency.isEnabled) -or
                            ($sc.persistentBrowser -and $sc.persistentBrowser.isEnabled) -or
                            ($sc.continuousAccessEvaluation -and $sc.continuousAccessEvaluation.mode -ne "disabled") -or
                            $sc.disableResilienceDefaults -eq $true)
                        if (-not $hasGrant -and -not $hasSession) { $issues += "No controls" }
                    }
                }

                $stateLabel = switch ($p.state) {
                    "enabled"                           { "Enabled" }
                    "disabled"                          { "Disabled" }
                    "enabledForReportingButNotEnforced" { "Report-Only" }
                    default                             { $p.state }
                }

                [PSCustomObject]@{
                    ClientName             = $name
                    TenantId               = $tid
                    PolicyId               = $p.id
                    PolicyName             = $p.displayName
                    State                  = $stateLabel
                    CreatedDate            = $p.createdDateTime
                    ModifiedDate           = $p.modifiedDateTime
                    UsersIncluded          = $userScope
                    UsersExcluded          = $excScope
                    AppsIncluded           = $appScope
                    GrantControls          = $grantStr
                    SessionControls        = $sessionStr
                    IsMisconfigured        = ($issues.Count -gt 0 -and $issues -notcontains "Disabled")
                    Issues                 = ($issues -join "; ")
                    IncludedUserNames      = $incUserNames
                    ExcludedUserNames      = $excUserNames
                    IncludedGroupNames     = $incGroupNames
                    ExcludedGroupNames     = $excGroupNames
                    IncludedRoleNames      = $incRoleNames
                    ExcludedRoleNames      = $excRoleNames
                    IncludedAppNames       = $incAppNames
                    ExcludedAppNames       = $excAppNames
                    IncludedLocationNames  = $incLocNames
                    ExcludedLocationNames  = $excLocNames
                    Platforms              = $platforms
                    SignInRisk             = $signInRisk
                    UserRisk               = $userRisk
                    ClientAppTypes         = $clientApps
                    GrantOperator          = if ($gc) { $gc.operator } else { "" }
                }
            }

            $enabled    = ($policyObjects | Where-Object { $_.State -eq "Enabled" }).Count
            $disabled   = ($policyObjects | Where-Object { $_.State -eq "Disabled" }).Count
            $reportOnly = ($policyObjects | Where-Object { $_.State -eq "Report-Only" }).Count
            $misconfig  = ($policyObjects | Where-Object { $_.IsMisconfigured }).Count

            [PSCustomObject]@{
                ClientName      = $name; TenantId        = $tid
                PolicyCount     = @($policyObjects).Count
                EnabledCount    = $enabled;    DisabledCount   = $disabled
                ReportOnlyCount = $reportOnly; MisconfigCount  = $misconfig
                HasCaLicense    = $hasCALicense; CaLicenseSku  = $caLicenseSku
                Error           = ""; Policies = @($policyObjects)
            }
        }
        catch {
            [PSCustomObject]@{ ClientName="$name"; TenantId="$tid"; PolicyCount=0
                EnabledCount=0; DisabledCount=0; ReportOnlyCount=0; MisconfigCount=0
                HasCaLicense=$false; CaLicenseSku="Unknown"
                Error="$_"; Policies=@() }
        }
    }

    $allPolicies = @($allData | ForEach-Object { $_.Policies } | Where-Object { $_ })

    $csvOut = Join-Path $resolvedOutput "ConditionalAccess.csv"
    if ($allPolicies.Count -gt 0) {
        $allPolicies | Select-Object ClientName,TenantId,PolicyName,State,UsersIncluded,UsersExcluded,
            IncludedUserNames,ExcludedUserNames,IncludedGroupNames,ExcludedGroupNames,
            IncludedRoleNames,ExcludedRoleNames,AppsIncluded,IncludedAppNames,ExcludedAppNames,
            GrantControls,SessionControls,Platforms,SignInRisk,UserRisk,ClientAppTypes,
            IncludedLocationNames,ExcludedLocationNames,IsMisconfigured,Issues,
            CreatedDate,ModifiedDate,PolicyId |
            Export-Csv -Path $csvOut -NoTypeInformation
    }

    $totalTenants     = $allData.Count
    $errTenants       = ($allData | Where-Object { $_.Error }).Count
    $noCaAll          = @($allData | Where-Object { $_.PolicyCount -eq 0 -and -not $_.Error })
    $noCaTenants      = $noCaAll.Count
    $noCaLicensed     = ($noCaAll | Where-Object {  $_.HasCaLicense }).Count
    $noCaUnlicensed   = ($noCaAll | Where-Object { -not $_.HasCaLicense }).Count
    $totalPolicies    = ($allData | Measure-Object -Property PolicyCount     -Sum).Sum
    $totalEnabled     = ($allData | Measure-Object -Property EnabledCount    -Sum).Sum
    $totalDisabled    = ($allData | Measure-Object -Property DisabledCount   -Sum).Sum
    $totalReportOnly  = ($allData | Measure-Object -Property ReportOnlyCount -Sum).Sum
    $totalMisconfig   = ($allData | Measure-Object -Property MisconfigCount  -Sum).Sum
    $misconfigTenants = ($allData | Where-Object { $_.MisconfigCount -gt 0 }).Count

    $genDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $htmlOut  = Join-Path $resolvedOutput "ConditionalAccess.html"

    $rows = ""
    $idx  = 0
    foreach ($p in ($allPolicies | Sort-Object ClientName, PolicyName)) {
        $idx++
        $rowClass = if     ($p.State -eq "Enabled" -and $p.IsMisconfigured) { "row-bad" }
                    elseif ($p.State -eq "Report-Only")                      { "row-warn" }
                    elseif ($p.State -eq "Disabled")                         { "row-disabled" }
                    else                                                      { "row-ok" }

        $stateBadge = switch ($p.State) {
            "Enabled"     { "<span class='badge badge-green'>Enabled</span>" }
            "Disabled"    { "<span class='badge badge-grey'>Disabled</span>" }
            "Report-Only" { "<span class='badge badge-orange'>Report-Only</span>" }
            default       { $p.State }
        }
        $issueCell = if ($p.Issues) { "<span class='badge badge-red'>$([System.Net.WebUtility]::HtmlEncode($p.Issues))</span>" } else { "" }
        $excCell   = if ($p.UsersExcluded) { "<span class='excl'>excl: $($p.UsersExcluded)</span>" } else { "" }

        # Detail panel data
        $incUsers  = @($p.IncludedUserNames  -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $excUsers  = @($p.ExcludedUserNames  -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $incGroups = @($p.IncludedGroupNames -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $excGroups = @($p.ExcludedGroupNames -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $incRoles  = @($p.IncludedRoleNames  -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $excRoles  = @($p.ExcludedRoleNames  -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $incApps   = @($p.IncludedAppNames   -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $excApps   = @($p.ExcludedAppNames   -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $incLocs   = @($p.IncludedLocationNames -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $excLocs   = @($p.ExcludedLocationNames -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $platforms = @($p.Platforms     -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $srisk     = @($p.SignInRisk    -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $urisk     = @($p.UserRisk      -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
        $capps     = @($p.ClientAppTypes -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })

        $d_incUsers  = New-HtmlList $incUsers
        $d_excUsers  = New-HtmlList $excUsers
        $d_incGroups = New-HtmlList $incGroups
        $d_excGroups = New-HtmlList $excGroups
        $d_incRoles  = New-HtmlList $incRoles
        $d_excRoles  = New-HtmlList $excRoles
        $d_incApps   = New-HtmlList $incApps
        $d_excApps   = New-HtmlList $excApps
        $d_incLocs   = New-HtmlList $incLocs
        $d_excLocs   = New-HtmlList $excLocs
        $d_platforms = New-HtmlList $platforms
        $d_srisk     = New-HtmlList $srisk
        $d_urisk     = New-HtmlList $urisk
        $d_capps     = New-HtmlList $capps

        $d_grant   = if ($p.GrantControls)   { [System.Net.WebUtility]::HtmlEncode($p.GrantControls)   } else { "<span style='color:#bbb'>—</span>" }
        $d_session = if ($p.SessionControls) { [System.Net.WebUtility]::HtmlEncode($p.SessionControls) } else { "<span style='color:#bbb'>—</span>" }

        $policyNameHtml = [System.Net.WebUtility]::HtmlEncode($p.PolicyName)
        $clientNameHtml = [System.Net.WebUtility]::HtmlEncode($p.ClientName)

        $rows += @"
        <tr class="$rowClass summary-row" data-state="$($p.State)" data-misconfig="$(if($p.IsMisconfigured){'yes'}else{'no'})" onclick="toggle($idx)" style="cursor:pointer">
            <td><span class="toggle-icon" id="ic-$idx">&#9654;</span></td>
            <td>$clientNameHtml</td>
            <td>$policyNameHtml</td>
            <td>$stateBadge</td>
            <td>$($p.UsersIncluded)</td>
            <td>$excCell</td>
            <td>$($p.AppsIncluded)</td>
            <td>$($p.GrantControls)</td>
            <td>$($p.SessionControls)</td>
            <td>$issueCell</td>
        </tr>
        <tr class="detail-row" id="dr-$idx" style="display:none">
            <td colspan="10" style="padding:0;border-bottom:2px solid #0078D4">
              <div class="detail-panel">
                <div class="detail-grid">
                  <div class="detail-col">
                    <div class="ds"><div class="ds-label">Users Included</div>$d_incUsers</div>
                    <div class="ds"><div class="ds-label">Users Excluded</div>$d_excUsers</div>
                    <div class="ds"><div class="ds-label">Groups Included</div>$d_incGroups</div>
                    <div class="ds"><div class="ds-label">Groups Excluded</div>$d_excGroups</div>
                    <div class="ds"><div class="ds-label">Roles Included</div>$d_incRoles</div>
                    <div class="ds"><div class="ds-label">Roles Excluded</div>$d_excRoles</div>
                  </div>
                  <div class="detail-col">
                    <div class="ds"><div class="ds-label">Apps Included</div>$d_incApps</div>
                    <div class="ds"><div class="ds-label">Apps Excluded</div>$d_excApps</div>
                    <div class="ds"><div class="ds-label">Client App Types</div>$d_capps</div>
                  </div>
                  <div class="detail-col">
                    <div class="ds"><div class="ds-label">Platforms</div>$d_platforms</div>
                    <div class="ds"><div class="ds-label">Locations Included</div>$d_incLocs</div>
                    <div class="ds"><div class="ds-label">Locations Excluded</div>$d_excLocs</div>
                    <div class="ds"><div class="ds-label">Sign-in Risk</div>$d_srisk</div>
                    <div class="ds"><div class="ds-label">User Risk</div>$d_urisk</div>
                  </div>
                  <div class="detail-col">
                    <div class="ds"><div class="ds-label">Grant Controls</div>$d_grant</div>
                    <div class="ds"><div class="ds-label">Session Controls</div>$d_session</div>
                    <div class="ds" style="font-size:11px;color:#888;margin-top:10px">
                      Created: $($p.CreatedDate)<br>
                      Modified: $($p.ModifiedDate)<br>
                      <span style="word-break:break-all">ID: $($p.PolicyId)</span>
                    </div>
                  </div>
                </div>
              </div>
            </td>
        </tr>
"@
    }

    # No-CA badge HTML (separate section — not in the policy table)
    $noCaHtml = ""
    foreach ($t in ($noCaAll | Sort-Object ClientName)) {
        $badgeColor = if ($t.HasCaLicense) { "#107C10" } else { "#888" }
        $badgeTip   = if ($t.HasCaLicense) { "Has $($t.CaLicenseSku) — CA license present but no policies configured" } else { "No AAD Premium license — CA not available" }
        $noCaHtml  += "<span class='noca-badge' style='background:$badgeColor' title='$([System.Net.WebUtility]::HtmlEncode($badgeTip))'>$([System.Net.WebUtility]::HtmlEncode($t.ClientName))</span>`n"
    }

    foreach ($t in ($allData | Where-Object { $_.Error } | Sort-Object ClientName)) {
        $rows += @"
        <tr class="row-error" data-state="Error" data-misconfig="no">
            <td></td>
            <td>$([System.Net.WebUtility]::HtmlEncode($t.ClientName))</td>
            <td colspan='8' style='color:#aaa;font-style:italic'>$([System.Net.WebUtility]::HtmlEncode($t.Error))</td>
        </tr>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Conditional Access Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
  h1,h2,h3{color:#0078D4}
  .container{max-width:1900px;margin:0 auto}
  .card{background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}
  .dash{display:flex;flex-wrap:wrap;gap:15px;margin-bottom:20px}
  .dc{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:15px;flex:1;min-width:140px;text-align:center}
  .dn{font-size:32px;font-weight:bold;margin:8px 0}
  .dl{font-size:12px;color:#666}
  .red{color:#E81123}.orange{color:#FF8C00}.green{color:#107C10}.blue{color:#0078D4}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #ddd;white-space:nowrap}
  th{background:#0078D4;color:#fff;cursor:pointer;user-select:none}
  th:hover{background:#005a9e}
  th.sort-asc::after{content:' \25B2';font-size:10px}
  th.sort-desc::after{content:' \25BC';font-size:10px}
  .summary-row:hover td{background:#f0f7ff}
  .row-bad      {background:#fde7e9;border-left:4px solid #E81123}
  .row-warn     {background:#fff4ce;border-left:4px solid #FF8C00}
  .row-disabled {background:#f5f5f5;border-left:4px solid #aaa;opacity:.75}
  .row-error    {background:#f0f0f0;border-left:4px solid #888}
  .row-ok       {border-left:4px solid #107C10}
  .noca-badge{display:inline-block;padding:4px 10px;border-radius:12px;font-size:12px;font-weight:bold;color:#fff;margin:3px 4px;cursor:default}
  .badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff}
  .badge-green{background:#107C10}.badge-grey{background:#666}
  .badge-orange{background:#FF8C00;color:#333}.badge-red{background:#E81123}
  .excl{font-size:11px;color:#888;font-style:italic}
  .toggle-icon{font-size:10px;color:#0078D4;display:inline-block;width:14px;transition:transform .15s}
  .toggle-icon.open{transform:rotate(90deg)}
  .detail-panel{padding:16px 20px;background:#f8fafc;border-top:1px solid #ddd}
  .detail-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:16px}
  .detail-col{}
  .ds{margin-bottom:12px}
  .ds-label{font-size:11px;font-weight:bold;color:#555;text-transform:uppercase;letter-spacing:.4px;margin-bottom:3px}
  .ds ul{margin:2px 0;padding-left:16px;font-size:12px}
  .ds li{margin-bottom:1px}
  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
  .btn{padding:6px 13px;border:none;border-radius:4px;cursor:pointer;font-weight:bold;font-size:13px}
  .btn-all{background:#0078D4;color:#fff}.btn-bad{background:#E81123;color:#fff}
  .btn-warn{background:#FF8C00;color:#fff}.btn-dis{background:#888;color:#fff}
  .btn-expand{background:#eee;color:#333}
  .btn:hover{opacity:.85}
  input[type=text]{padding:6px 10px;border:1px solid #ccc;border-radius:4px;min-width:200px}
  @media(max-width:1200px){.detail-grid{grid-template-columns:repeat(2,1fr)}}
  @media(max-width:700px){.detail-grid{grid-template-columns:1fr}}
</style>
<script>
  var sortCol=-1,sortAsc=true,af='all';

  function toggle(id) {
    var dr=document.getElementById('dr-'+id);
    var ic=document.getElementById('ic-'+id);
    if(dr.style.display==='none'){
      dr.style.display=''; ic.classList.add('open');
    } else {
      dr.style.display='none'; ic.classList.remove('open');
    }
  }
  function expandAll() {
    document.querySelectorAll('.detail-row').forEach(function(r){r.style.display='';});
    document.querySelectorAll('.toggle-icon').forEach(function(i){i.classList.add('open');});
  }
  function collapseAll() {
    document.querySelectorAll('.detail-row').forEach(function(r){r.style.display='none';});
    document.querySelectorAll('.toggle-icon').forEach(function(i){i.classList.remove('open');});
  }

  function sortTable(c) {
    sortAsc=(sortCol===c)?!sortAsc:true; sortCol=c;
    var tb=document.getElementById('tb');
    var pairs=[];
    var rows=Array.from(tb.rows);
    for(var i=0;i<rows.length;i++){
      if(rows[i].classList.contains('summary-row')){
        var dr=(i+1<rows.length&&rows[i+1].classList.contains('detail-row'))?rows[i+1]:null;
        pairs.push({s:rows[i],d:dr});
      }
    }
    pairs.sort(function(a,b){
      var av=a.s.cells[c+1]?a.s.cells[c+1].innerText.trim():'';
      var bv=b.s.cells[c+1]?b.s.cells[c+1].innerText.trim():'';
      var an=parseFloat(av),bn=parseFloat(bv);
      var cmp=(!isNaN(an)&&!isNaN(bn))?(an-bn):av.localeCompare(bv);
      return sortAsc?cmp:-cmp;
    });
    pairs.forEach(function(p){tb.appendChild(p.s);if(p.d)tb.appendChild(p.d);});
    document.querySelectorAll('th').forEach(function(th,i){
      th.classList.remove('sort-asc','sort-desc');
      if(i===c+1)th.classList.add(sortAsc?'sort-asc':'sort-desc');
    });
  }

  function applyFilters(){
    var s=document.getElementById('search').value.toLowerCase();
    var tb=document.getElementById('tb');
    var rows=Array.from(tb.rows);
    for(var i=0;i<rows.length;i++){
      var r=rows[i];
      if(r.classList.contains('detail-row')) continue;
      var state=r.dataset.state,mc=r.dataset.misconfig;
      var mf=(af==='all')||
             (af==='bad'&&mc==='yes'&&state==='Enabled')||
             (af==='warn'&&state==='Report-Only')||
             (af==='dis'&&state==='Disabled');
      var ms=(s===''||r.innerText.toLowerCase().indexOf(s)>-1);
      var show=mf&&ms;
      r.style.display=show?'':'none';
      // collapse and hide detail row when parent is hidden
      var dr=(i+1<rows.length&&rows[i+1].classList.contains('detail-row'))?rows[i+1]:null;
      if(dr){
        if(!show){ dr.style.display='none'; var ic=r.querySelector('.toggle-icon'); if(ic)ic.classList.remove('open'); }
      }
    }
  }
  function setFilter(f){af=f;applyFilters();}
</script>
</head>
<body>
<div class="container">
  <h1>Conditional Access Report</h1>
  <div class="card" style="padding:10px 20px;font-size:13px">
    Generated: $genDate &nbsp;|&nbsp; Tenants: $totalTenants
  </div>

  <div class="dash">
    <div class="dc"><div class="dn blue">$totalTenants</div><div class="dl">Total Tenants</div></div>
    <div class="dc"><div class="dn red">$noCaTenants</div><div class="dl">No CA Policies</div><div style="font-size:11px;color:#888;margin-top:4px">$noCaLicensed licensed &nbsp;|&nbsp; $noCaUnlicensed no license</div></div>
    <div class="dc"><div class="dn red">$misconfigTenants</div><div class="dl">Tenants w/ Misconfigs</div></div>
    <div class="dc"><div class="dn">$totalPolicies</div><div class="dl">Total Policies</div></div>
    <div class="dc"><div class="dn green">$totalEnabled</div><div class="dl">Enabled</div></div>
    <div class="dc"><div class="dn orange">$totalReportOnly</div><div class="dl">Report-Only</div></div>
    <div class="dc"><div class="dn">$totalDisabled</div><div class="dl">Disabled</div></div>
    <div class="dc"><div class="dn red">$totalMisconfig</div><div class="dl">Misconfigured</div></div>
    <div class="dc"><div class="dn red">$errTenants</div><div class="dl">Auth Errors</div></div>
  </div>

  <div class="card">
    <h2>Policies</h2>
    <div class="filters">
      <button class="btn btn-all"    onclick="setFilter('all')">All ($($allPolicies.Count))</button>
      <button class="btn btn-bad"    onclick="setFilter('bad')">Misconfigured ($totalMisconfig)</button>
      <button class="btn btn-warn"   onclick="setFilter('warn')">Report-Only ($totalReportOnly)</button>
      <button class="btn btn-dis"    onclick="setFilter('dis')">Disabled ($totalDisabled)</button>
      <button class="btn btn-expand" onclick="expandAll()">Expand All</button>
      <button class="btn btn-expand" onclick="collapseAll()">Collapse All</button>
      <input type="text" id="search" placeholder="Search..." oninput="applyFilters()">
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th style="width:24px"></th>
        <th onclick="sortTable(0)">Client</th>
        <th onclick="sortTable(1)">Policy Name</th>
        <th onclick="sortTable(2)">State</th>
        <th onclick="sortTable(3)">Users Included</th>
        <th onclick="sortTable(4)">Users Excluded</th>
        <th onclick="sortTable(5)">Apps</th>
        <th onclick="sortTable(6)">Grant Controls</th>
        <th onclick="sortTable(7)">Session Controls</th>
        <th onclick="sortTable(8)">Issues</th>
      </tr></thead>
      <tbody id="tb">
$rows
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h3>Issue Guide</h3>
    <ul style="font-size:13px;line-height:1.9">
      <li><strong>No user scope:</strong> Policy is enabled but targets no users, groups, or roles — it matches no one.</li>
      <li><strong>No app scope:</strong> Policy is enabled but <em>includeApplications</em> is empty or None — it applies to no app.</li>
      <li><strong>No controls:</strong> Policy has valid user and app scope but no grant or session controls — matched sessions pass through unchallenged.</li>
      <li><strong>Report-Only:</strong> Policy is not enforcing. Sessions are logged but users are not blocked or prompted.</li>
    </ul>
  </div>

  <div class="card">
    <h3>Clients Without Conditional Access ($noCaTenants)</h3>
    <p style="font-size:12px;color:#666;margin-bottom:12px">
      <span style="display:inline-block;background:#107C10;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold">Green</span>&nbsp;= Has AAD Premium license but no CA policies configured (actionable)&nbsp;&nbsp;
      <span style="display:inline-block;background:#888;color:#fff;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:bold">Gray</span>&nbsp;= No AAD Premium license (CA not available without upgrade)
    </p>
    <div style="line-height:2">
$noCaHtml
    </div>
  </div>
</div>
</body>
</html>
"@ | Out-File -FilePath $htmlOut -Encoding utf8

    Write-Host "`nDone." -ForegroundColor Green
    Write-Host "CSV : $csvOut"  -ForegroundColor Cyan
    Write-Host "HTML: $htmlOut" -ForegroundColor Cyan
    if ($PSVersionTable.Platform -ne 'Unix') { Invoke-Item $htmlOut }
}

else {
    if ([string]::IsNullOrWhiteSpace($TenantId) -or
        [string]::IsNullOrWhiteSpace($ClientId)  -or
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "Provide -CsvPath or all of -TenantId, -ClientId, -ClientSecret."
        return
    }

    try {
        $token = Get-MsGraphTokenMain -TenantId $TenantId -ClientId $ClientId -ClientSecret $ClientSecret
        $h = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }

        $rawPolicies = Get-AllPagesMain -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $h

        Write-Host "`nConditional Access — $TenantId" -ForegroundColor Cyan
        Write-Host "  Policies found: $($rawPolicies.Count)" -ForegroundColor White

        $enabled = 0; $disabled = 0; $reportOnly = 0; $misconfig = 0

        foreach ($p in $rawPolicies | Sort-Object displayName) {
            $issues    = Get-PolicyIssues -Policy $p
            $userScope = Resolve-UserScope -Users $p.conditions.users
            $appScope  = Resolve-AppScope  -Apps $p.conditions.applications -KnownApps $script:knownApps
            $grantStr  = Format-GrantControls  -GC $p.grantControls
            $sessionStr= Format-SessionControls -SC $p.sessionControls

            $stateLabel = switch ($p.state) {
                "enabled"                           { $enabled++;    "Enabled" }
                "disabled"                          { $disabled++;   "Disabled" }
                "enabledForReportingButNotEnforced" { $reportOnly++; "Report-Only" }
                default                             { $p.state }
            }
            $isMisconfig = $issues.Count -gt 0 -and $issues -notcontains "Disabled"
            if ($isMisconfig) { $misconfig++ }

            $color = if     ($issues -contains "Disabled") { "Gray" }
                     elseif ($isMisconfig)                 { "Red" }
                     else                                  { "Green" }

            Write-Host "`n  [$stateLabel] $($p.displayName)" -ForegroundColor $color
            Write-Host "    Users  : $userScope" -ForegroundColor White
            Write-Host "    Apps   : $appScope"  -ForegroundColor White
            if ($grantStr)           { Write-Host "    Grant  : $grantStr"              -ForegroundColor White }
            if ($sessionStr)         { Write-Host "    Session: $sessionStr"            -ForegroundColor White }
            if ($issues.Count -gt 0) { Write-Host "    Issues : $($issues -join ' | ')" -ForegroundColor Red }
        }

        Write-Host "`n  Summary: $($rawPolicies.Count) total | $enabled enabled | $reportOnly report-only | $disabled disabled | $misconfig misconfigured" `
            -ForegroundColor $(if ($misconfig -gt 0) { "Yellow" } else { "Green" })

        $csvOut = Join-Path $resolvedOutput "ConditionalAccess-$TenantId.csv"
        $rawPolicies | ForEach-Object {
            $pi = Get-PolicyIssues -Policy $_
            [PSCustomObject]@{
                PolicyName      = $_.displayName
                State           = switch ($_.state) { "enabled"{"Enabled"} "disabled"{"Disabled"} "enabledForReportingButNotEnforced"{"Report-Only"} default{$_.state} }
                UsersIncluded   = Resolve-UserScope -Users $_.conditions.users
                AppsIncluded    = Resolve-AppScope  -Apps $_.conditions.applications -KnownApps $script:knownApps
                GrantControls   = Format-GrantControls  -GC $_.grantControls
                SessionControls = Format-SessionControls -SC $_.sessionControls
                IsMisconfigured = ($pi.Count -gt 0 -and $pi -notcontains "Disabled")
                Issues          = ($pi -join "; ")
                CreatedDate     = $_.createdDateTime
                ModifiedDate    = $_.modifiedDateTime
                PolicyId        = $_.id
            }
        } | Export-Csv -Path $csvOut -NoTypeInformation
        Write-Host "  CSV: $csvOut" -ForegroundColor Cyan
    }
    catch { Write-Error "Error: $_" }
}
