<#
.SYNOPSIS
    Reports MFA method distribution across one or more Microsoft 365 / Entra ID tenants.

.DESCRIPTION
    Connects to Microsoft Graph via app-only credentials and collects MFA registration data
    for enabled, licensed users across one or more Entra ID tenants. Outputs a CSV and HTML
    report. Falls back to per-user /authentication/methods if the bulk report endpoint is
    unavailable.

.PARAMETER TenantId
    Azure AD / Entra ID tenant ID (GUID). Required when not using -CsvPath.

.PARAMETER ClientId
    Application (client) ID of the registered app. Required when not using -CsvPath.

.PARAMETER ClientSecret
    Client secret for the registered app. Required when not using -CsvPath.

.PARAMETER CsvPath
    Path to a CSV file with columns: Client, Tenant ID, Client ID, Key Value.
    Enables multi-tenant MSP mode.

.PARAMETER ClientName
    When used with -CsvPath, processes only the tenant whose Client column matches
    this value.

.PARAMETER OutputFolder
    Directory where CSV and HTML reports are written. Defaults to the current directory.

.PARAMETER IncludeUserDetails
    When specified, exports a per-user CSV (one file per tenant) listing each user's
    registered methods and MFA strength classification.

.EXAMPLE
    # Single tenant
    .\Get-TenantMFADistribution.ps1 `
        -TenantId  "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" `
        -ClientId  "yyyyyyyy-yyyy-yyyy-yyyy-yyyyyyyyyyyy" `
        -ClientSecret "your-secret" `
        -OutputFolder "C:\Reports"

.EXAMPLE
    # All tenants in CSV
    .\Get-TenantMFADistribution.ps1 -CsvPath ".\AzureAppKeys.csv" -OutputFolder "C:\Reports"

.EXAMPLE
    # Single client from CSV with per-user detail export
    .\Get-TenantMFADistribution.ps1 -CsvPath ".\AzureAppKeys.csv" -ClientName "Contoso" -IncludeUserDetails

.NOTES
    Required Graph API permissions (application):
        Reports.Read.All         — bulk registration report (preferred)
        AuditLog.Read.All        — alternative for bulk report
        UserAuthenticationMethod.Read.All — per-user fallback if report endpoint is unavailable
        Policy.Read.All          — security defaults + CA policies
        Directory.Read.All       — user enumeration + organization info

    Author : Geoff Tankersley
    Version: 2.0
#>
param(
    [Parameter(Mandatory=$false)] [string]$TenantId,
    [Parameter(Mandatory=$false)] [string]$ClientId,
    [Parameter(Mandatory=$false)] [string]$ClientSecret,
    [Parameter(Mandatory=$false)] [string]$CsvPath,
    [Parameter(Mandatory=$false)] [string]$ClientName,
    [Parameter(Mandatory=$false)] [string]$OutputFolder,
    [Parameter(Mandatory=$false)] [switch]$IncludeUserDetails
)

#Requires -Version 7.0

$ErrorActionPreference = "Continue"
$resolvedOutput = if ($OutputFolder) { $OutputFolder } else { ".\" }

function Get-MsGraphTokenMain {
    param([string]$TenantId, [string]$ClientId, [string]$ClientSecret)
    $body = @{
        client_id     = $ClientId
        client_secret = $ClientSecret
        scope         = "https://graph.microsoft.com/.default"
        grant_type    = "client_credentials"
    }
    $r = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -Method Post -Body $body -ContentType "application/x-www-form-urlencoded"
    return $r.access_token
}

function Get-AllPagesMain {
    param([string]$Uri, [hashtable]$Headers)
    $results = @()
    $next = $Uri
    do {
        $r = Invoke-RestMethod -Uri $next -Method Get -Headers $Headers
        $results += $r.value
        $next = $r.'@odata.nextLink'
    } while ($next)
    return $results
}

$script:weakMethods     = @("mobilePhone","alternateMobilePhone","officePhone","email")
$script:strongMethods   = @("appNotification","appNotificationAndCode","appCode",
                             "softwareOneTimePasscode","hardwareOath")
$script:phishingMethods = @("microsoftAuthenticatorPasswordless","fido2",
                             "windowsHelloForBusiness","passKeyDeviceBound",
                             "passKeyDeviceBoundAuthenticator")

function Measure-MFAStrength {
    param([string[]]$Methods, [bool]$IsMfaRegistered)
    $hasPhishing = ($Methods | Where-Object { $script:phishingMethods -contains $_ }).Count -gt 0
    $hasStrong   = ($Methods | Where-Object { $script:strongMethods   -contains $_ }).Count -gt 0
    $hasWeakOnly = ($Methods | Where-Object { $script:weakMethods     -contains $_ }).Count -gt 0 `
                   -and -not $hasStrong -and -not $hasPhishing
    if    (-not $IsMfaRegistered) { return "None" }
    elseif ($hasPhishing)         { return "PhishingResistant" }
    elseif ($hasStrong)           { return "Strong" }
    elseif ($hasWeakOnly)         { return "WeakOnly" }
    else                          { return "None" }
}

if ($CsvPath) {
    if (-not (Test-Path -Path $CsvPath)) {
        Write-Error "CSV file not found: $CsvPath"; return
    }

    $tenants = Import-Csv -Path $CsvPath
    if ($ClientName) {
        $tenants = @($tenants | Where-Object { $_.Client -eq $ClientName })
        if ($tenants.Count -eq 0) { Write-Error "Client '$ClientName' not found in CSV."; return }
    }

    Write-Host "Processing $($tenants.Count) tenant(s) in parallel (ThrottleLimit 20)..." -ForegroundColor Cyan

    $includeDetails = $IncludeUserDetails.IsPresent
    $outFolder      = $resolvedOutput

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

        $weakM     = @("mobilePhone","alternateMobilePhone","officePhone","email")
        $strongM   = @("appNotification","appNotificationAndCode","appCode",
                        "softwareOneTimePasscode","hardwareOath")
        $phishingM = @("microsoftAuthenticatorPasswordless","fido2",
                        "windowsHelloForBusiness","passKeyDeviceBound",
                        "passKeyDeviceBoundAuthenticator")

        $t      = $_
        $name   = $t.Client.Trim()
        $tid    = $t.'Tenant ID'.Trim()
        $cid    = $t.'Client ID'.Trim()
        $secret = $t.'Key Value'.Trim()

        if ([string]::IsNullOrWhiteSpace($tid) -or
            [string]::IsNullOrWhiteSpace($cid) -or
            [string]::IsNullOrWhiteSpace($secret)) {
            return [PSCustomObject]@{
                ClientName="$name"; TenantId="$tid"; EnforcementType="Skipped"
                SecurityDefaults=$false; CAMfaEnforced=$false; CAMfaPolicy=""
                TotalUsers=0; MFARegistered=0; MFAPercent=0; NoMFA=0
                WeakOnlyCount=0; WeakOnlyPct=0; StrongCount=0; PhishingResistant=0
                SMSCount=0; AuthenticatorCount=0; FIDO2Count=0; WHfBCount=0
                PasswordlessCount=0; TOTPCount=0; EmailCount=0; PhoneCount=0
                SMSOnlyUsers=""; DataSource=""; Error="Missing credentials"
                UserDetails=$null
            }
        }

        try {
            $token = Get-Token -Tid $tid -Cid $cid -Sec $secret
            $h  = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }
            $hc = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json"
                     "ConsistencyLevel"="eventual" }

            $secDef = $false
            try {
                $sd = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" `
                    -Method Get -Headers $h -ErrorAction SilentlyContinue
                $secDef = [bool]$sd.isEnabled
            } catch {}

            $caMfa = $false; $caPolicy = ""
            try {
                $caps = Get-Pages -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -H $h
                foreach ($p in $caps) {
                    if ($p.state -ne "enabled") { continue }
                    $gc = $p.grantControls
                    if (-not $gc) { continue }
                    if ($gc.builtInControls -contains "mfa" -or $gc.authenticationStrength) {
                        $caMfa = $true; $caPolicy = $p.displayName; break
                    }
                }
            } catch {}

            $enforcement = if ($secDef) { "Security Defaults" }
                           elseif ($caMfa) { "Conditional Access" }
                           else { "None" }

            $licIds = [System.Collections.Generic.HashSet[string]]::new(
                          [System.StringComparer]::OrdinalIgnoreCase)
            try {
                $lu = Get-Pages -Uri ("https://graph.microsoft.com/v1.0/users?" +
                    "`$filter=accountEnabled eq true and assignedLicenses/`$count ne 0" +
                    "&`$select=id&`$count=true") -H $hc
                foreach ($u in $lu) { $licIds.Add($u.id) | Out-Null }
            } catch {}

            $users = @(); $source = "Report API"
            try {
                $users = Get-Pages -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -H $h
            } catch { $source = "Per-User API" }

            if ($licIds.Count -gt 0 -and $users.Count -gt 0) {
                $users = $users | Where-Object { $licIds.Contains($_.id) }
            }

            if ($source -eq "Per-User API" -or $users.Count -eq 0) {
                $source = "Per-User API"
                $rawU = @()
                try {
                    $rawU = Get-Pages -Uri ("https://graph.microsoft.com/v1.0/users?" +
                        "`$filter=accountEnabled eq true and assignedLicenses/`$count ne 0" +
                        "&`$select=id,userPrincipalName,displayName&`$count=true") -H $hc
                } catch {}

                $users = foreach ($u in $rawU) {
                    $methods = @()
                    try {
                        $mr = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/authentication/methods" `
                            -Method Get -Headers $h -ErrorAction SilentlyContinue
                        foreach ($m in $mr.value) {
                            $otype = $m.'@odata.type'.Split('.')[-1]
                            $mapped = switch ($otype) {
                                "microsoftAuthenticatorAuthenticationMethod"              { "appNotification" }
                                "passwordlessMicrosoftAuthenticatorAuthenticationMethod"  { "microsoftAuthenticatorPasswordless" }
                                "phoneAuthenticationMethod"   { if ($m.phoneType -eq "mobile") { "mobilePhone" } else { "officePhone" } }
                                "emailAuthenticationMethod"                               { "email" }
                                "fido2AuthenticationMethod"                               { "fido2" }
                                "windowsHelloForBusinessAuthenticationMethod"             { "windowsHelloForBusiness" }
                                "softwareOathAuthenticationMethod"                        { "softwareOneTimePasscode" }
                                "hardwareOathAuthenticationMethod"                        { "hardwareOath" }
                                default                                                   { $null }
                            }
                            if ($mapped) { $methods += $mapped }
                        }
                    } catch {}
                    [PSCustomObject]@{
                        id                = $u.id
                        userPrincipalName = $u.userPrincipalName
                        userDisplayName   = $u.displayName
                        isMfaRegistered   = ($methods.Count -gt 0)
                        methodsRegistered = $methods
                    }
                }
            }

            $totalUsers=0; $noMfa=0; $weakOnly=0; $strong=0; $phishing=0
            $sms=0; $auth=0; $fido2=0; $whfb=0; $passless=0; $totp=0
            $email=0; $phone=0
            $smsOnlyList = @()
            $userDetailList = @()

            foreach ($u in $users) {
                $totalUsers++
                $reg = @($u.methodsRegistered)

                if ($reg -contains "mobilePhone" -or $reg -contains "alternateMobilePhone") { $sms++ }
                if ($reg -contains "appNotification" -or $reg -contains "appNotificationAndCode" -or $reg -contains "appCode") { $auth++ }
                if ($reg -contains "fido2")                              { $fido2++ }
                if ($reg -contains "windowsHelloForBusiness")            { $whfb++ }
                if ($reg -contains "microsoftAuthenticatorPasswordless") { $passless++ }
                if ($reg -contains "softwareOneTimePasscode")            { $totp++ }
                if ($reg -contains "email")                              { $email++ }
                if ($reg -contains "officePhone")                        { $phone++ }

                $hasP = ($reg | Where-Object { $phishingM -contains $_ }).Count -gt 0
                $hasS = ($reg | Where-Object { $strongM   -contains $_ }).Count -gt 0
                $hasW = ($reg | Where-Object { $weakM     -contains $_ }).Count -gt 0 -and -not $hasS -and -not $hasP

                $strength = if     (-not $u.isMfaRegistered) { "None" }
                            elseif ($hasP)                   { "PhishingResistant" }
                            elseif ($hasS)                   { "Strong" }
                            elseif ($hasW)                   { "WeakOnly" }
                            else                             { "None" }

                switch ($strength) {
                    "None"             { $noMfa++ }
                    "PhishingResistant"{ $phishing++ }
                    "Strong"           { $strong++ }
                    "WeakOnly"         {
                        $weakOnly++
                        if ($smsOnlyList.Count -lt 20) { $smsOnlyList += $u.userPrincipalName }
                    }
                }

                if ($using:includeDetails) {
                    $userDetailList += [PSCustomObject]@{
                        UserPrincipalName = $u.userPrincipalName
                        DisplayName       = $u.userDisplayName
                        MFAStrength       = $strength
                        MethodsRegistered = ($reg -join ", ")
                    }
                }
            }

            $mfaReg     = $totalUsers - $noMfa
            $mfaPct     = if ($totalUsers -gt 0) { [Math]::Round($mfaReg   / $totalUsers * 100, 1) } else { 0 }
            $weakPct    = if ($totalUsers -gt 0) { [Math]::Round($weakOnly  / $totalUsers * 100, 1) } else { 0 }

            if ($using:includeDetails -and $userDetailList.Count -gt 0) {
                $uFile = Join-Path $using:outFolder "MFAUsers-$($name -replace '[^A-Za-z0-9]','').csv"
                $userDetailList | Export-Csv -Path $uFile -NoTypeInformation
            }

            [PSCustomObject]@{
                ClientName        = $name
                TenantId          = $tid
                EnforcementType   = $enforcement
                SecurityDefaults  = $secDef
                CAMfaEnforced     = $caMfa
                CAMfaPolicy       = $caPolicy
                TotalUsers        = $totalUsers
                MFARegistered     = $mfaReg
                MFAPercent        = $mfaPct
                NoMFA             = $noMfa
                WeakOnlyCount     = $weakOnly
                WeakOnlyPct       = $weakPct
                StrongCount       = $strong
                PhishingResistant = $phishing
                SMSCount          = $sms
                AuthenticatorCount= $auth
                FIDO2Count        = $fido2
                WHfBCount         = $whfb
                PasswordlessCount = $passless
                TOTPCount         = $totp
                EmailCount        = $email
                PhoneCount        = $phone
                SMSOnlyUsers      = ($smsOnlyList -join "; ")
                DataSource        = $source
                Error             = ""
            }
        }
        catch {
            [PSCustomObject]@{
                ClientName="$name"; TenantId="$tid"; EnforcementType="Error"
                SecurityDefaults=$false; CAMfaEnforced=$false; CAMfaPolicy=""
                TotalUsers=0; MFARegistered=0; MFAPercent=0; NoMFA=0
                WeakOnlyCount=0; WeakOnlyPct=0; StrongCount=0; PhishingResistant=0
                SMSCount=0; AuthenticatorCount=0; FIDO2Count=0; WHfBCount=0
                PasswordlessCount=0; TOTPCount=0; EmailCount=0; PhoneCount=0
                SMSOnlyUsers=""; DataSource=""; Error="$_"
            }
        }
    }

    $csvOut  = Join-Path $resolvedOutput "MFADistribution.csv"
    $allData | Export-Csv -Path $csvOut -NoTypeInformation

    $total       = $allData.Count
    $errCount    = ($allData | Where-Object { $_.EnforcementType -eq "Error" }).Count
    $noneCount   = ($allData | Where-Object { $_.EnforcementType -eq "None"  }).Count
    $sdCount     = ($allData | Where-Object { $_.SecurityDefaults -eq $true  }).Count
    $caCount     = ($allData | Where-Object { $_.CAMfaEnforced    -eq $true  }).Count
    $smsT        = ($allData | Where-Object { $_.SMSCount      -gt 0 }).Count
    $weakT       = ($allData | Where-Object { $_.WeakOnlyCount -gt 0 }).Count

    $gTotal  = ($allData | Measure-Object -Property TotalUsers    -Sum).Sum
    $gMFA    = ($allData | Measure-Object -Property MFARegistered -Sum).Sum
    $gNoMFA  = ($allData | Measure-Object -Property NoMFA         -Sum).Sum
    $gWeak   = ($allData | Measure-Object -Property WeakOnlyCount -Sum).Sum
    $gAuth   = ($allData | Measure-Object -Property AuthenticatorCount -Sum).Sum
    $gSMS    = ($allData | Measure-Object -Property SMSCount      -Sum).Sum
    $gPhish  = ($allData | Measure-Object -Property PhishingResistant -Sum).Sum
    $oPct    = if ($gTotal -gt 0) { [Math]::Round($gMFA / $gTotal * 100, 1) } else { 0 }

    $htmlOut  = Join-Path $resolvedOutput "MFADistribution.html"
    $genDate  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    $rows = ""
    foreach ($t in ($allData | Sort-Object ClientName)) {
        $rowClass = switch ($t.EnforcementType) {
            "Error"  { "row-error" }
            "None"   { if ($t.NoMFA -gt 0) { "row-bad" } else { "row-noenforce" } }
            default  { if ($t.WeakOnlyCount -gt 0) { "row-weak" } else { "row-ok" } }
        }
        $mfaColor = if ($t.MFAPercent -ge 99) { "#107C10" } elseif ($t.MFAPercent -ge 80) { "#FF8C00" } else { "#E81123" }
        $enfBadge = switch ($t.EnforcementType) {
            "Security Defaults"  { "<span class='badge badge-blue'>Security Defaults</span>" }
            "Conditional Access" { "<span class='badge badge-green'>CA: $($t.CAMfaPolicy)</span>" }
            "None"               { "<span class='badge badge-red'>None</span>" }
            "Error"              { "<span class='badge badge-grey'>Error</span>" }
            "Skipped"            { "<span class='badge badge-grey'>Skipped</span>" }
            default              { $t.EnforcementType }
        }
        $weakBadge = if ($t.WeakOnlyCount -gt 0) { "<span class='badge badge-orange' title='$($t.SMSOnlyUsers)'>$($t.WeakOnlyCount) weak-only</span>" } else { "" }

        $rows += @"
        <tr class="$rowClass" data-enforce="$($t.EnforcementType)" data-weak="$(if($t.WeakOnlyCount -gt 0){'yes'}else{'no'})" data-nomfa="$(if($t.NoMFA -gt 0){'yes'}else{'no'})">
            <td>$($t.ClientName)</td>
            <td>$enfBadge</td>
            <td>$($t.TotalUsers)</td>
            <td style="color:$mfaColor;font-weight:bold">$($t.MFAPercent)%</td>
            <td>$($t.MFARegistered)</td>
            <td$(if($t.NoMFA -gt 0){" style='color:#E81123;font-weight:bold'"})>$($t.NoMFA)</td>
            <td$(if($t.WeakOnlyCount -gt 0){" style='color:#FF8C00;font-weight:bold'"})>$($t.WeakOnlyCount) $weakBadge</td>
            <td>$($t.StrongCount)</td>
            <td>$($t.PhishingResistant)</td>
            <td$(if($t.SMSCount -gt 0){" style='color:#FF8C00'"})>$($t.SMSCount)</td>
            <td>$($t.AuthenticatorCount)</td>
            <td>$($t.TOTPCount)</td>
            <td>$($t.FIDO2Count)</td>
            <td>$($t.WHfBCount)</td>
            <td>$($t.PasswordlessCount)</td>
            <td style="font-size:11px;color:#555">$($t.DataSource)</td>
            <td style="font-size:11px;color:#E81123">$($t.Error)</td>
        </tr>
"@
    }

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MFA Distribution Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
  h1,h2{color:#0078D4}
  .container{max-width:1900px;margin:0 auto}
  .card{background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}
  .dash{display:flex;flex-wrap:wrap;gap:15px;margin-bottom:20px}
  .dc{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:15px;flex:1;min-width:150px;text-align:center}
  .dn{font-size:32px;font-weight:bold;margin:8px 0}
  .dl{font-size:12px;color:#666}
  .red{color:#E81123}.orange{color:#FF8C00}.green{color:#107C10}.blue{color:#0078D4}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{padding:7px 9px;text-align:left;border-bottom:1px solid #ddd;white-space:nowrap}
  th{background:#0078D4;color:#fff;cursor:pointer;user-select:none}
  th:hover{background:#005a9e}
  th.sort-asc::after{content:' \25B2';font-size:10px}
  th.sort-desc::after{content:' \25BC';font-size:10px}
  tr:hover td{background:#f0f7ff}
  .row-bad       {background:#fde7e9;border-left:4px solid #E81123}
  .row-noenforce {background:#fff4ce;border-left:4px solid #FF8C00}
  .row-weak      {background:#fff8ed;border-left:4px solid #FFB900}
  .row-error     {background:#f0f0f0;border-left:4px solid #aaa}
  .row-ok        {border-left:4px solid #107C10}
  .badge{display:inline-block;padding:2px 7px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff}
  .badge-blue{background:#0078D4}.badge-green{background:#107C10}
  .badge-red{background:#E81123}.badge-orange{background:#FF8C00}.badge-grey{background:#666}
  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;align-items:center}
  .btn{padding:6px 13px;border:none;border-radius:4px;cursor:pointer;font-weight:bold;font-size:13px}
  .btn-all{background:#0078D4;color:#fff}.btn-err{background:#888;color:#fff}
  .btn-noenf{background:#FF8C00;color:#fff}.btn-weak{background:#FFB900;color:#333}
  .btn-nomfa{background:#8764B8;color:#fff}.btn:hover{opacity:.85}
  input[type=text]{padding:6px 10px;border:1px solid #ccc;border-radius:4px;min-width:200px}
</style>
<script>
  var sortCol=-1,sortAsc=true;
  function sortTable(c){
    sortAsc=(sortCol===c)?!sortAsc:true; sortCol=c;
    var tb=document.getElementById('tb');
    var rows=Array.from(tb.rows);
    rows.sort(function(a,b){
      var av=a.cells[c]?a.cells[c].innerText.trim():'';
      var bv=b.cells[c]?b.cells[c].innerText.trim():'';
      var an=parseFloat(av),bn=parseFloat(bv);
      var cmp=(!isNaN(an)&&!isNaN(bn))?(an-bn):av.localeCompare(bv);
      return sortAsc?cmp:-cmp;
    });
    rows.forEach(function(r){tb.appendChild(r);});
    document.querySelectorAll('th').forEach(function(th,i){
      th.classList.remove('sort-asc','sort-desc');
      if(i===c)th.classList.add(sortAsc?'sort-asc':'sort-desc');
    });
  }
  var af='all';
  function applyFilters(){
    var s=document.getElementById('search').value.toLowerCase();
    Array.from(document.getElementById('tb').rows).forEach(function(r){
      var enf=r.dataset.enforce,weak=r.dataset.weak,nomfa=r.dataset.nomfa;
      var mf=(af==='all')||(af==='noenforce'&&enf==='None')||(af==='weak'&&weak==='yes')||
             (af==='nomfa'&&nomfa==='yes')||(af==='errors'&&enf==='Error');
      var ms=(s===''||r.innerText.toLowerCase().indexOf(s)>-1);
      r.style.display=(mf&&ms)?'':'none';
    });
  }
  function setFilter(f){af=f;applyFilters();}
</script>
</head>
<body>
<div class="container">
  <h1>MFA Distribution Report</h1>
  <div class="card" style="padding:10px 20px;font-size:13px">
    Generated: $genDate &nbsp;|&nbsp; Tenants: $total &nbsp;|&nbsp; Enabled licensed users: $gTotal
  </div>

  <div class="dash">
    <div class="dc"><div class="dn blue">$total</div><div class="dl">Total Tenants</div></div>
    <div class="dc"><div class="dn green">$sdCount</div><div class="dl">Security Defaults On</div></div>
    <div class="dc"><div class="dn green">$caCount</div><div class="dl">CA MFA Enforcement</div></div>
    <div class="dc"><div class="dn red">$noneCount</div><div class="dl">No MFA Enforcement</div></div>
    <div class="dc"><div class="dn">$oPct%</div><div class="dl">Overall MFA Coverage</div></div>
    <div class="dc"><div class="dn red">$gNoMFA</div><div class="dl">Users — No MFA</div></div>
    <div class="dc"><div class="dn orange">$gWeak</div><div class="dl">Users — Weak/SMS Only</div></div>
    <div class="dc"><div class="dn orange">$smsT</div><div class="dl">Tenants with SMS Users</div></div>
    <div class="dc"><div class="dn green">$gPhish</div><div class="dl">Phishing-Resistant Users</div></div>
  </div>

  <div class="card">
    <h2>Results</h2>
    <div class="filters">
      <button class="btn btn-all"  onclick="setFilter('all')">All ($total)</button>
      <button class="btn btn-noenf" onclick="setFilter('noenforce')">No Enforcement ($noneCount)</button>
      <button class="btn btn-weak"  onclick="setFilter('weak')">Weak/SMS MFA ($weakT)</button>
      <button class="btn btn-nomfa" onclick="setFilter('nomfa')">Has No-MFA Users</button>
      <button class="btn btn-err"   onclick="setFilter('errors')">Auth Errors ($errCount)</button>
      <input type="text" id="search" placeholder="Search..." oninput="applyFilters()">
    </div>
    <div style="overflow-x:auto">
    <table>
      <thead><tr>
        <th onclick="sortTable(0)">Client</th>
        <th onclick="sortTable(1)">Enforcement</th>
        <th onclick="sortTable(2)">Users</th>
        <th onclick="sortTable(3)">MFA%</th>
        <th onclick="sortTable(4)">MFA Reg'd</th>
        <th onclick="sortTable(5)">No MFA</th>
        <th onclick="sortTable(6)">Weak/SMS-Only</th>
        <th onclick="sortTable(7)">Strong MFA</th>
        <th onclick="sortTable(8)">Phishing-Resistant</th>
        <th onclick="sortTable(9)">SMS Users</th>
        <th onclick="sortTable(10)">Authenticator</th>
        <th onclick="sortTable(11)">TOTP</th>
        <th onclick="sortTable(12)">FIDO2</th>
        <th onclick="sortTable(13)">WHfB</th>
        <th onclick="sortTable(14)">Passwordless</th>
        <th onclick="sortTable(15)">Source</th>
        <th onclick="sortTable(16)">Error</th>
      </tr></thead>
      <tbody id="tb">
$rows
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h3>Column Guide</h3>
    <ul style="font-size:13px;line-height:1.9">
      <li><strong>Weak/SMS-Only:</strong> Users whose only registered MFA method is SMS, voice call, or email — no Authenticator app or stronger method. Hover badge for usernames (first 20).</li>
      <li><strong>Strong MFA:</strong> Microsoft Authenticator push + software/hardware TOTP. Better than SMS but susceptible to push-fatigue and AiTM attacks.</li>
      <li><strong>Phishing-Resistant:</strong> FIDO2 keys, Windows Hello for Business, Passwordless Authenticator — cannot be bypassed by adversary-in-the-middle or push-fatigue.</li>
      <li><strong>Source:</strong> "Report API" = bulk registration report (<em>Reports.Read.All</em> required). "Per-User API" = per-user method query fallback (<em>UserAuthenticationMethod.Read.All</em>).</li>
    </ul>
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
        $h  = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }
        $hc = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json"
                 "ConsistencyLevel"="eventual" }

        $secDef = $false
        try {
            $sd = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy" `
                -Method Get -Headers $h -ErrorAction SilentlyContinue
            $secDef = [bool]$sd.isEnabled
        } catch {}

        $caMfa = $false; $caPolicy = ""
        try {
            $caps = Get-AllPagesMain -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $h
            foreach ($p in $caps) {
                if ($p.state -ne "enabled") { continue }
                $gc = $p.grantControls
                if ($gc -and ($gc.builtInControls -contains "mfa" -or $gc.authenticationStrength)) {
                    $caMfa = $true; $caPolicy = $p.displayName; break
                }
            }
        } catch {}

        $enforcement = if ($secDef) { "Security Defaults" } elseif ($caMfa) { "Conditional Access" } else { "None" }

        $licIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        try {
            $lu = Get-AllPagesMain -Uri ("https://graph.microsoft.com/v1.0/users?" +
                "`$filter=accountEnabled eq true and assignedLicenses/`$count ne 0&`$select=id&`$count=true") -Headers $hc
            foreach ($u in $lu) { $licIds.Add($u.id) | Out-Null }
        } catch {}

        $users = @(); $source = "Report API"
        try {
            $users = Get-AllPagesMain -Uri "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails" -Headers $h
        } catch { $source = "Per-User API" }

        if ($licIds.Count -gt 0 -and $users.Count -gt 0) {
            $users = $users | Where-Object { $licIds.Contains($_.id) }
        }

        if ($source -eq "Per-User API" -or $users.Count -eq 0) {
            $source = "Per-User API"
            $rawU = @()
            try {
                $rawU = Get-AllPagesMain -Uri ("https://graph.microsoft.com/v1.0/users?" +
                    "`$filter=accountEnabled eq true and assignedLicenses/`$count ne 0&`$select=id,userPrincipalName,displayName&`$count=true") -Headers $hc
            } catch {}
            $users = foreach ($u in $rawU) {
                $methods = @()
                try {
                    $mr = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users/$($u.id)/authentication/methods" `
                        -Method Get -Headers $h -ErrorAction SilentlyContinue
                    foreach ($m in $mr.value) {
                        $otype = $m.'@odata.type'.Split('.')[-1]
                        $mapped = switch ($otype) {
                            "microsoftAuthenticatorAuthenticationMethod"              { "appNotification" }
                            "passwordlessMicrosoftAuthenticatorAuthenticationMethod"  { "microsoftAuthenticatorPasswordless" }
                            "phoneAuthenticationMethod" { if ($m.phoneType -eq "mobile") { "mobilePhone" } else { "officePhone" } }
                            "emailAuthenticationMethod"                               { "email" }
                            "fido2AuthenticationMethod"                               { "fido2" }
                            "windowsHelloForBusinessAuthenticationMethod"             { "windowsHelloForBusiness" }
                            "softwareOathAuthenticationMethod"                        { "softwareOneTimePasscode" }
                            "hardwareOathAuthenticationMethod"                        { "hardwareOath" }
                            default                                                   { $null }
                        }
                        if ($mapped) { $methods += $mapped }
                    }
                } catch {}
                [PSCustomObject]@{
                    id = $u.id; userPrincipalName = $u.userPrincipalName
                    userDisplayName = $u.displayName
                    isMfaRegistered = ($methods.Count -gt 0); methodsRegistered = $methods
                }
            }
        }

        $totalU=0; $noMfa=0; $weakOnly=0; $strong=0; $phishing=0
        $sms=0; $auth=0; $fido2=0; $whfb=0; $passless=0; $totp=0; $email=0; $phone=0
        $userDetailList = @()

        foreach ($u in $users) {
            $totalU++
            $reg = @($u.methodsRegistered)
            if ($reg -contains "mobilePhone" -or $reg -contains "alternateMobilePhone") { $sms++ }
            if ($reg -contains "appNotification" -or $reg -contains "appNotificationAndCode" -or $reg -contains "appCode") { $auth++ }
            if ($reg -contains "fido2")                              { $fido2++ }
            if ($reg -contains "windowsHelloForBusiness")            { $whfb++ }
            if ($reg -contains "microsoftAuthenticatorPasswordless") { $passless++ }
            if ($reg -contains "softwareOneTimePasscode")            { $totp++ }
            if ($reg -contains "email")                              { $email++ }
            if ($reg -contains "officePhone")                        { $phone++ }

            $strength = Measure-MFAStrength -Methods $reg -IsMfaRegistered $u.isMfaRegistered
            switch ($strength) {
                "None"              { $noMfa++ }
                "PhishingResistant" { $phishing++ }
                "Strong"            { $strong++ }
                "WeakOnly"          { $weakOnly++ }
            }
            if ($IncludeUserDetails) {
                $userDetailList += [PSCustomObject]@{
                    UserPrincipalName = $u.userPrincipalName
                    DisplayName       = $u.userDisplayName
                    MFAStrength       = $strength
                    MethodsRegistered = ($reg -join ", ")
                }
            }
        }

        $mfaReg = $totalU - $noMfa
        $mfaPct = if ($totalU -gt 0) { [Math]::Round($mfaReg / $totalU * 100, 1) } else { 0 }

        Write-Host "`nMFA Distribution — Single Tenant" -ForegroundColor Cyan
        Write-Host "  Enforcement    : $enforcement$(if($caPolicy){" ($caPolicy)"})" -ForegroundColor White
        Write-Host "  Security Def.  : $secDef" -ForegroundColor White
        Write-Host "  Total users    : $totalU" -ForegroundColor White
        Write-Host "  MFA registered : $mfaReg ($mfaPct%)" -ForegroundColor $(if ($mfaPct -gt 90) {"Green"} elseif ($mfaPct -gt 50) {"Yellow"} else {"Red"})
        Write-Host "  No MFA         : $noMfa"     -ForegroundColor $(if ($noMfa -eq 0) {"Green"} else {"Red"})
        Write-Host "  Weak/SMS-only  : $weakOnly"  -ForegroundColor $(if ($weakOnly -eq 0) {"Green"} else {"Yellow"})
        Write-Host "  Strong MFA     : $strong"    -ForegroundColor White
        Write-Host "  Phish-resistant: $phishing"  -ForegroundColor $(if ($phishing -gt 0) {"Green"} else {"Gray"})
        Write-Host "  Authenticator  : $auth  | TOTP: $totp  | FIDO2: $fido2  | WHfB: $whfb  | Passwordless: $passless" -ForegroundColor White
        Write-Host "  SMS            : $sms   | Email: $email  | Phone: $phone" -ForegroundColor $(if ($sms -gt 0) {"Yellow"} else {"White"})
        Write-Host "  Data source    : $source" -ForegroundColor Gray

        $csvOut = Join-Path $resolvedOutput "MFADistribution-$TenantId.csv"
        [PSCustomObject]@{
            TenantId="$TenantId"; EnforcementType=$enforcement; SecurityDefaults=$secDef
            CAMfaEnforced=$caMfa; CAMfaPolicy=$caPolicy; TotalUsers=$totalU
            MFARegistered=$mfaReg; MFAPercent=$mfaPct; NoMFA=$noMfa
            WeakOnlyCount=$weakOnly; StrongCount=$strong; PhishingResistant=$phishing
            SMSCount=$sms; AuthenticatorCount=$auth; FIDO2Count=$fido2; WHfBCount=$whfb
            PasswordlessCount=$passless; TOTPCount=$totp; EmailCount=$email; PhoneCount=$phone
            DataSource=$source
        } | Export-Csv -Path $csvOut -NoTypeInformation

        if ($IncludeUserDetails -and $userDetailList.Count -gt 0) {
            $uFile = Join-Path $resolvedOutput "MFAUsers-$TenantId.csv"
            $userDetailList | Export-Csv -Path $uFile -NoTypeInformation
            Write-Host "  User details   : $uFile" -ForegroundColor Cyan
        }
        Write-Host "  CSV            : $csvOut" -ForegroundColor Cyan
    }
    catch {
        Write-Error "Error: $_"
    }
}
