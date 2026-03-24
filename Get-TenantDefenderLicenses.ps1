<#
.SYNOPSIS
    Reports Microsoft Defender product and suite licensing across one or more Entra ID tenants.

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
    .\Get-TenantDefenderLicenses.ps1 -CsvPath ".\AzureAppKeys.csv" -OutputFolder "C:\Reports"

.NOTES
    Required Graph API permissions (application):
        Organization.Read.All — tenant display name and domain
        Directory.Read.All    — subscribed SKUs

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

# ─── Single-tenant helper functions (used in the else branch only) ───────────

function Get-MsGraphToken {
    param([string]$Tid, [string]$Cid, [string]$Sec)
    $b = @{ client_id=$Cid; client_secret=$Sec
            scope="https://graph.microsoft.com/.default"; grant_type="client_credentials" }
    (Invoke-RestMethod "https://login.microsoftonline.com/$Tid/oauth2/v2.0/token" `
        -Method Post -Body $b -ContentType "application/x-www-form-urlencoded").access_token
}

function Get-AllPages {
    param([string]$Uri, [hashtable]$H)
    $out = @(); $next = $Uri
    do { $r = Invoke-RestMethod -Uri $next -Method Get -Headers $H
         $out += $r.value; $next = $r.'@odata.nextLink' } while ($next)
    return $out
}

# ─── CSV / multi-tenant path ─────────────────────────────────────────────────

if ($CsvPath) {
    if (-not (Test-Path $CsvPath)) { Write-Error "CSV not found: $CsvPath"; return }

    $tenants = Import-Csv -Path $CsvPath
    if ($ClientName) {
        $tenants = @($tenants | Where-Object { $_.Client -eq $ClientName -or $_.Client -like "*$ClientName*" })
        if ($tenants.Count -eq 0) { Write-Error "Client '$ClientName' not found in CSV."; return }
    }

    Write-Host "Processing $($tenants.Count) tenant(s) in parallel (ThrottleLimit 20)..." -ForegroundColor Cyan

    $allTenantsLicenseInfo = $tenants | ForEach-Object -ThrottleLimit 20 -Parallel {

        function Get-Token {
            param([string]$Tid, [string]$Cid, [string]$Sec)
            $b = @{ client_id=$Cid; client_secret=$Sec
                    scope="https://graph.microsoft.com/.default"; grant_type="client_credentials" }
            (Invoke-RestMethod "https://login.microsoftonline.com/$Tid/oauth2/v2.0/token" `
                -Method Post -Body $b -ContentType "application/x-www-form-urlencoded").access_token
        }
        function Get-Pages {
            param([string]$Uri, [hashtable]$H)
            $out = @(); $next = $Uri
            do { $r = Invoke-RestMethod -Uri $next -Method Get -Headers $H
                 $out += $r.value; $next = $r.'@odata.nextLink' } while ($next)
            return $out
        }

        $t      = $_
        $name   = $t.Client.Trim()
        $tid    = $t.'Tenant ID'.Trim()
        $cid    = $t.'Client ID'.Trim()
        $secret = $t.'Key Value'.Trim()

        $empty = [PSCustomObject]@{
            ClientName="$name"; TenantId="$tid"; InitialDomain=""; DisplayName=""
            DefenderForOffice365_P1=$false; DefenderForOffice365_P2=$false
            DefenderForEndpoint=$false;    DefenderForIdentity=$false
            DefenderForCloudApps=$false;   DefenderForServers=$false
            DefenderVulnerabilityManagement=$false
            AzureADPremium_P1=$false;      AzureADPremium_P2=$false
            Microsoft365_E3=$false;        Microsoft365_E5=$false
            Microsoft365_BusinessPremium=$false
            EMS_E3=$false;                 EMS_E5=$false
            Error=""
        }

        if ([string]::IsNullOrWhiteSpace($tid) -or [string]::IsNullOrWhiteSpace($cid) -or [string]::IsNullOrWhiteSpace($secret)) {
            $empty.Error = "Missing credentials"; return $empty
        }

        try {
            $token = Get-Token -Tid $tid -Cid $cid -Sec $secret
            $h = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }

            # Tenant domain
            $initialDomain = ""; $displayName = ""
            try {
                $org = (Invoke-RestMethod "https://graph.microsoft.com/v1.0/organization" -Headers $h).value[0]
                $displayName  = $org.displayName
                $initialDomain = ($org.verifiedDomains | Where-Object { $_.isInitial }).name
            } catch {}

            # License SKUs
            $skus = @()
            try { $skus = Get-Pages "https://graph.microsoft.com/v1.0/subscribedSkus" $h } catch {}

            # Detection maps
            $licenseMap = @{
                "DefenderForOffice365_P1"        = @("THREAT_INTELLIGENCE","ATP_ENTERPRISE","DEFENDER_ENDPOINT_P1")
                "DefenderForOffice365_P2"        = @("DEFENDER_ENDPOINT_P2","ATP_ENTERPRISE_FACULTY")
                "DefenderForEndpoint"            = @("MDATP_XPLAT","MDATP_AAD_PREMIUM")
                "DefenderForIdentity"            = @("ATA")
                "DefenderForCloudApps"           = @("ADALLOM_S_O365","ADALLOM_S_STANDALONE","MCOPSTNC")
                "DefenderForServers"             = @("DEFENDER_ENDPOINT_P1_VDA","DEFENDER_ENDPOINT_P2_VDA","MDATP_Server","MDATP_Server_SCCM")
                "DefenderVulnerabilityManagement"= @("DEFENDER_VULN_MGMT","MDATP_VULNERABILITY_MGMT")
                "AzureADPremium_P1"              = @("AAD_PREMIUM","AAD_PREMIUM_FACULTY","MFA_PREMIUM")
                "AzureADPremium_P2"              = @("AAD_PREMIUM_P2","AAD_PREMIUM_P2_FACULTY","MFA_PREMIUM_P2")
                "Microsoft365_E3"                = @("SPE_E3","SPE_E3_FACULTY","M365_E3_STUUSEBNFT")
                "Microsoft365_E5"                = @("SPE_E5","SPE_E5_FACULTY","M365_E5_STUUSEBNFT")
                "Microsoft365_BusinessPremium"   = @("SPB","O365_BUSINESS_PREMIUM")
                "EMS_E3"                         = @("EMS","EMSPREMIUM","EMS_FACULTY")
                "EMS_E5"                         = @("EMSPREMIUM_AAD_P2","EMSPREMIUM_SECCOMP","EMS_EDU_FACULTY")
            }

            $status = @{}
            foreach ($k in $licenseMap.Keys) { $status[$k] = $false }

            foreach ($sku in $skus) {
                $pn    = $sku.skuPartNumber
                $plans = $sku.servicePlans

                # SKU-level match
                foreach ($k in $licenseMap.Keys) {
                    if ($licenseMap[$k] -contains $pn) { $status[$k] = $true }
                }

                # Service plan checks for bundled products in suites
                if ($plans) {
                    $pnames = @($plans | Where-Object { $_.provisioningStatus -eq "Success" } | ForEach-Object { $_.servicePlanName })

                    if ($pnames -contains "THREAT_INTELLIGENCE" -or $pnames -contains "ATP_ENTERPRISE")      { $status["DefenderForOffice365_P2"] = $true }
                    if ($pnames -contains "ATP_ENTERPRISE" -and -not ($pnames -contains "THREAT_INTELLIGENCE")) { $status["DefenderForOffice365_P1"] = $true }
                    if ($pnames -contains "MDATP_XPLAT" -or $pnames -contains "MDATP_AAD_PREMIUM")          { $status["DefenderForEndpoint"] = $true }
                    if ($pnames -contains "ATA")                                                              { $status["DefenderForIdentity"] = $true }
                    if ($pnames -contains "ADALLOM_S_O365" -or $pnames -contains "ADALLOM_S_STANDALONE")    { $status["DefenderForCloudApps"] = $true }
                    if ($pnames -contains "MDATP_Server" -or $pnames -contains "MDATP_Server_SCCM")         { $status["DefenderForServers"] = $true }
                    if ($pnames -contains "DEFENDER_VULN_MGMT" -or $pnames -contains "MDATP_VULNERABILITY_MGMT") { $status["DefenderVulnerabilityManagement"] = $true }
                    if ($pnames -contains "AAD_PREMIUM")    { $status["AzureADPremium_P1"] = $true }
                    if ($pnames -contains "AAD_PREMIUM_P2") { $status["AzureADPremium_P2"] = $true }
                }
            }

            [PSCustomObject]@{
                ClientName   = $name;  TenantId      = $tid
                InitialDomain= $initialDomain; DisplayName = $displayName
                DefenderForOffice365_P1        = $status["DefenderForOffice365_P1"]
                DefenderForOffice365_P2        = $status["DefenderForOffice365_P2"]
                DefenderForEndpoint            = $status["DefenderForEndpoint"]
                DefenderForIdentity            = $status["DefenderForIdentity"]
                DefenderForCloudApps           = $status["DefenderForCloudApps"]
                DefenderForServers             = $status["DefenderForServers"]
                DefenderVulnerabilityManagement= $status["DefenderVulnerabilityManagement"]
                AzureADPremium_P1              = $status["AzureADPremium_P1"]
                AzureADPremium_P2              = $status["AzureADPremium_P2"]
                Microsoft365_E3                = $status["Microsoft365_E3"]
                Microsoft365_E5                = $status["Microsoft365_E5"]
                Microsoft365_BusinessPremium   = $status["Microsoft365_BusinessPremium"]
                EMS_E3                         = $status["EMS_E3"]
                EMS_E5                         = $status["EMS_E5"]
                Error = ""
            }
        }
        catch {
            $empty.Error = "$_"; return $empty
        }
    }

    # ── Summary statistics ────────────────────────────────────────────────────
    $totalTenants                  = $allTenantsLicenseInfo.Count
    $tenantsWithDefenderOffice365  = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForOffice365_P1 -or $_.DefenderForOffice365_P2 }).Count
    $tenantsWithDfO365P1           = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForOffice365_P1 }).Count
    $tenantsWithDfO365P2           = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForOffice365_P2 }).Count
    $tenantsWithDefenderEndpoint   = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForEndpoint }).Count
    $tenantsWithDefenderIdentity   = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForIdentity }).Count
    $tenantsWithDefenderCloudApps  = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForCloudApps }).Count
    $tenantsWithDefenderServers    = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForServers }).Count
    $tenantsWithDefenderVulnMgmt   = ($allTenantsLicenseInfo | Where-Object { $_.DefenderVulnerabilityManagement }).Count
    $tenantsWithAzureADP1          = ($allTenantsLicenseInfo | Where-Object { $_.AzureADPremium_P1 }).Count
    $tenantsWithAzureADP2          = ($allTenantsLicenseInfo | Where-Object { $_.AzureADPremium_P2 }).Count
    $tenantsWithM365E3             = ($allTenantsLicenseInfo | Where-Object { $_.Microsoft365_E3 }).Count
    $tenantsWithM365E5             = ($allTenantsLicenseInfo | Where-Object { $_.Microsoft365_E5 }).Count
    $tenantsWithBP                 = ($allTenantsLicenseInfo | Where-Object { $_.Microsoft365_BusinessPremium }).Count
    $tenantsWithEMSE3              = ($allTenantsLicenseInfo | Where-Object { $_.EMS_E3 }).Count
    $tenantsWithEMSE5              = ($allTenantsLicenseInfo | Where-Object { $_.EMS_E5 }).Count
    $tenantsWithAnySuite           = ($allTenantsLicenseInfo | Where-Object { $_.Microsoft365_E3 -or $_.Microsoft365_E5 -or $_.Microsoft365_BusinessPremium -or $_.EMS_E3 -or $_.EMS_E5 }).Count

    # ── Client lists for breakdown section ────────────────────────────────────
    $clientsWithDfO365P1    = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForOffice365_P1 }        | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDfO365P2    = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForOffice365_P2 }        | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDfEP        = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForEndpoint }            | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDfI         = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForIdentity }            | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDfCA        = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForCloudApps }           | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDfS         = ($allTenantsLicenseInfo | Where-Object { $_.DefenderForServers }             | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithDVM         = ($allTenantsLicenseInfo | Where-Object { $_.DefenderVulnerabilityManagement }| Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithAadP1       = ($allTenantsLicenseInfo | Where-Object { $_.AzureADPremium_P1 }             | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "
    $clientsWithAadP2       = ($allTenantsLicenseInfo | Where-Object { $_.AzureADPremium_P2 }             | Sort-Object ClientName | ForEach-Object { $_.ClientName }) -join ", "

    # ── CSV export ────────────────────────────────────────────────────────────
    $csvFile = Join-Path $resolvedOutput "MS-Defender-License-Report.csv"
    $allTenantsLicenseInfo | Export-Csv -Path $csvFile -NoTypeInformation

    # ── Build table rows ──────────────────────────────────────────────────────
    $tableRows = ""
    foreach ($t in ($allTenantsLicenseInfo | Sort-Object ClientName)) {
        $prods = @()
        if ($t.DefenderForOffice365_P1)         { $prods += "dfo1" }
        if ($t.DefenderForOffice365_P2)         { $prods += "dfo2" }
        if ($t.DefenderForEndpoint)             { $prods += "dfep" }
        if ($t.DefenderForIdentity)             { $prods += "dfi" }
        if ($t.DefenderForCloudApps)            { $prods += "dfca" }
        if ($t.DefenderForServers)              { $prods += "dfs" }
        if ($t.DefenderVulnerabilityManagement) { $prods += "dvm" }
        if ($t.AzureADPremium_P1)              { $prods += "aadp1" }
        if ($t.AzureADPremium_P2)              { $prods += "aadp2" }
        $prodAttr = $prods -join ","

        $tableRows += @"
                <tr data-products="$prodAttr">
                    <td>$([System.Net.WebUtility]::HtmlEncode($t.ClientName))</td>
                    <td>$([System.Net.WebUtility]::HtmlEncode($t.InitialDomain))</td>
                    <td class="$($t.DefenderForOffice365_P1.ToString().ToLower())">$(if($t.DefenderForOffice365_P1){'✔'}else{''})</td>
                    <td class="$($t.DefenderForOffice365_P2.ToString().ToLower())">$(if($t.DefenderForOffice365_P2){'✔'}else{''})</td>
                    <td class="$($t.DefenderForEndpoint.ToString().ToLower())">$(if($t.DefenderForEndpoint){'✔'}else{''})</td>
                    <td class="$($t.DefenderForIdentity.ToString().ToLower())">$(if($t.DefenderForIdentity){'✔'}else{''})</td>
                    <td class="$($t.DefenderForCloudApps.ToString().ToLower())">$(if($t.DefenderForCloudApps){'✔'}else{''})</td>
                    <td class="$($t.DefenderForServers.ToString().ToLower())">$(if($t.DefenderForServers){'✔'}else{''})</td>
                    <td class="$($t.DefenderVulnerabilityManagement.ToString().ToLower())">$(if($t.DefenderVulnerabilityManagement){'✔'}else{''})</td>
                    <td class="$($t.AzureADPremium_P1.ToString().ToLower())">$(if($t.AzureADPremium_P1){'✔'}else{''})</td>
                    <td class="$($t.AzureADPremium_P2.ToString().ToLower())">$(if($t.AzureADPremium_P2){'✔'}else{''})</td>
                </tr>
"@
    }

    $suiteRows = ""
    foreach ($t in ($allTenantsLicenseInfo | Sort-Object ClientName)) {
        $suites = @()
        if ($t.Microsoft365_E3)              { $suites += "e3" }
        if ($t.Microsoft365_E5)              { $suites += "e5" }
        if ($t.Microsoft365_BusinessPremium) { $suites += "bp" }
        if ($t.EMS_E3)                       { $suites += "emse3" }
        if ($t.EMS_E5)                       { $suites += "emse5" }
        $suiteAttr = $suites -join ","

        $suiteRows += @"
                <tr data-suites="$suiteAttr">
                    <td>$([System.Net.WebUtility]::HtmlEncode($t.ClientName))</td>
                    <td>$([System.Net.WebUtility]::HtmlEncode($t.InitialDomain))</td>
                    <td class="$($t.Microsoft365_E3.ToString().ToLower())">$(if($t.Microsoft365_E3){'✔'}else{''})</td>
                    <td class="$($t.Microsoft365_E5.ToString().ToLower())">$(if($t.Microsoft365_E5){'✔'}else{''})</td>
                    <td class="$($t.Microsoft365_BusinessPremium.ToString().ToLower())">$(if($t.Microsoft365_BusinessPremium){'✔'}else{''})</td>
                    <td class="$($t.EMS_E3.ToString().ToLower())">$(if($t.EMS_E3){'✔'}else{''})</td>
                    <td class="$($t.EMS_E5.ToString().ToLower())">$(if($t.EMS_E5){'✔'}else{''})</td>
                </tr>
"@
    }

    $genDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $htmlOut  = Join-Path $resolvedOutput "MS-Defender-License-Report.html"

    @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Microsoft Defender License Report</title>
<style>
  body{font-family:Arial,sans-serif;margin:20px;background:#f5f5f5}
  h1,h2,h3{color:#0078D4}
  .container{max-width:1800px;margin:0 auto}
  .card{background:#fff;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.1);padding:20px;margin-bottom:20px}
  .dash{display:flex;flex-wrap:wrap;gap:12px;margin-bottom:20px}
  .dc{background:#fff;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.1);padding:12px 16px;flex:1;min-width:130px;text-align:center}
  .dn{font-size:30px;font-weight:bold;margin:6px 0}
  .dl{font-size:12px;color:#666}
  table{border-collapse:collapse;width:100%;font-size:13px}
  th,td{padding:7px 10px;text-align:left;border-bottom:1px solid #ddd;white-space:nowrap}
  th{background:#0078D4;color:#fff;cursor:pointer;user-select:none}
  th:hover{background:#005a9e}
  tr:hover td{background:#f0f7ff}
  .true{color:#107C10;font-weight:bold;text-align:center}
  .false{color:#ddd;text-align:center}
  .filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
  .btn{padding:5px 12px;border:none;border-radius:4px;cursor:pointer;font-weight:bold;font-size:12px}
  .btn:hover{opacity:.85}
  .btn-all{background:#0078D4;color:#fff}
  .btn-prod{background:#eee;color:#333}
  .btn-active{background:#005a9e;color:#fff}
  input[type=text]{padding:5px 10px;border:1px solid #ccc;border-radius:4px;min-width:200px;font-size:13px}
  .breakdown-item{margin-bottom:12px;padding:10px;background:#f8f9fa;border-radius:5px;border-left:4px solid #0078D4}
  .breakdown-title{font-weight:bold;color:#0078D4;margin-bottom:4px;font-size:13px}
  .breakdown-clients{font-size:12px;color:#555;word-break:break-word}
  .desc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:16px}
  .desc-card{background:#f8fafc;border-radius:6px;padding:14px;border-left:4px solid #0078D4}
  .desc-card.orange{border-left-color:#FF8C00}
  .desc-card.green{border-left-color:#107C10}
  .desc-card.purple{border-left-color:#8764B8}
  .desc-card.red{border-left-color:#E81123}
  .desc-card.teal{border-left-color:#008575}
  .desc-title{font-weight:bold;color:#0078D4;font-size:13px;margin-bottom:6px}
  .desc-card.orange .desc-title{color:#FF8C00}
  .desc-card.green .desc-title{color:#107C10}
  .desc-card.purple .desc-title{color:#8764B8}
  .desc-card.red .desc-title{color:#E81123}
  .desc-card.teal .desc-title{color:#008575}
  .desc-body{font-size:12px;color:#444;line-height:1.6}
  .tag{display:inline-block;padding:1px 6px;border-radius:8px;font-size:10px;font-weight:bold;background:#e0f0ff;color:#0078D4;margin:1px}
</style>
<script>
  var licFilter='all', suiteFilter='all';

  function setLicFilter(f,el) {
    licFilter=f;
    document.querySelectorAll('.lic-btn').forEach(function(b){b.classList.remove('btn-active');b.classList.add('btn-prod');});
    if(el){el.classList.remove('btn-prod');el.classList.add('btn-active');}
    applyLicFilter();
  }
  function applyLicFilter() {
    var s=document.getElementById('licSearch').value.toLowerCase();
    document.querySelectorAll('#licTable tbody tr').forEach(function(r){
      var prods=r.dataset.products||'';
      var prodArr=prods?prods.split(','):[];
      var mf=licFilter==='all'||
             (licFilter==='none'&&prodArr.length===0)||
             prodArr.indexOf(licFilter)>-1;
      var ms=s===''||r.innerText.toLowerCase().indexOf(s)>-1;
      r.style.display=(mf&&ms)?'':'none';
    });
  }

  function setSuiteFilter(f,el) {
    suiteFilter=f;
    document.querySelectorAll('.suite-btn').forEach(function(b){b.classList.remove('btn-active');b.classList.add('btn-prod');});
    if(el){el.classList.remove('btn-prod');el.classList.add('btn-active');}
    applySuiteFilter();
  }
  function applySuiteFilter() {
    var s=document.getElementById('suiteSearch').value.toLowerCase();
    document.querySelectorAll('#suiteTable tbody tr').forEach(function(r){
      var suites=r.dataset.suites||'';
      var suiteArr=suites?suites.split(','):[];
      var mf=suiteFilter==='all'||
             (suiteFilter==='none'&&suiteArr.length===0)||
             suiteArr.indexOf(suiteFilter)>-1;
      var ms=s===''||r.innerText.toLowerCase().indexOf(s)>-1;
      r.style.display=(mf&&ms)?'':'none';
    });
  }
</script>
</head>
<body>
<div class="container">
  <h1>Microsoft Defender License Report</h1>
  <div class="card" style="padding:10px 20px;font-size:13px">
    Generated: $genDate &nbsp;|&nbsp; Tenants: $totalTenants
  </div>

  <div class="dash">
    <div class="dc"><div class="dn" style="color:#0078D4">$totalTenants</div><div class="dl">Total Tenants</div></div>
    <div class="dc"><div class="dn" style="color:#107C10">$tenantsWithDefenderOffice365</div><div class="dl">Defender for O365</div></div>
    <div class="dc"><div class="dn" style="color:#FF8C00">$tenantsWithDefenderEndpoint</div><div class="dl">Defender for Endpoint</div></div>
    <div class="dc"><div class="dn" style="color:#8764B8">$tenantsWithDefenderIdentity</div><div class="dl">Defender for Identity</div></div>
    <div class="dc"><div class="dn" style="color:#008575">$tenantsWithDefenderCloudApps</div><div class="dl">Defender for Cloud Apps</div></div>
    <div class="dc"><div class="dn" style="color:#E81123">$tenantsWithDefenderServers</div><div class="dl">Defender for Servers</div></div>
    <div class="dc"><div class="dn" style="color:#E81123">$tenantsWithDefenderVulnMgmt</div><div class="dl">Vuln Management</div></div>
    <div class="dc"><div class="dn">$tenantsWithAzureADP1</div><div class="dl">AAD Premium P1</div></div>
    <div class="dc"><div class="dn">$tenantsWithAzureADP2</div><div class="dl">AAD Premium P2</div></div>
  </div>

  <div class="card">
    <h2>Client Breakdown by License Type</h2>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Office 365 P1 — $tenantsWithDfO365P1 clients</div>
      <div class="breakdown-clients">$clientsWithDfO365P1</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Office 365 P2 — $tenantsWithDfO365P2 clients</div>
      <div class="breakdown-clients">$clientsWithDfO365P2</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Endpoint — $tenantsWithDefenderEndpoint clients</div>
      <div class="breakdown-clients">$clientsWithDfEP</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Identity — $tenantsWithDefenderIdentity clients</div>
      <div class="breakdown-clients">$clientsWithDfI</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Cloud Apps — $tenantsWithDefenderCloudApps clients</div>
      <div class="breakdown-clients">$clientsWithDfCA</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender for Servers — $tenantsWithDefenderServers clients</div>
      <div class="breakdown-clients">$clientsWithDfS</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Defender Vulnerability Management — $tenantsWithDefenderVulnMgmt clients</div>
      <div class="breakdown-clients">$clientsWithDVM</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Azure AD Premium P1 — $tenantsWithAzureADP1 clients</div>
      <div class="breakdown-clients">$clientsWithAadP1</div>
    </div>
    <div class="breakdown-item">
      <div class="breakdown-title">Azure AD Premium P2 — $tenantsWithAzureADP2 clients</div>
      <div class="breakdown-clients">$clientsWithAadP2</div>
    </div>
  </div>

  <div class="card">
    <h2>Defender &amp; Azure AD Premium License Status</h2>
    <div class="filters">
      <button class="btn btn-all lic-btn btn-active" onclick="setLicFilter('all',this)">All ($totalTenants)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfo1',this)">O365 P1 ($tenantsWithDfO365P1)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfo2',this)">O365 P2 ($tenantsWithDfO365P2)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfep',this)">Endpoint ($tenantsWithDefenderEndpoint)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfi',this)">Identity ($tenantsWithDefenderIdentity)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfca',this)">Cloud Apps ($tenantsWithDefenderCloudApps)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dfs',this)">Servers ($tenantsWithDefenderServers)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('dvm',this)">Vuln Mgmt ($tenantsWithDefenderVulnMgmt)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('aadp1',this)">AAD P1 ($tenantsWithAzureADP1)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('aadp2',this)">AAD P2 ($tenantsWithAzureADP2)</button>
      <button class="btn btn-prod lic-btn" onclick="setLicFilter('none',this)">No Products</button>
      <input type="text" id="licSearch" placeholder="Search..." oninput="applyLicFilter()">
    </div>
    <div style="overflow-x:auto">
    <table id="licTable">
      <thead><tr>
        <th>Client Name</th>
        <th>Tenant Domain</th>
        <th>O365 P1</th>
        <th>O365 P2</th>
        <th>Endpoint</th>
        <th>Identity</th>
        <th>Cloud Apps</th>
        <th>Servers</th>
        <th>Vuln Mgmt</th>
        <th>AAD P1</th>
        <th>AAD P2</th>
      </tr></thead>
      <tbody>
$tableRows
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h2>Suite Licensing</h2>
    <div class="dash" style="margin-bottom:16px">
      <div class="dc"><div class="dn" style="color:#0078D4">$tenantsWithAnySuite</div><div class="dl">Any Suite</div></div>
      <div class="dc"><div class="dn">$tenantsWithM365E3</div><div class="dl">M365 E3</div></div>
      <div class="dc"><div class="dn" style="color:#107C10">$tenantsWithM365E5</div><div class="dl">M365 E5</div></div>
      <div class="dc"><div class="dn" style="color:#FF8C00">$tenantsWithBP</div><div class="dl">Business Premium</div></div>
      <div class="dc"><div class="dn">$tenantsWithEMSE3</div><div class="dl">EMS E3</div></div>
      <div class="dc"><div class="dn">$tenantsWithEMSE5</div><div class="dl">EMS E5</div></div>
    </div>
    <div class="filters">
      <button class="btn btn-all suite-btn btn-active" onclick="setSuiteFilter('all',this)">All ($totalTenants)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('e3',this)">M365 E3 ($tenantsWithM365E3)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('e5',this)">M365 E5 ($tenantsWithM365E5)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('bp',this)">Business Premium ($tenantsWithBP)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('emse3',this)">EMS E3 ($tenantsWithEMSE3)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('emse5',this)">EMS E5 ($tenantsWithEMSE5)</button>
      <button class="btn btn-prod suite-btn" onclick="setSuiteFilter('none',this)">No Suite ($($totalTenants - $tenantsWithAnySuite))</button>
      <input type="text" id="suiteSearch" placeholder="Search..." oninput="applySuiteFilter()">
    </div>
    <div style="overflow-x:auto">
    <table id="suiteTable">
      <thead><tr>
        <th>Client Name</th>
        <th>Tenant Domain</th>
        <th>Microsoft 365 E3</th>
        <th>Microsoft 365 E5</th>
        <th>Business Premium</th>
        <th>EMS E3</th>
        <th>EMS E5</th>
      </tr></thead>
      <tbody>
$suiteRows
      </tbody>
    </table>
    </div>
  </div>

  <div class="card">
    <h2>License Capabilities &amp; Security Insights</h2>
    <div class="desc-grid">

      <div class="desc-card">
        <div class="desc-title">Defender for Office 365 Plan 1</div>
        <div class="desc-body">
          Email and collaboration threat protection. Key capabilities:
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>Safe Attachments</strong> — detonates email attachments in a sandbox before delivery. Catches zero-day malware that signature AV misses.</li>
            <li><strong>Safe Links</strong> — rewrites URLs and checks at time-of-click. Blocks links that turn malicious after delivery.</li>
            <li><strong>Anti-phishing (basic)</strong> — impersonation protection for domains and users, spoof intelligence.</li>
          </ul>
          <span class="tag">Email logs in Threat Explorer</span>
          <span class="tag">Unified audit log</span>
          <span class="tag">Real-time detections dashboard</span>
        </div>
      </div>

      <div class="desc-card">
        <div class="desc-title">Defender for Office 365 Plan 2</div>
        <div class="desc-body">
          Everything in P1 plus advanced hunting and automation:
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>Threat Explorer</strong> — 30-day searchable email log with full header/URL/attachment metadata. Essential for phishing investigations.</li>
            <li><strong>Automated Investigation &amp; Response (AIR)</strong> — auto-remediates email threats across mailboxes without analyst intervention.</li>
            <li><strong>Attack Simulator</strong> — run phishing simulations to measure user susceptibility.</li>
            <li><strong>Threat Trackers</strong> — trending campaign intelligence.</li>
          </ul>
          <span class="tag">30-day email hunt</span>
          <span class="tag">Auto-remediation</span>
          <span class="tag">Campaign correlation</span>
        </div>
      </div>

      <div class="desc-card orange">
        <div class="desc-title">Defender for Endpoint (Plan 1 / Plan 2)</div>
        <div class="desc-body">
          <strong>P1:</strong> Attack surface reduction rules, next-gen AV, device control, web content filtering. Detection only — no timeline or hunting.<br><br>
          <strong>P2 adds:</strong>
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>6-month device timeline</strong> — full process, file, network, and registry event history per endpoint.</li>
            <li><strong>Advanced Hunting</strong> — KQL queries across device telemetry. Critical for incident scope assessment.</li>
            <li><strong>Automated Investigation</strong> — isolates compromised devices, kills malicious processes automatically.</li>
            <li><strong>Live Response</strong> — remote shell to collect forensic artifacts or run remediation scripts.</li>
          </ul>
          <span class="tag">Device timeline</span>
          <span class="tag">KQL hunting</span>
          <span class="tag">Live response</span>
          <span class="tag">Sentinel connector</span>
        </div>
      </div>

      <div class="desc-card purple">
        <div class="desc-title">Defender for Identity</div>
        <div class="desc-body">
          Monitors on-premises Active Directory and Entra ID sign-ins via a sensor on domain controllers. Detects:
          <ul style="margin:6px 0;padding-left:16px">
            <li>Pass-the-hash, pass-the-ticket, overpass-the-hash</li>
            <li>DCSync (credential dumping via replication)</li>
            <li>Kerberoasting, AS-REP roasting</li>
            <li>LDAP reconnaissance (BloodHound-style enumeration)</li>
            <li>Lateral movement via SMB, RDP, WMI</li>
          </ul>
          Critical for detecting post-exploitation and AD persistence. Produces alerts visible in the Defender portal and Sentinel.
          <br><span class="tag">AD attack detection</span>
          <span class="tag">Lateral movement</span>
          <span class="tag">Sentinel UEBA source</span>
        </div>
      </div>

      <div class="desc-card teal">
        <div class="desc-title">Defender for Cloud Apps</div>
        <div class="desc-body">
          Cloud Access Security Broker (CASB). Capabilities:
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>Shadow IT discovery</strong> — identifies OAuth apps and non-sanctioned SaaS usage.</li>
            <li><strong>Activity logs</strong> — unified log of user actions across connected apps (Exchange, SharePoint, Teams, Salesforce, etc.).</li>
            <li><strong>Session controls</strong> — proxy-based inspection of browser sessions to block download/upload/paste on unmanaged devices.</li>
            <li><strong>Anomaly detection</strong> — impossible travel, mass download, suspicious OAuth consent.</li>
          </ul>
          <span class="tag">OAuth app inventory</span>
          <span class="tag">Cross-app activity log</span>
          <span class="tag">Insider threat detection</span>
        </div>
      </div>

      <div class="desc-card red">
        <div class="desc-title">Defender for Servers</div>
        <div class="desc-body">
          Extends Defender for Endpoint to Azure VMs, on-prem servers, and multi-cloud VMs via Azure Arc.<br><br>
          <strong>Plan 2 adds:</strong> Just-in-time VM access (eliminates standing RDP/SSH exposure), file integrity monitoring, adaptive application controls, and vulnerability assessment via Qualys or built-in scanner.<br><br>
          Produces security alerts for server-based threats that feed into Defender XDR and Sentinel.
          <span class="tag">Server EDR</span>
          <span class="tag">JIT VM access</span>
          <span class="tag">File integrity monitoring</span>
        </div>
      </div>

      <div class="desc-card red">
        <div class="desc-title">Defender Vulnerability Management</div>
        <div class="desc-body">
          Continuous CVE and misconfiguration scanning across all Defender-enrolled devices. Provides:
          <ul style="margin:6px 0;padding-left:16px">
            <li>Per-device software inventory with CVE mappings and CVSS scores</li>
            <li>Security Recommendations ranked by exposure impact</li>
            <li>Microsoft Secure Score for Devices</li>
            <li>Browser extension inventory and certificate/network share assessments</li>
          </ul>
          Useful for prioritizing patch cycles and demonstrating posture improvement over time.
          <span class="tag">CVE tracking</span>
          <span class="tag">Patch prioritization</span>
          <span class="tag">Exposure scoring</span>
        </div>
      </div>

      <div class="desc-card green">
        <div class="desc-title">Azure AD Premium P1</div>
        <div class="desc-body">
          The foundation license for identity-based security controls:
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>Conditional Access</strong> — require MFA, compliant device, or block access based on user, app, location, and device platform.</li>
            <li><strong>SSPR</strong> — self-service password reset with on-prem writeback.</li>
            <li><strong>Dynamic Groups</strong> — auto-assign licenses and policies based on user attributes.</li>
            <li><strong>MFA per CA policy</strong> — replaces legacy per-user MFA with policy-driven enforcement.</li>
          </ul>
          Without P1, clients cannot enforce CA policies. This is the minimum required for meaningful access control.
          <span class="tag">Conditional Access</span>
          <span class="tag">MFA enforcement</span>
          <span class="tag">SSPR</span>
        </div>
      </div>

      <div class="desc-card green">
        <div class="desc-title">Azure AD Premium P2</div>
        <div class="desc-body">
          All P1 capabilities plus:
          <ul style="margin:6px 0;padding-left:16px">
            <li><strong>Identity Protection</strong> — machine learning-based risky sign-in and risky user detection (leaked credentials, anonymous IPs, atypical travel, malware-linked IPs). Enables risk as a CA condition.</li>
            <li><strong>Privileged Identity Management (PIM)</strong> — just-in-time admin role activation with approval workflow and audit log.</li>
            <li><strong>Access Reviews</strong> — periodic recertification of group/app/role membership.</li>
          </ul>
          <span class="tag">Risk-based CA</span>
          <span class="tag">Leaked credential detection</span>
          <span class="tag">JIT admin (PIM)</span>
          <span class="tag">Access Reviews</span>
        </div>
      </div>

    </div>
  </div>

</div>
</body>
</html>
"@ | Out-File -FilePath $htmlOut -Encoding utf8

    Write-Host "`nDone. Reports saved to: $resolvedOutput" -ForegroundColor Green
    Write-Host "CSV : $csvFile"  -ForegroundColor Cyan
    Write-Host "HTML: $htmlOut"  -ForegroundColor Cyan
    if ($PSVersionTable.Platform -ne 'Unix') { Invoke-Item $htmlOut }
}

# ─── Single-tenant path ───────────────────────────────────────────────────────
else {
    if ([string]::IsNullOrWhiteSpace($TenantId) -or
        [string]::IsNullOrWhiteSpace($ClientId)  -or
        [string]::IsNullOrWhiteSpace($ClientSecret)) {
        Write-Error "Provide -CsvPath or all of -TenantId, -ClientId, -ClientSecret."
        return
    }

    try {
        $token = Get-MsGraphToken -Tid $TenantId -Cid $ClientId -Sec $ClientSecret
        $h     = @{ "Authorization"="Bearer $token"; "Content-Type"="application/json" }

        $org = (Invoke-RestMethod "https://graph.microsoft.com/v1.0/organization" -Headers $h).value[0]
        Write-Host "`nTenant: $($org.displayName)" -ForegroundColor Cyan

        $skus = Get-AllPages "https://graph.microsoft.com/v1.0/subscribedSkus" $h

        $skus | ForEach-Object {
            $plans = ($_.servicePlans | Where-Object { $_.provisioningStatus -eq "Success" } | ForEach-Object { $_.servicePlanName }) -join ", "
            Write-Host "  $($_.skuPartNumber) [$($_.capabilityStatus)] — $($_.consumedUnits)/$($_.prepaidUnits.enabled) used"
            if ($plans) { Write-Host "    Plans: $plans" -ForegroundColor Gray }
        }
    }
    catch {
        Write-Error "Error: $_"
    }
}
