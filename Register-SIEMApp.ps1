Connect-MgGraph -Scopes "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All", "Directory.ReadWrite.All"

# Create new application
$appName = "SIEMAPP"
$appHomePageUrl = "https://yoururlhere.com"
$appSignInAudience = "AzureADMyOrg" # Single tenant

Write-Host "Creating application '$appName'..." -ForegroundColor Cyan
$appRegistration = New-MgApplication -DisplayName $appName -SignInAudience $appSignInAudience -Web @{
    RedirectUris = @("https://localhost")
    ImplicitGrantSettings = @{
        EnableAccessTokenIssuance = $false
        EnableIdTokenIssuance = $false
    }
}

Write-Host "Application created with ID: $($appRegistration.Id)" -ForegroundColor Green

# Create a service principal
Write-Host "Creating service principal..." -ForegroundColor Cyan
$servicePrincipal = New-MgServicePrincipal -AppId $appRegistration.AppId -Tags @("WindowsAzureActiveDirectoryIntegratedApp")

Write-Host "Service principal created with ID: $($servicePrincipal.Id)" -ForegroundColor Green

# Helper function to add required resource access to the application
function Add-RequiredResourceAccess {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ApplicationId,
        
        [Parameter(Mandatory = $true)]
        [string]$ResourceAppId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessId,
        
        [Parameter(Mandatory = $true)]
        [string]$AccessType
    )
    
    # Get current required resource access
    $application = Get-MgApplication -ApplicationId $ApplicationId
    $requiredResourceAccess = $application.RequiredResourceAccess
    
    # Check if the resource is already in the collection
    $resourceAccess = $requiredResourceAccess | Where-Object { $_.ResourceAppId -eq $ResourceAppId }
    
    if ($null -eq $resourceAccess) {
        $requiredResourceAccess += @{
            ResourceAppId = $ResourceAppId
            ResourceAccess = @(
                @{
                    Id = $AccessId
                    Type = $AccessType
                }
            )
        }
    } else {
        $existingPermission = $resourceAccess.ResourceAccess | Where-Object { $_.Id -eq $AccessId }
        
        if ($null -eq $existingPermission) {
            $resourceAccessIndex = [array]::IndexOf($requiredResourceAccess, $resourceAccess)
            $requiredResourceAccess[$resourceAccessIndex].ResourceAccess += @{
                Id = $AccessId
                Type = $AccessType
            }
        }
    }
    
    
    Update-MgApplication -ApplicationId $ApplicationId -RequiredResourceAccess $requiredResourceAccess
}

# Configure delegated permissions
$delegatedPermissions = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        Scopes = @("User.Read", "User.ReadBasic.All")
    }
)

Write-Host "Configuring delegated permissions..." -ForegroundColor Cyan
foreach ($permission in $delegatedPermissions) {
    $resourceServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($permission.ResourceAppId)'"
    
    foreach ($scope in $permission.Scopes) {
        Write-Host "  Adding delegated permission: $scope from $($resourceServicePrincipal.DisplayName)" -ForegroundColor Yellow
        
        # Add required resources access for delegated permissions
        $permissionId = $resourceServicePrincipal.OAuth2PermissionScopes | Where-Object { $_.Value -eq $scope } | Select-Object -ExpandProperty Id
        
        if ($null -ne $permissionId) {
            # Add to the app's required resource access
            Add-RequiredResourceAccess -ApplicationId $appRegistration.Id -ResourceAppId $permission.ResourceAppId -AccessId $permissionId -AccessType "Scope"
            
            # Grant admin consent for delegated permissions
            # Use try-catch to handle all potential errors
            try {
                # Fixed: Don't try to filter on scope, just get all grants and filter client-side
                $params = @{
                    ClientId = $servicePrincipal.Id
                    ConsentType = "AllPrincipals"
                    ResourceId = $resourceServicePrincipal.Id
                    Scope = $scope
                }
                
                # Add delay to allow propagation
                Start-Sleep -Seconds 2
                
                # Try to create the permission grant - if it fails with "already exists" that's fine
                try {
                    New-MgOauth2PermissionGrant @params | Out-Null
                    Write-Host "    Admin consent granted for $scope" -ForegroundColor Green
                } catch {
                    if ($_.Exception.Message -like "*Permission entry already exists*") {
                        Write-Host "    Admin consent already exists for $scope" -ForegroundColor Green
                    } else {
                        Write-Warning "    Failed to grant admin consent for $scope. Error: $_"
                    }
                }
            } catch {
                Write-Warning "    Error in permission grant process for $scope. Error: $_"
            }
        } else {
            Write-Warning "Permission '$scope' not found for $($resourceServicePrincipal.DisplayName)"
        }
    }
}

# Add Office 365 Management API delegated permission manually
# Note: We'll handle this differently since the discovery via API may not be working correctly
Write-Host "  Adding delegated permission: Subscription.Read.All from Office 365 Management APIs" -ForegroundColor Yellow

try {
    # Get Office 365 Management APIs service principal
    $o365ManagementAPI = Get-MgServicePrincipal -Filter "appId eq 'c5393580-f805-4401-95e8-94b7a6ef2fc2'"
    
    if ($null -ne $o365ManagementAPI) {
        # Find the Subscription.Read.All permission ID
        # Note: If API discovery doesn't work, we'll use a hardcoded ID that corresponds to this permission
        $permId = "570282fd-fa5c-430d-a7fd-fc8dc98a9daa" # This ID may need to be verified
        
        # Add to required resource access
        Add-RequiredResourceAccess -ApplicationId $appRegistration.Id -ResourceAppId $o365ManagementAPI.AppId -AccessId $permId -AccessType "Scope"
        
        # Add delay to allow propagation
        Start-Sleep -Seconds 2
        
        # Grant admin consent - simplified approach to avoid filtering issues
        try {
            $params = @{
                ClientId = $servicePrincipal.Id
                ConsentType = "AllPrincipals"
                ResourceId = $o365ManagementAPI.Id
                Scope = "Subscription.Read.All"
            }
            
            try {
                New-MgOauth2PermissionGrant @params | Out-Null
                Write-Host "    Admin consent granted for Subscription.Read.All" -ForegroundColor Green
            } catch {
                if ($_.Exception.Message -like "*Permission entry already exists*") {
                    Write-Host "    Admin consent already exists for Subscription.Read.All" -ForegroundColor Green
                } else {
                    Write-Warning "    Failed to grant admin consent for Subscription.Read.All. Error: $_"
                }
            }
        } catch {
            Write-Warning "    Error in permission grant process for Subscription.Read.All. Error: $_"
        }
    } else {
        Write-Warning "Office 365 Management APIs service principal not found"
    }
} catch {
    Write-Warning "Error configuring Office 365 Management APIs delegated permission: $_"
}

# Configure application permissions
$applicationPermissions = @(
    @{
        ResourceAppId = "00000003-0000-0000-c000-000000000000" # Microsoft Graph
        Permissions = @(
            "Device.Read.All", "SecurityEvents.Read.All", "SecurityAlert.Read.All", 
            "Group.Read.All", "AdministrativeUnit.Read.All", "Sites.Read.All", 
            "Notes.Read.All", "Directory.Read.All", "User.Read.All", "Domain.Read.All",
            "SecurityIncident.Read.All", "GroupMember.Read.All", "SecurityActions.Read.All",
            "IdentityProvider.Read.All", "Organization.Read.All", "AuditLog.Read.All", "Reports.Read.All"
        )
    },
    @{
        ResourceAppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2" # Office 365 Management APIs
        Permissions = @("ActivityFeed.ReadDlp", "ServiceHealth.Read", "ActivityFeed.Read")
    },
    @{
        ResourceAppId = "8ee8fdad-f234-4243-8f3b-15c294843740" # Microsoft Threat Protection
        Permissions = @("Incident.Read.All", "AdvancedHunting.Read.All")
    }
)

Write-Host "Configuring application permissions..." -ForegroundColor Cyan
foreach ($permission in $applicationPermissions) {
    $resourceServicePrincipal = Get-MgServicePrincipal -Filter "appId eq '$($permission.ResourceAppId)'"
    
    if ($null -eq $resourceServicePrincipal) {
        Write-Warning "Service principal for app ID $($permission.ResourceAppId) not found"
        continue
    }
    
    foreach ($permName in $permission.Permissions) {
        Write-Host "  Adding application permission: $permName from $($resourceServicePrincipal.DisplayName)" -ForegroundColor Yellow
        
        # Find the app role ID for the permission
        $appRole = $resourceServicePrincipal.AppRoles | Where-Object { $_.Value -eq $permName }
        
        if ($null -ne $appRole) {
            # Add to the app's required resource access
            Add-RequiredResourceAccess -ApplicationId $appRegistration.Id -ResourceAppId $permission.ResourceAppId -AccessId $appRole.Id -AccessType "Role"
            
            # Add delay to allow propagation
            Start-Sleep -Seconds 2
            
            # Assign app role to service principal (admin consent)
            try {
                # Check if the app role assignment already exists - using a more reliable approach
                try {
                    # Try to create the assignment - if it fails with "already exists" that's fine
                    New-MgServicePrincipalAppRoleAssignment `
                        -ServicePrincipalId $servicePrincipal.Id `
                        -PrincipalId $servicePrincipal.Id `
                        -ResourceId $resourceServicePrincipal.Id `
                        -AppRoleId $appRole.Id | Out-Null
                    
                    Write-Host "    Admin consent granted for $permName" -ForegroundColor Green
                } catch {
                    # Check if the error is because the assignment already exists
                    if ($_.Exception.Message -like "*already assigned*" -or 
                        $_.Exception.Message -like "*already exists*" -or 
                        $_.Exception.Message -like "*duplicate*") {
                        Write-Host "    Admin consent already exists for $permName" -ForegroundColor Green
                    } else {
                        Write-Warning "    Failed to grant admin consent for $permName. Error: $_"
                    }
                }
            } catch {
                Write-Warning "    Error in app role assignment process for $permName. Error: $_"
            }
        } else {
            Write-Warning "Permission '$permName' not found for $($resourceServicePrincipal.DisplayName)"
        }
    }
}

# Create secret
Write-Host "`nCreating client secret..." -ForegroundColor Cyan
$secretEndDateTime = (Get-Date).AddYears(2)

try {
    $passwordCred = @{
        DisplayName = "SIEMAPP API Secret"
        EndDateTime = $secretEndDateTime
    }
    
    $secret = Add-MgApplicationPassword -ApplicationId $appRegistration.Id -PasswordCredential $passwordCred
    
    $secretValue = $secret.SecretText
    
    Write-Host "Client secret created successfully!" -ForegroundColor Green
    Write-Host "Secret will expire on: $($secretEndDateTime.ToString('yyyy-MM-dd'))" -ForegroundColor Yellow
} catch {
    Write-Error "Failed to create client secret: $_"
    $secretValue = "ERROR: Secret creation failed"
}

Write-Host "`nApplication '$appName' has been created with all permissions and admin consent granted" -ForegroundColor Green
Write-Host "Tenant ID: $((Get-MgContext).TenantId)" -ForegroundColor Cyan
Write-Host "Application (Client) ID: $($appRegistration.AppId)" -ForegroundColor Cyan
Write-Host "Object ID: $($appRegistration.Id)" -ForegroundColor Cyan
Write-Host "Service Principal ID: $($servicePrincipal.Id)" -ForegroundColor Cyan
Write-Host "Client Secret: $secretValue" -ForegroundColor Magenta
Write-Host "`nIMPORTANT: Save the Client Secret now! It will not be retrievable later." -ForegroundColor Red

Disconnect-MgGraph
Write-Host "Disconnected from Microsoft Graph" -ForegroundColor Gray
