<#
.SYNOPSIS
    Grant Microsoft Graph API permissions to a service principal for stale device and user management.

.DESCRIPTION
    Interactive script to grant Graph API permissions required by the Entra ID Stale Resource Management functions:
    
    Device Management (StaleDeviceSweep):
    - Device.Read.All: Read Entra ID device information
    - Device.ReadWrite.All: Disable devices and tag with open extensions
    - DeviceManagementManagedDevices.Read.All: Read Intune managed device data
    - DeviceManagementManagedDevices.ReadWrite.All: Retire/wipe/delete Intune devices
    - GroupMember.Read.All: Support for exception groups
    
    User Management (StaleUserSweep):
    - User.Read.All: Read Entra ID user information
    - AuditLog.Read.All: Read sign-in activity data
    - User.ReadWrite.All: Disable user accounts
    - Directory.ReadWrite.All: Tag users with open extensions
    - GroupMember.Read.All: Support for exception groups

.PARAMETER ServicePrincipalObjectId
    The object ID of the service principal (managed identity or app registration) to grant permissions to.

.PARAMETER ResourceType
    The type of resource to grant permissions for: 'Device', 'User', or 'Both'. Default: 'Device'

.EXAMPLE
    # Grant device management permissions
    .\Grant-Permissions.ps1 -ServicePrincipalObjectId "12345678-1234-1234-1234-123456789abc"

.EXAMPLE
    # Grant user management permissions
    .\Grant-Permissions.ps1 -ServicePrincipalObjectId "12345678-1234-1234-1234-123456789abc" -ResourceType User

.EXAMPLE
    # Grant both device and user management permissions
    .\Grant-Permissions.ps1 -ServicePrincipalObjectId "12345678-1234-1234-1234-123456789abc" -ResourceType Both
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$ServicePrincipalObjectId, # The Microsoft Entra object id of the enterprise application to which we are granting the app role.
    
    [ValidateSet('Device', 'User', 'Both')]
    [string]$ResourceType = 'Device'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Available permission bundles for devices
$devicePermissionBundles = @(
    [PSCustomObject]@{
        Name = 'Device: Entra Read Only'
        Description = 'Read Entra ID device information (detect mode only)'
        Permissions = @('Device.Read.All')
        Recommended = 'For preview/reporting only'
    },
    [PSCustomObject]@{
        Name = 'Device: Entra Read + Write'
        Description = 'Disable devices and tag with open extensions'
        Permissions = @('Device.ReadWrite.All')
        Recommended = 'For disable/tag modes without Intune'
    },
    [PSCustomObject]@{
        Name = 'Device: Entra + Intune Read'
        Description = 'Read Entra ID and Intune managed device data'
        Permissions = @('Device.Read.All', 'DeviceManagementManagedDevices.Read.All')
        Recommended = 'For Intune-aware decision planning (MODE=decide)'
    },
    [PSCustomObject]@{
        Name = 'Device: Entra + Intune Full Access'
        Description = 'Full access: Disable, tag, retire, wipe, delete devices'
        Permissions = @('Device.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All', 'GroupMember.Read.All')
        Recommended = 'For complete automation (MODE=execute with all actions)'
    }
)

# Available permission bundles for users
$userPermissionBundles = @(
    [PSCustomObject]@{
        Name = 'User: Read Only'
        Description = 'Read Entra ID user and sign-in activity (detect mode only)'
        Permissions = @('AuditLog.Read.All', 'User.Read.All', 'GroupMember.Read.All')
        Recommended = 'For preview/reporting only (without exception groups)'
    },
    [PSCustomObject]@{
        Name = 'User: Read + Write'
        Description = 'Disable user accounts and tag with open extensions'
        Permissions = @('AuditLog.Read.All', 'User.ReadWrite.All', 'Directory.ReadWrite.All', 'GroupMember.Read.All')
        Recommended = 'For disable/tag modes (without exception groups)'
    }
)

# Select which bundles to show based on ResourceType
$permissionBundles = @()
switch ($ResourceType) {
    'Device' { $permissionBundles = $devicePermissionBundles }
    'User' { $permissionBundles = $userPermissionBundles }
    'Both' { $permissionBundles = $devicePermissionBundles + $userPermissionBundles }
}

# Prompt for service principal object ID if not provided
if (-not $ServicePrincipalObjectId) {
    Write-Host "`nEnter the Object ID of the service principal (managed identity or app registration):" -ForegroundColor Cyan
    Write-Host "  - For Managed Identity: Find in Azure Portal > Function App > Identity > Object ID"
    Write-Host "  - For App Registration: Find in Azure Portal > App Registrations > [Your App] > Overview > Object ID (Application)"
    $ServicePrincipalObjectId = Read-Host "`nObject ID"
    
    if ([string]::IsNullOrWhiteSpace($ServicePrincipalObjectId)) {
        throw "Object ID is required."
    }
}

# Display available permission bundles
Write-Host "`n=== Microsoft Graph API Permission Bundles ($ResourceType) ===" -ForegroundColor Green
Write-Host ""
for ($i = 0; $i -lt $permissionBundles.Count; $i++) {
    $bundle = $permissionBundles[$i]
    Write-Host "[$($i + 1)] " -NoNewline -ForegroundColor Yellow
    Write-Host "$($bundle.Name)" -ForegroundColor White
    Write-Host "    $($bundle.Description)" -ForegroundColor Gray
    Write-Host "    Permissions: " -NoNewline -ForegroundColor DarkGray
    Write-Host "$($bundle.Permissions -join ', ')" -ForegroundColor DarkCyan
    Write-Host "    Use case: $($bundle.Recommended)" -ForegroundColor DarkGray
    Write-Host ""
}

# Prompt for bundle selection
Write-Host "Select a permission bundle (enter number):" -ForegroundColor Cyan
if ($ResourceType -eq 'Both') {
    Write-Host "  TIP: You can select multiple bundles by running this script multiple times" -ForegroundColor Gray
}
Write-Host "  Example: 2" -ForegroundColor Gray
$selection = Read-Host "`nSelection"

if ([string]::IsNullOrWhiteSpace($selection) -or $selection -notmatch '^\d+$') {
    throw "Invalid selection. Please enter a number."
}

$selectedIndex = [int]$selection
if ($selectedIndex -lt 1 -or $selectedIndex -gt $permissionBundles.Count) {
    throw "Invalid selection. Please enter a number between 1 and $($permissionBundles.Count)."
}

$selectedBundle = $permissionBundles[$selectedIndex - 1]

# Display selected bundle
Write-Host "`n=== Selected Permission Bundle ===" -ForegroundColor Green
Write-Host "  Bundle: $($selectedBundle.Name)" -ForegroundColor White
Write-Host "  Description: $($selectedBundle.Description)" -ForegroundColor Gray
Write-Host "  Permissions to grant:" -ForegroundColor White
foreach ($perm in $selectedBundle.Permissions) {
    Write-Host "    - $perm" -ForegroundColor Cyan
}

Write-Host "`nTarget Service Principal Object ID: $ServicePrincipalObjectId" -ForegroundColor Cyan
Write-Host "`nProceed with granting these permissions? (y/n): " -NoNewline -ForegroundColor Yellow
$confirm = Read-Host
if ($confirm -ne 'y') {
    Write-Host "Aborted." -ForegroundColor Red
    exit
}

try {
    Write-Host "`nConnecting to Microsoft Graph..." -ForegroundColor Cyan
    Connect-MgGraph -Scope AppRoleAssignment.ReadWrite.All -NoWelcome

    # Get the Microsoft Graph service principal
    Write-Host "Retrieving Microsoft Graph service principal..." -ForegroundColor Cyan
    $graph = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '00000003-0000-0000-c000-000000000000'"
    $graph = $graph.value[0]
    
    if (-not $graph) {
        throw 'Microsoft Graph service principal not found.'
    }

    # Get existing app role assignments to avoid duplicates
    Write-Host "Checking existing permissions..." -ForegroundColor Cyan
    $existing = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId/appRoleAssignments"
    $existingAppRoleIds = $existing.value | Select-Object -ExpandProperty appRoleId | ForEach-Object { $_ -split ' ' } | Select-Object -Unique

    $grantedCount = 0
    $skippedCount = 0
    $errorCount = 0

    foreach ($permName in $selectedBundle.Permissions) {
        Write-Host "`nProcessing: $permName" -ForegroundColor White
        
        # Get the graph app role for this permission
        $graphAppRole = $graph.AppRoles | Where-Object Value -eq $permName
        
        if (-not $graphAppRole) {
            Write-Warning "  App role '$permName' not found in Microsoft Graph. Skipping."
            $errorCount++
            continue
        }

        # Check if already granted
        if ($existingAppRoleIds -contains $graphAppRole.Id) {
            Write-Host "  ✓ Already granted. Skipping." -ForegroundColor DarkGray
            $skippedCount++
            continue
        }

        # Prepare the app role assignment
        $appRoleAssignment = @{
            principalId = $ServicePrincipalObjectId
            resourceId  = $graph.Id
            appRoleId   = $graphAppRole.Id
        }

        # Grant the app role
        try {
            Write-Host "  Granting..." -ForegroundColor Cyan
            Invoke-MgGraphRequest -Method POST -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$ServicePrincipalObjectId/appRoleAssignments" -Body $appRoleAssignment | Out-Null
            Write-Host "  ✓ Granted successfully" -ForegroundColor Green
            $grantedCount++
        }
        catch {
            Write-Warning "  ✗ Failed to grant: $($_.Exception.Message)"
            $errorCount++
        }
    }

    Write-Host "`n=== Summary ===" -ForegroundColor Green
    Write-Host "  Granted: $grantedCount" -ForegroundColor Green
    Write-Host "  Already existed: $skippedCount" -ForegroundColor Gray
    if ($errorCount -gt 0) {
        Write-Host "  Errors: $errorCount" -ForegroundColor Red
    }
    
    if ($errorCount -eq 0) {
        Write-Host "`n✓ All permissions configured successfully!" -ForegroundColor Green
    }
    else {
        Write-Host "`n⚠ Some permissions failed. Check errors above." -ForegroundColor Yellow
    }
}
catch {
    Write-Error "Failed to grant permissions: $_"
    throw
}
finally {
    Disconnect-MgGraph | Out-Null
}