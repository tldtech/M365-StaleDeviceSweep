#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

<#
.SYNOPSIS
    Grant Microsoft Graph API permissions to a service principal for stale device management.

.DESCRIPTION
    Interactive script to grant one or more Graph API permissions required by the
    Stale Device Sweep Azure Function:
    - Device.Read.All: Read Entra ID device information
    - Device.ReadWrite.All: Disable devices and tag with open extensions
    - Device.Read.All + DeviceManagementManagedDevices.Read.All: Read Intune managed device data
    - Device.ReadWrite.All + DeviceManagementManagedDevices.ReadWrite.All: Retire/wipe/delete Intune devices

.PARAMETER ServicePrincipalObjectId
    The object ID of the service principal (managed identity or app registration) to grant permissions to.

.EXAMPLE
    .\AppEntraPermissions.ps1
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ServicePrincipalObjectId = '4e8943ad-b64d-4312-9717-12af9e84a212'  # Microsoft Graph Command Line Tools; the Microsoft Entra object id of the enterprise application to which we are granting the app role.
)

# Available permission bundles
$permissionBundles = @(
    [PSCustomObject]@{
        Name = 'Entra Read Only'
        Description = 'Read Entra ID device information (detect mode only)'
        Permissions = @('Device.Read.All')
        Recommended = 'For preview/reporting only'
    },
    [PSCustomObject]@{
        Name = 'Entra Read + Write'
        Description = 'Disable devices and tag with open extensions'
        Permissions = @('Device.ReadWrite.All')
        Recommended = 'For disable/tag modes without Intune'
    },
    [PSCustomObject]@{
        Name = 'Entra + Intune Read'
        Description = 'Read Entra ID and Intune managed device data'
        Permissions = @('Device.Read.All', 'DeviceManagementManagedDevices.Read.All')
        Recommended = 'For Intune-aware decision planning (MODE=decide)'
    },
    [PSCustomObject]@{
        Name = 'Entra + Intune Full Access'
        Description = 'Full access: Disable, tag, retire, wipe, and delete devices'
        Permissions = @('Device.ReadWrite.All', 'DeviceManagementManagedDevices.ReadWrite.All')
        Recommended = 'For complete automation (MODE=execute with all actions)'
    }
)

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
Write-Host "`n=== Microsoft Graph API Permission Bundles ===" -ForegroundColor Green
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
    $graph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
    
    if (-not $graph) {
        throw 'Microsoft Graph service principal not found.'
    }

    # Get existing app role assignments to avoid duplicates
    Write-Host "Checking existing permissions..." -ForegroundColor Cyan
    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalObjectId -ErrorAction SilentlyContinue
    $existingAppRoleIds = $existing | Select-Object -ExpandProperty AppRoleId

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
            New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $ServicePrincipalObjectId -BodyParameter $appRoleAssignment | Out-Null
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