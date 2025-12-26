#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The object id of the enterprise application to which we are granting the app role
$objectId = '4e8943ad-b64d-4312-9717-12af9e84a212' # Microsoft Graph Command Line

# Add the correct Graph scope to grant (e.g., User.Read, Device.ReadWrite.All)
$graphScope = 'Device.ReadWrite.All'

try {
    Write-Host 'Connecting to Microsoft Graph...'
    Connect-MgGraph -Scope AppRoleAssignment.ReadWrite.All

    # Get the Microsoft Graph service principal
    Write-Host 'Retrieving Microsoft Graph service principal...'
    $graph = Get-MgServicePrincipal -Filter "AppId eq '00000003-0000-0000-c000-000000000000'"
    
    if (-not $graph) {
        throw 'Microsoft Graph service principal not found.'
    }

    # Get the graph app role for the scope that we want to grant
    Write-Host "Looking for app role: $graphScope"
    $graphAppRole = $graph.AppRoles | Where-Object Value -eq $graphScope
    
    if (-not $graphAppRole) {
        throw "App role '$graphScope' not found. Available roles: $($graph.AppRoles.Value -join ', ')"
    }

    # Prepare the app role assignment
    $appRoleAssignment = @{
        principalId = $objectId
        resourceId  = $graph.Id
        appRoleId   = $graphAppRole.Id
    }

    # Grant the app role
    Write-Host 'Granting app role assignment...'
    $result = New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $objectId -BodyParameter $appRoleAssignment
    
    Write-Host 'App role assignment successful!' -ForegroundColor Green
    $result | Format-List
}
catch {
    Write-Error "Failed to grant app role: $_"
    throw
}