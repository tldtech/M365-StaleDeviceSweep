<#
.SYNOPSIS
    Azure Function to identify and manage stale Entra ID devices.

.DESCRIPTION
    This Azure Function automatically identifies stale devices in Entra ID (Azure AD) based on their
    last sign-in date and performs actions according to the configured mode. It supports three modes:

    - detect:  Shows which stale devices would be acted on (dry-run/preview) - DEFAULT
    - disable: Disables stale devices (requires CONFIRM_DISABLE=true for safety)
    - tag:     Tags stale devices with metadata using open extensions (requires CONFIRM_TAG=true)

    Optional Intune enrichment:
    - When enabled (INCLUDE_INTUNE=true), the function can pull Intune managed device properties 
    and optionally use Intune activity (lastSyncDateTime) in staleness evaluation.

    Activity source (when INCLUDE_INTUNE=true):
    - ACTIVITY_SOURCE=signin      -> Entra approximateLastSignInDateTime only (default behavior)
    - ACTIVITY_SOURCE=intune      -> Intune lastSyncDateTime only
    - ACTIVITY_SOURCE=mostRecent  -> Newest of sign-in vs Intune sync

    All modes generate a report showing device inventory, classifications, and an action plan
    identifying which stale devices will be or would be acted upon.

    The function uses the approximateLastSignInDateTime property from Microsoft Graph API to determine
    if a device hasn't been used within the configured threshold (default 90 days). For devices without
    sign-in data, it falls back to the createdDateTime.

    Classification logic:
    - Active:         Device has activity recently (within threshold)
    - Stale:          Device has not had activity within the threshold period
    - Stale-NoSignIn: Device was created before threshold but has no activity data
    - Unknown:        Unable to determine staleness (conservative approach - no action taken)

    Safety features:
    - MAX_ACTIONS limits the number of actions per run to prevent accidental bulk operations
    - CONFIRM_DISABLE and CONFIRM_TAG flags must be explicitly set to true for those modes
    - Comprehensive logging and reporting with action plans before execution

    Authentication:
    - In Azure: Uses Managed Identity automatically
    - Local dev: Falls back to Azure CLI authentication (requires 'az login')

    Output:
    - Generates a JSON report written to blob storage via output binding
    - Report includes device inventory, classifications, action plans, and execution results
    
    Permissions:
    Requires appropriate permissions to read devices from Entra ID and optionally Intune,
    as well as to disable devices or update open extensions if those modes are used.
    - Detect only: Entra-only: Device.Read.All  ￼
	- Disable enabled: Device.ReadWrite.All  ￼
	- Tag enabled: Device.ReadWrite.All  ￼
	- Any of the above + Intune enrichment: add DeviceManagementManagedDevices.Read.All 

.PARAMETER Timer
    Timer trigger input from Azure Functions. This is provided automatically by the Azure Functions runtime. ￼

.NOTES
    Version:        1.3 (Entra-only + optional Intune enrichment)
    Author:         TLDTech.io
    Purpose:        Automated stale device lifecycle management for Entra ID (+ optional Intune context)

.EXAMPLE
    # Run in detect mode (default) - preview what would be acted on
    MODE=detect

.EXAMPLE
    # Preview with custom staleness threshold
    MODE=detect STALE_DAYS=60

.EXAMPLE
    # Actually disable stale devices (requires confirmation)
    MODE=disable CONFIRM_DISABLE=true MAX_ACTIONS=100

.EXAMPLE
    # Tag stale devices with metadata (requires confirmation)
    MODE=tag CONFIRM_TAG=true

.EXAMPLE
    # Include Intune properties in the report, but keep Entra sign-in as activity
    INCLUDE_INTUNE=true ACTIVITY_SOURCE=signin

.EXAMPLE
    # Include Intune and use most recent of Entra sign-in vs Intune last sync
    INCLUDE_INTUNE=true ACTIVITY_SOURCE=mostRecent
#>

param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------
# Load configuration from environment variables with sensible defaults
# These can be set in the Function App's Application Settings or local.settings.json

# Core staleness configuration
$staleDays = [int]($env:STALE_DAYS ?? 90)                # Days of inactivity before a device is considered stale
$mode = ($env:MODE ?? 'detect').ToLowerInvariant()  # Operating mode: detect | disable | tag
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')          # Microsoft Graph API version to use

# Safety rails and tagging configuration
$maxActions = [int]($env:MAX_ACTIONS ?? 50)                                  # Maximum number of devices to act on per execution (throttle)
$confirmDisable = (($env:CONFIRM_DISABLE ?? 'false').ToLowerInvariant() -eq 'true') # Must be explicitly set to 'true' to disable devices
$confirmTag = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true')     # Must be explicitly set to 'true' to tag devices
$extensionName = ($env:EXTENSION_NAME ?? 'STALE')                               # Open extension name for storing metadata on devices

# Optional Intune enrichment
$includeIntune = (($env:INCLUDE_INTUNE ?? 'false').ToLowerInvariant() -eq 'true')

# How to treat "activity" when Intune is enabled:
# - signin      = use Entra approximateLastSignInDateTime only (default behavior)
# - intune      = use Intune lastSyncDateTime only
# - mostRecent  = use whichever is newer: sign-in vs Intune sync
$activitySource = ($env:ACTIVITY_SOURCE ?? 'signin').ToLowerInvariant()
if ($activitySource -notin @('signin', 'intune', 'mostrecent')) { $activitySource = 'signin' }

# Calculate time boundaries for staleness evaluation (UTC)
$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)
$nowUtcStr = $nowUtc.ToString('o')
$cutoffUtcStr = $cutoffUtc.ToString('o')

# Display configuration summary for visibility in function logs
Write-Host "=== Entra stale device sweep (v1.3: Intune optional) ==="
Write-Host "Now (UTC):        $nowUtcStr"
Write-Host "Cutoff (UTC):     $cutoffUtcStr"
Write-Host "Mode:             $mode"
Write-Host "Graph:            $graphApiVersion"
Write-Host "Max actions:      $maxActions"
Write-Host "Confirm disable:  $confirmDisable"
Write-Host "Confirm tag:      $confirmTag"
Write-Host "Ext name:         $extensionName"
Write-Host "Include Intune:   $includeIntune"
Write-Host "Activity source:  $activitySource"

# ---------------------------
# Authentication Helpers
# ---------------------------

function Get-GraphTokenManagedIdentity {
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) {
        return $null
    }

    $resource = "https://graph.microsoft.com"
    $apiVersion = "2019-08-01"
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($resource))&api-version=$apiVersion"
    $headers = @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER }

    $tokenResponse = Invoke-RestMethod -Method GET -Uri $uri -Headers $headers
    return $tokenResponse.access_token
}

function Get-GraphTokenAzCli {
    $az = Get-Command az -ErrorAction SilentlyContinue
    if (-not $az) {
        throw "Azure CLI not found. Install 'az' or run in Azure with Managed Identity."
    }

    $json = & az account get-access-token --resource-type ms-graph --output json 2>$null
    if (-not $json) { throw "Failed to get Graph token from Azure CLI. Run 'az login' first." }

    ($json | ConvertFrom-Json).accessToken
}

function Get-GraphAccessToken {
    $mi = Get-GraphTokenManagedIdentity
    if ($mi) { return $mi }

    Write-Host "Managed Identity not detected; using Azure CLI token (local dev)."
    return Get-GraphTokenAzCli
}

# ---------------------------
# Microsoft Graph API Helpers
# ---------------------------

function Invoke-Graph {
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    if ($null -ne $Body) { $headers['Content-Type'] = 'application/json' }

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 8)
        }
        else {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers
        }
    }
    catch {
        $resp = $_.Exception.Response
        if ($resp -and $resp.StatusCode) {
            $code = [int]$resp.StatusCode
            throw "Graph $Method $Uri failed (HTTP $code): $($_.Exception.Message)"
        }
        throw
    }
}

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri

    while ($next) {
        $resp = Invoke-Graph -Method GET -Uri $next -AccessToken $AccessToken

        if ($resp.value) {
            foreach ($v in $resp.value) { $items.Add($v) }
        }

        $next = if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') {
            $resp.'@odata.nextLink'
        }
        else {
            $null
        }
    }

    return $items
}

function Disable-EntraDevice {
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId"
    Invoke-Graph -Method PATCH -Uri $uri -AccessToken $AccessToken -Body @{ accountEnabled = $false } | Out-Null
}

function Update-DeviceOpenExtension {
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion,
        [Parameter(Mandatory)][string]$ExtensionName,
        [Parameter(Mandatory)][hashtable]$Properties
    )

    $patchUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions/$ExtensionName"
    try {
        Invoke-Graph -Method PATCH -Uri $patchUri -AccessToken $AccessToken -Body $Properties | Out-Null
        return "patched"
    }
    catch {
        if ($_ -match 'HTTP 404') {
            $postUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions"
            $body = @{
                "@odata.type" = "microsoft.graph.openTypeExtension"
                extensionName = $ExtensionName
            } + $Properties

            Invoke-Graph -Method POST -Uri $postUri -AccessToken $AccessToken -Body $body | Out-Null
            return "created"
        }
        throw
    }
}

# ---------------------------
# Summary Helper Function
# ---------------------------

function New-HumanSummaryText {
    param(
        [Parameter(Mandatory)] [string] $Version,
        [Parameter(Mandatory)] [string] $GeneratedAtUtc,
        [Parameter(Mandatory)] [string] $Mode,
        [Parameter(Mandatory)] [int]    $StaleDaysThreshold,
        [Parameter(Mandatory)] [string] $CutoffUtc,
        [Parameter(Mandatory)] [bool]   $IncludeIntune,
        [Parameter(Mandatory)] [string] $ActivitySource,
        [Parameter(Mandatory)] $Counts,         # array of {classification,count}
        [Parameter(Mandatory)] $ActionSummary,  # your object
        [Parameter(Mandatory)] $ActionPlan,     # list
        [Parameter(Mandatory)] $ActionsExecuted,
        [Parameter(Mandatory)] [int] $TotalDevices
    )

    $countsMap = @{}
    foreach ($c in $Counts) { $countsMap[$c.classification] = [int]$c.count }

    $active = ($countsMap['Active'] ?? 0)
    $stale = ($countsMap['Stale'] ?? 0)
    $staleNoSignIn = ($countsMap['Stale-NoSignIn'] ?? 0)
    $unknown = ($countsMap['Unknown'] ?? 0)

    $candidateCount = [int]$ActionSummary.candidateCount
    $plannedCount = [int]$ActionSummary.plannedActionCount
    $executedCount = [int]$ActionsExecuted.Count

    $preview = @(
        $ActionPlan | Select-Object -First 25 displayName, classification, daysSince, plannedAction
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("Entra Stale Device Sweep — $Version")
    $lines.Add("Generated (UTC): $GeneratedAtUtc")
    $lines.Add("Mode: $Mode")
    $lines.Add("Threshold: $StaleDaysThreshold days   Cutoff (UTC): $CutoffUtc")
    $lines.Add("Intune enrichment: $IncludeIntune   Activity source: $ActivitySource")
    $lines.Add("")

    $lines.Add("Inventory Summary")
    $lines.Add("  Total devices:        $TotalDevices")
    $lines.Add("  Active:               $active")
    $lines.Add("  Stale:                $stale")
    $lines.Add("  Stale (no sign-in):   $staleNoSignIn")
    $lines.Add("  Unknown:              $unknown")
    $lines.Add("")

    $lines.Add("Action Summary")
    $lines.Add("  Candidates:           $candidateCount")
    $lines.Add("  Planned actions:      $plannedCount (MAX_ACTIONS=$($ActionSummary.maxActions))")
    $lines.Add("  Will execute:         $($ActionSummary.willExecute)")
    $lines.Add("  Executed actions:     $executedCount")
    $lines.Add("  Confirm disable:      $($ActionSummary.confirmDisable)")
    $lines.Add("  Confirm tag:          $($ActionSummary.confirmTag)")
    $lines.Add("  Extension name:       $($ActionSummary.extensionName)")
    $lines.Add("")

    $lines.Add("Planned Action Preview (first $([Math]::Min(25, $plannedCount)))")
    if ($preview.Count -eq 0) {
        $lines.Add("  (none)")
    }
    else {
        $lines.Add("  DisplayName | Classification | DaysSince | Action")
        $lines.Add("  ---------- | -------------- | --------- | ------")
        foreach ($p in $preview) {
            $dn = ($p.displayName ?? "").ToString().Trim()
            if ($dn.Length -gt 60) { $dn = $dn.Substring(0, 57) + "..." }
            $lines.Add(("  {0} | {1} | {2} | {3}" -f $dn, $p.classification, $p.daysSince, $p.plannedAction))
        }
    }

    $lines.Add("")
    $lines.Add("Notes")
    $lines.Add("  - 'Unknown' devices are never acted on.")
    $lines.Add("  - 'Stale-NoSignIn' means no activity timestamp was available; createdDateTime was older than cutoff.")
    $lines.Add("")

    return ($lines -join "`n")
}

# ---------------------------
# Staleness Evaluation Logic
# ---------------------------

function ConvertTo-GraphDateUtc {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::Parse($Value)).ToUniversalTime() } catch { return $null }
}

function Get-ActivityTimestamp {
    <#
        Calculates the activity timestamp based on the configured source.
        Returns the activity datetime (UTC) or $null if no activity found.
    #>
    param(
        [datetime]$LastSignInUtc = $null,
        [datetime]$IntuneLastSyncUtc = $null,
        [Parameter(Mandatory)][ValidateSet('signin', 'intune', 'mostrecent')][string]$ActivitySource
    )

    switch ($ActivitySource) {
        'signin' { return $LastSignInUtc }
        'intune' { return $IntuneLastSyncUtc }
        'mostrecent' {
            if ($LastSignInUtc -and $IntuneLastSyncUtc) {
                return if ($LastSignInUtc -gt $IntuneLastSyncUtc) { $LastSignInUtc } else { $IntuneLastSyncUtc }
            }
            return if ($LastSignInUtc) { $LastSignInUtc } else { $IntuneLastSyncUtc }
        }
    }
}

function Get-IntuneManagedDevicesMap {
    <#
        Returns a hashtable keyed by azureADDeviceId (lowercase).
        If duplicates exist, keeps the record with the newest lastSyncDateTime.
    #>
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $select = "id,deviceName,azureADDeviceId,lastSyncDateTime,enrolledDateTime,complianceState,managementAgent,operatingSystem,osVersion,userPrincipalName"
    $uri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/managedDevices?`$select=$([uri]::EscapeDataString($select))&`$top=999"

    $all = Invoke-GraphGetAll -Uri $uri -AccessToken $AccessToken

    $map = @{}
    foreach ($md in $all) {
        if ([string]::IsNullOrWhiteSpace($md.azureADDeviceId)) { continue }
        $key = ($md.azureADDeviceId.ToString()).ToLowerInvariant()

        $newSync = ConvertTo-GraphDateUtc -Value $md.lastSyncDateTime
        $existing = $map[$key]
        
        # Store only needed properties as lightweight object
        $intuneData = @{
            id                  = $md.id
            deviceName          = $md.deviceName
            lastSyncDateTimeUtc = $newSync
            lastSyncDateTime    = $md.lastSyncDateTime
            enrolledDateTime    = $md.enrolledDateTime
            complianceState     = $md.complianceState
            managementAgent     = $md.managementAgent
            operatingSystem     = $md.operatingSystem
            osVersion           = $md.osVersion
            userPrincipalName   = $md.userPrincipalName
        }
        
        if (-not $existing) {
            $map[$key] = $intuneData
            continue
        }

        $oldSync = $existing.lastSyncDateTimeUtc
        if ($newSync -and (-not $oldSync -or $newSync -gt $oldSync)) {
            $map[$key] = $intuneData
        }
    }

    Write-Host "Intune managedDevices fetched: $($all.Count); joinable keys: $($map.Count)"
    return $map
}

function Get-DeviceClassification {
    <#
        Classifies a device based on chosen activity timestamp:
        - signin      => Entra approximateLastSignInDateTime
        - intune      => Intune lastSyncDateTime
        - mostrecent  => max(signin, intune)
        Fallback if no activity: createdDateTime -> Stale-NoSignIn/Unknown
    #>
    param(
        [Parameter(Mandatory)] [datetime] $CutoffUtc,
        [datetime] $ActivityUtc = $null,
        [datetime] $CreatedUtc = $null
    )

    if ($ActivityUtc) {
        return if ($ActivityUtc -lt $CutoffUtc) { 'Stale' } else { 'Active' }
    }

    if ($CreatedUtc -and $CreatedUtc -lt $CutoffUtc) {
        return 'Stale-NoSignIn'
    }

    return 'Unknown'
}

# ---------------------------
# Main Execution Flow
# ---------------------------

try {
    # Step 1: Auth
    $token = Get-GraphAccessToken

    # Step 2: Fetch Entra devices
    $select = "id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,createdDateTime,approximateLastSignInDateTime"
    $uri = "https://graph.microsoft.com/$graphApiVersion/devices?`$select=$([uri]::EscapeDataString($select))&`$top=999"

    $devices = Invoke-GraphGetAll -Uri $uri -AccessToken $token
    Write-Host "Entra devices fetched: $($devices.Count)"

    # Step 2b: Optional Intune enrichment (join map keyed by azureADDeviceId == Entra deviceId)
    $intuneMap = $null
    if ($includeIntune) {
        $intuneMap = Get-IntuneManagedDevicesMap -AccessToken $token -GraphApiVersion $graphApiVersion
    }

    # Step 3: Classify devices
    $results = [System.Collections.Generic.List[object]]::new($devices.Count)

    foreach ($d in $devices) {
        # Parse dates once and cache
        $lastSignInUtc = ConvertTo-GraphDateUtc -Value $d.approximateLastSignInDateTime
        $createdUtc = ConvertTo-GraphDateUtc -Value $d.createdDateTime
        
        # Lookup Intune data if enabled
        $intune = $null
        $intuneLastSyncUtc = $null
        if ($includeIntune -and $intuneMap -and $d.deviceId) {
            $k = ($d.deviceId.ToString()).ToLowerInvariant()
            $intune = $intuneMap[$k]
            $intuneLastSyncUtc = if ($intune) { $intune.lastSyncDateTimeUtc } else { $null }
        }

        # Calculate activity timestamp once using helper
        $activityUtc = Get-ActivityTimestamp `
            -LastSignInUtc $lastSignInUtc `
            -IntuneLastSyncUtc $intuneLastSyncUtc `
            -ActivitySource $activitySource

        # Classify using simplified function
        $classification = Get-DeviceClassification `
            -CutoffUtc $cutoffUtc `
            -ActivityUtc $activityUtc `
            -CreatedUtc $createdUtc

        # Calculate days since activity
        $daysSinceLastActivity = if ($activityUtc) {
            [int]($nowUtc - $activityUtc).TotalDays
        }
        elseif ($createdUtc) {
            [int]($nowUtc - $createdUtc).TotalDays
        }
        else {
            $null
        }

        # Build result object with streamlined Intune properties
        $resultObj = [pscustomobject]@{
            # Entra
            id                            = $d.id
            displayName                   = $d.displayName
            deviceId                      = $d.deviceId
            accountEnabled                = $d.accountEnabled
            operatingSystem               = $d.operatingSystem
            operatingSystemVersion        = $d.operatingSystemVersion
            trustType                     = $d.trustType
            createdDateTime               = $d.createdDateTime
            approximateLastSignInDateTime = $d.approximateLastSignInDateTime
            lastSignInUtc                 = if ($lastSignInUtc) { $lastSignInUtc.ToString('o') } else { $null }

            # Evaluation
            includeIntune                 = $includeIntune
            activitySourceUsed            = $activitySource
            activityTimestampUtc          = if ($activityUtc) { $activityUtc.ToString('o') } else { $null }
            classification                = $classification
            daysSinceLastActivity         = $daysSinceLastActivity
            staleThresholdDateUtc         = $cutoffUtcStr
            staleDaysThreshold            = $staleDays
        }

        # Add Intune properties if enabled (avoids repeated conditionals)
        if ($includeIntune) {
            $resultObj | Add-Member -NotePropertyName intuneManagedDeviceId -NotePropertyValue ($intune?.id) -Force
            $resultObj | Add-Member -NotePropertyName intuneDeviceName -NotePropertyValue ($intune?.deviceName) -Force
            $resultObj | Add-Member -NotePropertyName intuneLastSyncDateTime -NotePropertyValue ($intuneLastSyncUtc?.ToString('o')) -Force
            $resultObj | Add-Member -NotePropertyName intuneEnrolledDateTime -NotePropertyValue ($intune?.enrolledDateTime) -Force
            $resultObj | Add-Member -NotePropertyName intuneComplianceState -NotePropertyValue ($intune?.complianceState) -Force
            $resultObj | Add-Member -NotePropertyName intuneManagementAgent -NotePropertyValue ($intune?.managementAgent) -Force
            $resultObj | Add-Member -NotePropertyName intuneUserPrincipalName -NotePropertyValue ($intune?.userPrincipalName) -Force
            $resultObj | Add-Member -NotePropertyName intuneOs -NotePropertyValue ($intune?.operatingSystem) -Force
            $resultObj | Add-Member -NotePropertyName intuneOsVersion -NotePropertyValue ($intune?.osVersion) -Force
        }

        $results.Add($resultObj)
    }

    # Summary statistics
    $counts = @($results | Group-Object classification | ForEach-Object {
            [pscustomobject]@{ classification = $_.Name; count = $_.Count }
        })

    # Base report
    $report = [pscustomobject]@{
        version            = "v1.3-intune-optional"
        generatedAtUtc     = $nowUtcStr
        staleDaysThreshold = $staleDays
        totalDevices       = $devices.Count
        includeIntune      = $includeIntune
        activitySource     = $activitySource
        summary            = $counts
        items              = $results
    }

    # ---------------------------
    # Step 4: Build Action Plan
    # ---------------------------
    
    $candidates = @($results | Where-Object { $_.classification -in @('Stale', 'Stale-NoSignIn') })

    $actionPlan = [System.Collections.Generic.List[object]]::new()
    $plannedCount = [Math]::Min($candidates.Count, $maxActions)
    for ($i = 0; $i -lt $plannedCount; $i++) {
        $c = $candidates[$i]
        $actionPlan.Add([pscustomobject]@{
                deviceObjectId = $c.id
                displayName    = $c.displayName
                classification = $c.classification
                daysSince      = $c.daysSinceLastActivity
                plannedAction  = $mode
            })
    }

    $actionSummary = [pscustomobject]@{
        modeRequested      = $mode
        candidateCount     = $candidates.Count
        plannedActionCount = $actionPlan.Count
        maxActions         = $maxActions
        willExecute        = $false
        confirmDisable     = $confirmDisable
        confirmTag         = $confirmTag
        extensionName      = $extensionName
        includeIntune      = $includeIntune
        activitySource     = $activitySource
    }

    # Step 5: Execute actions
    $actionsExecuted = [System.Collections.Generic.List[object]]::new()

    switch ($mode) {
        'detect' {
            # Preview only
        }

        'disable' {
            if (-not $confirmDisable) {
                Write-Warning "MODE=disable requested but CONFIRM_DISABLE=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true

            foreach ($a in $actionPlan) {
                Disable-EntraDevice -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion
                $actionsExecuted.Add([pscustomobject]@{
                        deviceObjectId = $a.deviceObjectId
                        action         = 'disable'
                        status         = 'ok'
                    })
            }
        }

        'tag' {
            if (-not $confirmTag) {
                Write-Warning "MODE=tag requested but CONFIRM_TAG=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true

            foreach ($a in $actionPlan) {
                $props = @{
                    status             = "stale"
                    classification     = $a.classification
                    version            = "v1.3-intune-optional"
                    evaluatedAtUtc     = $nowUtcStr
                    staleDaysThreshold = $staleDays
                    cutoffUtc          = $cutoffUtcStr
                    includeIntune      = $includeIntune
                    activitySource     = $activitySource
                }

                $result = Update-DeviceOpenExtension `
                    -DeviceObjectId $a.deviceObjectId `
                    -AccessToken $token `
                    -GraphApiVersion $graphApiVersion `
                    -ExtensionName $extensionName `
                    -Properties $props

                $actionsExecuted.Add([pscustomobject]@{
                        deviceObjectId = $a.deviceObjectId
                        action         = 'tag'
                        status         = $result
                    })
            }
        }

        default {
            Write-Warning "Unknown MODE='$mode'. Valid modes: detect, disable, tag. No actions executed."
        }
    }

    # Step 6: Output report
    $report | Add-Member -NotePropertyName mode -NotePropertyValue $mode -Force
    $report | Add-Member -NotePropertyName actionSummary -NotePropertyValue $actionSummary -Force
    $report | Add-Member -NotePropertyName actionPlan -NotePropertyValue $actionPlan -Force
    $report | Add-Member -NotePropertyName actionsExecuted -NotePropertyValue $actionsExecuted -Force

    # JSON report output
    $json = $report | ConvertTo-Json -Depth 10
    Push-OutputBinding -Name reportBlob -Value $json

    # Human-readable summary output
    $summaryText = New-HumanSummaryText `
        -Version $report.version `
        -GeneratedAtUtc $nowUtcStr `
        -Mode $mode `
        -StaleDaysThreshold $staleDays `
        -CutoffUtc $cutoffUtcStr `
        -IncludeIntune $includeIntune `
        -ActivitySource $activitySource `
        -Counts $counts `
        -ActionSummary $actionSummary `
        -ActionPlan $actionPlan `
        -ActionsExecuted $actionsExecuted `
        -TotalDevices $devices.Count
    Push-OutputBinding -Name summaryBlob -Value $summaryText

    Write-Host "Reports written to blob output binding."
}
catch {
    Write-Error $_
    throw
}