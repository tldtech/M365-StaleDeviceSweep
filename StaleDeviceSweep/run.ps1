<#
.SYNOPSIS
    Azure Function to identify and manage stale Entra ID devices (with optional Intune decisioning/actions).

.DESCRIPTION
    This Azure Function identifies stale devices in Entra ID (Azure AD) and can optionally enrich with
    Intune managed device data to refine staleness decisions and avoid false positives.

    Legacy modes (v1 behavior):
    - detect:  Shows which stale devices would be acted on (dry-run/preview)
    - disable: Disables stale devices (requires CONFIRM_DISABLE=true)
    - tag:     Tags stale devices using open extensions (requires CONFIRM_TAG=true)

    New "full set" modes (v2 behavior):
    - decide:   Builds an Intune-aware action plan (no execution). Planned actions may include:
                disable, tag, intune-retire, intune-wipe, intune-delete, none
    - execute:  Executes the Intune-aware action plan (requires confirm flags per action)

    Optional Intune enrichment (INCLUDE_INTUNE=true):
    - Pulls Intune managedDevices properties and adds correlation status to the report.
    - Supports decision rules such as:
        * disable only if Entra stale AND Intune stale
        * don't disable if Intune recently synced
        * don't disable if compliant
        * handle duplicates/mismatches conservatively

    Activity timestamp for "classification" (still produced for reporting):
    - ACTIVITY_SOURCE=signin      -> Entra approximateLastSignInDateTime only
    - ACTIVITY_SOURCE=intune      -> Intune lastSyncDateTime only
    - ACTIVITY_SOURCE=mostRecent  -> Newest of sign-in vs Intune sync

    Output:
    - JSON report written to blob via output binding (reportBlob)
    - Human-readable summary text written to blob via output binding (summaryBlob)

.NOTES
    Version:        2.0 (Intune-aware decision rules + optional Intune actions + correlation improvements)
    Author:         TLDTech.io

.PARAMETER Timer
    Timer trigger input from Azure Functions.

.EXAMPLE
    # Legacy Mode: Preview what would be acted on (detect mode)
    MODE=detect STALE_DAYS=90

.EXAMPLE
    # Legacy Mode: Disable stale devices (requires confirmation)
    MODE=disable STALE_DAYS=90 CONFIRM_DISABLE=true MAX_ACTIONS=50

.EXAMPLE
    # Legacy Mode: Tag stale devices with metadata
    MODE=tag CONFIRM_TAG=true EXTENSION_NAME=STALE

.EXAMPLE
    # V2 Mode: Build Intune-aware decision plan (no execution)
    MODE=decide INCLUDE_INTUNE=true STALE_DAYS=90

.EXAMPLE
    # V2 Mode: Execute Intune-aware action plan with all protections enabled
    MODE=execute INCLUDE_INTUNE=true CONFIRM_DISABLE=true CONFIRM_TAG=true
    REQUIRE_BOTH_STALE_FOR_DISABLE=true DONT_DISABLE_IF_INTUNE_RECENT_SYNC=true
    DONT_DISABLE_IF_COMPLIANT=true

.EXAMPLE
    # V2 Mode: Execute with Intune retire action enabled
    MODE=execute INCLUDE_INTUNE=true CONFIRM_INTUNE_RETIRE=true MAX_RETIRE=10

.EXAMPLE
    # V2 Mode: Execute with aggressive cleanup (wipe + delete, use with caution)
    MODE=execute INCLUDE_INTUNE=true CONFIRM_INTUNE_WIPE=true CONFIRM_INTUNE_DELETE=true
    MAX_WIPE=5 MAX_INTUNE_DELETE=10

.EXAMPLE
    # Advanced: Use Intune lastSyncDateTime as activity source
    MODE=decide INCLUDE_INTUNE=true ACTIVITY_SOURCE=intune INTUNE_STALE_DAYS=60

.EXAMPLE
    # Advanced: Use most recent of Entra sign-in or Intune sync
    MODE=decide INCLUDE_INTUNE=true ACTIVITY_SOURCE=mostRecent

.EXAMPLE
    # Advanced: Only disable MDM-managed devices
    MODE=execute INCLUDE_INTUNE=true CONFIRM_DISABLE=true
    ONLY_DISABLE_IF_MANAGEDAGENT_IN=mdm

.EXAMPLE
    # Advanced: Allow disable even with duplicate Intune matches
    MODE=execute INCLUDE_INTUNE=true CONFIRM_DISABLE=true ALLOW_DISABLE_ON_DUPLICATE=true

.EXAMPLE
    # Exception lists: Protect specific devices from any actions
    MODE=execute EXCEPTION_GROUP_ID=<guid>
    EXCEPTION_NAME_PATTERNS=VIP-*,Executive-*,CEO-*
    EXCEPTION_DEVICE_IDS=<guid>,<guid>

.ENVIRONMENT
    Core:
        STALE_DAYS=90
        MODE=detect | disable | tag | decide | execute
        GRAPH_API_VERSION=v1.0
        MAX_ACTIONS=50

    Safety confirms (legacy):
        CONFIRM_DISABLE=false
        CONFIRM_TAG=false

    Intune:
        INCLUDE_INTUNE=false
        ACTIVITY_SOURCE=signin | intune | mostRecent

    Decision rules (used by MODE=decide/execute; recommended INCLUDE_INTUNE=true):
        INTUNE_STALE_DAYS=90               # default: STALE_DAYS
        REQUIRE_BOTH_STALE_FOR_DISABLE=true
        DONT_DISABLE_IF_INTUNE_RECENT_SYNC=true
        INTUNE_RECENT_SYNC_DAYS=14
        DONT_DISABLE_IF_COMPLIANT=true
        ONLY_DISABLE_IF_MANAGEDAGENT_IN=mdm,easmdm  # optional; empty disables this constraint
        ALLOW_DISABLE_ON_DUPLICATE=false            # if duplicate Intune matches exist

    Intune action confirms (used by MODE=execute only):
        CONFIRM_INTUNE_RETIRE=false
        CONFIRM_INTUNE_WIPE=false
        CONFIRM_INTUNE_DELETE=false

    Per-action throttles (optional; defaults shown):
        MAX_DISABLE=50
        MAX_TAG=50
        MAX_RETIRE=25
        MAX_WIPE=5
        MAX_INTUNE_DELETE=25

    Extension:
        EXTENSION_NAME=STALE
    
    Optional outputs (disabled by default):
        OUTPUT_ACTION_PLAN_CSV=false    # Set to true to generate action plan CSV
        OUTPUT_INVENTORY_CSV=false      # Set to true to generate full device inventory CSV
    
    Exceptions (devices never acted on):
        EXCEPTION_GROUP_ID=<guid>                      # Entra group containing protected devices
        EXCEPTION_NAME_PATTERNS=VIP-*,Executive-*      # Comma-separated wildcards
        EXCEPTION_DEVICE_IDS=<guid>,<guid>             # Comma-separated device object IDs

.PERMISSIONS (Graph application permissions; managed identity / app-only)
    - Entra read:    Device.Read.All, GroupMember.Read.All (latter required for EXCEPTION_GROUP_ID)
    - Entra write:   Device.ReadWrite.All (required for disable + open extensions tagging)
    - Intune read:   DeviceManagementManagedDevices.Read.All (required when INCLUDE_INTUNE=true)
    - Intune write:  DeviceManagementManagedDevices.ReadWrite.All (required for retire/wipe/delete)

.TUNING GUIDANCE
    Small environments (<100 devices): ACTION_PARALLELISM=3
    Medium environments (100-1000): ACTION_PARALLELISM=5 (default)
    Large environments (1000-10000): ACTION_PARALLELISM=8
    Very large (10000+): ACTION_PARALLELISM=10 (max recommended to avoid throttling)
#>

param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------

$staleDays = [int]($env:STALE_DAYS ?? 90)
$mode = ($env:MODE ?? 'detect').ToLowerInvariant()
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')

$maxActions = [int]($env:MAX_ACTIONS ?? 50)

$confirmDisable = (($env:CONFIRM_DISABLE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmTag = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true')
$extensionName = ($env:EXTENSION_NAME ?? 'STALE')

$includeIntune = (($env:INCLUDE_INTUNE ?? 'false').ToLowerInvariant() -eq 'true')

$activitySource = ($env:ACTIVITY_SOURCE ?? 'signin').ToLowerInvariant()
if ($activitySource -notin @('signin', 'intune', 'mostrecent')) { $activitySource = 'signin' }

# Decision rules (used by MODE=decide/execute)
$intuneStaleDays = [int]($env:INTUNE_STALE_DAYS ?? $staleDays)
$requireBothStaleForDisable = (($env:REQUIRE_BOTH_STALE_FOR_DISABLE ?? 'true').ToLowerInvariant() -eq 'true')
$dontDisableIfIntuneRecentSync = (($env:DONT_DISABLE_IF_INTUNE_RECENT_SYNC ?? 'true').ToLowerInvariant() -eq 'true')
$intuneRecentSyncDays = [int]($env:INTUNE_RECENT_SYNC_DAYS ?? 14)
$dontDisableIfCompliant = (($env:DONT_DISABLE_IF_COMPLIANT ?? 'true').ToLowerInvariant() -eq 'true')
$allowDisableOnDuplicate = (($env:ALLOW_DISABLE_ON_DUPLICATE ?? 'false').ToLowerInvariant() -eq 'true')

$onlyDisableIfManagementAgentInRaw = ($env:ONLY_DISABLE_IF_MANAGEDAGENT_IN ?? 'mdm,easmdm')
$onlyDisableAgents = @()
if (-not [string]::IsNullOrWhiteSpace($onlyDisableIfManagementAgentInRaw)) {
    $onlyDisableAgents = $onlyDisableIfManagementAgentInRaw.Split(',') | ForEach-Object { $_.Trim().ToLowerInvariant() } | Where-Object { $_ }
}

# Intune action confirms (execute only)
$confirmIntuneRetire = (($env:CONFIRM_INTUNE_RETIRE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmIntuneWipe = (($env:CONFIRM_INTUNE_WIPE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmIntuneDelete = (($env:CONFIRM_INTUNE_DELETE ?? 'false').ToLowerInvariant() -eq 'true')

# Per-action throttles (defaults tuned to safety)
$maxDisable = [int]($env:MAX_DISABLE ?? $maxActions)
$maxTag = [int]($env:MAX_TAG ?? $maxActions)
$maxRetire = [int]($env:MAX_RETIRE ?? 25)
$maxWipe = [int]($env:MAX_WIPE ?? 5)
$maxIntuneDelete = [int]($env:MAX_INTUNE_DELETE ?? 25)

# CSV outputs (optional, disabled by default)
$outputActionPlanCsv = ($env:OUTPUT_ACTION_PLAN_CSV ?? 'false') -eq 'true'
$outputInventoryCsv = ($env:OUTPUT_INVENTORY_CSV ?? 'false') -eq 'true'

# Times (UTC)
$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)
$intuneCutoffUtc = $nowUtc.AddDays(-$intuneStaleDays)
$nowUtcStr = $nowUtc.ToString('o')
$cutoffUtcStr = $cutoffUtc.ToString('o')
$intuneCutoffUtcStr = $intuneCutoffUtc.ToString('o')

# Parallelism for actions (tune based on environment size)
$actionParallelism = [int]($env:ACTION_PARALLELISM ?? 5)  # 3-10 recommended

# Exception lists (devices never acted on)
$exceptionGroupId = $env:EXCEPTION_GROUP_ID
$exceptionNamePatternsRaw = $env:EXCEPTION_NAME_PATTERNS ?? ''
$exceptionNamePatterns = @()
if (-not [string]::IsNullOrWhiteSpace($exceptionNamePatternsRaw)) {
    $exceptionNamePatterns = $exceptionNamePatternsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$exceptionDeviceIdsRaw = $env:EXCEPTION_DEVICE_IDS ?? ''
$exceptionDeviceIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not [string]::IsNullOrWhiteSpace($exceptionDeviceIdsRaw)) {
    $exceptionDeviceIdsRaw.Split(',') | ForEach-Object { 
        $id = $_.Trim()
        if ($id) { $exceptionDeviceIds.Add($id) | Out-Null }
    }
}

Write-Host "=== Entra stale device sweep (v2.0: Intune decisioning/actions) ==="
Write-Host "Now (UTC):               $nowUtcStr"
Write-Host "Entra cutoff (UTC):      $cutoffUtcStr  (STALE_DAYS=$staleDays)"
Write-Host "Intune cutoff (UTC):     $intuneCutoffUtcStr  (INTUNE_STALE_DAYS=$intuneStaleDays)"
Write-Host "Mode:                    $mode"
Write-Host "Graph:                   $graphApiVersion"
Write-Host "Include Intune:          $includeIntune"
Write-Host "Activity source:         $activitySource"
Write-Host "MAX_ACTIONS:             $maxActions"
Write-Host "Confirm disable/tag:     disable=$confirmDisable  tag=$confirmTag"
Write-Host "Confirm Intune actions:  retire=$confirmIntuneRetire  wipe=$confirmIntuneWipe  delete=$confirmIntuneDelete"
Write-Host "Per-action caps:         disable=$maxDisable tag=$maxTag retire=$maxRetire wipe=$maxWipe intuneDelete=$maxIntuneDelete"
Write-Host "Decision rules:          requireBothStaleForDisable=$requireBothStaleForDisable dontDisableIfRecentSync=$dontDisableIfIntuneRecentSync recentDays=$intuneRecentSyncDays dontDisableIfCompliant=$dontDisableIfCompliant allowDisableOnDuplicate=$allowDisableOnDuplicate"
# ---------------------------
# Structured config snapshot for App Insights (Workbook-friendly)
# ---------------------------

$cfgEvent = @{
    eventType         = "staleDeviceSweep.config"
    version           = "v2.0-intune-decisioning"
    mode              = $mode
    includeIntune     = $includeIntune
    activitySource    = $activitySource
    staleDays         = $staleDays
    intuneStaleDays   = $intuneStaleDays
    maxActions        = $maxActions
    actionParallelism = $actionParallelism

    confirms          = @{
        disable      = $confirmDisable
        tag          = $confirmTag
        intuneRetire = $confirmIntuneRetire
        intuneWipe   = $confirmIntuneWipe
        intuneDelete = $confirmIntuneDelete
    }

    limits            = @{
        maxDisable      = $maxDisable
        maxTag          = $maxTag
        maxRetire       = $maxRetire
        maxWipe         = $maxWipe
        maxIntuneDelete = $maxIntuneDelete
    }

    decisionRules     = @{
        requireBothStaleForDisable = $requireBothStaleForDisable
        dontDisableIfRecentSync    = $dontDisableIfIntuneRecentSync
        intuneRecentSyncDays       = $intuneRecentSyncDays
        dontDisableIfCompliant     = $dontDisableIfCompliant
        onlyDisableAgents          = ($onlyDisableAgents -join ",")
        allowDisableOnDuplicate    = $allowDisableOnDuplicate
    }
}

# Prefix makes this trivial to find in KQL
Write-Host ("CFG " + ($cfgEvent | ConvertTo-Json -Compress))
if ($onlyDisableAgents.Count -gt 0) { Write-Host "Only disable if managementAgent in: $($onlyDisableAgents -join ', ')" }

# ---------------------------
# Authentication Helpers
# ---------------------------

function Get-GraphTokenManagedIdentity {
    if (-not $env:IDENTITY_ENDPOINT -or -not $env:IDENTITY_HEADER) { return $null }

    $resource = "https://graph.microsoft.com"
    $apiVersion = "2019-08-01"
    $uri = "$($env:IDENTITY_ENDPOINT)?resource=$([uri]::EscapeDataString($resource))&api-version=$apiVersion"
    $headers = @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER }

    (Invoke-RestMethod -Method GET -Uri $uri -Headers $headers).access_token
}

function Get-GraphTokenAzCli {
    $az = Get-Command az -ErrorAction SilentlyContinue
    if (-not $az) { throw "Azure CLI not found. Install 'az' or run in Azure with Managed Identity." }

    $json = & az account get-access-token --resource-type ms-graph --output json 2>$null
    if (-not $json) { throw "Failed to get Graph token from Azure CLI. Run 'az login' first." }

    ($json | ConvertFrom-Json).accessToken
}

function Get-GraphAccessToken {
    $mi = Get-GraphTokenManagedIdentity
    if ($mi) { return $mi }

    Write-Host "Managed Identity not detected; using Azure CLI token (local dev)."
    Get-GraphTokenAzCli
}

# ---------------------------
# Graph Helpers
# ---------------------------

function Invoke-Graph {
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    if ($null -ne $Body) { $headers['Content-Type'] = 'application/json' }

    try {
        if ($Method -in @('POST', 'PATCH') -and $null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 10)
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
        [Parameter(Mandatory)] [string] $AccessToken,
        [int] $MaxRetries = 5
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri

    while ($next) {
        $resp = Invoke-GraphWithRetry -Method GET -Uri $next -AccessToken $AccessToken -MaxRetries $MaxRetries

        if ($resp.value) {
            foreach ($v in $resp.value) { $items.Add($v) }
        }

        $next = if ($resp.PSObject.Properties.Name -contains '@odata.nextLink') { $resp.'@odata.nextLink' } else { $null }
    }

    $items
}

function Invoke-GraphWithRetry {
    param(
        [Parameter(Mandatory)] [ValidateSet('GET', 'POST', 'PATCH', 'DELETE')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null,
        [int] $MaxRetries = 5,
        [int] $InitialDelaySeconds = 2
    )

    $attempt = 0
    $delay = $InitialDelaySeconds

    while ($attempt -lt $MaxRetries) {
        try {
            return Invoke-Graph -Method $Method -Uri $Uri -AccessToken $AccessToken -Body $Body
        }
        catch {
            $attempt++
            $statusCode = $null
            $retryAfter = $null

            # Extract status code and Retry-After header
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $retryAfter = $_.Exception.Response.Headers['Retry-After']
            }

            # Only retry on transient errors
            if ($statusCode -in @(429, 503, 504) -and $attempt -lt $MaxRetries) {
                # Use Retry-After if provided, otherwise exponential backoff
                if ($retryAfter) {
                    $waitSeconds = [int]$retryAfter
                }
                else {
                    $waitSeconds = $delay
                    $delay = [Math]::Min($delay * 2, 60)  # Cap at 60 seconds
                }

                Write-Warning "Graph API returned $statusCode. Retry $attempt/$MaxRetries after $waitSeconds seconds..."
                Start-Sleep -Seconds $waitSeconds
                continue
            }

            # Non-retriable error or max retries exceeded
            throw
        }
    }

    throw "Max retries ($MaxRetries) exceeded for $Method $Uri"
}
# ---------------------------
# Entra Actions
# ---------------------------

function Disable-EntraDevice {
    param(
        [Parameter(Mandatory)][string]$DeviceObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId"
    Invoke-GraphWithRetry -Method PATCH -Uri $uri -AccessToken $AccessToken -Body @{ accountEnabled = $false } | Out-Null
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
        Invoke-GraphWithRetry -Method PATCH -Uri $patchUri -AccessToken $AccessToken -Body $Properties | Out-Null
        return "patched"
    }
    catch {
        if ($_ -match 'HTTP 404') {
            $postUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions/$ExtensionName"
            $body = @{
                "@odata.type" = "microsoft.graph.openTypeExtension"
                extensionName = $ExtensionName
            } + $Properties

            Invoke-GraphWithRetry -Method POST -Uri $postUri -AccessToken $AccessToken -Body $body | Out-Null
            return "created"
        }
        throw
    }
}

# ---------------------------
# Intune Actions
# ---------------------------

function Invoke-IntuneRetire {
    param(
        [Parameter(Mandatory)][string]$ManagedDeviceId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/managedDevices/$ManagedDeviceId/retire"
    Invoke-GraphWithRetry -Method POST -Uri $uri -AccessToken $AccessToken | Out-Null
}

function Invoke-IntuneWipe {
    param(
        [Parameter(Mandatory)][string]$ManagedDeviceId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/managedDevices/$ManagedDeviceId/wipe"
    # Optional body parameters exist; we keep it empty for safety.
    Invoke-GraphWithRetry -Method POST -Uri $uri -AccessToken $AccessToken | Out-Null
}

function Remove-IntuneManagedDevice {
    param(
        [Parameter(Mandatory)][string]$ManagedDeviceId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/managedDevices/$ManagedDeviceId"
    Invoke-GraphWithRetry -Method DELETE -Uri $uri -AccessToken $AccessToken | Out-Null
}

# ---------------------------
# Tag Properties Helper
# ---------------------------

function Get-TagProperties {
    param(
        [Parameter(Mandatory)] $ActionItem,
        [Parameter(Mandatory)] [string] $Version,
        [Parameter(Mandatory)] [string] $NowUtcStr,
        [Parameter(Mandatory)] [int] $StaleDays,
        [Parameter(Mandatory)] [string] $CutoffUtcStr,
        [Parameter(Mandatory)] [bool] $IncludeIntune,
        [Parameter(Mandatory)] [string] $ActivitySource,
        [Parameter(Mandatory)] [bool] $UseDecisionEngine,
        [Parameter(Mandatory)] [int] $IntuneStaleDays,
        [Parameter(Mandatory)] [string] $IntuneCutoffUtcStr
    )

    $props = @{
        status             = "stale"
        classification     = $ActionItem.classification
        version            = $Version
        evaluatedAtUtc     = $NowUtcStr
        staleDaysThreshold = $StaleDays
        cutoffUtc          = $CutoffUtcStr
        includeIntune      = $IncludeIntune
        activitySource     = $ActivitySource
    }

    if ($UseDecisionEngine) {
        $props['decisionEngine'] = $true
        $props['decisionPlannedAction'] = $ActionItem.plannedAction
        $props['decisionReason'] = $ActionItem.decisionReason
        $props['intuneStaleDays'] = $IntuneStaleDays
        $props['intuneCutoffUtc'] = $IntuneCutoffUtcStr
        $props['intuneMatchStatus'] = $ActionItem.intuneMatchStatus
        $props['intuneManagedDeviceId'] = $ActionItem.intuneManagedDeviceId
    }

    return $props
}

# ---------------------------
# Action Execution Helpers
# ---------------------------

function Invoke-ActionWithErrorHandling {
    param(
        [Parameter(Mandatory)] [string] $ActionType,
        [Parameter(Mandatory)] $ActionItem,
        [Parameter(Mandatory)] [scriptblock] $ActionBlock,
        [string] $IntuneManagedDeviceId = $null
    )

    try {
        & $ActionBlock
        $result = [pscustomobject]@{
            deviceObjectId = $ActionItem.deviceObjectId
            action         = $ActionType
            status         = 'ok'
        }
        if ($ActionItem.decisionReason) { $result | Add-Member -NotePropertyName reason -NotePropertyValue $ActionItem.decisionReason }
        if ($IntuneManagedDeviceId) { $result | Add-Member -NotePropertyName intuneManagedDeviceId -NotePropertyValue $IntuneManagedDeviceId }
        return $result
    }
    catch {
        $result = [pscustomobject]@{
            deviceObjectId = $ActionItem.deviceObjectId
            action         = $ActionType
            status         = 'error'
            message        = $_.Exception.Message
        }
        if ($ActionItem.decisionReason) { $result | Add-Member -NotePropertyName reason -NotePropertyValue $ActionItem.decisionReason }
        if ($IntuneManagedDeviceId) { $result | Add-Member -NotePropertyName intuneManagedDeviceId -NotePropertyValue $IntuneManagedDeviceId }
        return $result
    }
}

# ---------------------------
# Summary Helper
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
        [Parameter(Mandatory)] [int]    $IntuneStaleDaysThreshold,
        [Parameter(Mandatory)] [string] $IntuneCutoffUtc,
        [Parameter(Mandatory)] $Counts,         # array of {classification,count}
        [Parameter(Mandatory)] $ActionSummary,
        [Parameter(Mandatory)] $ActionPlan,
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
        $ActionPlan | Select-Object -First 25 displayName, classification, daysSince, plannedAction, decisionReason
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("Entra Stale Device Sweep — $Version")
    $lines.Add("Generated (UTC): $GeneratedAtUtc")
    $lines.Add("Mode: $Mode")
    $lines.Add("Entra threshold: $StaleDaysThreshold days   Cutoff (UTC): $CutoffUtc")
    if ($IncludeIntune) {
        $lines.Add("Intune threshold: $IntuneStaleDaysThreshold days   Cutoff (UTC): $IntuneCutoffUtc")
    }
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
    $lines.Add("")

    $lines.Add("Planned Action Preview (first $([Math]::Min(25, $plannedCount)))")
    if ($preview.Count -eq 0) {
        $lines.Add("  (none)")
    }
    else {
        $lines.Add("  DisplayName | Class | DaysSince | Action | Reason")
        $lines.Add("  ---------- | ----- | -------- | ------ | ------")
        foreach ($p in $preview) {
            $dn = ($p.displayName ?? "").ToString().Trim()
            if ($dn.Length -gt 45) { $dn = $dn.Substring(0, 42) + "..." }
            $reason = ($p.decisionReason ?? "").ToString()
            if ($reason.Length -gt 70) { $reason = $reason.Substring(0, 67) + "..." }
            $lines.Add(("  {0} | {1} | {2} | {3} | {4}" -f $dn, $p.classification, $p.daysSince, $p.plannedAction, $reason))
        }
    }

    $lines.Add("")
    $lines.Add("Notes")
    $lines.Add("  - 'Unknown' devices are never acted on.")
    $lines.Add("  - 'Stale-NoSignIn' means no activity timestamp was available; createdDateTime was older than cutoff.")
    $lines.Add("  - In MODE=decide/execute, plannedAction may differ per-device (disable/tag/intune-retire/intune-wipe/intune-delete/none).")
    $lines.Add("")

    ($lines -join "`n")
}

# ---------------------------
# Evaluation Helpers
# ---------------------------

function ConvertTo-GraphDateUtc {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::Parse($Value)).ToUniversalTime() } catch { return $null }
}

function Get-ActivityTimestamp {
    param(
        [datetime]$LastSignInUtc = $null,
        [Nullable[datetime]]$IntuneLastSyncUtc = $null,
        [Parameter(Mandatory)][ValidateSet('signin', 'intune', 'mostrecent')][string]$ActivitySource
    )

    switch ($ActivitySource) {
        'signin' { return $LastSignInUtc }
        'intune' { return $IntuneLastSyncUtc }
        'mostrecent' {
            if ($LastSignInUtc -and $IntuneLastSyncUtc) {
                if ($LastSignInUtc -gt $IntuneLastSyncUtc) { 
                    return $LastSignInUtc 
                } 
                else { 
                    return $IntuneLastSyncUtc 
                }
            }
            if ($LastSignInUtc) { 
                return $LastSignInUtc 
            } 
            else { 
                return $IntuneLastSyncUtc 
            }
        }
    }
}

function Get-DeviceClassification {
    param(
        [Parameter(Mandatory)] [datetime] $CutoffUtc,
        [datetime] $ActivityUtc = $null,
        [datetime] $CreatedUtc = $null
    )

    if ($ActivityUtc) {
        if ($ActivityUtc -lt $CutoffUtc) { 
            return 'Stale' 
        } 
        else { 
            return 'Active' 
        }
    }

    if ($CreatedUtc -and $CreatedUtc -lt $CutoffUtc) { return 'Stale-NoSignIn' }

    'Unknown'
}

function Get-IntuneManagedDevicesIndex {
    <#
        Returns:
        - index: hashtable keyed by azureADDeviceId (lowercase) -> list of managedDevice lightweight objects
        - stats: counts for reporting
    #>
    param(
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $select = "id,deviceName,azureADDeviceId,lastSyncDateTime,enrolledDateTime,complianceState,managementAgent,operatingSystem,osVersion,userPrincipalName"
    $uri = "https://graph.microsoft.com/$GraphApiVersion/deviceManagement/managedDevices?`$select=$([uri]::EscapeDataString($select))&`$top=999"
    $all = Invoke-GraphGetAll -Uri $uri -AccessToken $AccessToken

    $index = @{}
    $noAzureAdId = 0

    foreach ($md in $all) {
        if ([string]::IsNullOrWhiteSpace($md.azureADDeviceId)) { $noAzureAdId++; continue }
        $key = ($md.azureADDeviceId.ToString()).ToLowerInvariant()

        $syncUtc = ConvertTo-GraphDateUtc -Value $md.lastSyncDateTime

        $lite = [pscustomobject]@{
            id                  = $md.id
            deviceName          = $md.deviceName
            azureADDeviceId     = $md.azureADDeviceId
            lastSyncDateTime    = $md.lastSyncDateTime
            lastSyncDateTimeUtc = $syncUtc
            enrolledDateTime    = $md.enrolledDateTime
            complianceState     = $md.complianceState
            managementAgent     = $md.managementAgent
            operatingSystem     = $md.operatingSystem
            osVersion           = $md.osVersion
            userPrincipalName   = $md.userPrincipalName
        }

        if (-not $index.ContainsKey($key)) {
            $index[$key] = New-Object System.Collections.Generic.List[object]
        }
        $index[$key].Add($lite)
    }

    $stats = [pscustomobject]@{
        fetchedCount           = $all.Count
        missingAzureAdDeviceId = $noAzureAdId
        joinableKeys           = $index.Count
    }

    Write-Host "Intune managedDevices fetched: $($stats.fetchedCount); missing azureADDeviceId: $($stats.missingAzureAdDeviceId); joinable keys: $($stats.joinableKeys)"
    return [pscustomobject]@{ index = $index; stats = $stats }
}

function Select-IntunePrimary {
    param(
        [Parameter(Mandatory)] $MatchList  # list
    )
    # Choose newest lastSyncDateTimeUtc; if all null, choose first
    $best = $null
    foreach ($m in $MatchList) {
        if (-not $best) { $best = $m; continue }
        $a = $m.lastSyncDateTimeUtc
        $b = $best.lastSyncDateTimeUtc
        if ($a -and (-not $b -or $a -gt $b)) { $best = $m }
    }
    $best
}

function Get-IntuneCorrelationStatus {
    param(
        $MatchList
    )
    if (-not $MatchList) { return 'NoMatch' }
    if ($MatchList.Count -eq 1) { return 'Exact-Unique' }
    'Exact-Duplicate'
}

function Get-ExceptionGroupMembers {
    <#
        Fetches device members from an Entra ID group for exception list.
        Returns HashSet of device object IDs.
    #>
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )
    
    try {
        # Fetch group members that are devices
        $uri = "https://graph.microsoft.com/$GraphApiVersion/groups/$GroupId/members/microsoft.graph.device?`$select=id"
        $members = Invoke-GraphGetAll -Uri $uri -AccessToken $AccessToken
        
        $deviceIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $members) {
            if ($m.id) { $deviceIds.Add($m.id) | Out-Null }
        }
        
        Write-Host "Exception group members: $($deviceIds.Count) devices"
        return $deviceIds
    }
    catch {
        Write-Warning "Failed to fetch exception group members: $($_.Exception.Message)"
        return [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
}

function Test-DeviceException {
    <#
        Checks if a device matches any exception criteria (group, pattern, or explicit ID).
        Returns: [pscustomobject]@{ isException=$true/$false; reason="..." }
    #>
    param(
        [Parameter(Mandatory)][string]$DeviceId,
        [Parameter(Mandatory)][string]$DisplayName,
        [System.Collections.Generic.HashSet[string]]$GroupMemberIds = [System.Collections.Generic.HashSet[string]]::new(),
        [string[]]$NamePatterns = @(),
        [System.Collections.Generic.HashSet[string]]$ExplicitDeviceIds = [System.Collections.Generic.HashSet[string]]::new()
    )
    
    # Check explicit device ID list first (fastest)
    if ($ExplicitDeviceIds.Count -gt 0 -and $ExplicitDeviceIds.Contains($DeviceId)) {
        return [pscustomobject]@{ isException = $true; reason = 'Explicit exception list' }
    }
    
    # Check group membership
    if ($GroupMemberIds.Count -gt 0 -and $GroupMemberIds.Contains($DeviceId)) {
        return [pscustomobject]@{ isException = $true; reason = 'Exception group member' }
    }
    
    # Check name patterns
    if ($NamePatterns.Count -gt 0) {
        foreach ($pattern in $NamePatterns) {
            if ($DisplayName -like $pattern) {
                return [pscustomobject]@{ isException = $true; reason = "Name matches pattern '$pattern'" }
            }
        }
    }
    
    return [pscustomobject]@{ isException = $false; reason = $null }
}

function Get-Decision {
    <#
        Produces an Intune-aware decision (for MODE=decide/execute).
        Returns object: { plannedAction, reason, signals }

        plannedAction values: none | disable | tag | intune-retire | intune-wipe | intune-delete
    #>
    param(
        [Parameter(Mandatory)] $EntraItem,          # result object (has classification, accountEnabled, etc.)
        [Parameter(Mandatory)] [datetime] $NowUtc,
        [Parameter(Mandatory)] [datetime] $EntraCutoffUtc,
        [Parameter(Mandatory)] [datetime] $IntuneCutoffUtc,
        [Parameter(Mandatory)] [bool] $IncludeIntune,
        $IntunePrimary = $null,
        [Parameter(Mandatory)] [string] $IntuneMatchStatus,
        [Parameter(Mandatory)] [bool] $RequireBothStaleForDisable,
        [Parameter(Mandatory)] [bool] $DontDisableIfRecentSync,
        [Parameter(Mandatory)] [int]  $RecentSyncDays,
        [Parameter(Mandatory)] [bool] $DontDisableIfCompliant,
        [Parameter(Mandatory)] [string[]] $OnlyDisableAgents,
        [Parameter(Mandatory)] [bool] $AllowDisableOnDuplicate
    )

    # Exception check (highest priority - never action exception devices)
    if ($EntraItem.isException) {
        return & $buildResult 'none' $EntraItem.exceptionReason
    }

    # Pre-calculate Entra signals once
    $isEntraCandidate = ($EntraItem.classification -in @('Stale', 'Stale-NoSignIn'))
    $isAlreadyDisabled = ($EntraItem.accountEnabled -eq $false)

    # Pre-calculate Intune properties once (avoid repeated null checks and property access)
    $intuneLastSyncUtc = if ($IncludeIntune -and $IntunePrimary) { $IntunePrimary.lastSyncDateTimeUtc } else { $null }
    $intuneCompliance = if ($IncludeIntune -and $IntunePrimary) { $IntunePrimary.complianceState } else { $null }
    $intuneAgent = if ($IncludeIntune -and $IntunePrimary) { $IntunePrimary.managementAgent } else { $null }
    $intuneManagedId = if ($IncludeIntune -and $IntunePrimary) { $IntunePrimary.id } else { $null }

    # Compute derived Intune signals
    $isIntuneStale = if ($intuneLastSyncUtc) { $intuneLastSyncUtc -lt $IntuneCutoffUtc } else { $null }
    $isIntuneRecentSync = if ($intuneLastSyncUtc) { ($NowUtc - $intuneLastSyncUtc).TotalDays -lt $RecentSyncDays } else { $false }
    $isCompliant = if ($intuneCompliance) { $intuneCompliance.ToString().ToLowerInvariant() -eq 'compliant' } else { $false }
    
    # Agent eligibility check (optimized)
    $agentOk = if ($OnlyDisableAgents.Count -eq 0) { 
        $true 
    }
    elseif ($intuneAgent) { 
        $OnlyDisableAgents -contains $intuneAgent.ToString().ToLowerInvariant() 
    }
    else { 
        $false 
    }

    # Helper to build result object (reduces duplication)
    $buildResult = {
        param($action, $reason, $includeManagedId = $false)
        $result = [pscustomobject]@{
            plannedAction = $action
            reason        = $reason
            signals       = [pscustomobject]@{
                isEntraCandidate   = $isEntraCandidate
                isAlreadyDisabled  = $isAlreadyDisabled
                intuneMatchStatus  = $IntuneMatchStatus
                isIntuneStale      = $isIntuneStale
                isIntuneRecentSync = $isIntuneRecentSync
                isCompliant        = $isCompliant
                agentOk            = $agentOk
            }
        }
        if ($includeManagedId -and $intuneManagedId) {
            $result.signals | Add-Member -NotePropertyName intuneManagedDeviceId -NotePropertyValue $intuneManagedId
        }
        return $result
    }

    # Early exit: not a candidate
    if (-not $isEntraCandidate) {
        return & $buildResult 'none' 'Not a candidate'
    }

    # If already disabled, prefer tag (audit trail)
    if ($isAlreadyDisabled) {
        return & $buildResult 'tag' 'Entra candidate but already disabled; tag for audit'
    }

    # Duplicate Intune matches => conservative: tag only unless explicitly allowed
    if ($IncludeIntune -and $IntuneMatchStatus -eq 'Exact-Duplicate' -and -not $AllowDisableOnDuplicate) {
        return & $buildResult 'tag' 'Duplicate Intune matches; tag only (no destructive actions)'
    }

    # Intune-aware protections
    if ($IncludeIntune) {
        if ($DontDisableIfRecentSync -and $isIntuneRecentSync) {
            return & $buildResult 'tag' "Intune recently synced (<$RecentSyncDays days); tag only"
        }

        if ($DontDisableIfCompliant -and $isCompliant) {
            return & $buildResult 'tag' 'Intune compliant; tag only'
        }

        if (-not $agentOk) {
            return & $buildResult 'tag' 'Management agent not eligible for disable; tag only'
        }

        if ($RequireBothStaleForDisable) {
            # If Intune match exists, require Intune stale. If no Intune match, allow disable on Entra stale.
            if ($IntuneMatchStatus -eq 'Exact-Unique' -and $IntunePrimary) {
                if ($isIntuneStale -eq $true) {
                    return & $buildResult 'disable' 'Entra stale and Intune stale' $true
                }
                else {
                    return & $buildResult 'tag' 'Entra stale but Intune not stale/unknown; tag only'
                }
            }
            else {
                return & $buildResult 'disable' 'Entra stale; no unique Intune match (or Intune disabled)' $true
            }
        }
        else {
            return & $buildResult 'disable' 'Entra stale (policy does not require Intune stale)' $true
        }
    }

    # No Intune: default to disable for candidates
    & $buildResult 'disable' 'Entra stale (no Intune signals)'
}

# ---------------------------
# Main
# ---------------------------

try {
    $token = Get-GraphAccessToken

    # Fetch Entra devices
    $select = "id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,createdDateTime,approximateLastSignInDateTime"
    $uri = "https://graph.microsoft.com/$graphApiVersion/devices?`$select=$([uri]::EscapeDataString($select))&`$top=999"
    $devices = Invoke-GraphGetAll -Uri $uri -AccessToken $token
    Write-Host "Entra devices fetched: $($devices.Count)"

    # Optional Intune index (duplicates preserved)
    $intuneIndex = $null
    $intuneStats = $null
    # Fetch exception group members if configured
    $exceptionGroupMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrWhiteSpace($exceptionGroupId)) {
        $exceptionGroupMembers = Get-ExceptionGroupMembers -GroupId $exceptionGroupId -AccessToken $token -GraphApiVersion $graphApiVersion
    }

    # Log exception configuration
    $totalExceptionSources = 0
    if ($exceptionGroupMembers.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: Group ($($exceptionGroupMembers.Count) devices)" }
    if ($exceptionNamePatterns.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: Name patterns ($($exceptionNamePatterns -join ', '))" }
    if ($exceptionDeviceIds.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: Explicit IDs ($($exceptionDeviceIds.Count) devices)" }
    if ($totalExceptionSources -eq 0) { Write-Host "Exception sources: None configured" }
    if ($includeIntune) {
        $idxObj = Get-IntuneManagedDevicesIndex -AccessToken $token -GraphApiVersion $graphApiVersion
        $intuneIndex = $idxObj.index
        $intuneStats = $idxObj.stats
    }

    # Evaluate devices
    $results = [System.Collections.Generic.List[object]]::new($devices.Count)

    foreach ($d in $devices) {
        $lastSignInUtc = ConvertTo-GraphDateUtc -Value $d.approximateLastSignInDateTime
        $createdUtc = ConvertTo-GraphDateUtc -Value $d.createdDateTime

        # Intune correlation
        $intuneMatches = $null
        $intunePrimary = $null
        $intuneMatchStatus = 'NoMatch'
        $intuneLastSyncUtc = $null

        if ($includeIntune -and $intuneIndex -and $d.deviceId) {
            $k = ($d.deviceId.ToString()).ToLowerInvariant()
            $intuneMatches = $intuneIndex[$k]
            $intuneMatchStatus = Get-IntuneCorrelationStatus -MatchList $intuneMatches
            if ($intuneMatches) {
                $intunePrimary = Select-IntunePrimary -MatchList $intuneMatches
                $intuneLastSyncUtc = $intunePrimary.lastSyncDateTimeUtc
            }
        }

        # Activity + classification (reporting)
        $activityUtc = Get-ActivityTimestamp -LastSignInUtc $lastSignInUtc -IntuneLastSyncUtc $intuneLastSyncUtc -ActivitySource $activitySource
        $classification = Get-DeviceClassification -CutoffUtc $cutoffUtc -ActivityUtc $activityUtc -CreatedUtc $createdUtc

        $daysSinceLastActivity = if ($activityUtc) {
            [int]($nowUtc - $activityUtc).TotalDays
        }
        elseif ($createdUtc) {
            [int]($nowUtc - $createdUtc).TotalDays
        }
        else { $null }

        # Check exception lists
        $exceptionCheck = Test-DeviceException `
            -DeviceId $d.id `
            -DisplayName ($d.displayName ?? '') `
            -GroupMemberIds $exceptionGroupMembers `
            -NamePatterns $exceptionNamePatterns `
            -ExplicitDeviceIds $exceptionDeviceIds

        # Build base result object
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

            # Evaluation (legacy)
            includeIntune                 = $includeIntune
            activitySourceUsed            = $activitySource
            activityTimestampUtc          = if ($activityUtc) { $activityUtc.ToString('o') } else { $null }
            classification                = $classification
            daysSinceLastActivity         = $daysSinceLastActivity
            staleThresholdDateUtc         = $cutoffUtcStr
            staleDaysThreshold            = $staleDays

            # Intune correlation
            intuneMatchStatus             = $intuneMatchStatus
            intuneMatchesCount            = if ($intuneMatches) { [int]$intuneMatches.Count } else { 0 }
            
            # Exception tracking (always included - used by decision logic)
            isException                   = $exceptionCheck.isException
            exceptionReason               = $exceptionCheck.reason
        }

        if ($includeIntune) {
            $resultObj | Add-Member -NotePropertyName intuneManagedDeviceId -NotePropertyValue ($intunePrimary?.id) -Force
            $resultObj | Add-Member -NotePropertyName intuneDeviceName -NotePropertyValue ($intunePrimary?.deviceName) -Force
            $resultObj | Add-Member -NotePropertyName intuneLastSyncDateTime -NotePropertyValue ($intuneLastSyncUtc?.ToString('o')) -Force
            $resultObj | Add-Member -NotePropertyName intuneEnrolledDateTime -NotePropertyValue ($intunePrimary?.enrolledDateTime) -Force
            $resultObj | Add-Member -NotePropertyName intuneComplianceState -NotePropertyValue ($intunePrimary?.complianceState) -Force
            $resultObj | Add-Member -NotePropertyName intuneManagementAgent -NotePropertyValue ($intunePrimary?.managementAgent) -Force
            $resultObj | Add-Member -NotePropertyName intuneUserPrincipalName -NotePropertyValue ($intunePrimary?.userPrincipalName) -Force
            $resultObj | Add-Member -NotePropertyName intuneOs -NotePropertyValue ($intunePrimary?.operatingSystem) -Force
            $resultObj | Add-Member -NotePropertyName intuneOsVersion -NotePropertyValue ($intunePrimary?.osVersion) -Force
        }

        # Decision (only meaningful for decide/execute; but we compute always for visibility)
        $decisionObj = Get-Decision `
            -EntraItem $resultObj `
            -NowUtc $nowUtc `
            -EntraCutoffUtc $cutoffUtc `
            -IntuneCutoffUtc $intuneCutoffUtc `
            -IncludeIntune $includeIntune `
            -IntunePrimary $intunePrimary `
            -IntuneMatchStatus $intuneMatchStatus `
            -RequireBothStaleForDisable $requireBothStaleForDisable `
            -DontDisableIfRecentSync $dontDisableIfIntuneRecentSync `
            -RecentSyncDays $intuneRecentSyncDays `
            -DontDisableIfCompliant $dontDisableIfCompliant `
            -OnlyDisableAgents $onlyDisableAgents `
            -AllowDisableOnDuplicate $allowDisableOnDuplicate

        $resultObj | Add-Member -NotePropertyName decisionPlannedAction -NotePropertyValue $decisionObj.plannedAction -Force
        $resultObj | Add-Member -NotePropertyName decisionReason -NotePropertyValue $decisionObj.reason -Force
        $resultObj | Add-Member -NotePropertyName decisionSignals -NotePropertyValue $decisionObj.signals -Force

        $results.Add($resultObj)
    }

    # Classification summary
    $counts = @($results | Group-Object classification | ForEach-Object {
            [pscustomobject]@{ classification = $_.Name; count = $_.Count }
        })

    # Report base
    $report = [pscustomobject]@{
        version            = "v2.0-intune-decisioning"
        generatedAtUtc     = $nowUtcStr
        staleDaysThreshold = $staleDays
        intuneStaleDays    = $intuneStaleDays
        totalDevices       = $devices.Count
        includeIntune      = $includeIntune
        activitySource     = $activitySource
        summary            = $counts
        intuneStats        = $intuneStats
        items              = $results
    }

    # ---------------------------
    # Build Action Plan
    # ---------------------------

    $actionsExecuted = [System.Collections.Generic.List[object]]::new()
    $actionPlan = [System.Collections.Generic.List[object]]::new()

    $useDecisionEngine = ($mode -in @('decide', 'execute'))

    if (-not $useDecisionEngine) {
        # Legacy candidate selection (classification-based)
        $candidates = @($results | Where-Object { $_.classification -in @('Stale', 'Stale-NoSignIn') })
        $plannedCount = [Math]::Min($candidates.Count, $maxActions)

        for ($i = 0; $i -lt $plannedCount; $i++) {
            $c = $candidates[$i]
            $actionPlan.Add([pscustomobject]@{
                    deviceObjectId        = $c.id
                    displayName           = $c.displayName
                    classification        = $c.classification
                    daysSince             = $c.daysSinceLastActivity
                    plannedAction         = $mode
                    decisionReason        = $null
                    intuneManagedDeviceId = if ($includeIntune) { $c.intuneManagedDeviceId } else { $null }
                })
        }

        $candidateCount = $candidates.Count
    }
    else {
        # Decision engine plan (per-device)
        $candidates = @($results | Where-Object { $_.decisionPlannedAction -and $_.decisionPlannedAction -ne 'none' })

        # Apply overall MAX_ACTIONS after sorting by staleness (oldest first)
        $candidates = $candidates | Sort-Object -Property daysSinceLastActivity -Descending

        $plannedCount = [Math]::Min($candidates.Count, $maxActions)
        for ($i = 0; $i -lt $plannedCount; $i++) {
            $c = $candidates[$i]
            $actionPlan.Add([pscustomobject]@{
                    deviceObjectId        = $c.id
                    displayName           = $c.displayName
                    classification        = $c.classification
                    daysSince             = $c.daysSinceLastActivity
                    plannedAction         = $c.decisionPlannedAction
                    decisionReason        = $c.decisionReason
                    intuneMatchStatus     = $c.intuneMatchStatus
                    intuneManagedDeviceId = if ($includeIntune) { $c.intuneManagedDeviceId } else { $null }
                })
        }

        $candidateCount = $candidates.Count
    }

    # Action summary
    $actionSummary = [pscustomobject]@{
        modeRequested       = $mode
        decisionEngine      = $useDecisionEngine
        candidateCount      = $candidateCount
        plannedActionCount  = $actionPlan.Count
        maxActions          = $maxActions
        willExecute         = $false

        # Confirms
        confirmDisable      = $confirmDisable
        confirmTag          = $confirmTag
        confirmIntuneRetire = $confirmIntuneRetire
        confirmIntuneWipe   = $confirmIntuneWipe
        confirmIntuneDelete = $confirmIntuneDelete

        # Per-action caps
        maxDisable          = $maxDisable
        maxTag              = $maxTag
        maxRetire           = $maxRetire
        maxWipe             = $maxWipe
        maxIntuneDelete     = $maxIntuneDelete

        extensionName       = $extensionName
        includeIntune       = $includeIntune
        activitySource      = $activitySource

        # Decision rule snapshot
        decisionRules       = [pscustomobject]@{
            intuneStaleDays                = $intuneStaleDays
            requireBothStaleForDisable     = $requireBothStaleForDisable
            dontDisableIfRecentSync        = $dontDisableIfIntuneRecentSync
            intuneRecentSyncDays           = $intuneRecentSyncDays
            dontDisableIfCompliant         = $dontDisableIfCompliant
            onlyDisableIfManagementAgentIn = ($onlyDisableAgents -join ',')
            allowDisableOnDuplicate        = $allowDisableOnDuplicate
        }
    }

    # ---------------------------
    # Execute
    # ---------------------------

    switch ($mode) {
        'detect' {
            # legacy preview
        }

        'disable' {
            if (-not $confirmDisable) {
                Write-Warning "MODE=disable requested but CONFIRM_DISABLE=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true
            $count = 0
            foreach ($a in $actionPlan) {
                if ($count -ge $maxDisable) { break }
                try {
                    Disable-EntraDevice -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion
                    $actionsExecuted.Add([pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'disable'; status = 'ok' })
                }
                catch {
                    $actionsExecuted.Add([pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'disable'; status = 'error'; message = $_.Exception.Message })
                }
                $count++
            }
        }

        'tag' {
            if (-not $confirmTag) {
                Write-Warning "MODE=tag requested but CONFIRM_TAG=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true
            $count = 0
            foreach ($a in $actionPlan) {
                if ($count -ge $maxTag) { break }

                $props = Get-TagProperties `
                    -ActionItem $a `
                    -Version $report.version `
                    -NowUtcStr $nowUtcStr `
                    -StaleDays $staleDays `
                    -CutoffUtcStr $cutoffUtcStr `
                    -IncludeIntune $includeIntune `
                    -ActivitySource $activitySource `
                    -UseDecisionEngine $useDecisionEngine `
                    -IntuneStaleDays $intuneStaleDays `
                    -IntuneCutoffUtcStr $intuneCutoffUtcStr

                $result = Invoke-ActionWithErrorHandling -ActionType 'tag' -ActionItem $a -ActionBlock {
                    $tagResult = Update-DeviceOpenExtension `
                        -DeviceObjectId $a.deviceObjectId `
                        -AccessToken $token `
                        -GraphApiVersion $graphApiVersion `
                        -ExtensionName $extensionName `
                        -Properties $props
                    $result.status = $tagResult
                }

                $actionsExecuted.Add($result)
                $count++
            }
        }

        'decide' {
            # decision preview only
        }

        'execute' {
            $actionSummary.willExecute = $true

            # Group actions by type for parallel processing
            $actionsByType = $actionPlan | Group-Object plannedAction

            foreach ($group in $actionsByType) {
                $act = ($group.Name ?? 'none').ToLowerInvariant()
                $items = $group.Group

                switch ($act) {
                    'disable' {
                        if (-not $confirmDisable) { continue }
                        $toProcess = $items | Select-Object -First $maxDisable
                
                        $results = $toProcess | ForEach-Object -Parallel {
                            $a = $_
                            $token = $using:token
                            $graphApiVersion = $using:graphApiVersion
                    
                            # Copy functions into parallel scope (needed for -Parallel)
                            $invokeGraph = ${using:function:Invoke-GraphWithRetry}
                    
                            try {
                                $uri = "https://graph.microsoft.com/$graphApiVersion/devices/$($a.deviceObjectId)"
                                & $invokeGraph -Method PATCH -Uri $uri -AccessToken $token -Body @{ accountEnabled = $false }
                                [pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'disable'; status = 'ok'; reason = $a.decisionReason }
                            }
                            catch {
                                [pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'disable'; status = 'error'; message = $_.Exception.Message }
                            }
                        } -ThrottleLimit $actionParallelism
                
                        $results | ForEach-Object { $actionsExecuted.Add($_) }
                    }

                    'tag' {
                        if (-not $confirmTag) { continue }
                        $toProcess = $items | Select-Object -First $maxTag
                
                        $results = $toProcess | ForEach-Object -Parallel {
                            $a = $_
                            $token = $using:token
                            $graphApiVersion = $using:graphApiVersion
                            $extensionName = $using:extensionName
                            $report = $using:report
                            $nowUtcStr = $using:nowUtcStr
                            $staleDays = $using:staleDays
                            $cutoffUtcStr = $using:cutoffUtcStr
                            $includeIntune = $using:includeIntune
                            $activitySource = $using:activitySource
                            $intuneStaleDays = $using:intuneStaleDays
                            $intuneCutoffUtcStr = $using:intuneCutoffUtcStr
                    
                            # Build tag properties inline (simpler than copying function)
                            $props = @{
                                status                = "stale"
                                classification        = $a.classification
                                version               = $report.version
                                evaluatedAtUtc        = $nowUtcStr
                                staleDaysThreshold    = $staleDays
                                cutoffUtc             = $cutoffUtcStr
                                includeIntune         = $includeIntune
                                activitySource        = $activitySource
                                decisionEngine        = $true
                                decisionPlannedAction = $a.plannedAction
                                decisionReason        = $a.decisionReason
                                intuneStaleDays       = $intuneStaleDays
                                intuneCutoffUtc       = $intuneCutoffUtcStr
                                intuneMatchStatus     = $a.intuneMatchStatus
                                intuneManagedDeviceId = $a.intuneManagedDeviceId
                            }
                    
                            $invokeGraph = ${using:function:Invoke-GraphWithRetry}
                    
                            try {
                                $patchUri = "https://graph.microsoft.com/$graphApiVersion/devices/$($a.deviceObjectId)/extensions/$extensionName"
                                try {
                                    & $invokeGraph -Method PATCH -Uri $patchUri -AccessToken $token -Body $props
                                    $status = 'patched'
                                }
                                catch {
                                    if ($_ -match 'HTTP 404') {
                                        $postUri = "https://graph.microsoft.com/$graphApiVersion/devices/$($a.deviceObjectId)/extensions"
                                        $body = @{ "@odata.type" = "microsoft.graph.openTypeExtension"; extensionName = $extensionName } + $props
                                        & $invokeGraph -Method POST -Uri $postUri -AccessToken $token -Body $body
                                        $status = 'created'
                                    }
                                    else { throw }
                                }
                                [pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'tag'; status = $status; reason = $a.decisionReason }
                            }
                            catch {
                                [pscustomobject]@{ deviceObjectId = $a.deviceObjectId; action = 'tag'; status = 'error'; message = $_.Exception.Message }
                            }
                        } -ThrottleLimit $actionParallelism
                
                        $results | ForEach-Object { $actionsExecuted.Add($_) }
                    }

                    'intune-retire' {
                        if (-not $confirmIntuneRetire) { continue }
                        $toProcess = $items | Select-Object -First $maxRetire
                
                        $results = $toProcess | ForEach-Object -Parallel {
                            $a = $_
                            $token = $using:token
                            $graphApiVersion = $using:graphApiVersion
                            $invokeGraph = ${using:function:Invoke-GraphWithRetry}
                    
                            try {
                                if (-not $a.intuneManagedDeviceId) {
                                    throw "No Intune managed device ID available"
                                }
                                $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/managedDevices/$($a.intuneManagedDeviceId)/retire"
                                & $invokeGraph -Method POST -Uri $uri -AccessToken $token
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-retire'; 
                                    status                = 'ok'; 
                                    reason                = $a.decisionReason;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                            catch {
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-retire'; 
                                    status                = 'error'; 
                                    message               = $_.Exception.Message;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                        } -ThrottleLimit $actionParallelism
                
                        $results | ForEach-Object { $actionsExecuted.Add($_) }
                    }

                    'intune-wipe' {
                        if (-not $confirmIntuneWipe) { continue }
                        $toProcess = $items | Select-Object -First $maxWipe
                
                        $results = $toProcess | ForEach-Object -Parallel {
                            $a = $_
                            $token = $using:token
                            $graphApiVersion = $using:graphApiVersion
                            $invokeGraph = ${using:function:Invoke-GraphWithRetry}
                    
                            try {
                                if (-not $a.intuneManagedDeviceId) {
                                    throw "No Intune managed device ID available"
                                }
                                $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/managedDevices/$($a.intuneManagedDeviceId)/wipe"
                                & $invokeGraph -Method POST -Uri $uri -AccessToken $token
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-wipe'; 
                                    status                = 'ok'; 
                                    reason                = $a.decisionReason;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                            catch {
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-wipe'; 
                                    status                = 'error'; 
                                    message               = $_.Exception.Message;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                        } -ThrottleLimit $actionParallelism
                
                        $results | ForEach-Object { $actionsExecuted.Add($_) }
                    }

                    'intune-delete' {
                        if (-not $confirmIntuneDelete) { continue }
                        $toProcess = $items | Select-Object -First $maxIntuneDelete
                
                        $results = $toProcess | ForEach-Object -Parallel {
                            $a = $_
                            $token = $using:token
                            $graphApiVersion = $using:graphApiVersion
                            $invokeGraph = ${using:function:Invoke-GraphWithRetry}
                    
                            try {
                                if (-not $a.intuneManagedDeviceId) {
                                    throw "No Intune managed device ID available"
                                }
                                $uri = "https://graph.microsoft.com/$graphApiVersion/deviceManagement/managedDevices/$($a.intuneManagedDeviceId)"
                                & $invokeGraph -Method DELETE -Uri $uri -AccessToken $token
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-delete'; 
                                    status                = 'ok'; 
                                    reason                = $a.decisionReason;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                            catch {
                                [pscustomobject]@{ 
                                    deviceObjectId        = $a.deviceObjectId; 
                                    action                = 'intune-delete'; 
                                    status                = 'error'; 
                                    message               = $_.Exception.Message;
                                    intuneManagedDeviceId = $a.intuneManagedDeviceId
                                }
                            }
                        } -ThrottleLimit $actionParallelism
                
                        $results | ForEach-Object { $actionsExecuted.Add($_) }
                    }

                    'none' {
                        # No action needed
                    }

                    default {
                        Write-Warning "Unknown planned action '$act' for device group. Skipping."
                    }
                }
            }
        }

        default {
            Write-Warning "Unknown MODE='$mode'. Valid modes: detect, disable, tag, decide, execute. No actions executed."
        }
    }

    # Attach action metadata
    $report | Add-Member -NotePropertyName mode -NotePropertyValue $mode -Force
    $report | Add-Member -NotePropertyName actionSummary -NotePropertyValue $actionSummary -Force
    $report | Add-Member -NotePropertyName actionPlan -NotePropertyValue $actionPlan -Force
    $report | Add-Member -NotePropertyName actionsExecuted -NotePropertyValue $actionsExecuted -Force

    # Outputs - JSON report
    Write-Host "Preparing JSON report..."
    $json = $report | ConvertTo-Json -Depth 12
    if ([string]::IsNullOrWhiteSpace($json)) {
        Write-Error "JSON report is empty or null!"
        throw "Failed to generate JSON report"
    }
    $jsonBytes = [System.Text.Encoding]::UTF8.GetByteCount($json)
    Write-Host "JSON report size: $jsonBytes bytes ($($report.items.Count) items)"
    Push-OutputBinding -Name reportBlob -Value $json
    Write-Host "✓ JSON report written to reportBlob"

    # Outputs - Summary text
    Write-Host "Preparing summary text..."
    $summaryText = New-HumanSummaryText `
        -Version $report.version `
        -GeneratedAtUtc $nowUtcStr `
        -Mode $mode `
        -StaleDaysThreshold $staleDays `
        -CutoffUtc $cutoffUtcStr `
        -IncludeIntune $includeIntune `
        -ActivitySource $activitySource `
        -IntuneStaleDaysThreshold $intuneStaleDays `
        -IntuneCutoffUtc $intuneCutoffUtcStr `
        -Counts $counts `
        -ActionSummary $actionSummary `
        -ActionPlan $actionPlan `
        -ActionsExecuted $actionsExecuted `
        -TotalDevices $devices.Count
    
    if ([string]::IsNullOrWhiteSpace($summaryText)) {
        Write-Error "Summary text is empty or null!"
        throw "Failed to generate summary text"
    }
    $summaryBytes = [System.Text.Encoding]::UTF8.GetByteCount($summaryText)
    Write-Host "Summary text size: $summaryBytes bytes"
    Write-Host "=== SUMMARY TEXT START ==="
    Write-Host $summaryText
    Write-Host "=== SUMMARY TEXT END ==="
    Push-OutputBinding -Name summaryBlob -Value $summaryText
    Write-Host "✓ Summary text written to summaryBlob"

    # Outputs - Action Plan CSV (optional, only if enabled)
    if ($outputActionPlanCsv -and $actionPlan.Count -gt 0) {
        Write-Host "Preparing action plan CSV..."
        $actionPlanCsv = $actionPlan | ConvertTo-Csv -NoTypeInformation | Out-String
        if ([string]::IsNullOrWhiteSpace($actionPlanCsv)) {
            Write-Warning "Action plan CSV is empty despite having $($actionPlan.Count) planned actions"
        } else {
            $actionPlanBytes = [System.Text.Encoding]::UTF8.GetByteCount($actionPlanCsv)
            Write-Host "Action plan CSV size: $actionPlanBytes bytes ($($actionPlan.Count) actions)"
            Push-OutputBinding -Name actionPlanCsvBlob -Value $actionPlanCsv
            Write-Host "✓ Action plan CSV written to actionPlanCsvBlob"
        }
    } elseif ($outputActionPlanCsv -and $actionPlan.Count -eq 0) {
        Write-Host "Action plan CSV enabled but no actions to write (0 actions planned)"
    } else {
        Write-Host "Action plan CSV output disabled (set OUTPUT_ACTION_PLAN_CSV=true to enable)"
    }

    # Outputs - Inventory CSV (optional, only if enabled)
    if ($outputInventoryCsv) {
        Write-Host "Preparing inventory CSV..."
        $inventoryCsv = $report.items | Select-Object -Property deviceId, displayName, classification, 
            entraActivityUtc, entraStale, intuneActivityUtc, intuneStale, 
            accountEnabled, osVersion, trustType, managementType, 
            intuneCorrelation, intuneDeviceId, intuneCompliant, intuneEncrypted, 
            recommendedAction, reasoning | ConvertTo-Csv -NoTypeInformation | Out-String
        
        if ([string]::IsNullOrWhiteSpace($inventoryCsv)) {
            Write-Warning "Inventory CSV is empty despite having $($report.items.Count) items"
        } else {
            $inventoryBytes = [System.Text.Encoding]::UTF8.GetByteCount($inventoryCsv)
            Write-Host "Inventory CSV size: $inventoryBytes bytes ($($report.items.Count) devices)"
            Push-OutputBinding -Name inventoryCsvBlob -Value $inventoryCsv
            Write-Host "✓ Inventory CSV written to inventoryCsvBlob"
        }
    } else {
        Write-Host "Inventory CSV output disabled (set OUTPUT_INVENTORY_CSV=true to enable)"
    }

    Write-Host "All blob outputs completed successfully."

    # Emit structured result for workbook metrics
    $resultEvent = @{
        eventType          = "staleDeviceSweep.result"
        totalDevices       = $report.totalDevices
        candidateCount     = $report.items.Count
        activeCount        = ($counts | Where-Object { $_.classification -eq 'Active' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        staleCount         = ($counts | Where-Object { $_.classification -eq 'Stale' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        staleNoSignInCount = ($counts | Where-Object { $_.classification -eq 'Stale-NoSignIn' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        unknownCount       = ($counts | Where-Object { $_.classification -eq 'Unknown' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        plannedActions     = $actionPlan.Count
        executedActions    = $actionsExecuted.Count
        actionBreakdown    = @{
            disable = @($actionsExecuted | Where-Object { $_.action -eq 'disable' }).Count
            tag     = @($actionsExecuted | Where-Object { $_.action -eq 'tag' }).Count
            retire  = @($actionsExecuted | Where-Object { $_.action -eq 'intune-retire' }).Count
            wipe    = @($actionsExecuted | Where-Object { $_.action -eq 'intune-wipe' }).Count
            delete  = @($actionsExecuted | Where-Object { $_.action -eq 'intune-delete' }).Count
        }
    }
    Write-Host ("RESULT " + ($resultEvent | ConvertTo-Json -Compress))
    
    # Final verification summary
    Write-Host "`n=========================================="
    Write-Host "BLOB OUTPUTS VERIFICATION SUMMARY"
    Write-Host "=========================================="
    Write-Host "JSON Report:       $jsonBytes bytes"
    Write-Host "Summary Text:      $summaryBytes bytes"
    if ($outputActionPlanCsv -and $actionPlan.Count -gt 0) {
        Write-Host "Action Plan CSV:   $actionPlanBytes bytes ($($actionPlan.Count) actions)"
    } elseif ($outputActionPlanCsv) {
        Write-Host "Action Plan CSV:   Not written (no actions planned)"
    } else {
        Write-Host "Action Plan CSV:   Disabled"
    }
    if ($outputInventoryCsv) {
        Write-Host "Inventory CSV:     $inventoryBytes bytes ($($report.items.Count) devices)"
    } else {
        Write-Host "Inventory CSV:     Disabled"
    }
    Write-Host "==========================================`n"
}
catch {
    Write-Error $_
    throw
}