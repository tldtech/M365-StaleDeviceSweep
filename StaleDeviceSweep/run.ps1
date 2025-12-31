param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------
$staleDays = [int]($env:STALE_DAYS ?? 90)
$mode = ($env:MODE ?? 'report').ToLowerInvariant()
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')

# V1.1 safety rails + tagging config
$maxActions     = [int]($env:MAX_ACTIONS ?? 50)
$confirmDisable = (($env:CONFIRM_DISABLE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmTag     = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true')
$extensionName  = ($env:EXTENSION_NAME ?? 'com.staleDeviceSweep')

$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)

Write-Host "=== Entra stale device sweep (v1.1: Entra-only) ==="
Write-Host "Now (UTC):     $($nowUtc.ToString('o'))"
Write-Host "Cutoff (UTC):  $($cutoffUtc.ToString('o'))"
Write-Host "Mode:          $mode"
Write-Host "Graph:         $graphApiVersion"
Write-Host "Max actions:   $maxActions"
Write-Host "Ext name:      $extensionName"

# ---------------------------
# Auth helpers
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
    # Requires user to be logged in: az login
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
# Graph helpers
# ---------------------------

function Invoke-Graph {
    param(
        [Parameter(Mandatory)] [ValidateSet('GET','POST','PATCH')] [string] $Method,
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken,
        [object] $Body = $null
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    if ($null -ne $Body) { $headers['Content-Type'] = 'application/json' }

    try {
        if ($null -ne $Body) {
            return Invoke-RestMethod -Method $Method -Uri $Uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 8)
        } else {
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
        } else {
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

    # Try PATCH first; create via POST if not found
    $patchUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions/$ExtensionName"
    try {
        Invoke-Graph -Method PATCH -Uri $patchUri -AccessToken $AccessToken -Body $Properties | Out-Null
        return "patched"
    } catch {
        if ($_ -match 'HTTP 404') {
            $postUri = "https://graph.microsoft.com/$GraphApiVersion/devices/$DeviceObjectId/extensions"
            $body = @{
                "@odata.type"  = "microsoft.graph.openTypeExtension"
                extensionName  = $ExtensionName
            } + $Properties

            Invoke-Graph -Method POST -Uri $postUri -AccessToken $AccessToken -Body $body | Out-Null
            return "created"
        }
        throw
    }
}

# ---------------------------
# Staleness evaluation
# ---------------------------

function ConvertTo-GraphDateUtc {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::Parse($Value)).ToUniversalTime() } catch { return $null }
}

function Get-DeviceClassification {
    param(
        [Parameter(Mandatory)] $Device,
        [Parameter(Mandatory)] [datetime] $CutoffUtc
    )

    # This property is commonly used when present, but may be null in some tenants.
    $lastSignInUtc = ConvertTo-GraphDateUtc -Value $Device.approximateLastSignInDateTime
    $createdUtc    = ConvertTo-GraphDateUtc -Value $Device.createdDateTime

    if ($lastSignInUtc) {
        if ($lastSignInUtc -lt $CutoffUtc) { return 'Stale' }
        return 'Active'
    }

    if ($createdUtc -and $createdUtc -lt $CutoffUtc) {
        return 'Stale-NoSignIn'
    }

    # If we don't have lastSignIn, be conservative: treat as Unknown (report only).
    return 'Unknown'
}

# ---------------------------
# Main
# ---------------------------

try {
    $token = Get-GraphAccessToken

    # Keep select tight to reduce payload and throttling.
    # NOTE: approximateLastSignInDateTime may be null for some devices/tenants.
    $select = "id,displayName,deviceId,accountEnabled,operatingSystem,operatingSystemVersion,trustType,createdDateTime,approximateLastSignInDateTime"
    $uri = "https://graph.microsoft.com/$graphApiVersion/devices?`$select=$([uri]::EscapeDataString($select))&`$top=999"

    $devices = Invoke-GraphGetAll -Uri $uri -AccessToken $token
    Write-Host "Devices fetched: $($devices.Count)"

    $results = @(foreach ($d in $devices) {
        $classification = Get-DeviceClassification -Device $d -CutoffUtc $cutoffUtc

        $lastSignInUtc = ConvertTo-GraphDateUtc -Value $d.approximateLastSignInDateTime
        $createdUtc = ConvertTo-GraphDateUtc -Value $d.createdDateTime

        # Calculate days since last activity (sign-in or creation)
        $daysSinceLastActivity = if ($lastSignInUtc) {
            [int]($nowUtc - $lastSignInUtc).TotalDays
        } elseif ($createdUtc) {
            [int]($nowUtc - $createdUtc).TotalDays
        } else {
            $null
        }

        [pscustomobject]@{
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
            classification                = $classification
            daysSinceLastActivity         = $daysSinceLastActivity
            staleThresholdDateUtc         = $cutoffUtc.ToString('o')
            staleDaysThreshold            = $staleDays
        }
    })

    $counts = @($results | Group-Object classification | ForEach-Object {
        [pscustomobject]@{ classification = $_.Name; count = $_.Count }
    })

    # Build report object (we'll append action sections below)
    $report = [pscustomobject]@{
        version            = "v1.1-entra-only"
        generatedAtUtc     = $nowUtc.ToString('o')
        staleDaysThreshold = $staleDays
        totalDevices       = $devices.Count
        summary            = $counts
        items              = $results
    }

    # ---------------------------
    # V1.1 Action pipeline
    # ---------------------------

    # Only act on trusted stale classifications
    $candidates = @($results | Where-Object { $_.classification -in @('Stale','Stale-NoSignIn') })

    $actionPlan = @($candidates | Select-Object -First $maxActions | ForEach-Object {
        [pscustomobject]@{
            deviceObjectId = $_.id
            displayName    = $_.displayName
            classification = $_.classification
            daysSince      = $_.daysSinceLastActivity
            plannedAction  = $mode
        }
    })

    $actionSummary = [pscustomobject]@{
        modeRequested      = $mode
        candidateCount     = $candidates.Count
        plannedActionCount = $actionPlan.Count
        maxActions         = $maxActions
        willExecute        = $false
        confirmDisable     = $confirmDisable
        confirmTag         = $confirmTag
        extensionName      = $extensionName
    }

    $actionsExecuted = @()

    switch ($mode) {
        'report' {
            # no-op
        }

        'detect' {
            # no execution, just include plan
        }

        'disable' {
            if (-not $confirmDisable) {
                Write-Warning "MODE=disable requested but CONFIRM_DISABLE=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true

            foreach ($a in $actionPlan) {
                Disable-EntraDevice -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion
                $actionsExecuted += [pscustomobject]@{
                    deviceObjectId = $a.deviceObjectId
                    action         = 'disable'
                    status         = 'ok'
                }
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
                    version            = "v1.1-entra-only"
                    evaluatedAtUtc     = $nowUtc.ToString('o')
                    staleDaysThreshold = $staleDays
                    cutoffUtc          = $cutoffUtc.ToString('o')
                }

                $result = Upsert-DeviceOpenExtension -DeviceObjectId $a.deviceObjectId -AccessToken $token -GraphApiVersion $graphApiVersion -ExtensionName $extensionName -Properties $props

                $actionsExecuted += [pscustomobject]@{
                    deviceObjectId = $a.deviceObjectId
                    action         = 'tag'
                    status         = $result
                }
            }
        }

        default {
            Write-Warning "Unknown MODE='$mode'. No actions executed."
        }
    }

    # Attach action metadata to report
    $report | Add-Member -NotePropertyName mode -NotePropertyValue $mode -Force
    $report | Add-Member -NotePropertyName actionSummary -NotePropertyValue $actionSummary -Force
    $report | Add-Member -NotePropertyName actionPlan -NotePropertyValue $actionPlan -Force
    $report | Add-Member -NotePropertyName actionsExecuted -NotePropertyValue $actionsExecuted -Force

    # Write report to blob output binding
    $json = $report | ConvertTo-Json -Depth 8
    Push-OutputBinding -Name reportBlob -Value $json

    Write-Host "Report written to blob output binding."
}
catch {
    Write-Error $_
    throw
}