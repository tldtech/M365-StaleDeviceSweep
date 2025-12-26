param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------
$staleDays = [int]($env:STALE_DAYS ?? 90)
$mode = ($env:MODE ?? 'report').ToLowerInvariant()
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')

$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)

Write-Host "=== Entra stale device sweep (v1: Entra-only) ==="
Write-Host "Now (UTC):     $($nowUtc.ToString('o'))"
Write-Host "Cutoff (UTC):  $($cutoffUtc.ToString('o'))"
Write-Host "Mode:          $mode"
Write-Host "Graph:         $graphApiVersion"

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
# Graph paging
# ---------------------------

function Invoke-GraphGetAll {
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $AccessToken
    )

    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri

    while ($next) {
        $resp = Invoke-RestMethod -Method GET -Uri $next -Headers @{
            Authorization = "Bearer $AccessToken"
        }

        if ($resp.value) {
            foreach ($v in $resp.value) { $items.Add($v) }
        }

        $next = $resp.'@odata.nextLink'
    }

    return $items
}

# ---------------------------
# Staleness evaluation
# ---------------------------

function Parse-GraphDateUtcOrNull {
    param([string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return $null }
    try { return ([datetime]::Parse($Value)).ToUniversalTime() } catch { return $null }
}

function Classify-Device {
    param(
        [Parameter(Mandatory)] $Device,
        [Parameter(Mandatory)] [datetime] $CutoffUtc
    )

    # This property is commonly used when present, but may be null in some tenants.
    $lastSignInUtc = Parse-GraphDateUtcOrNull -Value $Device.approximateLastSignInDateTime
    $createdUtc    = Parse-GraphDateUtcOrNull -Value $Device.createdDateTime

    if ($lastSignInUtc) {
        if ($lastSignInUtc -lt $CutoffUtc) { return 'Stale' }
        return 'Active'
    }

    if ($createdUtc -and $createdUtc -lt $CutoffUtc) {
        return 'Stale-NoSignIn'
    }

    # If we don't have lastSignIn, be conservative: treat as Unknown (report only).
    # You can later add fallback signals here if you decide they're reliable.
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

    $results = foreach ($d in $devices) {
        $classification = Classify-Device -Device $d -CutoffUtc $cutoffUtc

        $lastSignInUtc = Parse-GraphDateUtcOrNull -Value $d.approximateLastSignInDateTime

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
            staleCutoffUtc                = $cutoffUtc.ToString('o')
            staleDays                     = $staleDays
        }
    }

    $counts = $results | Group-Object classification | ForEach-Object {
        [pscustomobject]@{ classification = $_.Name; count = $_.Count }
    }

    $report = [pscustomobject]@{
        version        = "v1-entra-only"
        generatedAtUtc = $nowUtc.ToString('o')
        staleDays      = $staleDays
        totalDevices   = $devices.Count
        summary        = $counts
        items          = $results
    }

    $json = $report | ConvertTo-Json -Depth 6
    Push-OutputBinding -Name reportBlob -Value $json

    Write-Host "Report written to blob output binding."

    if ($mode -ne 'report') {
        Write-Warning "MODE='$mode' requested, but v1 is report-only. No actions will be taken."
    }
}
catch {
    Write-Error $_
    throw
}