<#
.SYNOPSIS
    Azure Function to identify and manage stale Entra ID user accounts.

.DESCRIPTION
    This Azure Function identifies stale user accounts in Entra ID (Azure AD) based on sign-in activity.

    Modes:
    - detect:  Shows which stale users would be acted on (dry-run/preview)
    - disable: Disables stale user accounts (requires CONFIRM_DISABLE=true)
    - tag:     Tags stale users using open extensions (requires CONFIRM_TAG=true)

    Activity timestamp:
    - Uses signInActivity.lastSignInDateTime (interactive sign-ins)
    - Falls back to createdDateTime if no sign-in data available

    Output:
    - JSON report written to blob via output binding (reportBlob)
    - Human-readable summary text written to blob via output binding (summaryBlob)

.NOTES
    Version:        1.0 (User account staleness sweep)
    Author:         TLDTech.io

.PARAMETER Timer
    Timer trigger input from Azure Functions.

.EXAMPLE
    # Preview what would be acted on (detect mode)
    MODE=detect STALE_DAYS=90

.EXAMPLE
    # Disable stale users (requires confirmation)
    MODE=disable STALE_DAYS=180 CONFIRM_DISABLE=true MAX_ACTIONS=25

.EXAMPLE
    # Tag stale users with metadata
    MODE=tag CONFIRM_TAG=true EXTENSION_NAME=STALE

.EXAMPLE
    # Exception lists: Protect specific users from any actions
    MODE=execute EXCEPTION_GROUP_ID=<guid>
    EXCEPTION_UPN_PATTERNS=admin@*,svc-*@*
    EXCEPTION_USER_IDS=<guid>,<guid>

.ENVIRONMENT
    Core:
        STALE_DAYS=180
        MODE=detect | disable | tag
        GRAPH_API_VERSION=v1.0
        MAX_ACTIONS=25

    Safety confirms:
        CONFIRM_DISABLE=false
        CONFIRM_TAG=false

    Per-action throttles:
        MAX_DISABLE=25
        MAX_TAG=25

    Extension:
        EXTENSION_NAME=STALE
    
    Optional outputs:
        OUTPUT_ACTION_PLAN_CSV=false
        OUTPUT_INVENTORY_CSV=false
    
    Exceptions (users never acted on):
        EXCEPTION_GROUP_ID=<guid>                    # Entra group containing protected users
        EXCEPTION_UPN_PATTERNS=admin@*,svc-*@*       # Comma-separated wildcards
        EXCEPTION_USER_IDS=<guid>,<guid>             # Comma-separated user object IDs

.PERMISSIONS (Graph application permissions; managed identity / app-only)
    - User read:     User.Read.All, AuditLog.Read.All, GroupMember.Read.All
    - User write:    User.ReadWrite.All (required for disable)
    - Extensions:    Directory.ReadWrite.All (required for open extensions tagging)

.TUNING GUIDANCE
    Small environments (<500 users): ACTION_PARALLELISM=3
    Medium environments (500-5000): ACTION_PARALLELISM=5 (default)
    Large environments (5000+): ACTION_PARALLELISM=8
#>

param($Timer)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Config
# ---------------------------

$staleDays = [int]($env:STALE_DAYS ?? 180)
$mode = ($env:MODE ?? 'detect').ToLowerInvariant()
$graphApiVersion = ($env:GRAPH_API_VERSION ?? 'v1.0')

$maxActions = [int]($env:MAX_ACTIONS ?? 25)

$confirmDisable = (($env:CONFIRM_DISABLE ?? 'false').ToLowerInvariant() -eq 'true')
$confirmTag = (($env:CONFIRM_TAG ?? 'false').ToLowerInvariant() -eq 'true')
$extensionName = ($env:EXTENSION_NAME ?? 'STALE')

# Per-action throttles
$maxDisable = [int]($env:MAX_DISABLE ?? $maxActions)
$maxTag = [int]($env:MAX_TAG ?? $maxActions)

# CSV outputs
$outputActionPlanCsv = ($env:OUTPUT_ACTION_PLAN_CSV ?? 'false') -eq 'true'
$outputInventoryCsv = ($env:OUTPUT_INVENTORY_CSV ?? 'false') -eq 'true'

# Times (UTC)
$nowUtc = (Get-Date).ToUniversalTime()
$cutoffUtc = $nowUtc.AddDays(-$staleDays)
$nowUtcStr = $nowUtc.ToString('o')
$cutoffUtcStr = $cutoffUtc.ToString('o')

# Parallelism for actions
$actionParallelism = [int]($env:ACTION_PARALLELISM ?? 5)

# Exception lists
$exceptionGroupId = $env:EXCEPTION_GROUP_ID
$exceptionUpnPatternsRaw = $env:EXCEPTION_UPN_PATTERNS ?? ''
$exceptionUpnPatterns = @()
if (-not [string]::IsNullOrWhiteSpace($exceptionUpnPatternsRaw)) {
    $exceptionUpnPatterns = $exceptionUpnPatternsRaw.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$exceptionUserIdsRaw = $env:EXCEPTION_USER_IDS ?? ''
$exceptionUserIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
if (-not [string]::IsNullOrWhiteSpace($exceptionUserIdsRaw)) {
    $exceptionUserIdsRaw.Split(',') | ForEach-Object { 
        $id = $_.Trim()
        if ($id) { $exceptionUserIds.Add($id) | Out-Null }
    }
}

Write-Host "=== Entra stale user account sweep (v1.0) ==="
Write-Host "Now (UTC):               $nowUtcStr"
Write-Host "Cutoff (UTC):            $cutoffUtcStr  (STALE_DAYS=$staleDays)"
Write-Host "Mode:                    $mode"
Write-Host "Graph:                   $graphApiVersion"
Write-Host "MAX_ACTIONS:             $maxActions"
Write-Host "Confirm disable/tag:     disable=$confirmDisable  tag=$confirmTag"
Write-Host "Per-action caps:         disable=$maxDisable tag=$maxTag"

# ---------------------------
# Structured config snapshot
# ---------------------------

$cfgEvent = @{
    eventType         = "staleUserSweep.config"
    version           = "v1.0"
    mode              = $mode
    staleDays         = $staleDays
    maxActions        = $maxActions
    actionParallelism = $actionParallelism
    confirms          = @{
        disable = $confirmDisable
        tag     = $confirmTag
    }
    limits            = @{
        maxDisable = $maxDisable
        maxTag     = $maxTag
    }
}

Write-Host ("CFG " + ($cfgEvent | ConvertTo-Json -Compress))

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

            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $retryAfter = $_.Exception.Response.Headers['Retry-After']
            }

            if ($statusCode -in @(429, 503, 504) -and $attempt -lt $MaxRetries) {
                if ($retryAfter) {
                    $waitSeconds = [int]$retryAfter
                }
                else {
                    $waitSeconds = $delay
                    $delay = [Math]::Min($delay * 2, 60)
                }

                Write-Warning "Graph API returned $statusCode. Retry $attempt/$MaxRetries after $waitSeconds seconds..."
                Start-Sleep -Seconds $waitSeconds
                continue
            }

            throw
        }
    }

    throw "Max retries ($MaxRetries) exceeded for $Method $Uri"
}

# ---------------------------
# Entra Actions
# ---------------------------

function Disable-EntraUser {
    param(
        [Parameter(Mandatory)][string]$UserObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )

    $uri = "https://graph.microsoft.com/$GraphApiVersion/users/$UserObjectId"
    Invoke-GraphWithRetry -Method PATCH -Uri $uri -AccessToken $AccessToken -Body @{ accountEnabled = $false } | Out-Null
}

function Update-UserOpenExtension {
    param(
        [Parameter(Mandatory)][string]$UserObjectId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion,
        [Parameter(Mandatory)][string]$ExtensionName,
        [Parameter(Mandatory)][hashtable]$Properties
    )

    $patchUri = "https://graph.microsoft.com/$GraphApiVersion/users/$UserObjectId/extensions/$ExtensionName"
    try {
        Invoke-GraphWithRetry -Method PATCH -Uri $patchUri -AccessToken $AccessToken -Body $Properties | Out-Null
        return "patched"
    }
    catch {
        if ($_ -match 'HTTP 404') {
            $postUri = "https://graph.microsoft.com/$GraphApiVersion/users/$UserObjectId/extensions/$ExtensionName"
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
# Tag Properties Helper
# ---------------------------

function Get-TagProperties {
    param(
        [Parameter(Mandatory)] $ActionItem,
        [Parameter(Mandatory)] [string] $Version,
        [Parameter(Mandatory)] [string] $NowUtcStr,
        [Parameter(Mandatory)] [int] $StaleDays,
        [Parameter(Mandatory)] [string] $CutoffUtcStr
    )

    @{
        status             = "stale"
        classification     = $ActionItem.classification
        version            = $Version
        evaluatedAtUtc     = $NowUtcStr
        staleDaysThreshold = $StaleDays
        cutoffUtc          = $CutoffUtcStr
    }
}

# ---------------------------
# Action Execution Helpers
# ---------------------------

function Invoke-ActionWithErrorHandling {
    param(
        [Parameter(Mandatory)] [string] $ActionType,
        [Parameter(Mandatory)] $ActionItem,
        [Parameter(Mandatory)] [scriptblock] $ActionBlock
    )

    try {
        & $ActionBlock
        $result = [pscustomobject]@{
            userObjectId = $ActionItem.userObjectId
            action       = $ActionType
            status       = 'ok'
        }
        if ($ActionItem.decisionReason) { $result | Add-Member -NotePropertyName reason -NotePropertyValue $ActionItem.decisionReason }
        return $result
    }
    catch {
        $result = [pscustomobject]@{
            userObjectId = $ActionItem.userObjectId
            action       = $ActionType
            status       = 'error'
            message      = $_.Exception.Message
        }
        if ($ActionItem.decisionReason) { $result | Add-Member -NotePropertyName reason -NotePropertyValue $ActionItem.decisionReason }
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
        [Parameter(Mandatory)] $Counts,
        [Parameter(Mandatory)] $ActionSummary,
        [Parameter(Mandatory)] $ActionPlan,
        [Parameter(Mandatory)] $ActionsExecuted,
        [Parameter(Mandatory)] [int] $TotalUsers
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
        $ActionPlan | Select-Object -First 25 userPrincipalName, displayName, classification, daysSince, plannedAction
    )

    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add("Entra Stale User Account Sweep — $Version")
    $lines.Add("Generated (UTC): $GeneratedAtUtc")
    $lines.Add("Mode: $Mode")
    $lines.Add("Threshold: $StaleDaysThreshold days   Cutoff (UTC): $CutoffUtc")
    $lines.Add("")

    $lines.Add("Inventory Summary")
    $lines.Add("  Total users:          $TotalUsers")
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
        $lines.Add("  UPN | DisplayName | Class | DaysSince | Action")
        $lines.Add("  --- | ----------- | ----- | --------- | ------")
        foreach ($p in $preview) {
            $upn = ($p.userPrincipalName ?? "").ToString().Trim()
            if ($upn.Length -gt 35) { $upn = $upn.Substring(0, 32) + "..." }
            $dn = ($p.displayName ?? "").ToString().Trim()
            if ($dn.Length -gt 30) { $dn = $dn.Substring(0, 27) + "..." }
            $lines.Add(("  {0} | {1} | {2} | {3} | {4}" -f $upn, $dn, $p.classification, $p.daysSince, $p.plannedAction))
        }
    }

    $lines.Add("")
    $lines.Add("Notes")
    $lines.Add("  - 'Unknown' users are never acted on.")
    $lines.Add("  - 'Stale-NoSignIn' means no sign-in data available; createdDateTime was older than cutoff.")
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

function Get-UserClassification {
    param(
        [Parameter(Mandatory)] [datetime] $CutoffUtc,
        [datetime] $LastSignInUtc = $null,
        [datetime] $CreatedUtc = $null
    )

    if ($LastSignInUtc) {
        if ($LastSignInUtc -lt $CutoffUtc) { 
            return 'Stale' 
        } 
        else { 
            return 'Active' 
        }
    }

    if ($CreatedUtc -and $CreatedUtc -lt $CutoffUtc) { return 'Stale-NoSignIn' }

    'Unknown'
}

function Get-ExceptionGroupMembers {
    param(
        [Parameter(Mandatory)][string]$GroupId,
        [Parameter(Mandatory)][string]$AccessToken,
        [Parameter(Mandatory)][string]$GraphApiVersion
    )
    
    try {
        $uri = "https://graph.microsoft.com/$GraphApiVersion/groups/$GroupId/members/microsoft.graph.user?`$select=id"
        $members = Invoke-GraphGetAll -Uri $uri -AccessToken $AccessToken
        
        $userIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($m in $members) {
            if ($m.id) { $userIds.Add($m.id) | Out-Null }
        }
        
        Write-Host "Exception group members: $($userIds.Count) users"
        return $userIds
    }
    catch {
        Write-Warning "Failed to fetch exception group members: $($_.Exception.Message)"
        return [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    }
}

function Test-UserException {
    param(
        [Parameter(Mandatory)][string]$UserId,
        [Parameter(Mandatory)][string]$UserPrincipalName,
        [System.Collections.Generic.HashSet[string]]$GroupMemberIds = [System.Collections.Generic.HashSet[string]]::new(),
        [string[]]$UpnPatterns = @(),
        [System.Collections.Generic.HashSet[string]]$ExplicitUserIds = [System.Collections.Generic.HashSet[string]]::new()
    )
    
    if ($ExplicitUserIds.Count -gt 0 -and $ExplicitUserIds.Contains($UserId)) {
        return [pscustomobject]@{ isException = $true; reason = 'Explicit exception list' }
    }
    
    if ($GroupMemberIds.Count -gt 0 -and $GroupMemberIds.Contains($UserId)) {
        return [pscustomobject]@{ isException = $true; reason = 'Exception group member' }
    }
    
    if ($UpnPatterns.Count -gt 0) {
        foreach ($pattern in $UpnPatterns) {
            if ($UserPrincipalName -like $pattern) {
                return [pscustomobject]@{ isException = $true; reason = "UPN matches pattern '$pattern'" }
            }
        }
    }
    
    return [pscustomobject]@{ isException = $false; reason = $null }
}

# ---------------------------
# Main
# ---------------------------

try {
    $token = Get-GraphAccessToken

    # Fetch Entra users with sign-in activity
    $select = "id,userPrincipalName,displayName,accountEnabled,userType,createdDateTime,signInActivity"
    $uri = "https://graph.microsoft.com/$graphApiVersion/users?`$select=$([uri]::EscapeDataString($select))&`$top=999"
    $users = Invoke-GraphGetAll -Uri $uri -AccessToken $token
    Write-Host "Entra users fetched: $($users.Count)"

    # Fetch exception group members if configured
    $exceptionGroupMembers = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrWhiteSpace($exceptionGroupId)) {
        $exceptionGroupMembers = Get-ExceptionGroupMembers -GroupId $exceptionGroupId -AccessToken $token -GraphApiVersion $graphApiVersion
    }

    # Log exception configuration
    $totalExceptionSources = 0
    if ($exceptionGroupMembers.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: Group ($($exceptionGroupMembers.Count) users)" }
    if ($exceptionUpnPatterns.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: UPN patterns ($($exceptionUpnPatterns -join ', '))" }
    if ($exceptionUserIds.Count -gt 0) { $totalExceptionSources++; Write-Host "Exception sources: Explicit IDs ($($exceptionUserIds.Count) users)" }
    if ($totalExceptionSources -eq 0) { Write-Host "Exception sources: None configured" }

    # Evaluate users
    $results = [System.Collections.Generic.List[object]]::new($users.Count)

    foreach ($u in $users) {
        $lastSignInUtc = ConvertTo-GraphDateUtc -Value $u.signInActivity.lastSignInDateTime
        $createdUtc = ConvertTo-GraphDateUtc -Value $u.createdDateTime

        $classification = Get-UserClassification -CutoffUtc $cutoffUtc -LastSignInUtc $lastSignInUtc -CreatedUtc $createdUtc

        $daysSinceLastActivity = if ($lastSignInUtc) {
            [int]($nowUtc - $lastSignInUtc).TotalDays
        }
        elseif ($createdUtc) {
            [int]($nowUtc - $createdUtc).TotalDays
        }
        else { $null }

        # Check exception lists
        $exceptionCheck = Test-UserException `
            -UserId $u.id `
            -UserPrincipalName ($u.userPrincipalName ?? '') `
            -GroupMemberIds $exceptionGroupMembers `
            -UpnPatterns $exceptionUpnPatterns `
            -ExplicitUserIds $exceptionUserIds

        $resultObj = [pscustomobject]@{
            id                    = $u.id
            userPrincipalName     = $u.userPrincipalName
            displayName           = $u.displayName
            accountEnabled        = $u.accountEnabled
            userType              = $u.userType
            createdDateTime       = $u.createdDateTime
            lastSignInDateTime    = $u.signInActivity.lastSignInDateTime
            lastSignInUtc         = if ($lastSignInUtc) { $lastSignInUtc.ToString('o') } else { $null }
            classification        = $classification
            daysSinceLastActivity = $daysSinceLastActivity
            staleThresholdDateUtc = $cutoffUtcStr
            staleDaysThreshold    = $staleDays
            isException           = $exceptionCheck.isException
            exceptionReason       = $exceptionCheck.reason
        }

        $results.Add($resultObj)
    }

    # Classification summary
    $counts = @($results | Group-Object classification | ForEach-Object {
            [pscustomobject]@{ classification = $_.Name; count = $_.Count }
        })

    # Report base
    $report = [pscustomobject]@{
        version            = "v1.0-user-sweep"
        generatedAtUtc     = $nowUtcStr
        staleDaysThreshold = $staleDays
        totalUsers         = $users.Count
        summary            = $counts
        items              = $results
    }

    # ---------------------------
    # Build Action Plan
    # ---------------------------

    $actionsExecuted = [System.Collections.Generic.List[object]]::new()
    $actionPlan = [System.Collections.Generic.List[object]]::new()

    # Select candidates (stale users, not exceptions, not already disabled)
    $candidates = @($results | Where-Object { 
            $_.classification -in @('Stale', 'Stale-NoSignIn') -and 
            -not $_.isException
        })

    $plannedCount = [Math]::Min($candidates.Count, $maxActions)

    for ($i = 0; $i -lt $plannedCount; $i++) {
        $c = $candidates[$i]
        $actionPlan.Add([pscustomobject]@{
                userObjectId      = $c.id
                userPrincipalName = $c.userPrincipalName
                displayName       = $c.displayName
                classification    = $c.classification
                daysSince         = $c.daysSinceLastActivity
                plannedAction     = $mode
            })
    }

    $candidateCount = $candidates.Count

    # Action summary
    $actionSummary = [pscustomobject]@{
        modeRequested      = $mode
        candidateCount     = $candidateCount
        plannedActionCount = $actionPlan.Count
        maxActions         = $maxActions
        willExecute        = $false
        confirmDisable     = $confirmDisable
        confirmTag         = $confirmTag
        maxDisable         = $maxDisable
        maxTag             = $maxTag
        extensionName      = $extensionName
    }

    # ---------------------------
    # Execute
    # ---------------------------

    switch ($mode) {
        'detect' {
            # preview only
        }

        'disable' {
            if (-not $confirmDisable) {
                Write-Warning "MODE=disable requested but CONFIRM_DISABLE=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true
            $toProcess = $actionPlan | Select-Object -First $maxDisable

            $results = $toProcess | ForEach-Object -Parallel {
                $a = $_
                $token = $using:token
                $graphApiVersion = $using:graphApiVersion
                $invokeGraph = ${using:function:Invoke-GraphWithRetry}

                try {
                    $uri = "https://graph.microsoft.com/$graphApiVersion/users/$($a.userObjectId)"
                    & $invokeGraph -Method PATCH -Uri $uri -AccessToken $token -Body @{ accountEnabled = $false }
                    [pscustomobject]@{ userObjectId = $a.userObjectId; action = 'disable'; status = 'ok' }
                }
                catch {
                    [pscustomobject]@{ userObjectId = $a.userObjectId; action = 'disable'; status = 'error'; message = $_.Exception.Message }
                }
            } -ThrottleLimit $actionParallelism

            $results | ForEach-Object { $actionsExecuted.Add($_) }
        }

        'tag' {
            if (-not $confirmTag) {
                Write-Warning "MODE=tag requested but CONFIRM_TAG=true not set. No actions executed."
                break
            }

            $actionSummary.willExecute = $true
            $toProcess = $actionPlan | Select-Object -First $maxTag

            $results = $toProcess | ForEach-Object -Parallel {
                $a = $_
                $token = $using:token
                $graphApiVersion = $using:graphApiVersion
                $extensionName = $using:extensionName
                $nowUtcStr = $using:nowUtcStr
                $staleDays = $using:staleDays
                $cutoffUtcStr = $using:cutoffUtcStr

                $props = @{
                    status             = "stale"
                    classification     = $a.classification
                    version            = "v1.0-user-sweep"
                    evaluatedAtUtc     = $nowUtcStr
                    staleDaysThreshold = $staleDays
                    cutoffUtc          = $cutoffUtcStr
                }

                $invokeGraph = ${using:function:Invoke-GraphWithRetry}

                try {
                    $patchUri = "https://graph.microsoft.com/$graphApiVersion/users/$($a.userObjectId)/extensions/$extensionName"
                    try {
                        & $invokeGraph -Method PATCH -Uri $patchUri -AccessToken $token -Body $props
                        [pscustomobject]@{ userObjectId = $a.userObjectId; action = 'tag'; status = 'patched' }
                    }
                    catch {
                        if ($_ -match 'HTTP 404') {
                            $postUri = "https://graph.microsoft.com/$graphApiVersion/users/$($a.userObjectId)/extensions/$extensionName"
                            $body = @{
                                "@odata.type" = "microsoft.graph.openTypeExtension"
                                extensionName = $extensionName
                            } + $props
                            & $invokeGraph -Method POST -Uri $postUri -AccessToken $token -Body $body
                            [pscustomobject]@{ userObjectId = $a.userObjectId; action = 'tag'; status = 'created' }
                        }
                        else { throw }
                    }
                }
                catch {
                    [pscustomobject]@{ userObjectId = $a.userObjectId; action = 'tag'; status = 'error'; message = $_.Exception.Message }
                }
            } -ThrottleLimit $actionParallelism

            $results | ForEach-Object { $actionsExecuted.Add($_) }
        }

        default {
            Write-Warning "Unknown MODE='$mode'. Valid modes: detect, disable, tag. No actions executed."
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
        -Counts $counts `
        -ActionSummary $actionSummary `
        -ActionPlan $actionPlan `
        -ActionsExecuted $actionsExecuted `
        -TotalUsers $users.Count

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

    # Outputs - Action Plan CSV (optional)
    if ($outputActionPlanCsv -and $actionPlan.Count -gt 0) {
        Write-Host "Preparing action plan CSV..."
        $actionPlanCsv = $actionPlan | ConvertTo-Csv -NoTypeInformation | Out-String
        if (-not [string]::IsNullOrWhiteSpace($actionPlanCsv)) {
            $actionPlanBytes = [System.Text.Encoding]::UTF8.GetByteCount($actionPlanCsv)
            Write-Host "Action plan CSV size: $actionPlanBytes bytes"
            Push-OutputBinding -Name actionPlanBlob -Value $actionPlanCsv
            Write-Host "✓ Action plan CSV written to actionPlanBlob"
        }
    }

    # Outputs - Inventory CSV (optional)
    if ($outputInventoryCsv) {
        Write-Host "Preparing inventory CSV..."
        $inventoryCsv = $report.items | Select-Object -Property id, userPrincipalName, displayName, 
        accountEnabled, userType, classification, daysSinceLastActivity, 
        lastSignInDateTime, createdDateTime, isException, exceptionReason | 
        ConvertTo-Csv -NoTypeInformation | Out-String

        if (-not [string]::IsNullOrWhiteSpace($inventoryCsv)) {
            $inventoryBytes = [System.Text.Encoding]::UTF8.GetByteCount($inventoryCsv)
            Write-Host "Inventory CSV size: $inventoryBytes bytes"
            Push-OutputBinding -Name inventoryBlob -Value $inventoryCsv
            Write-Host "✓ Inventory CSV written to inventoryBlob"
        }
    }

    Write-Host "All blob outputs completed successfully."

    # Emit structured result
    $resultEvent = @{
        eventType          = "staleUserSweep.result"
        totalUsers         = $report.totalUsers
        candidateCount     = $candidateCount
        activeCount        = ($counts | Where-Object { $_.classification -eq 'Active' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        staleCount         = ($counts | Where-Object { $_.classification -eq 'Stale' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        staleNoSignInCount = ($counts | Where-Object { $_.classification -eq 'Stale-NoSignIn' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        unknownCount       = ($counts | Where-Object { $_.classification -eq 'Unknown' } | Select-Object -ExpandProperty count -ErrorAction SilentlyContinue) ?? 0
        plannedActions     = $actionPlan.Count
        executedActions    = $actionsExecuted.Count
        mode               = $mode
    }
    Write-Host ("RESULT " + ($resultEvent | ConvertTo-Json -Compress))
}
catch {
    Write-Error $_
    throw
}
