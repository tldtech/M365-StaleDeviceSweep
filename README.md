# Stale Device Sweep - Azure Function

An Azure Function that identifies and manages stale devices in Microsoft Entra ID with optional Intune integration for intelligent decision-making and automated actions.

## Overview

This function runs on a timer schedule to scan all devices in your Entra ID tenant, classify them based on activity, and optionally take automated actions. The function adds Intune-aware decision rules to prevent false positives and support advanced device lifecycle management scenarios.

## Features

- **Automated Device Classification**: Categorizes devices as Active, Stale, Stale-NoSignIn, or Unknown
- **Intune Integration**: Optional enrichment with Intune managed device data for smarter decisions
- **Multiple Operation Modes**: detect, disable, tag, decide, execute
- **Intelligent Decision Rules**: Prevent false positives with configurable safety checks
- **Flexible Activity Sources**: Use Entra sign-in, Intune sync, or most recent timestamp
- **Action Execution**: Disable, tag, retire, wipe, or delete devices
- **Safety Controls**: Per-action confirmation flags and throttle limits
- **Dual Authentication**: Supports both Managed Identity (production) and Azure CLI (local development)
- **Comprehensive Reporting**: JSON reports and human-readable summaries to Azure Blob Storage
- **Azure Monitor Workbook**: Pre-built workbook for visualizing run history, trends, and metrics

## Version History

- **v2.0**: Intune-aware decision rules + optional Intune actions + correlation improvements
- **v1.0**: Basic Entra-only reporting and simple disable/tag actions

## Operation Modes

### Basic Modes
- **detect**: Preview which stale devices would be acted on (dry-run)
- **disable**: Disable stale devices in Entra ID (requires `CONFIRM_DISABLE=true`)
- **tag**: Tag stale devices using open extensions (requires `CONFIRM_TAG=true`)

### Advanced Modes
- **decide**: Build an Intune-aware action plan without execution (preview with intelligence)
- **execute**: Execute the Intune-aware action plan with per-action confirmations

## Configuration

### Core Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_DAYS` | `90` | Number of days of inactivity before a device is considered stale |
| `MODE` | `detect` | Operation mode: `detect`, `disable`, `tag`, `decide`, `execute` |
| `GRAPH_API_VERSION` | `v1.0` | Microsoft Graph API version to use |
| `MAX_ACTIONS` | `50` | Maximum total actions to perform in a single run |

### Intune Integration

| Variable | Default | Description |
|----------|---------|-------------|
| `INCLUDE_INTUNE` | `false` | Enable Intune managed device data enrichment |
| `ACTIVITY_SOURCE` | `signin` | Activity timestamp source: `signin`, `intune`, `mostRecent` |
| `INTUNE_STALE_DAYS` | `90` | Intune staleness threshold (defaults to `STALE_DAYS`) |

### Decision Rules (MODE=decide/execute)

| Variable | Default | Description |
|----------|---------|-------------|
| `REQUIRE_BOTH_STALE_FOR_DISABLE` | `true` | Require both Entra AND Intune stale before disabling |
| `DONT_DISABLE_IF_INTUNE_RECENT_SYNC` | `true` | Skip devices that recently synced with Intune |
| `INTUNE_RECENT_SYNC_DAYS` | `14` | Days to consider "recent" sync |
| `DONT_DISABLE_IF_COMPLIANT` | `true` | Skip compliant devices |
| `ONLY_DISABLE_IF_MANAGEDAGENT_IN` | `mdm,easmdm` | Only disable if management agent matches (empty = no filter) |
| `ALLOW_DISABLE_ON_DUPLICATE` | `false` | Allow disable when multiple Intune matches exist |

### Action Confirmations

| Variable | Default | Description |
|----------|---------|-------------|
| `CONFIRM_DISABLE` | `false` | Enable Entra device disabling |
| `CONFIRM_TAG` | `false` | Enable open extension tagging |
| `CONFIRM_INTUNE_RETIRE` | `false` | Enable Intune retire action |
| `CONFIRM_INTUNE_WIPE` | `false` | Enable Intune wipe action (⚠️ destructive) |
| `CONFIRM_INTUNE_DELETE` | `false` | Enable Intune delete action (⚠️ destructive) |

### Action Throttles

| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_DISABLE` | `50` | Maximum Entra devices to disable |
| `MAX_TAG` | `50` | Maximum devices to tag |
| `MAX_RETIRE` | `25` | Maximum Intune retires |
| `MAX_WIPE` | `5` | Maximum Intune wipes |
| `MAX_INTUNE_DELETE` | `25` | Maximum Intune deletes |

### Other Settings

| Variable | Default | Description |
|----------|---------|-------------|
| `EXTENSION_NAME` | `STALE` | Open extension name for tagging |
| `OUTPUT_ACTION_PLAN_CSV` | `false` | Generate action plan CSV output to blob storage |
| `OUTPUT_INVENTORY_CSV` | `false` | Generate full device inventory CSV output to blob storage |

### Schedule

The function is triggered by a timer using a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) defined in `function.json`:

- **Default**: `0 30 1 * * *` (daily at 1:30 AM UTC)
- Format: `{second} {minute} {hour} {day} {month} {day-of-week}`

### Required Permissions

The Managed Identity or service principal needs the following Microsoft Graph API permissions:

#### Permission Bundles

Choose the appropriate permission bundle based on your deployment needs:

**1. Entra Read Only** (Minimal - Reporting Only)
- `Device.Read.All` - Read Entra ID device information
- **Use case**: Detection/reporting mode only (`MODE=detect`)

**2. Entra Read + Write** (Basic Actions)
- `Device.ReadWrite.All` - Read/Disable devices and tag with open extensions
- **Use case**: Disable/tag modes without Intune integration (`MODE=disable`, `MODE=tag`)

**3. Entra + Intune Read** (Intune-Aware Decisions)
- `Device.Read.All` - Read Entra ID device information
- `DeviceManagementManagedDevices.Read.All` - Read Intune managed device data
- **Use case**: Intune-aware decision planning (`MODE=decide` with `INCLUDE_INTUNE=true`)

**4. Entra + Intune Full Access** (Complete Automation)
- `Device.ReadWrite.All` - Read/Disable devices and tag with open extensions
- `DeviceManagementManagedDevices.ReadWrite.All` - Read, Retire, wipe, and delete Intune devices
- **Use case**: Full automation with all actions (`MODE=execute` with all Intune actions enabled)

#### Granting Permissions

Use the included `Grant-DeviceSweepPermissions.ps1` script to interactively grant application-type permissions:

```powershell
# Specify a service principal, managed identity or enterprise application.
.\Grant-DeviceSweepPermissions.ps1 -ServicePrincipalObjectId "your-object-id-here"
```

## Monitoring

### Azure Monitor Workbook

A pre-built Azure Monitor Workbook is included for visualizing function execution and device management trends:

**Location**: `StaleDeviceSweep/Workbooks/M365-StaleDeviceSweep.json`

**Features**:
- Recent function runs with configuration and results
- Device classification trends over time
- Device distribution pie chart (latest run)
- Actions executed over time
- Errors and warnings tracking
- Performance metrics (success rate, duration)

**Setup**:
1. Open Azure Monitor in the Azure Portal
2. Navigate to **Workbooks** > **+ New**
3. Click the **Advanced Editor** button (code icon)
4. Paste the contents of `M365-StaleDeviceSweep.json`
5. Click **Apply** and save the workbook
6. Select your Log Analytics workspace from the dropdown

The workbook queries Application Insights logs and correlates CFG (configuration) and RESULT (execution summary) structured logs with function execution data.

#### Deployment
[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Ftldtech%2FM365---Device-MGMT%2Frefs%2Fheads%2Fmain%2FInfra%2Fazuredeploy.json)