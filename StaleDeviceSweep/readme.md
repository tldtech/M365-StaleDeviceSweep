# Stale Device Sweep - Azure Function

An Azure Function that identifies and reports stale devices in Microsoft Entra ID (formerly Azure AD) based on last sign-in activity.

## Overview

This function runs on a timer schedule to scan all devices in your Entra ID tenant and classifies them based on their last sign-in activity. It generates a JSON report that can be used for compliance, security auditing, or device lifecycle management.

## Features

- **Automated Device Classification**: Categorizes devices as Active, Stale, Stale-NoSignIn, or Unknown
- **Configurable Staleness Threshold**: Set custom day thresholds via environment variables
- **Dual Authentication**: Supports both Managed Identity (production) and Azure CLI (local development)
- **Report Generation**: Outputs detailed JSON reports to Azure Blob Storage
- **Timer-based Execution**: Runs automatically on a schedule (default: every 5 minutes)

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STALE_DAYS` | `90` | Number of days of inactivity before a device is considered stale |
| `MODE` | `report` | Operation mode: `report` (v1 is report-only) |
| `GRAPH_API_VERSION` | `v1.0` | Microsoft Graph API version to use |

### Schedule

The function is triggered by a timer using a [cron expression](https://en.wikipedia.org/wiki/Cron#CRON_expression) defined in `function.json`:

- **Default**: `0 */5 * * * *` (every 5 minutes)
- Format: `{second} {minute} {hour} {day} {month} {day-of-week}`

### Required Permissions

The Managed Identity or service principal needs the following Microsoft Graph API permission:

- `Device.ReadWrite.All` (Application permission)

Use the included `AppEntraPermissions.ps1` script to grant permissions.

## Device Classification Logic

1. **Active**: Device has `approximateLastSignInDateTime` within the staleness threshold
2. **Stale**: Device has `approximateLastSignInDateTime` older than the staleness threshold
3. **Stale-NoSignIn**: Device has never signed in and `createdDateTime` is older than the threshold
4. **Unknown**: Device lacks sign-in data and was created recently (conservative classification)

## Output

Reports are written to Azure Blob Storage with the following structure:

```json
{
  "version": "v1-entra-only",
  "generatedAtUtc": "2025-12-26T10:00:00.000Z",
  "staleDays": 90,
  "totalDevices": 150,
  "summary": [
    { "classification": "Active", "count": 100 },
    { "classification": "Stale", "count": 30 },
    { "classification": "Stale-NoSignIn", "count": 15 },
    { "classification": "Unknown", "count": 5 }
  ],
  "items": [ /* Array of device details */ ]
}
```

Each device item includes:
- Device identifiers (id, displayName, deviceId)
- Status information (accountEnabled, trustType)
- Operating system details
- Classification and timestamps

## Local Development

1. Install Azure Functions Core Tools
2. Install PowerShell modules: `Microsoft.Graph.Authentication`, `Microsoft.Graph.Applications`
3. Authenticate with Azure CLI: `az login`
4. Run: `func host start`

The function will use your Azure CLI credentials when Managed Identity is not available.

## Deployment

Deploy to Azure Functions with PowerShell runtime. Ensure:
- System-assigned or user-assigned Managed Identity is enabled
- Graph API permissions are granted
- Environment variables are configured
- Storage account connection string is set in `AzureWebJobsStorage`

## Future Enhancements

Version 1 is report-only. Future versions may include:
- Automatic device deletion or disablement
- Integration with Intune for hybrid device management
- Email notifications for stale device reports
- Custom retention policies per device type
