# SQL DB Monitoring Least Privilege Security Configuration

This PowerShell project provides a structured approach to configuring least privilege security permissions for SQL DB monitoring accounts. The solution is organized as a modular PowerShell framework that can be easily maintained, tested, and deployed.

## Project Structure

```
SQLServerMonitor-LeastPriv/
├── Config/
│   └── accounts.json              # Configuration file for multiple accounts
├── Modules/
│   └── SQLServerMonitoringSecurity/
│       ├── SQLServerMonitoringSecurity.psd1    # Module manifest
│       ├── SQLServerMonitoringSecurity.psm1    # Main module file
│       └── Functions/
│           ├── AccountUtilities.ps1           # Account and SID conversion functions
│           ├── ServicePermissions.ps1         # Windows service permission functions
│           ├── ServiceUtilities.ps1           # Service restart utilities
│           ├── Set-SQLServerMonitoringPermissions.ps1  # Main orchestration function
│           ├── SqlPermissions.ps1             # SQL Server permission functions
│           └── WmiPermissions.ps1             # WMI namespace permission functions
├── Scripts/
|   └── Set-SQLServerMonitoringSecurity.ps1    # Main execution script
```

## Features

### Security Configurations
- **Local Group Membership**: Adds accounts to Performance Monitor Users and Distributed COM Users groups
- **WMI Permissions**: Configures namespace permissions for `root\cimv2` with enable, remote access, and method execute permissions
- **SQL Server Access**: Sets up file system permissions and network shares for SQL Server log files
- **Service Permissions**: Configures permissions for Service Control Manager and SQL Server service

### Key Benefits
- **Modular Design**: Functions are organized by category for easy maintenance
- **Idempotent Operations**: Can be run multiple times without adverse effects
- **Comprehensive Logging**: Verbose output and error handling throughout
- **Flexible Configuration**: Support for single account or batch processing via configuration files
- **Parameter Validation**: Built-in validation for accounts and permissions

## Prerequisites

- Windows PowerShell 5.1 or later
- Administrator privileges
- SQL Server installed (if configuring SQL permissions)

## Installation

1. Clone or download the project to your target system
2. Ensure the executing user has administrative privileges
3. Optionally, modify the configuration file `Config\accounts.json` for your environment

## Usage

### Basic Usage (Single Account)

```powershell
# Configure permissions for default account
.\Scripts\Set-SQLServerMonitoringSecurity.ps1 -Verbose

# Configure permissions for custom account
.\Scripts\Set-SQLServerMonitoringSecurity.ps1 -AccountName "DOMAIN\ServiceAccount" -Verbose

# Skip SQL Server configurations
.\Scripts\Set-SQLServerMonitoringSecurity.ps1 -AccountName "DOMAIN\ServiceAccount" -SkipSqlPermissions
```

### Batch Configuration

```powershell
# Configure multiple accounts from configuration file
.\Scripts\Set-SQLServerMonitoringSecurity.ps1 -ConfigFile ".\Config\accounts.json" -Verbose
```

### Advanced Options

```powershell
# Skip specific configuration types
.\Scripts\Set-SQLServerMonitoringSecurity.ps1 -AccountName "DOMAIN\Account" `
    -SkipGroupMembership `
    -SkipWmiPermissions `
    -RestartWmi
```

## Module Functions

### Core Functions

- **`Set-SQLServerMonitoringPermissions`**: Main orchestration function that applies all security configurations
- **`Add-ServiceAcl`**: Adds access control entries to Windows service permissions
- **`Set-WmiNamespaceSecurity`**: Configures WMI namespace security permissions
- **`Set-SqlLogPermissions`**: Sets file system permissions for SQL Server logs
- **`Set-SqlLogsShare`**: Creates and configures network share for SQL Server logs

### Utility Functions

- **`Test-LocalGroupMembership`**: Checks if an account is a member of a local group
- **`Convert-AccountToSid`**: Converts account names to Security Identifiers (SIDs)
- **`Restart-ServiceWithDependants`**: Safely restarts services with their dependencies

## Configuration File Format

The `accounts.json` file supports configuring multiple accounts with individual settings:

```json
{
  "accounts": [
    {
      "name": "DOMAIN\\ServiceAccount",
      "description": "Primary monitoring account",
      "skipGroupMembership": false,
      "skipWmiPermissions": false,
      "skipSqlPermissions": false,
      "skipServicePermissions": false,
      "restartWmi": true
    }
  ]
}
```

## Error Handling

The solution includes comprehensive error handling:
- Account validation before configuration begins
- Graceful handling of missing services or components
- Detailed warning messages for partial failures
- Non-blocking errors to allow maximum configuration completion

## Security Considerations

- **Least Privilege**: Only grants minimum necessary permissions for monitoring operations
- **Account Validation**: Verifies accounts exist before granting permissions
- **Existing Permission Check**: Avoids duplicate permission grants
- **Service Restart Control**: Optional WMI service restart to apply changes

## Logging and Monitoring

- Use `-Verbose` parameter for detailed operational logging
- Monitor Windows Event Logs for service permission changes
- Review PowerShell execution policies and transcript logging as needed

## Troubleshooting

### Common Issues

1. **"Access Denied" errors**: Ensure the script is run with administrator privileges
2. **Account resolution failures**: Verify account names are correct and domain is reachable
3. **SQL Server path not found**: Ensure SQL Server is installed and registry keys exist
4. **WMI permission errors**: May require WMI service restart with `-RestartWmi` parameter

### Verification

After running the script, verify permissions using:
- `Get-LocalGroupMember` for group memberships
- SQL Server Management Studio for SQL log access
- WMI tools or PowerShell for WMI namespace permissions
- `sc.exe sdshow <service>` for service permissions

## Contributing

When adding new functionality:
1. Create functions in appropriate category files under `Functions/`
2. Update the module manifest (`SQLServerMonitoringSecurity.psd1`) to export new functions
3. Add comprehensive help documentation using PowerShell comment-based help
4. Include parameter validation and error handling
5. Add examples and update this README

## Version History

- **0.0.1**: Initial release with core security configuration functionality
