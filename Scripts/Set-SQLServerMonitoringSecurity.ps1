#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
SQL DB Monitoring Least Privilege Security Configuration Script

.DESCRIPTION
This script configures least privilege security permissions for SQL DB monitoring accounts.
It imports the SQLServerMonitoringSecurity module and applies all necessary permissions for monitoring operations.

.PARAMETER AccountName
The account name to configure permissions for.

.PARAMETER ConfigFile
Path to a configuration file containing account names and settings. If specified, AccountName parameter is ignored.

.PARAMETER SkipGroupMembership
Skip adding the account to local groups (Performance Monitor Users, Distributed COM Users).

.PARAMETER SkipWmiPermissions  
Skip configuring WMI namespace permissions.

.PARAMETER SkipSqlPermissions
Skip configuring SQL Server log permissions and share.

.PARAMETER SkipServicePermissions
Skip configuring Windows service permissions.

.PARAMETER RestartWmi
Restart the WMI service after making permission changes.

.EXAMPLE
.\Set-SQLServerMonitoringSecurity.ps1 -Verbose

Configures permissions for the default account with verbose output.

.EXAMPLE
.\Set-SQLServerMonitoringSecurity.ps1 -AccountName "DOMAIN\MonitoringAccount" -SkipSqlPermissions

Configures permissions for a custom account but skips SQL Server configurations.

.EXAMPLE
.\Set-SQLServerMonitoringSecurity.ps1 -ConfigFile ".\Config\config.json"

Configures permissions for multiple accounts defined in a configuration file.

.NOTES
This script requires administrative privileges to execute successfully.
It's designed to be idempotent - running it multiple times will not cause issues.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$AccountName,
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile,
    
    [Parameter()]
    [switch]$SkipGroupMembership,
    
    [Parameter()]
    [switch]$SkipWmiPermissions,
    
    [Parameter()]
    [switch]$SkipSqlPermissions,
    
    [Parameter()]
    [switch]$SkipServicePermissions,
    
    [Parameter()]
    [switch]$RestartWmi
)

# Set error action preference
$ErrorActionPreference = 'Stop'

# Validate parameters - ensure we have either a config file or account name
if (-not $ConfigFile -and [string]::IsNullOrWhiteSpace($AccountName)) {
    # No config file and no account name provided, use default
    throw "No parameters provided. Config File or AccountName must be specified."
}

if ($ConfigFile -and -not [string]::IsNullOrWhiteSpace($AccountName)) {
    Write-Warning "Both ConfigFile and AccountName specified. ConfigFile takes precedence, AccountName will be ignored."
}

# Get script directory
$ScriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$ModulePath = Split-Path -Parent $ScriptDirectory
$ModulePath = Join-Path $ModulePath "Modules\SQLServerMonitoringSecurity"

try {
    # Import the SQLServerMonitoringSecurity module
    Write-Host "Importing SQLServerMonitoringSecurity module..." -ForegroundColor Cyan
    Import-Module $ModulePath -Force -Verbose:$($VerbosePreference -eq 'Continue')
    
    if ($ConfigFile) {
        # Process configuration file
        if (-not (Test-Path $ConfigFile)) {
            throw "Configuration file not found: $ConfigFile"
        }
        
        Write-Host "Processing configuration file: $ConfigFile" -ForegroundColor Cyan
        $config = Get-Content $ConfigFile | ConvertFrom-Json
        
        # Extract service configurations if available
        $serviceConfigs = if ($config.serviceConfigurations -and $config.serviceConfigurations.services) {
            $config.serviceConfigurations.services
        } else {
            $null
        }
        
        foreach ($account in $config.accounts) {
            Write-Host "`nConfiguring permissions for account: $($account.name)" -ForegroundColor Yellow
            
            $params = @{
                AccountName = $account.name
                SkipGroupMembership = $account.skipGroupMembership -eq $true
                SkipWmiPermissions = $account.skipWmiPermissions -eq $true
                SkipSqlPermissions = $account.skipSqlPermissions -eq $true
                SkipServicePermissions = $account.skipServicePermissions -eq $true
                RestartWmi = $account.restartWmi -eq $true
            }
            
            # Add service configurations if available
            if ($serviceConfigs) {
                $params['ServiceConfigurations'] = $serviceConfigs
            }
            
            Set-SQLServerMonitoringPermissions @params -Verbose:$($VerbosePreference -eq 'Continue')
        }
    }
    else {
        # Process single account
        Write-Host "Configuring permissions for account: $AccountName" -ForegroundColor Yellow
        
        $params = @{
            AccountName = $AccountName
            SkipGroupMembership = $SkipGroupMembership
            SkipWmiPermissions = $SkipWmiPermissions
            SkipSqlPermissions = $SkipSqlPermissions
            SkipServicePermissions = $SkipServicePermissions
            RestartWmi = $RestartWmi
        }
        
        # If config file exists in default location, try to read service configurations
        $defaultConfigPath = Join-Path $ScriptDirectory "..\Config\config.json"
        if (Test-Path $defaultConfigPath) {
            try {
                $config = Get-Content $defaultConfigPath | ConvertFrom-Json
                if ($config.serviceConfigurations -and $config.serviceConfigurations.services) {
                    $params['ServiceConfigurations'] = $config.serviceConfigurations.services
                }
            }
            catch {
                Write-Warning "Failed to read service configurations from default config file: $_"
            }
        }
        
        Set-SQLServerMonitoringPermissions @params -Verbose:$($VerbosePreference -eq 'Continue')
    }
    
    Write-Host "`nSQL DB monitoring security configuration completed successfully!" -ForegroundColor Green
}
catch {
    Write-Error "Failed to configure SQL DB monitoring security: $_"
    exit 1
}