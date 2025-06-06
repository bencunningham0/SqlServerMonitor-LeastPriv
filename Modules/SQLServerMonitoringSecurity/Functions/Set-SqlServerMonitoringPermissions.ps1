function Set-SQLServerMonitoringPermissions {
    <#
    .SYNOPSIS
    Configures least privilege security permissions for SQL Server monitoring accounts.

    .DESCRIPTION
    This function sets up all necessary permissions for a SQL DB monitoring account including:
    - Local group memberships (Performance Monitor Users, Distributed COM Users)
    - WMI namespace permissions for system monitoring
    - SQL Server log file access permissions
    - SQL Server logs network share configuration
    - Windows service permissions for monitoring and management
    
    .PARAMETER AccountName
    The account name to configure permissions for. Can be in DOMAIN\Account format.
    Typically a Group Managed Service Account (gMSA) ending with $.
    
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
    
    .PARAMETER ServiceConfigurations
    Array of service configurations with name and access flags. If not provided, default configurations will be used.
    
    .EXAMPLE
    Set-SQLServerMonitoringPermissions -AccountName "DOMAIN\MonitoringAccount" -Verbose
    
    Configures all permissions for the specified group managed service account with verbose output.
    
    .EXAMPLE
    Set-SQLServerMonitoringPermissions -AccountName "DOMAIN\MonitoringAccount" -SkipSqlPermissions
    
    Configures permissions but skips SQL Server related configurations.
    
    .EXAMPLE
    $serviceConfigs = @(
        @{
            name = "scmanager"
            accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
        }
    )
    Set-SQLServerMonitoringPermissions -AccountName "DOMAIN\MonitoringAccount" -ServiceConfigurations $serviceConfigs
    
    Configures permissions with custom service configurations.
    
    .NOTES
    This function requires administrative privileges to execute successfully.
    It's designed to be idempotent - running it multiple times will not cause issues.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AccountName,
        
        [Parameter()]
        [switch]$SkipGroupMembership,
        
        [Parameter()]
        [switch]$SkipWmiPermissions,
        
        [Parameter()]
        [switch]$SkipSqlPermissions,
        
        [Parameter()]
        [switch]$SkipServicePermissions,
        
        [Parameter()]
        [switch]$RestartWmi,
        
        [Parameter()]
        [array]$ServiceConfigurations = @(
            @{
                name = "scmanager"
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            },
            @{
                name = "mssqlserver" 
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            },
            @{
                name = "SQLSERVERAGENT"
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            },
            @{
                name = "sqlbrowser"
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            },
            @{
                name = "MSSQLFDLauncher"
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            }
        )
    )
    
    Begin {
        Write-Verbose "Starting SQL DB monitoring security configuration for account: $AccountName"
        
        # Validate account exists
        try {
            $accountSid = Convert-AccountToSid -account $AccountName
            Write-Verbose "Account validated. SID: $accountSid"
        }
        catch {
            throw "Failed to validate account $AccountName`: $_"
        }
    }
    
    Process {
        $errorCount = 0
        
        # Configure local group memberships
        if (-not $SkipGroupMembership) {
            Write-Verbose "Configuring local group memberships..."
            $groups = @("Performance Monitor Users", "Distributed COM Users")
            
            foreach ($group in $groups) {
                try {
                    if (-not (Test-LocalGroupMembership -GroupName $group -MemberName $AccountName)) {
                        Add-LocalGroupMember -Group $group -Member $AccountName -ErrorAction Stop
                        Write-Verbose "Added $AccountName to $group"
                    }
                    else {
                        Write-Verbose "$AccountName is already a member of $group"
                    }
                }
                catch {
                    Write-Warning "Failed to add $AccountName to $group`: $_"
                    $errorCount++
                }
            }
        }
        
        # Configure WMI permissions
        if (-not $SkipWmiPermissions) {
            Write-Verbose "Configuring WMI namespace permissions..."
            try {
                Set-WmiNamespaceSecurity -namespace "root\cimv2" -operation add -account $AccountName -permissions enable, remoteaccess, methodexecute -verbose:$($VerbosePreference -eq 'Continue') -restart:$RestartWmi
                Write-Verbose "WMI permissions configured successfully"
            }
            catch {
                Write-Warning "Failed to configure WMI permissions: $_"
                $errorCount++
            }
        }
        
        # Configure SQL Server permissions
        if (-not $SkipSqlPermissions) {
            Write-Verbose "Configuring SQL Server permissions..."
            
            # Set SQL Server log permissions
            try {
                Set-SqlLogPermissions -UserAccount $AccountName
                Write-Verbose "SQL Server log permissions configured successfully"
            }
            catch {
                Write-Warning "Failed to configure SQL Server log permissions: $_"
                $errorCount++
            }
                  # Set SQL Server logs share
            try {
                Set-SqlLogsShare -UserAccount $AccountName
                Write-Verbose "SQL Server logs share configured successfully"
            }
            catch {
                Write-Warning "Failed to configure SQL Server logs share: $_"
                $errorCount++
            }
        }

        # Configure service permissions
        if (-not $SkipServicePermissions) {
            Write-Verbose "Configuring Windows service permissions..."
            
            foreach ($service in $ServiceConfigurations) {
                try {
                    $result = Add-ServiceAcl -Service $service.name -Group $AccountName -AccessFlags $service.accessFlags -Verbose:$($VerbosePreference -eq 'Continue')
                    if ($result) {
                        Write-Verbose "Service permissions configured for $($service.name)"
                    }
                }
                catch {
                    Write-Warning "Failed to configure permissions for service $($service.name): $_"
                    $errorCount++
                }
            }
        }
    }
    
    End {
        if ($errorCount -eq 0) {
            Write-Host "SQL DB monitoring security configuration completed successfully for $AccountName" -ForegroundColor Green
        }
        else {
            Write-Warning "SQL DB monitoring security configuration completed with $errorCount error(s). Check the warnings above for details."
        }
        
        Write-Verbose "Security configuration process finished"
    }
}