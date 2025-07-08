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

    .PARAMETER SqlLogFolder
    The path to the SQL Server log folder. If specified, this path will be used for log permission and share configuration.

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
        [string]$SqlLogFolder,

        [Parameter()]
        [array]$ServiceConfigurations = @(
            @{
                name = "scmanager"
                accessFlags = @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
            },
            @{
                DisplayNameRegex = "^SQL Server.*"
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
                        $computer = $env:COMPUTERNAME
                        $groupPath = "WinNT://$computer/$group,group"
                        $adsiGroup = [ADSI]$groupPath
                        $sid = Convert-AccountToSid -account $AccountName
                        $memberPath = "WinNT://$sid"
                        $adsiGroup.Add($memberPath)
                        Write-Verbose "Added $AccountName (SID: $sid) to $group"
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
                if ($SqlLogFolder) {
                    Set-SqlLogPermissions -UserAccount $AccountName -LogFolder $SqlLogFolder
                } else {
                    Set-SqlLogPermissions -UserAccount $AccountName
                }
                Write-Verbose "SQL Server log permissions configured successfully"
            }
            catch {
                Write-Warning "Failed to configure SQL Server log permissions: $_"
                $errorCount++
            }
            # Set SQL Server logs share
            try {
                if ($SqlLogFolder) {
                    Set-SqlLogsShare -UserAccount $AccountName -LogFolder $SqlLogFolder
                } else {
                    Set-SqlLogsShare -UserAccount $AccountName
                }
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
                    # If DisplayNameRegex is specified, try to find all matching services by display name or name
                    if ($service.PSObject.Properties.Name -contains 'DisplayNameRegex' -and $service.DisplayNameRegex) {
                        $matchedServices = Get-Service | Where-Object { $_.DisplayName -match $service.DisplayNameRegex -or $_.Name -match $service.DisplayNameRegex }
                        if ($matchedServices) {
                            foreach ($matchedService in $matchedServices) {
                                $serviceName = $matchedService.Name
                                Write-Verbose "Matched service by DisplayNameRegex '$($service.DisplayNameRegex)': $serviceName"
                                Write-Verbose "Configuring permissions for service: $serviceName"
                                $result = Add-ServiceAcl -Service $serviceName -Group $AccountName -AccessFlags $service.accessFlags -Verbose:$($VerbosePreference -eq 'Continue')
                                if ($result) {
                                    Write-Verbose "Service permissions configured for $serviceName"
                                }
                            }
                        } else {
                            Write-Warning "No service matched DisplayNameRegex '$($service.DisplayNameRegex)'. Skipping."
                            continue
                        }
                    } elseif ($service.PSObject.Properties.Name -contains 'name' -and $service.name) {
                        $serviceName = $service.name
                        Write-Verbose "Configuring permissions for service: $serviceName"
                        $result = Add-ServiceAcl -Service $serviceName -Group $AccountName -AccessFlags $service.accessFlags -Verbose:$($VerbosePreference -eq 'Continue')
                        if ($result) {
                            Write-Verbose "Service permissions configured for $serviceName"
                        }
                    } else {
                        Write-Warning "Service configuration missing both 'name' and 'DisplayNameRegex'. Skipping."
                        continue
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