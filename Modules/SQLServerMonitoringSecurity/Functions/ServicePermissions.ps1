function Add-ServiceAcl {
    <#
    .SYNOPSIS
    Adds access control entries to Windows service permissions.
    
    .DESCRIPTION
    This function modifies Windows service permissions by adding access control entries (ACEs) 
    for specified accounts or groups. It uses the Windows Service Control Manager (SCM) to 
    modify service security descriptors.
    
    .PARAMETER Service
    The name of the Windows service to modify permissions for.
    
    .PARAMETER Group
    The account or group name to grant permissions to.
    
    .PARAMETER Computer
    The target computer name. If not specified, operates on the local computer.
    
    .PARAMETER AccessFlags
    Array of access rights to grant. Valid values include:
    - QueryConfig: Permission to query service configuration
    - ChangeConfig: Permission to change service configuration
    - QueryStatus: Permission to query service status
    - EnumerateDependents: Permission to enumerate service dependents
    - Start: Permission to start the service
    - Stop: Permission to stop the service
    - PauseContinue: Permission to pause/continue the service
    - Interrogate: Permission to interrogate the service
    - UserDefinedControl: Permission for user-defined control codes
    - Delete: Permission to delete the service
    - ReadControl: Permission to read security descriptor
    - WriteDac: Permission to write discretionary access control list
    - WriteOwner: Permission to change ownership
    - AllAccess: Full access to the service
    
    .EXAMPLE
    Add-ServiceAcl -Service "wuauserv" -Group "DOMAIN\MonitoringAccount" -AccessFlags @("QueryStatus", "QueryConfig")
    
    Grants query permissions for the Windows Update service to the specified domain account.
    
    .EXAMPLE
    Add-ServiceAcl -Service "mssqlserver" -Group "DOMAIN\MonitoringAccount" -AccessFlags @("ChangeConfig", "QueryStatus", "QueryConfig", "ReadControl")
    
    Grants management permissions for SQL Server service to the specified group managed service account.
    
    .NOTES
    This function requires administrative privileges to modify service permissions.
    The function will check if the specified account already has the requested permissions before making changes.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Service,

        [Parameter(Mandatory = $true)]
        [string]$Group,

        [Parameter()]
        [string]$Computer,

        [Parameter()]
        [ValidateSet('QueryConfig', 'ChangeConfig', 'QueryStatus', 'EnumerateDependents', 
                    'Start', 'Stop', 'PauseContinue', 'Interrogate', 'UserDefinedControl',
                    'Delete', 'ReadControl', 'WriteDac', 'WriteOwner', 'AllAccess')]
        [string[]]$AccessFlags = @('QueryConfig', 'QueryStatus', 'EnumerateDependents', 'ReadControl')
    )

    Write-Host "Processing $Service service"

    # Check if the service exists before proceeding
    $serviceObj = if ($Computer) { 
        Get-Service -Name $Service -ComputerName $Computer -ErrorAction SilentlyContinue 
    } else { 
        Get-Service -Name $Service -ErrorAction SilentlyContinue 
    }
    if (-not $serviceObj) {
        Write-Warning "Service '$Service' does not exist. Skipping."
        return $false
    }

    # Map access rights to their numeric values
    $accessMap = @{
        'QueryConfig' = 'RP'; 'ChangeConfig' = 'CC'; 'QueryStatus' = 'LC';
        'EnumerateDependents' = 'DC'; 'Start' = 'ST'; 'Stop' = 'SP';
        'PauseContinue' = 'PP'; 'Interrogate' = 'IN'; 'UserDefinedControl' = 'DT';
        'Delete' = 'DT'; 'ReadControl' = 'RC'; 'WriteDac' = 'WD';
        'WriteOwner' = 'WO'; 'AllAccess' = 'GA'
    }

    try {
        # Get SID for the group
        $GroupSID = Convert-AccountToSid -account $Group
        if (-not $GroupSID) { throw "Unable to resolve SID for $Group" }

        # Build SC command arguments
        $scArgs = @()
        if ($Computer) { $scArgs += "\\$Computer" }
        $scArgs += @('sdshow', $Service)

        # Get current SDDL
        $currentSddl = & "$env:SystemRoot\System32\sc.exe" $scArgs
        if ($LASTEXITCODE -ne 0) { 
            throw "Failed to get current SDDL. Error: $($currentSddl -join ' ')" 
        }

        # Check if SID already exists in SDDL
        if ($currentSddl[1] -match $GroupSID) {
            Write-Verbose "SID $GroupSID already exists in service permissions. Skipping modification."
            return
        }

        # Build permission string
        $perms = $AccessFlags | ForEach-Object { 
            if (-not $accessMap.ContainsKey($_)) {
                Write-Warning "Unknown permission: $_"
                return
            }
            $accessMap[$_]
        } | Where-Object { $_ }
        
        if (-not $perms) {
            throw "No valid permissions specified"
        }
        $permString = $perms -join ''

        # Build new ACE
        $newAce = "(A;;$permString;;;$GroupSID)"
        
        # Add new ACE to DACL (after the existing DACL)
        $newSddl = $currentSddl[1] -replace '(S:.*)', "$newAce`$1"
        if ($newSddl -eq $currentSddl[1]) {
            throw "Failed to modify SDDL string"
        }

        # Apply new SDDL
        $scArgs = @()
        if ($Computer) { $scArgs += "\\$Computer" }
        $scArgs += @('sdset', $Service, $newSddl)

        Write-Verbose "Setting new SDDL: $newSddl"
        $result = & "$env:SystemRoot\System32\sc.exe" $scArgs 2>&1
        if ($LASTEXITCODE -ne 0) { 
            throw "Failed to set SDDL. SC.exe returned: $($result -join ' ')" 
        }

        Write-Verbose "Successfully updated service permissions"
    }
    catch {
        Write-Error "Failed to set service permissions: $_"
        return $false
    }
    return $true
}
