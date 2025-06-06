function Set-SqlLogPermissions {
    <#
    .SYNOPSIS
    Sets file system permissions for SQL Server log directory.
    
    .DESCRIPTION
    This function locates the SQL Server installation directory and grants the specified
    user account Modify permissions on the SQL Server log directory. This is typically
    required for monitoring accounts that need to read SQL Server log files.
    
    .PARAMETER UserAccount
    The user account or group to grant permissions to, in DOMAIN\User format.
    
    .EXAMPLE
    Set-SqlLogPermissions -UserAccount "DOMAIN\User"
    
    Grants Modify permissions to the specified group managed service account on the SQL Server logs directory.
    
    .NOTES
    This function requires administrative privileges to modify file system permissions.
    The function will automatically locate the SQL Server installation path from the registry.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserAccount
    )

    try {
        # Test account
        if (-not (Convert-AccountToSid -account $UserAccount)) {
            throw "Account $UserAccount does not exist or cannot be resolved"
        }

        # Find SQL Server instance path from registry
        $sqlPath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*.MSSQLSERVER\Setup" -ErrorAction Stop | 
            Select-Object -ExpandProperty SQLPath -First 1

        if (-not $sqlPath) {
            throw "SQL Server installation path not found"
        }

        # Construct logs path
        $logsPath = Join-Path $sqlPath "Log"
        
        if (-not (Test-Path $logsPath)) {
            throw "SQL Server logs directory not found at: $logsPath"
        }

        # Get current ACL
        $acl = Get-Acl $logsPath

        # Check if permission already exists
        $exists = $acl.Access | Where-Object {
            $_.IdentityReference -eq $UserAccount -and
            $_.FileSystemRights -like "*Modify*" -and
            $_.InheritanceFlags -eq "ContainerInherit, ObjectInherit" -and
            $_.PropagationFlags -eq "None" -and
            $_.AccessControlType -eq "Allow"
        }

        if ($exists) {
            Write-Verbose "Permission already exists for $UserAccount on $logsPath"
            return
        }

        # Create new rule
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $UserAccount,
            "Modify",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )

        # Add rule and set ACL
        $acl.AddAccessRule($rule)
        Set-Acl -Path $logsPath -AclObject $acl

        Write-Verbose "Successfully granted Modify permissions to $UserAccount on $logsPath"
    }
    catch {
        Write-Error "Failed to set permissions: $_"
    }
}

function Set-SqlLogsShare {
    <#
    .SYNOPSIS
    Creates and configures a network share for SQL Server logs.
    
    .DESCRIPTION
    This function creates a hidden network share for the SQL Server logs directory
    and grants read-only access to the specified user account. This allows remote
    monitoring tools to access SQL Server logs over the network.
    
    .PARAMETER UserAccount
    The user account or group to grant read access to the share.
    
    .EXAMPLE
    Set-SqlLogsShare -UserAccount "DOMAIN\MonitoringAccount"
    
    Creates a SQLLogs$ share and grants read access to the specified account.
    
    .NOTES
    This function requires administrative privileges to create network shares and modify share permissions.
    The share is created as a hidden share (ending with $) for security purposes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$UserAccount
    )

    try {
        # Test account
        if (-not (Convert-AccountToSid -account $UserAccount)) {
            throw "Account $UserAccount does not exist or cannot be resolved"
        }

        # Find SQL Server instance path from registry
        $sqlPath = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL*.MSSQLSERVER\Setup" -ErrorAction Stop | 
            Select-Object -ExpandProperty SQLPath -First 1

        if (-not $sqlPath) {
            throw "SQL Server installation path not found"
        }

        # Construct logs path
        $logsPath = Join-Path $sqlPath "Log"
        
        if (-not (Test-Path $logsPath)) {
            throw "SQL Server logs directory not found at: $logsPath"
        }

        $shareName = "SQLLogs$"
        
        # Check if share already exists
        $existingShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
        
        if (-not $existingShare) {
            # Create the share
            New-SmbShare -Name $shareName -Path $logsPath -Description "SQL Server Logs" -ErrorAction Stop
            
            # Remove Everyone permissions for security
            Revoke-SmbShareAccess -Name $shareName -AccountName "Everyone" -Force
            Write-Verbose "Removed Everyone permissions from share $shareName"
            
            Write-Verbose "Created share $shareName at path $logsPath"
        } else {
            Write-Verbose "Share $shareName already exists"
        }

        # Check if permission already exists
        $existingAccess = Get-SmbShareAccess -Name $shareName | Where-Object { 
            $_.AccountName -eq $UserAccount -and $_.AccessRight -eq "Read"
        }

        if (-not $existingAccess) {
            # Grant read-only permissions
            Grant-SmbShareAccess -Name $shareName -AccountName $UserAccount -AccessRight Read -Force
            Write-Verbose "Granted Read permissions to $UserAccount on share $shareName"
        } else {
            Write-Verbose "Read permissions already exist for $UserAccount on share $shareName"
        }
    }
    catch {
        Write-Error "Failed to configure SQL logs share: $_"
    }
}
