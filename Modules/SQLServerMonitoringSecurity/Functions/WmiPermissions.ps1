function Set-WmiNamespaceSecurity {
    <#
    .SYNOPSIS
    Sets security permissions for WMI namespaces.

    .DESCRIPTION
    This function allows you to add or delete security permissions for a specified WMI namespace.
    It modifies the WMI namespace security descriptor to grant or revoke specific permissions
    for user accounts or groups.

    .PARAMETER namespace
    The WMI namespace to modify (e.g., "root\cimv2").

    .PARAMETER operation
    The operation to perform: "add" or "delete".

    .PARAMETER account
    The account to which the permissions will be applied.

    .PARAMETER permissions
    The permissions to set (only required for "add" operation). Valid values include:
    - enable: Permission to enable WMI operations
    - methodexecute: Permission to execute WMI methods
    - fullwrite: Permission for full write access
    - partialwrite: Permission for partial write access
    - providerwrite: Permission for provider write access
    - remoteaccess: Permission for remote access
    - readsecurity: Permission to read security descriptors
    - writesecurity: Permission to write security descriptors

    .PARAMETER allowInherit
    Whether to allow inheritance of permissions.

    .PARAMETER deny
    Whether to deny the specified permissions.

    .PARAMETER computerName
    The name of the computer where the WMI namespace is located (default is local computer).

    .PARAMETER credential
    Credentials for remote access if needed.
    
    .PARAMETER restart
    Whether to restart the WMI service after making changes.
    
    .EXAMPLE
    Set-WmiNamespaceSecurity -namespace "root\cimv2" -operation "add" -account "DOMAIN\User" -permissions "enable", "readsecurity"
    
    Adds the specified permissions for the user in the given namespace.
    
    .EXAMPLE
    Set-WmiNamespaceSecurity -namespace "root\cimv2" -operation "delete" -account "DOMAIN\User"
    
    Deletes all permissions for the user in the given namespace.

    .NOTES
    Converted to function from https://github.com/grbray/PowerShell/blob/main/Windows/Set-WMINameSpaceSecurity.ps1
    Requires administrative privileges to modify WMI namespace security.
    #>
    Param ( 
        [parameter(Mandatory=$true,Position=0)]
        [string] $namespace,

        [parameter(Mandatory=$true,Position=1)]
        [ValidateSet("add", "delete")]
        [string] $operation,

        [parameter(Mandatory=$true,Position=2)]
        [string] $account,

        [parameter(Position=3)]
        [ValidateSet("partialwrite", "enable", "providerwrite", "readsecurity", "writesecurity", "methodexecute", "remoteaccess", "fullwrite")]
        [string[]] $permissions = $null,

        [bool] $allowInherit = $false,

        [bool] $deny = $false,

        [string] $computerName = ".",

        [System.Management.Automation.PSCredential] $credential = $null,

        [Parameter()]
        [switch]$restart = $false)
    
    Process {
        $ErrorActionPreference = "Stop"
        $changesApplied = $false
        $ACCESS_ALLOWED_ACE_TYPE = 0x0
        $ACCESS_DENIED_ACE_TYPE = 0x1
        
        # Add helper function to check existing permissions
        Function Test-ExistingPermissions {
            param (
                [System.Management.ManagementBaseObject[]]$DACL,
                [string]$SID,
                [int]$RequiredMask,
                [int]$AceType
            )
            
            foreach ($ace in $DACL) {
                Write-Verbose "Checking ACE: SID=$($ace.Trustee.SidString), Type=$($ace.AceType), Mask=$($ace.AccessMask)"
                
                if ($ace.Trustee.SidString -eq $SID -and 
                    $ace.AceType -eq $AceType -and
                    ($ace.AccessMask -band $RequiredMask) -eq $RequiredMask) {
                    Write-Verbose "Found matching permissions for SID $SID"
                    return $true
                }
            }
            Write-Verbose "No matching permissions found for SID $SID with required mask $RequiredMask"
            return $false
        }

        Write-Verbose "Starting WMI namespace security modification for namespace: $namespace"
        
        Function Get-AccessMaskFromPermission($permissions) {
            $WBEM_ENABLE = 1
            $WBEM_METHOD_EXECUTE = 2
            $WBEM_FULL_WRITE_REP = 4
            $WBEM_PARTIAL_WRITE_REP = 8
            $WBEM_WRITE_PROVIDER = 0x10
            $WBEM_REMOTE_ACCESS = 0x20
            $WBEM_RIGHT_SUBSCRIBE = 0x40
            $WBEM_RIGHT_PUBLISH = 0x80
            $READ_CONTROL = 0x20000
            $WRITE_DAC = 0x40000
        
            $WBEM_RIGHTS_FLAGS = $WBEM_ENABLE,$WBEM_METHOD_EXECUTE,$WBEM_FULL_WRITE_REP,`
                $WBEM_PARTIAL_WRITE_REP,$WBEM_WRITE_PROVIDER,$WBEM_REMOTE_ACCESS,`
                $READ_CONTROL,$WRITE_DAC
            $WBEM_RIGHTS_STRINGS = "Enable","MethodExecute","FullWrite","PartialWrite",`
                "ProviderWrite","RemoteAccess","ReadSecurity","WriteSecurity"
    
            $permissionTable = @{}
    
            for ($i = 0; $i -lt $WBEM_RIGHTS_FLAGS.Length; $i++) {
                $permissionTable.Add($WBEM_RIGHTS_STRINGS[$i].ToLower(), $WBEM_RIGHTS_FLAGS[$i])
            }
        
            $accessMask = 0
    
            foreach ($permission in $permissions) {
                if (-not $permissionTable.ContainsKey($permission.ToLower())) {
                    throw "Unknown permission: $permission`nValid permissions: $($permissionTable.Keys)"
                }
                $accessMask += $permissionTable[$permission.ToLower()]
            }
        
            $accessMask
        }
    
        if ($PSBoundParameters.ContainsKey("Credential")) {
            $remoteparams = @{ComputerName=$computerName;Credential=$credential}
        } else {
            $remoteparams = @{ComputerName=$computerName}
        }
        
        $invokeparams = @{Namespace=$namespace;Path="__systemsecurity=@"} + $remoteParams
    
        $output = Invoke-WmiMethod @invokeparams -Name GetSecurityDescriptor
        Write-Verbose "Retrieved security descriptor for namespace $namespace"
        if ($output.ReturnValue -ne 0) {
            throw "GetSecurityDescriptor failed: $($output.ReturnValue)"
        }
    
        $acl = $output.Descriptor
        $OBJECT_INHERIT_ACE_FLAG = 0x1
        $CONTAINER_INHERIT_ACE_FLAG = 0x2
    
        $computerName = (Get-WmiObject @remoteparams Win32_ComputerSystem).Name
    
        $win32account = Convert-AccountToSid -account $account
        if ($win32account -eq $null) {
            throw "Account was not found: $account"
        }
    
        switch ($operation) {
            "add" {
                Write-Verbose "Adding permissions for account: $account"
                if ($permissions -eq $null) {
                    throw "-Permissions must be specified for an add operation"
                }
                $accessMask = Get-AccessMaskFromPermission($permissions)
                Write-Verbose "Access mask calculated: $accessMask"
    
                # Check if permissions already exist
                if (Test-ExistingPermissions -DACL $acl.DACL -SID $win32account -RequiredMask $accessMask -AceType $ACCESS_ALLOWED_ACE_TYPE) {
                    Write-Verbose "Account $account already has the requested permissions"
                } else {
                    $ace = (New-Object System.Management.ManagementClass("win32_Ace")).CreateInstance()
                    $ace.AccessMask = $accessMask
                    if ($allowInherit) {
                        $ace.AceFlags = $CONTAINER_INHERIT_ACE_FLAG
                    } else {
                        $ace.AceFlags = 0
                    }
                        
                    $trustee = (New-Object System.Management.ManagementClass("win32_Trustee")).CreateInstance()
                    $trustee.SidString = $win32account
                    $ace.Trustee = $trustee
        
    
                    if ($deny) {
                        $ace.AceType = $ACCESS_DENIED_ACE_TYPE
                    } else {
                        $ace.AceType = $ACCESS_ALLOWED_ACE_TYPE
                    }
    
                    $acl.DACL += $ace.psobject.immediateBaseObject
                    $changesApplied = $true
                    Write-Verbose "Added new ACE to DACL"
                }
            }
        
            "delete" {
                Write-Verbose "Removing permissions for account: $account"
                if ($permissions -ne $null) {
                    throw "Permissions cannot be specified for a delete operation"
                }
        
                [System.Management.ManagementBaseObject[]]$newDACL = @()
                foreach ($ace in $acl.DACL) {
                    if ($ace.Trustee.SidString -ne $win32account) {
                        $newDACL += $ace.psobject.immediateBaseObject
                    }
                }
                if ($acl.DACL.Length -ne $newDACL.Length) {
                    $changesApplied = $true
                }
                Write-Verbose "Removed $(($acl.DACL.Length - $newDACL.Length)) ACE entries for $account"
                $acl.DACL = $newDACL.psobject.immediateBaseObject
            }
        }
    
        $setparams = @{Name="SetSecurityDescriptor";ArgumentList=$acl.psobject.immediateBaseObject} + $invokeParams
        Write-Verbose "Applying security descriptor changes"
    
        $output = Invoke-WmiMethod @setparams
        if ($output.ReturnValue -ne 0) {
            throw "SetSecurityDescriptor failed: $($output.ReturnValue)"
        }
        Write-Verbose "Successfully updated WMI namespace security"

        if ($restart -and $changesApplied) {
            Restart-ServiceWithDependants -ServiceName "Winmgmt"
        }
        elseif ($restart) {
            Write-Verbose "No changes were made - skipping service restart"
        }
    }
}
