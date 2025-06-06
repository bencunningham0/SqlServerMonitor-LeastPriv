function Test-LocalGroupMembership {
    <#
    .SYNOPSIS
    Checks if a user is a member of a local group.
    
    .DESCRIPTION
    This function verifies whether a specified user account is a member of a local Windows group.
    It supports checking both domain accounts and local accounts.
    
    .PARAMETER GroupName
    The name of the local group to check membership for.
    
    .PARAMETER MemberName
    The name of the member to check. Can be in DOMAIN\User format or just username.
    
    .EXAMPLE
    Test-LocalGroupMembership -GroupName "Performance Monitor Users" -MemberName "DOMAIN\MonitoringAccount"
    
    Returns $true if the specified account is a member of the Performance Monitor Users group.
    
    .NOTES
    This function handles exceptions gracefully and returns $false if the group doesn't exist
    or if there are permission issues accessing group membership.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GroupName,
        
        [Parameter(Mandatory = $true)]
        [string]$MemberName
    )
    
    try {
        $group = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
        return ($group | Where-Object { $_.Name -eq $MemberName -or $_.Name.EndsWith("\$MemberName") }) -ne $null
    }
    catch {
        Write-Verbose "Failed to check group membership for $MemberName in $GroupName`: $_"
        return $false
    }
}

function Convert-AccountToSid {
    <#
    .SYNOPSIS
    Converts an account name to a Security Identifier (SID).
    
    .DESCRIPTION
    This function converts various account name formats to their corresponding SID values.
    It supports domain accounts, local accounts, and different naming formats.
    
    .PARAMETER account
    The account name to convert. Supports formats:
    - DOMAIN\account
    - account@domain.com
    - account (assumes local computer)
    
    .EXAMPLE
    Convert-AccountToSid -account "DOMAIN\MonitoringAccount"
    
    Returns the SID for the specified domain account.
    
    .EXAMPLE
    Convert-AccountToSid -account "Administrator"
    
    Returns the SID for the local Administrator account.
    
    .NOTES
    This function is essential for security operations that require SID values
    instead of account names, such as service permissions and access control lists.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$account
    )
    
    $computerName = (Get-WmiObject Win32_ComputerSystem).Name

    if ($account.Contains('\')) {
        $domainaccount = $account.Split('\')
        $domain = $domainaccount[0]
        if (($domain -eq ".") -or ($domain -eq "BUILTIN")) {
            $domain = $computerName
        }
        $accountname = $domainaccount[1]
    } elseif ($account.Contains('@')) {
        $domainaccount = $account.Split('@')
        $domain = $domainaccount[1].Split('.')[0]
        $accountname = $domainaccount[0]
    } else {
        $domain = $computerName
        $accountname = $account
    }

    try {
        Write-Verbose "Resolving account: $account"
        $ntAccount = New-Object System.Security.Principal.NTAccount($domain, $accountname)
        $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])
        Write-Verbose "Account resolved to SID: $($sid.Value)"
        
        return $sid.Value  # Return just the SID value instead of a hashtable
    } catch {
        throw "Account was not found or cannot be resolved: $account"
    }
}
