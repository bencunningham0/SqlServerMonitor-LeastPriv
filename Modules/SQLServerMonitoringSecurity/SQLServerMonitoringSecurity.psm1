# SQLServerMonitoringSecurity PowerShell Module
# Main module file that imports all function modules

# Get the directory where this module is located
$ModuleRoot = $PSScriptRoot

# Import all function files
$FunctionFiles = Get-ChildItem -Path "$ModuleRoot\Functions" -Filter "*.ps1" -Recurse

foreach ($FunctionFile in $FunctionFiles) {
    Write-Verbose "Importing function file: $($FunctionFile.Name)"
    . $FunctionFile.FullName
}

# Export module members
Export-ModuleMember -Function @(
    'Set-SQLServerMonitoringPermissions',
    'Add-ServiceAcl',
    'Set-WmiNamespaceSecurity', 
    'Set-SqlLogPermissions',
    'Set-SqlLogsShare',
    'Test-LocalGroupMembership',
    'Convert-AccountToSid',
    'Restart-ServiceWithDependants'
)
