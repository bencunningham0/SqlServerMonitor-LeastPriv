@{
    # Module manifest for SQLServerMonitoringSecurity
    RootModule = 'SQLServerMonitoringSecurity.psm1'
    ModuleVersion = '0.0.1'
    GUID = '9e3d5cc8-665c-4135-8ac7-c0d432cf4de2'
    Description = 'PowerShell module for configuring least privilege security permissions for SQL DB monitoring accounts'
    
    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '4.0'
    
    # Functions to export from this module
    FunctionsToExport = @(
        'Set-SQLServerMonitoringPermissions',
        'Add-ServiceAcl',
        'Set-WmiNamespaceSecurity',
        'Set-SqlLogPermissions',
        'Set-SqlLogsShare',
        'Test-LocalGroupMembership',
        'Convert-AccountToSid',
        'Restart-ServiceWithDependants'
    )
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            Tags = @('Security', 'Permissions', 'WMI', 'SQL', 'Services')
            LicenseUri = ''
            ProjectUri = ''
            IconUri = ''
            ReleaseNotes = 'Initial release of SQLServerMonitoringSecurity module'
        }
    }
}
