function Restart-ServiceWithDependants {
    <#
    .SYNOPSIS
    Restarts a Windows service along with its dependent services.
    
    .DESCRIPTION
    This function restarts a specified Windows service and its dependent services in the correct order.
    It ensures that only services that are currently running are stopped and restarted, leaving
    stopped dependent services unchanged to maintain system stability.
    
    .PARAMETER ServiceName
    The name of the service to restart.
    
    .EXAMPLE
    Restart-ServiceWithDependants -ServiceName "Winmgmt"
    
    Restarts the WMI service and all its running dependent services.
    
    .EXAMPLE
    Restart-ServiceWithDependants -ServiceName "wuauserv"
    
    Restarts the Windows Update service and its dependencies.
    
    .NOTES
    From: https://gallery.technet.microsoft.com/PowerShell-Script-for-8243e5d1
    This function maintains the original system services state after restart.
    Only services that were running before the restart will be started again.
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)] 
        [String]$ServiceName
    )

    [System.Collections.ArrayList]$ServicesToRestart = @()

    function Get-DependServices ($ServiceInput) {
        Write-Verbose "Analyzing service: $($ServiceInput.Name)"
        Write-Verbose "Number of dependents: $($ServiceInput.DependentServices.Count)"
        
        If ($ServiceInput.DependentServices.Count -gt 0) {
            ForEach ($DepService in $ServiceInput.DependentServices) {
                Write-Verbose "Dependent of $($ServiceInput.Name): $($DepService.Name)"
                If ($DepService.Status -eq "Running") {
                    Write-Verbose "$($DepService.Name) is running."
                    $CurrentService = Get-Service -Name $DepService.Name
                    
                    # Get dependencies of running service recursively
                    Get-DependServices $CurrentService                
                }
                Else {
                    Write-Verbose "$($DepService.Name) is stopped. No need to stop or start or check dependencies."
                }
            }
        }
        
        Write-Verbose "Service to restart: $($ServiceInput.Name)"
        if ($ServicesToRestart.Contains($ServiceInput.Name) -eq $false) {
            Write-Verbose "Adding service to restart: $($ServiceInput.Name)"
            $ServicesToRestart.Add($ServiceInput.Name) | Out-Null
        }
    }

    try {
        # Get the main service
        $Service = Get-Service -Name $ServiceName -ErrorAction Stop

        # Get dependencies and determine stop order
        Get-DependServices -ServiceInput $Service

        Write-Verbose "Stopping Services"
        foreach($ServiceToStop in $ServicesToRestart) {
            Write-Verbose "Stopping service: $ServiceToStop"
            Stop-Service $ServiceToStop -Verbose -ErrorAction Continue
        }
        
        Write-Verbose "Starting Services"
        # Reverse stop order to get start order
        $ServicesToRestart.Reverse()

        foreach($ServiceToStart in $ServicesToRestart) {
            Write-Verbose "Starting service: $ServiceToStart"
            Start-Service $ServiceToStart -Verbose -ErrorAction Continue
        }
        
        Write-Verbose "Restart of services completed"
    }
    catch {
        Write-Error "Failed to restart service $ServiceName and its dependents: $_"
        throw
    }
}
