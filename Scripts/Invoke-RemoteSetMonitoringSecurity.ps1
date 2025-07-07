# List of servers
$servers = @('server1', 'server2', 'server3')

# Path to local files
$localScript = "$PSScriptRoot\Set-SQLServerMonitoringSecurity.ps1"
$localModule = Join-Path $PSScriptRoot "..\Modules\SQLServerMonitoringSecurity"
$localConfig = Join-Path $PSScriptRoot "..\Config\config.json"

# Remote destination
$remoteBase = "C:\Temp\SqlServerMonitor-LeastPriv"
$remoteScript = "$remoteBase\Scripts\Set-SQLServerMonitoringSecurity.ps1"
$remoteConfig = "$remoteBase\Config\config.json"

# Create sessions
$sessions = $servers | ForEach-Object { New-PSSession -ComputerName $_ }

foreach ($session in $sessions) {
    # Create remote folders
    Invoke-Command -Session $session -ScriptBlock {
        param($remoteBase)
        New-Item -Path $remoteBase -ItemType Directory -Force | Out-Null
        New-Item -Path "$remoteBase\Scripts" -ItemType Directory -Force | Out-Null
        New-Item -Path "$remoteBase\Modules" -ItemType Directory -Force | Out-Null
        New-Item -Path "$remoteBase\Config" -ItemType Directory -Force | Out-Null
    } -ArgumentList $remoteBase

    # Copy files
    Copy-Item $localScript -Destination $remoteScript -ToSession $session
    Copy-Item $localModule -Destination "$remoteBase\Modules" -Recurse -ToSession $session
    Copy-Item $localConfig -Destination $remoteConfig -ToSession $session

    # Run the script or function
    Invoke-Command -Session $session -ScriptBlock {
        & $using:remoteScript -AccountName "DOMAIN\MonitoringAccount" -Verbose
        # Clean-up the remote files
        Remove-Item -Path $using:remoteBase -Recurse -Force
    }
}

# Clean up sessions
$sessions | Remove-PSSession