<#
    Register-LogShipperTask.ps1

    Registers Copy-WASHistoricalLogs.ps1 as a Windows Scheduled Task that runs
    continuously and heals itself in production, without relying on any
    third-party service wrapper (NSSM, etc.).

    WHY TWO TRIGGERS:
      - "At startup"    - starts the shipper when the box boots.
      - "Every 1 minute, forever" watchdog - combined with
        -MultipleInstances IgnoreNew, this trigger is a no-op whenever the
        shipper is already running (Task Scheduler just skips launching a
        second copy). If the process ever dies (crash, OOM, host reclaim),
        the very next minute's tick relaunches it. This avoids the normal
        "Restart on failure" setting's capped restart count, which is not
        enough for a process meant to run indefinitely.
      - ExecutionTimeLimit is explicitly set to zero (no limit). Task
        Scheduler's default execution time limit is 72 hours - without
        clearing it, Task Scheduler would kill this long-running script
        after 3 days.
      - The internal named Mutex in Copy-WASHistoricalLogs.ps1 is a second,
        independent guard against double-running (e.g. someone launches the
        script by hand while the task is also active).

    This script is idempotent: re-running it replaces any existing task of
    the same name with the current settings.

    USAGE (run elevated, as an administrator):

      # Run under a domain service account that already has write access to
      # the destination share (recommended - simplest permissions story):
      .\Register-LogShipperTask.ps1 `
          -ScriptPath 'C:\WebSphere\LogShipper\Copy-WASHistoricalLogs.ps1' `
          -SourcePath 'C:\WebSphere\AppServer\profiles\AppSrv01\logs\server1' `
          -DestinationPath '\\fileshare\WASLogArchive' `
          -TaskUser 'CONTOSO\svc-was-logshipper'

      # Run as SYSTEM instead (no password to manage), with the shipper
      # script authenticating to the share itself via -CredentialPath - see
      # the note on DPAPI scope in that script's header before choosing this:
      .\Register-LogShipperTask.ps1 `
          -ScriptPath 'C:\WebSphere\LogShipper\Copy-WASHistoricalLogs.ps1' `
          -SourcePath 'C:\WebSphere\AppServer\profiles\AppSrv01\logs\server1' `
          -DestinationPath '\\fileshare\WASLogArchive' `
          -UseSystemAccount

      # Also drop a static XML copy of the registered task (e.g. to check
      # into config management or import elsewhere with schtasks /create /xml):
      .\Register-LogShipperTask.ps1 ... -ExportXmlPath 'C:\WebSphere\LogShipper\WAS-LogShipper.task.xml'
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$TaskName = 'WAS-LogShipper',

    [Parameter(Mandatory = $true)]
    [string]$ScriptPath,

    [Parameter(Mandatory = $true)]
    [string]$SourcePath,

    [Parameter(Mandatory = $true)]
    [string]$DestinationPath,

    [string]$CredentialPath,

    [string]$ScriptLogPath = 'C:\WebSphere\LogShipper\LogShipper.log',

    # Account the *task* runs under. Ignored if -UseSystemAccount is set.
    # If omitted (and -UseSystemAccount is not set), you'll be prompted for
    # credentials interactively - never hardcode a password in this file.
    [string]$TaskUser,

    [switch]$UseSystemAccount,

    [string]$ExportXmlPath
)

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This script must be run elevated (as Administrator) to register a scheduled task.'
}

if (-not (Test-Path -LiteralPath $ScriptPath)) {
    throw "ScriptPath '$ScriptPath' does not exist."
}

Import-Module ScheduledTasks -ErrorAction Stop

# ---------------------------------------------------------------------------
# Build the action: powershell.exe running the shipper with fixed arguments.
# ---------------------------------------------------------------------------
$argParts = @(
    '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden',
    '-File', ('"{0}"' -f $ScriptPath),
    '-SourcePath', ('"{0}"' -f $SourcePath),
    '-DestinationPath', ('"{0}"' -f $DestinationPath),
    '-ScriptLogPath', ('"{0}"' -f $ScriptLogPath)
)
if ($CredentialPath) {
    $argParts += @('-CredentialPath', ('"{0}"' -f $CredentialPath))
}
$argString = $argParts -join ' '

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $argString -WorkingDirectory (Split-Path -Parent $ScriptPath)

# ---------------------------------------------------------------------------
# Triggers: at startup, plus a forever-repeating watchdog tick.
# ---------------------------------------------------------------------------
$startupTrigger = New-ScheduledTaskTrigger -AtStartup

$watchdogTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 1) -RepetitionDuration ([TimeSpan]::MaxValue)

# ---------------------------------------------------------------------------
# Settings: no execution time limit, ignore the watchdog tick while an
# instance is already running, start ASAP if a trigger was missed.
# ---------------------------------------------------------------------------
$settings = New-ScheduledTaskSettingsSet `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1) `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries

# ---------------------------------------------------------------------------
# Principal (identity the task runs as).
# ---------------------------------------------------------------------------
if ($UseSystemAccount) {
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
} else {
    if (-not $TaskUser) {
        $cred = Get-Credential -Message "Account to run scheduled task '$TaskName' as (needs write access to $DestinationPath unless -CredentialPath is used)"
    } else {
        $cred = Get-Credential -UserName $TaskUser -Message "Password for '$TaskUser' (account that will run scheduled task '$TaskName')"
    }
}

# ---------------------------------------------------------------------------
# Register (idempotent - replace any existing task of the same name).
# ---------------------------------------------------------------------------
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
    if ($PSCmdlet.ShouldProcess($TaskName, 'Unregister existing scheduled task before re-registering')) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Register scheduled task')) {
    if ($UseSystemAccount) {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($startupTrigger, $watchdogTrigger) `
            -Settings $settings -Principal $principal -Description 'Ships WebSphere historical JVM logs to a file share. Managed by Register-LogShipperTask.ps1.' | Out-Null
    } else {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger @($startupTrigger, $watchdogTrigger) `
            -Settings $settings -User $cred.UserName -Password $cred.GetNetworkCredential().Password -RunLevel Highest `
            -Description 'Ships WebSphere historical JVM logs to a file share. Managed by Register-LogShipperTask.ps1.' | Out-Null
    }
    Write-Host "Registered scheduled task '$TaskName'."
}

if ($ExportXmlPath) {
    if ($PSCmdlet.ShouldProcess($ExportXmlPath, 'Export task definition as XML')) {
        (Get-ScheduledTask -TaskName $TaskName | Export-ScheduledTask) | Out-File -FilePath $ExportXmlPath -Encoding unicode
        Write-Host "Exported task definition to '$ExportXmlPath'."
        Write-Host "  (import elsewhere with: schtasks /create /tn `"$TaskName`" /xml `"$ExportXmlPath`")"
    }
}

if ($PSCmdlet.ShouldProcess($TaskName, 'Start scheduled task now')) {
    Start-ScheduledTask -TaskName $TaskName
    Write-Host "Started '$TaskName'. Check $ScriptLogPath for activity."
}
