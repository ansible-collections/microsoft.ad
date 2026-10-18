# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.

using namespace System.Collections

Function Install-DomainServicesFeature {
    <#
    .SYNOPSIS
    Installs the required features for installing AD DS roles.

    .PARAMETER CheckMode
    If specified, the module will only check if the features are installed and
    return what would have changed without actually installing the features.

    .PARAMETER GetDomainModes
    If specified, the module will return the valid domain and forest modes for
    the currently installed version of Windows.
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]
        $CheckMode,

        [Parameter()]
        [switch]
        $GetDomainModes
    )

    try {
        $requiredFeatures = @("AD-Domain-Services", "RSAT-ADDS")
        $features = Get-WindowsFeature -Name $requiredFeatures
        $unavailableFeatures = Compare-Object -ReferenceObject $requiredFeatures -DifferenceObject $features.Name -PassThru

        if ($unavailableFeatures) {
            throw "The following features required for a domain controller are unavailable: $($unavailableFeatures -join ',')"
        }

        $res = [PSCustomObject]@{
            Changed = $false
            RebootRequired = $false
            ValidDomainModes = @()
            ValidForestModes = @()
        }

        $missingFeatures = $features | Where-Object InstallState -NE Installed
        if ($missingFeatures) {
            $featureRes = Install-WindowsFeature -Name $missingFeatures -WhatIf:$CheckMode
            $res.Changed = $true
            $res.RebootRequired = [bool]$featureRes.RestartNeeded

            # When in check mode and the prereq was "installed" we need to exit early as
            # the AD cmdlets weren't really installed
            if ($CheckMode) {
                return $res
            }
        }

        if (-not $GetDomainModes) {
            return $res
        }

        $cmd = Get-Command -Name Install-ADDSForest
        if ($cmd.Module.PrivateData.ImplicitRemoting) {
            # The ADDSDeployment module does not support pwsh 7 directly and
            # is loaded in an implicit remoting session. We need to get the
            # valid modes from inside that session instead. A future version
            # of Windows may fix this problem and allow us to get the modes
            # directly.
            $winPS = New-PSSession -UseWindowsPowerShell
            try {
                $domainModes, $forestModes = Invoke-Command -Session $winPS -ScriptBlock {
                    $cmd = Get-Command -Name Install-ADDSForest
                    $domainModes = [Enum]::GetNames($cmd.Parameters.DomainMode.ParameterType)
                    $forestModes = [Enum]::GetNames($cmd.Parameters.ForestMode.ParameterType)
                    return $domainModes, $forestModes
                }

                $res.ValidDomainModes = $domainModes
                $res.ValidForestModes = $forestModes
            }
            finally {
                $winPS | Remove-PSSession
            }
        }
        else {
            $res.ValidDomainModes = [Enum]::GetNames($cmd.Parameters.DomainMode.ParameterType)
            $res.ValidForestModes = [Enum]::GetNames($cmd.Parameters.ForestMode.ParameterType)
        }

        $res
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

Function Invoke-ADDSWrapper {
    <#
    .SYNOPSIS
    Invokes the AD DS installation cmdlet requested and handles the common
    logic around error handling, check mode, rebooting, and PowerShell 7
    implicit remoting compatibility.

    .PARAMETER AnsibleModule
    The AnsibleModule object from the calling module.

    .PARAMETER Command
    The AD DS cmdlet to invoke, e.g. Install-ADDSDomain, etc

    .PARAMETER CommandParams
    The parameters to pass to the cmdlet specified in Command.

    .PARAMETER Reboot
    If specified, the module will attempt to reboot the server if the command
    indicates a reboot is required. This is designed to be used by an action
    plugin on the Ansible controller side that can handle the connection being
    closed during the reboot.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]
        $AnsibleModule,

        [Parameter(Mandatory)]
        [ValidateSet('Install-ADDSDomain', 'Install-ADDSDomainController', 'Install-ADDSForest', 'Uninstall-ADDSDomainController')]
        [string]
        $Command,

        [Parameter(Mandatory)]
        [IDictionary]
        $CommandParams,

        [Parameter()]
        [switch]
        $Reboot
    )

    $installer = {
        param([string]$Command, [System.Collections.IDictionary]$CommandParams, [bool]$CheckMode)

        $ErrorActionPreference = 'Stop'

        $res = [PSCustomObject]@{
            RebootRequired = $false
            ActionReboot = $false
            Warning = $null
            ErrorMsg = $null
        }

        try {
            $null = & $Command @CommandParams
            $res.RebootRequired = $true
        }
        catch [Microsoft.DirectoryServices.Deployment.DCPromoExecutionException] {
            # ExitCode 15 == 'Role change is in progress or this computer needs
            # to be restarted.' DCPromo exit codes details can be found at
            # https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/deploy/troubleshooting-domain-controller-deployment
            if ($_.Exception.ExitCode -in @(15, 19)) {
                $res.RebootRequired = $true
                $res.ActionReboot = $true
            }

            $res.ErrorMsg = "Failed to run $Command, DCPromo exited with $($_.Exception.ExitCode): $($_.Exception.Message)"
        }
        catch {
            $res.ErrorMsg = "Failed to run ${Command}: $($_.Exception.Message)"
        }
        finally {
            # The Netlogon service is set to auto start but is not started. This
            # is required for Ansible to connect back to the host and reboot in
            # a later task. Even if this fails Ansible can still connect but
            # only with ansible_winrm_transport=basic so we just display a
            # warning if this fails.
            if (-not $CheckMode) {
                try {
                    Start-Service -Name Netlogon
                }
                catch {
                    $msg = -join @(
                        "Failed to start the Netlogon service after promoting the host, "
                        "Ansible may be unable to connect until the host is manually rebooting: $($_.Exception.Message)"
                    )
                    $res.Warning = $msg
                }
            }
        }

        $res
    }

    $cmd = Get-Command -Name $Command -ErrorAction Stop
    if ($cmd.Module.PrivateData.ImplicitRemoting) {
        # If running in ImplicitRemoting for pwsh 7, we need to call our wrapper
        # inside the WinPS session as it requires access to types not importable
        # in this process.
        $winPS = New-PSSession -UseWindowsPowerShell
        try {
            $res = Invoke-Command -Session $winPS -ScriptBlock $installer -ArgumentList $Command, $CommandParams, $AnsibleModule.CheckMode
        }
        finally {
            $winPS | Remove-PSSession
        }
    }
    else {
        $res = & $installer -Command $Command -CommandParams $CommandParams -CheckMode $AnsibleModule.CheckMode
    }

    # The return value after -WhatIf does not have RebootRequired populated so
    # we manually set reboot_required to True.
    $AnsibleModule.Result.reboot_required = $AnsibleModule.CheckMode -or $res.RebootRequired
    $AnsibleModule.Result._do_action_reboot = $res.ActionReboot
    if ($res.ErrorMsg) {
        $AnsibleModule.FailJson($res.ErrorMsg)
    }
    if ($res.Warning) {
        $AnsibleModule.Warn($res.Warning)
    }

    $AnsibleModule.Result.changed = $true

    if ($Reboot -and $AnsibleModule.Result.reboot_required -and -not $AnsibleModule.CheckMode) {
        # Promoting or depromoting puts the server in a very funky state and it
        # may not be possible for Ansible to connect back without a reboot is
        # done. If the user requested the action plugin to perform the reboot
        # then start it here and get the action plugin to continue where this
        # left off.

        $lastBootTime = (Get-CimInstance -ClassName Win32_OperatingSystem -Property LastBootUpTime).LastBootUpTime.ToFileTime()
        $AnsibleModule.Result._previous_boot_time = $lastBootTime

        $shutdownRegPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked'
        Remove-Item -LiteralPath $shutdownRegPath -Force -ErrorAction SilentlyContinue

        $comment = 'Reboot initiated by Ansible'
        $stdout = $null
        $stderr = . { shutdown.exe /r /t 10 /c $comment | Set-Variable stdout } 2>&1 | ForEach-Object ToString
        if ($LASTEXITCODE -eq 1190) {
            # A reboot was already scheduled, abort it and try again
            shutdown.exe /a
            $stdout = $null
            $stderr = . { shutdown.exe /r /t 10 /c $comment | Set-Variable stdout } 2>&1 | ForEach-Object ToString
        }

        if ($LASTEXITCODE) {
            $AnsibleModule.Result.rc = $LASTEXITCODE
            $AnsibleModule.Result.stdout = $stdout
            $AnsibleModule.Result.stderr = $stderr
            $AnsibleModule.FailJson("Failed to initiate reboot, see rc, stdout, stderr for more information")
        }
    }
}

Export-ModuleMember -Function Install-DomainServicesFeature, Invoke-ADDSWrapper
