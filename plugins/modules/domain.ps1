#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._DomainFeature

$spec = @{
    options = @{
        create_dns_delegation = @{
            type = 'bool'
        }
        database_path = @{
            type = 'path'
        }
        dns_domain_name = @{
            required = $true
            type = 'str'
        }
        domain_mode = @{
            type = 'str'
        }
        domain_netbios_name = @{
            type = 'str'
        }
        forest_mode = @{
            type = 'str'
        }
        install_dns = @{
            default = $true
            type = 'bool'
        }
        log_path = @{
            type = 'path'
        }
        reboot = @{
            default = $false
            type = 'bool'
        }
        reboot_timeout = @{
            default = 600
            type = 'int'
        }
        safe_mode_password = @{
            no_log = $true
            required = $true
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$create_dns_delegation = $module.Params.create_dns_delegation
$database_path = $module.Params.database_path
$dns_domain_name = $module.Params.dns_domain_name
$domain_mode = $module.Params.domain_mode
$domain_netbios_name = $module.Params.domain_netbios_name
$forest_mode = $module.Params.forest_mode
$install_dns = $module.Params.install_dns
$log_path = $module.Params.log_path
$safe_mode_password = $module.Params.safe_mode_password
$sysvol_path = $module.Params.sysvol_path

if ([System.Environment]::OSVersion.Version -lt [Version]"6.2") {
    $module.FailJson("microsoft.ad.domain requires Windows Server 2012 or higher")
}

if ($domain_netbios_name -and $domain_netbios_name.Length -gt 15) {
    $module.FailJson("The parameter 'domain_netbios_name' should not exceed 15 characters in length")
}

$featureRes = Install-DomainServicesFeature -CheckMode:$module.CheckMode -GetDomainModes
$module.Result.changed = $featureRes.Changed
$module.Result.reboot_required = $featureRes.RebootRequired

if ($featureRes.Changed -and $module.CheckMode) {
    # If we had to install features in check mode then we need to exit early as
    # the AD cmdlets won't be available
    $module.ExitJson()
}

# Check that we got a valid domain_mode
$validDomainModes = $featureRes.ValidDomainModes
if (($null -ne $domain_mode) -and -not ($domain_mode -in $validDomainModes)) {
    $validModes = $validDomainModes -join ", "
    $module.FailJson("The parameter 'domain_mode' does not accept '$domain_mode', please use one of: $validModes")
}

# Check that we got a valid forest_mode
$validForestModes = $featureRes.ValidForestModes
if (($null -ne $forest_mode) -and -not ($forest_mode -in $validForestModes)) {
    $validModes = $validForestModes -join ", "
    $module.FailJson("The parameter 'forest_mode' does not accept '$forest_mode', please use one of: $validModes")
}

try {
    $forestContext = New-Object -TypeName System.DirectoryServices.ActiveDirectory.DirectoryContext -ArgumentList @(
        'Forest', $dns_domain_name
    )
    $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($forestContext)
}
catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
    $forest = $null
}
catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryOperationException] {
    $forest = $null
}

# Check if the host is already a domain controller
try {
    Get-ADDomainController | Out-Null
    $host_is_dc = $true
}
catch {
    $host_is_dc = $null
}

# Only installing the domain if the forest does not exist or the host is not a domain controller
# This is to avoid an issue where the domain already exists in another domain controller but the host itself is not a DC leaving the host in a limbo state
if (-not $forest -or -not $host_is_dc) {
    $installParams = @{
        DomainName = $dns_domain_name
        SafeModeAdministratorPassword = (ConvertTo-SecureString $safe_mode_password -AsPlainText -Force)
        Confirm = $false
        SkipPreChecks = $true
        InstallDns = $install_dns
        NoRebootOnCompletion = $true
        WhatIf = $module.CheckMode
    }

    if ($database_path) {
        $installParams.DatabasePath = $database_path
    }

    if ($sysvol_path) {
        $installParams.SysvolPath = $sysvol_path
    }

    if ($log_path) {
        $installParams.LogPath = $log_path
    }

    if ($domain_netbios_name) {
        $installParams.DomainNetBiosName = $domain_netbios_name
    }

    if ($null -ne $create_dns_delegation) {
        $installParams.CreateDnsDelegation = $create_dns_delegation
    }

    if ($domain_mode) {
        $installParams.DomainMode = $domain_mode
    }

    if ($forest_mode) {
        $installParams.ForestMode = $forest_mode
    }

    $wrapperParams = @{
        AnsibleModule = $module
        Command = 'Install-ADDSForest'
        CommandParams = $installParams
    }
    Invoke-ADDSWrapper @wrapperParams
}

$module.ExitJson()
