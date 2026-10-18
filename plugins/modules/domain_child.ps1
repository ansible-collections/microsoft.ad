#!powershell

# Copyright (c) 2024 Ansible Project
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
            type = 'str'
        }
        domain_admin_password = @{
            type = 'str'
            required = $true
            no_log = $true
        }
        domain_admin_user = @{
            type = 'str'
            required = $true
        }
        domain_mode = @{
            type = 'str'
        }
        domain_type = @{
            choices = 'child', 'tree'
            default = 'child'
            type = 'str'
        }
        install_dns = @{
            type = 'bool'
        }
        log_path = @{
            type = 'path'
        }
        parent_domain_name = @{
            type = 'str'
        }
        reboot = @{
            default = $false
            type = 'bool'
        }
        reboot_timeout = @{
            default = 600
            type = 'int'
        }
        replication_source_dc = @{
            type = 'str'
        }
        safe_mode_password = @{
            type = 'str'
            required = $true
            no_log = $true
        }
        site_name = @{
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    required_if = @(
        , @('domain_type', 'tree', @('parent_domain_name'))
    )
    required_together = @(
        , @("domain_admin_user", "domain_admin_password")
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$createDnsDelegation = $module.Params.create_dns_delegation
$databasePath = $module.Params.database_path
$dnsDomainName = $module.Params.dns_domain_name
$domainMode = $module.Params.domain_mode
$domainType = $module.Params.domain_type
$installDns = $module.Params.install_dns
$logPath = $module.Params.log_path
$parentDomainName = $module.Params.parent_domain_name
$replicationSourceDC = $module.Params.replication_source_dc
$safeModePassword = $module.Params.safe_mode_password
$siteName = $module.Params.site_name
$sysvolPath = $module.Params.sysvol_path

$domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
    $module.Params.domain_admin_user,
    (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_admin_password)
)

if ($domainType -eq 'child' -and $parentDomainName) {
    $module.FailJson("parent_domain_name must not be set when domain_type=child")
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
if (($null -ne $domainMode) -and -not ($domainMode -in $validDomainModes)) {
    $validModes = $validDomainModes -join ", "
    $module.FailJson("The parameter 'domain_mode' does not accept '$domainMode', please use one of: $validModes")
}

$systemRole = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, DomainRole
if ($systemRole.DomainRole -in @(4, 5)) {
    if ($systemRole.Domain -ne $dnsDomainName) {
        $module.FailJson("Host is already a domain controller in another domain $($systemRole.Domain)")
    }
    $module.ExitJson()
}

$installParams = @{
    Confirm = $false
    Credential = $domainCredential
    Force = $true
    NoRebootOnCompletion = $true
    SafeModeAdministratorPassword = (ConvertTo-SecureString $safeModePassword -AsPlainText -Force)
    SkipPreChecks = $true
    WhatIf = $module.CheckMode
}

if ($domainType -eq 'child') {
    $newDomainName, $parentDomainName = $dnsDomainName.Split([char[]]".", 2)
    $installParams.DomainType = 'ChildDomain'
    $installParams.NewDomainName = $newDomainName
    $installParams.ParentDomainName = $parentDomainName
}
else {
    $installParams.DomainType = 'TreeDomain'
    $installParams.NewDomainName = $dnsDomainName
    $installParams.ParentDomainName = $parentDomainName
}

if ($null -ne $createDnsDelegation) {
    $installParams.CreateDnsDelegation = $createDnsDelegation
}
if ($databasePath) {
    $installParams.DatabasePath = $databasePath
}
if ($domainMode) {
    $installParams.DomainMode = $domainMode
}
if ($null -ne $installDns) {
    $installParams.InstallDns = $installDns
}
if ($logPath) {
    $installParams.LogPath = $logPath
}
if ($replicationSourceDC) {
    $installParams.ReplicationSourceDC = $replicationSourceDC
}
if ($siteName) {
    $installParams.SiteName = $siteName
}
if ($sysvolPath) {
    $installParams.SysvolPath = $sysvolPath
}

$wrapperParams = @{
    AnsibleModule = $module
    Command = 'Install-ADDSDomain'
    CommandParams = $installParams
    Reboot = $module.Params.reboot
}
Invoke-ADDSWrapper @wrapperParams

$module.ExitJson()
