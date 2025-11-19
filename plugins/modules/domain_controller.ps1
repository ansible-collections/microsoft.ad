#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._DomainFeature

$spec = @{
    options = @{
        database_path = @{
            type = 'path'
        }
        dns_domain_name = @{
            type = 'str'
        }
        domain_admin_password = @{
            no_log = $true
            required = $true
            type = 'str'
        }
        domain_admin_user = @{
            required = $true
            type = 'str'
        }
        domain_log_path = @{
            # FUTURE: Add alias for log_path once some time has passed
            type = 'path'
        }
        install_dns = @{
            type = 'bool'
        }
        install_media_path = @{
            type = 'path'
        }
        local_admin_password = @{
            no_log = $true
            type = 'str'
        }
        read_only = @{
            default = $false
            type = 'bool'
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
            no_log = $true
            type = 'str'
        }
        site_name = @{
            type = 'str'
        }
        state = @{
            choices = 'domain_controller', 'member_server'
            required = $true
            type = 'str'
        }
        sysvol_path = @{
            type = 'path'
        }
    }
    required_if = @(
        , @('state', 'domain_controller', @('dns_domain_name', 'safe_mode_password'))
        , @('state', 'member_server', @(, 'local_admin_password'))
    )
    supports_check_mode = $true
}
$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.reboot_required = $false
$module.Result._do_action_reboot = $false  # Used by action plugin

$databasePath = $module.Params.database_path
$dnsDomainName = $module.Params.dns_domain_name
$installDns = $module.Params.install_dns
$installMediaPath = $module.Params.install_media_path
$logPath = $module.Params.domain_log_path
$readOnly = $module.Params.read_only
$replicationSourceDC = $module.Params.replication_source_dc
$siteName = $module.Params.site_name
$state = $module.Params.state
$sysvolPath = $module.Params.sysvol_path

$domainCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
    $module.Params.domain_admin_user,
    (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_admin_password)
)

if ([System.Environment]::OSVersion.Version -lt [Version]"6.2") {
    $module.FailJson("microsoft.ad.domain_controller requires Windows Server 2012 or higher")
}

# short-circuit "member server" check, since we don't need feature checks for this...
# role 4/5 - backup/primary DC
$win32CS = Get-CimInstance -ClassName Win32_ComputerSystem -Property Domain, DomainRole
$isKdc = $win32CS.DomainRole -in @(4, 5)
If ($state -eq "member_server" -and -not $isKdc) {
    $module.ExitJson()
}

$featureRes = Install-DomainServicesFeature -CheckMode:$module.CheckMode
$module.Result.changed = $featureRes.Changed
$module.Result.reboot_required = $featureRes.RebootRequired

if ($featureRes.Changed -and $module.CheckMode) {
    # If we had to install features in check mode then we need to exit early as
    # the AD cmdlets won't be available
    $module.ExitJson()
}

if ($state -eq 'domain_controller') {
    # ensure that domain admin user is in UPN or down-level domain format (prevent hang from https://support.microsoft.com/en-us/kb/2737935)
    If (-not $domainCredential.UserName.Contains("\") -and -not $domainCredential.UserName.Contains("@")) {
        $module.FailJson("domain_admin_user must be in domain\user or user@domain.com format")
    }

    If ($isKdc) {
        # FUTURE: implement managed Remove/Add to change domains?
        If ($dnsDomainName -ne $win32CS.Domain) {
            $msg = -join @(
                "The host $env:COMPUTERNAME is a domain controller for the domain $($win32CS.Domain); "
                "changing DC domains is not implemented"
            )
            $module.FailJson($msg)
        }
    }
    else {
        $safeModePassword = $module.Params.safe_mode_password | ConvertTo-SecureString -AsPlainText -Force

        $installParams = @{
            Confirm = $false
            Credential = $domainCredential
            DomainName = $dnsDomainName
            Force = $true
            NoRebootOnCompletion = $true
            SafeModeAdministratorPassword = $safeModePassword
            SkipPreChecks = $true
            WhatIf = $module.CheckMode
        }
        if ($databasePath) {
            $installParams.DatabasePath = $databasePath
        }
        if ($logPath) {
            $installParams.LogPath = $logPath
        }
        if ($sysvolPath) {
            $installParams.SysvolPath = $sysvolPath
        }
        if ($installMediaPath) {
            $installParams.InstallationMediaPath = $installMediaPath
        }
        if ($readOnly) {
            # while this is a switch value, if we set on $false site_name is required
            # https://github.com/ansible/ansible/issues/35858
            $installParams.ReadOnlyReplica = $true
        }
        if ($replicationSourceDC) {
            $installParams.ReplicationSourceDC = $replicationSourceDC
        }
        if ($siteName) {
            $installParams.SiteName = $siteName
        }
        if ($null -ne $installDns) {
            $installParams.InstallDns = $installDns
        }

        $wrapperParams = @{
            AnsibleModule = $module
            Command = 'Install-ADDSDomainController'
            CommandParams = $installParams
            Reboot = $module.Params.reboot
        }
        Invoke-ADDSWrapper @wrapperParams
    }
}
else {
    # at this point we already know we're a DC and shouldn't be (due to short circuit check)...
    $assignedRoles = @((Get-ADDomainController -Server localhost).OperationMasterRoles)
    $localAdminPassword = $module.Params.local_admin_password | ConvertTo-SecureString -AsPlainText -Force

    # FUTURE: figure out a sane way to hand off roles automatically (designated recipient server, randomly look one up?)
    If ($assignedRoles.Count -gt 0) {
        $msg = -join @(
            "This domain controller has operation master role(s) ({0}) assigned;  " -f ($assignedRoles -join ", ")
            "they must be moved to other DCs before demotion (see Move-ADDirectoryServerOperationMasterRole)"
        )
        $module.FailJson($msg)
    }

    if ($module.CheckMode) {
        $module.Result.changed = $true
        $module.Result.reboot_required = $true
    }
    else {
        # While the cmdlet has -WhatIf, it doesn't seem to work properly. Only
        # run when not in check mode.
        Invoke-ADDSWrapper -Command 'Uninstall-ADDSDomainController' -CommandParams @{
            Confirm = $false
            Credential = $domainCredential
            Force = $true
            LocalAdministratorPassword = $localAdminPassword
            NoRebootOnCompletion = $true
        } -AnsibleModule $module -Reboot:$module.Params.reboot
    }
}

$module.ExitJson()
