#!powershell

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject


function Get-FormattedKdsRootKeyInfo {
    param ()
    $keys = Get-KdsRootKey
    $result = @()
    foreach ($key in $keys) {
        $result += @{
            key_id = $key.KeyId.Guid.ToString()
            effective_time = $key.EffectiveTime.DateTime.ToString()
        }
    }
    return , $result
}


function Invoke-PresentState {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $module
    )

    if ($effective_time_hours -eq 0) {
        $effctive_time_cmdlet_param = @{ EffectiveImmediately = $true }
    }
    else {
        $effctive_time_cmdlet_param = @{ EffectiveTime = (Get-Date).AddHours($effective_time_hours) }
    }

    try {
        $existing_kds_keys = Get-FormattedKdsRootKeyInfo
    }
    catch {
        $module.FailJson("Failed to get KDS root keys: $_", $_)
    }

    $module.Result.kds_root_keys = $existing_kds_keys
    if ((-not $existing_kds_keys) -or $force) {
        $module.Result.changed = $true
        if (-not $module.CheckMode) {
            try {
                $module.Result.created_kds_root_key = (Add-KdsRootKey @effctive_time_cmdlet_param).KeyId
            }
            catch {
                $module.FailJson("Failed to create KDS root key: $_", $_)
            }
            $module.Result.kds_root_keys = Get-FormattedKdsRootKeyInfo
        }
    }
}


$spec = @{
    options = @{
        effective_time_hours = @{
            type = 'int'
            default = 10
        }
        force = @{
            type = 'bool'
            default = $false
        }
        domain_credentials = @{
            default = @()
            type = 'list'
            elements = 'dict'
            options = @{
                name = @{
                    type = 'str'
                }
                username = @{
                    required = $true
                    type = 'str'
                }
                password = @{
                    no_log = $true
                    required = $true
                    type = 'str'
                }
            }
        }
        domain_password = @{
            no_log = $true
            type = 'str'
        }
        domain_server = @{
            type = 'str'
        }
        domain_username = @{
            type = 'str'
        }
    }
    supports_check_mode = $true
}


$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.kds_root_keys = @()
$module.Result.created_kds_root_key = $null
$module.Result.changed = $false

$effective_time_hours = $module.Params.effective_time_hours
$force = $module.Params.force

Initialize-ADConnection -Module $module > $null
if ($effective_time_hours -eq 0) {
    $effctive_time_cmdlet_param = @{ EffectiveImmediately = $true }
}
else {
    $effctive_time_cmdlet_param = @{ EffectiveTime = (Get-Date).AddHours($effective_time_hours) }
}

try {
    $existing_kds_keys = Get-FormattedKdsRootKeyInfo
}
catch {
    $module.FailJson("Failed to get KDS root keys: $_", $_)
}

$module.Result.kds_root_keys = $existing_kds_keys
if ((-not $existing_kds_keys) -or $force) {
    $module.Result.changed = $true
    if (-not $module.CheckMode) {
        try {
            $new_key = Add-KdsRootKey @effctive_time_cmdlet_param
            $module.Result.created_kds_root_key = $new_key
        }
        catch {
            $module.FailJson("Failed to create KDS root key: $_", $_)
        }
        $module.Result.kds_root_keys = Get-FormattedKdsRootKeyInfo
    }
}

$module.ExitJson()
