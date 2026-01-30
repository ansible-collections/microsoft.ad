#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic


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
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
        }
        key_id = @{
            type = 'str'
        }
    }
    supports_check_mode = $true
    required_if = @(
        , @('state', 'absent', @('key_id'))
    )
}


$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.kds_root_key = $null
$module.Result.changed = $false

$effective_time_hours = $module.Params.effective_time_hours
$force = $module.Params.force
$state = $module.Params.state
$key_id = $module.Params.key_id

if ($effective_time_hours -eq 0) {
    # Note: The EffectiveImmediately parameter does not seem to work as expected.
    # https://learn.microsoft.com/en-us/answers/questions/441587/i-ran-add-kdsrootkey-effectiveimmediately-and-now
    $effctive_time_cmdlet_param = @{ EffectiveTime = (Get-Date).AddHours(-10) }
}
else {
    $effctive_time_cmdlet_param = @{ EffectiveTime = (Get-Date).AddHours($effective_time_hours) }
}

try {
    $existing_kds_keys = Get-KdsRootKey
}
catch {
    $module.FailJson("Failed to get KDS root keys: $_", $_)
}

if ($state -eq "present") {
    if ((-not $existing_kds_keys) -or $force) {
        $module.Result.changed = $true
        if (-not $module.CheckMode) {
            try {
                $new_key = Add-KdsRootKey @effctive_time_cmdlet_param
                $module.Result.kds_root_key = $new_key
            }
            catch {
                $module.FailJson("Failed to create KDS root key: $_", $_)
            }
        }
    }
}
else {
    $domain = Get-ADDomain
    $ldap_filter = "(&(objectClass=msKds-ProvRootKey)(name=$key_id))"
    $search_base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,$($domain.DistinguishedName)"
    try {
        $key_result = Get-ADObject -ldapfilter $ldap_filter -SearchBase $search_base
    }
    catch {
        $module.FailJson("Failed to lookup KDS root keys for removal: $_", $_)
    }
    if ($null -ne $key_result) {
        $module.Result.changed = $true
        $module.Result.kds_root_key = $key_id
        if (-not $module.CheckMode) {
            try {
                $key_result | Remove-ADObject -Confirm:$False
            }
            catch {
                $module.FailJson("Failed to remove KDS root key: $_", $_)
            }
        }
    }
}

$module.ExitJson()
