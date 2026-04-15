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
        match_by = @{
            type = 'str'
            default = 'any'
            choices = @('any', 'key_id', 'never')
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
        , @('match_by', 'key_id', @('key_id'))
    )
}


$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.key_id = $null
$module.Result.changed = $false

$effective_time_hours = $module.Params.effective_time_hours
$state = $module.Params.state
$key_id = $module.Params.key_id
$match_by = $module.Params.match_by

# Note: The EffectiveImmediately parameter does not seem to work as expected.
# https://learn.microsoft.com/en-us/answers/questions/441587/i-ran-add-kdsrootkey-effectiveimmediately-and-now
$effctive_time_cmdlet = $effective_time_hours - 10
$effctive_time_cmdlet_param = @{ EffectiveTime = (Get-Date).AddHours($effctive_time_cmdlet) }

try {
    $existing_kds_keys = Get-KdsRootKey
}
catch {
    $module.FailJson("Failed to get KDS root keys: $_", $_)
}

if ($state -eq "present") {
    if ($match_by -eq "any" -and $existing_kds_keys) {
        $module.Result.key_id = [Guid]::Empty.Guid
    }
    elseif ($match_by -eq "key_id" -and $existing_kds_keys.KeyId -contains $key_id) {
        $module.Result.key_id = $key_id.Guid
    }
    else {
        $module.Result.changed = $true
        if (-not $module.CheckMode) {
            try {
                $new_key = Add-KdsRootKey @effctive_time_cmdlet_param
                $module.Result.key_id = $new_key.Guid
            }
            catch {
                $module.FailJson("Failed to create KDS root key: $_", $_)
            }
        }
        else {
            $module.Result.key_id = [Guid]::Empty.Guid
        }
    }
}
else {
    $dse = Get-ADRootDSE
    $ldap_filter = "(&(objectClass=msKds-ProvRootKey)(name=$key_id))"
    $search_base = "CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,$($dse.configurationNamingContext)"
    try {
        $key_result = Get-ADObject -ldapfilter $ldap_filter -SearchBase $search_base
    }
    catch {
        $module.FailJson("Failed to lookup KDS root keys for removal: $_", $_)
    }
    $module.Result.key_id = $key_id
    if ($null -ne $key_result) {
        $module.Result.changed = $true
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
