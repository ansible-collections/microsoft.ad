#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell Ansible.ModuleUtils.AddType


function Get-FormattedKdsRootKeyInfo {
    param (
        [string][AllowNull()]$searchKeyId = $null
    )
    $result = @()
    foreach ($key in $(Get-KdsRootKey)) {
        # Syntax: UTC Coded Time - .NET DateTimes serialized as in the form "Date(FILETIME)" which isn't easily
        # parsable by Ansible, instead return as an ISO 8601 string in the UTC timezone.
        # Matches the time format in the object info module
        $time = [TimeZoneInfo]::ConvertTimeToUtc($key.EffectiveTime.DateTime).ToString("o")
        $found_key_id = $key.KeyId.Guid.ToString()
        $found_key = @{
            key_id = $found_key_id
            effective_time = $time
        }
        if ((-not [string]::IsNullOrWhiteSpace($searchKeyId))) {
            # only emit the key that matches the specified ID
            if ($searchKeyId -eq $found_key_id) {
                $result += $found_key
                break
            }
        }
        else {
            # No search key specfied, emit all keys
            $result += $found_key
        }
    }
    return , $result
}


$spec = @{
    options = @{
        key_id = @{
            type = 'str'
        }
    }
    supports_check_mode = $true
}


$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false
$module.Result.kds_root_keys = @()


try {
    foreach ($key in $(Get-KdsRootKey)) {
        # Syntax: UTC Coded Time - .NET DateTimes serialized as in the form "Date(FILETIME)" which isn't easily
        # parsable by Ansible, instead return as an ISO 8601 string in the UTC timezone.
        # Matches the time format in the object info module
        $time = [TimeZoneInfo]::ConvertTimeToUtc($key.EffectiveTime.DateTime).ToString("o")
        $found_key_id = $key.KeyId.Guid.ToString()
        $found_key = @{
            key_id = $found_key_id
            effective_time = $time
        }

        if ((-not [string]::IsNullOrWhiteSpace($searchKeyId))) {
            # only emit the key that matches the specified ID
            if ($searchKeyId -eq $found_key_id) {
                $module.Result.kds_root_keys += $found_key
                break
            }
        }
        else {
            # No search key specfied, emit all keys
            $module.Result.kds_root_keys += $found_key
        }
    }
}
catch {
    $module.FailJson("Failed to get KDS root keys: $_", $_)
}


$module.ExitJson()
