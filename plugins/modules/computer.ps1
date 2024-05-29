#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'delegates'
            Option = @{
                aliases = 'principals_allowed_to_delegate'
                type = 'add_remove_set'
            }
            Attribute = 'PrincipalsAllowedToDelegateToAccount'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'dns_hostname'
            Option = @{ type = 'str' }
            Attribute = 'DNSHostName'
        }
        [PSCustomObject]@{
            Name = 'enabled'
            Option = @{ type = 'bool' }
            Attribute = 'Enabled'
        }
        [PSCustomObject]@{
            Name = 'kerberos_encryption_types'
            Option = @{
                type = 'add_remove_set'
                choices = 'aes128', 'aes256', 'des', 'rc4'
            }
            Attribute = 'KerberosEncryptionType'
            CaseInsensitive = $true

            New = {
                param($Module, $ADParams, $NewParams)

                $encTypes = @(
                    $Module.Params.kerberos_encryption_types.add
                    $Module.Params.kerberos_encryption_types.set
                ) | Select-Object -Unique

                $NewParams.KerberosEncryptionType = $encTypes
                $Module.Diff.after.kerberos_encryption_types = $MencTypes
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                # This is an enum value and needs custom handling for things like
                # unsetting the values with none.
                $rawValue = $ADObject.KerberosEncryptionType.Value

                $existing = foreach ($v in [System.Enum]::GetValues($rawValue.GetType())) {
                    if ($rawValue -band $v) { $v.ToString() }
                }
                if ($existing -eq 'None') {
                    $existing = @()
                }
                $module.Diff.before.kerberos_encryption_types = $existing

                $desired = $Module.Params.kerberos_encryption_types
                $compareParams = @{
                    Existing = $existing
                    CaseInsensitive = $true
                }
                $res = Compare-AnsibleADIdempotentList @compareParams @desired
                if ($res.Changed) {
                    if ($res.Value) {
                        $SetParams.KerberosEncryptionType = $res.Value -join ', '
                    }
                    else {
                        $SetParams.KerberosEncryptionType = 'None'
                    }
                }
                $module.Diff.after.kerberos_encryption_types = $res.Value
            }
        }
        [PSCustomObject]@{
            Name = 'location'
            Option = @{ type = 'str' }
            Attribute = 'Location'
        }
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'raw' }
            Attribute = 'ManagedBy'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }
        [PSCustomObject]@{
            Name = 'spn'
            Option = @{
                aliases = 'spns'
                type = 'add_remove_set'
            }
            Attribute = 'servicePrincipalName'
            CaseInsensitive = $true
            IsRawAttribute = $true
        }
        [PSCustomObject]@{
            Name = 'trusted_for_delegation'
            Option = @{ type = 'bool' }
            Attribute = 'TrustedForDelegation'
        }
        [PSCustomObject]@{
            Name = 'upn'
            Option = @{ type = 'str' }
            Attribute = 'userPrincipalName'
        }
    )
    ModuleNoun = 'ADComputer'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_COMPUTERS_CONTAINER_W = 'AA312825768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_COMPUTERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if ($Module.Params.sam_account_name -and -not $Module.Params.sam_account_name.EndsWith('$')) {
            $Module.Params.sam_account_name = "$($Module.Params.sam_account_name)$"
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($ADObject) {
            $Module.Result.sid = $ADObject.SID.Value
        }
        elseif ($Module.Params.state -eq 'present') {
            # Use dummy value for check mode when creating a new user
            $Module.Result.sid = 'S-1-5-0000'
        }
    }
}
Invoke-AnsibleADObject @setParams
