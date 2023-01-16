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
                type = 'list'
                elements = 'str'
            }
            Attribute = 'PrincipalsAllowedToDelegateToAccount'
            CaseInsensitive = $true
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
                choices = 'aes128', 'aes256', 'des', 'none', 'rc4'
                type = 'list'
                elements = 'str'
            }
            Attribute = 'KerberosEncryptionType'
            CaseInsensitive = $true
        }
        [PSCustomObject]@{
            Name = 'location'
            Option = @{ type = 'str' }
            Attribute = 'Location'
        }
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'str' }
            Attribute = 'ManagedBy'
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }
        [PSCustomObject]@{
            Name = 'spn'
            Option = @{
                type = 'list'
                elements = 'str'
                aliases = 'spns'
            }
            Attribute = 'servicePrincipalNames'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                [string[]]$existing = @($ADObject.servicePrincipalNames.Value)
                [string[]]$desired = @($Module.Params.spn)

                $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase

                [string[]]$toAdd = @()
                [string[]]$toRemove = @()
                [string[]]$diffAfter = @()
                switch ($Module.Params.spn_action) {
                    add {
                        $toAdd = [System.Linq.Enumerable]::Except($desired, $existing, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Union($desired, $existing, $ignoreCase)
                    }
                    remove {
                        $toRemove = [System.Linq.Enumerable]::Intersect($desired, $existing, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Except($existing, $desired, $ignoreCase)
                    }
                    set {
                        $toAdd = [System.Linq.Enumerable]::Except($desired, $existing, $ignoreCase)
                        $toRemove = [System.Linq.Enumerable]::Except($existing, $desired, $ignoreCase)
                        $diffAfter = $desired
                    }
                }

                $spnValue = @{}
                if ($toAdd) {
                    # For whatever reason the Set-ADComputer doesn't like a
                    # tainted [string[]] typed array, use ForEach-Object to
                    # bypass this
                    $spnValue.Add = $toAdd | ForEach-Object { "$_" }
                }
                if ($toRemove) {
                    $spnValue.Remove = $toRemove | ForEach-Object { "$_" }
                }

                if ($spnValue.Count) {
                    $SetParams.ServicePrincipalNames = $spnValue
                }

                $Module.Diff.after.spn = @($diffAfter | Sort-Object)
            }
        }
        [PSCustomObject]@{
            Name = 'spn_action'
            Option = @{
                choices = 'add', 'remove', 'set'
                default = 'set'
                type = 'str'
            }
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
