#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
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
            Name = 'managed_by'
            Option = @{ type = 'str' }
            Attribute = 'ManagedBy'
        }
        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
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
