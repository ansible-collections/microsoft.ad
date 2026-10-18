#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'location'
            Option = @{ type = 'str' }
            Attribute = 'Location'
        }
        [PSCustomObject]@{
            Name = 'site'
            Option = @{ type = 'str' }
            Attribute = 'Site'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $currentDN = $ADObject.Site
                $currentName = $null
                if ($currentDN -match '^CN=([^,]+),') {
                    $currentName = $Matches[1]
                }
                $Module.Diff.before.site = $currentName

                $desired = $Module.Params.site
                if ($desired -ne $currentName) {
                    $SetParams.Site = $desired
                }
                $Module.Diff.after.site = $desired
            }
        }
    )
    ModuleNoun = 'ADReplicationSubnet'
    DefaultPath = {
        param($Module, $ADParams)
        $configNC = (Get-ADRootDSE @ADParams -Properties configurationNamingContext).configurationNamingContext
        "CN=Subnets,CN=Sites,$configNC"
    }
}
Invoke-AnsibleADObject @setParams
