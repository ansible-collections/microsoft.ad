#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'managed_by'
            Option = @{ type = 'raw' }
            Attribute = 'ManagedBy'
            DNLookup = $true
        }
        [PSCustomObject]@{
            Name = 'automatic_inter_site_topology_generation_enabled'
            Option = @{ type = 'bool' }
            Attribute = 'AutomaticInterSiteTopologyGenerationEnabled'
        }
        [PSCustomObject]@{
            Name = 'automatic_topology_generation_enabled'
            Option = @{ type = 'bool' }
            Attribute = 'AutomaticTopologyGenerationEnabled'
        }
        [PSCustomObject]@{
            Name = 'universal_group_caching_enabled'
            Option = @{ type = 'bool' }
            Attribute = 'UniversalGroupCachingEnabled'
        }
    )
    ModuleNoun = 'ADReplicationSite'
    DefaultPath = {
        param($Module, $ADParams)
        $configNC = (Get-ADRootDSE @ADParams -Properties configurationNamingContext).configurationNamingContext
        "CN=Sites,$configNC"
    }
}
Invoke-AnsibleADObject @setParams
