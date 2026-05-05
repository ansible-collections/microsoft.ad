#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        name = @{
            type = 'str'
            required = $true
        }
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
        }
        description = @{
            type = 'str'
        }
        managed_by = @{
            type = 'str'
        }
        protected_from_accidental_deletion = @{
            type = 'bool'
        }
        automatic_inter_site_topology_generation_enabled = @{
            type = 'bool'
        }
        automatic_topology_generation_enabled = @{
            type = 'bool'
        }
        universal_group_caching_enabled = @{
            type = 'bool'
        }
        domain_server = @{
            type = 'str'
        }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.changed = $false
$module.Result.distinguished_name = $null
$module.Result.name = $module.Params.name
$module.Result.description = $null
$module.Diff.before = @{}
$module.Diff.after = @{}

$name = $module.Params.name
$state = $module.Params.state

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

$propertyMap = @(
    @{ Param = 'description'; CmdletParam = 'Description' }
    @{ Param = 'managed_by'; CmdletParam = 'ManagedBy' }
    @{ Param = 'protected_from_accidental_deletion'; CmdletParam = 'ProtectedFromAccidentalDeletion' }
    @{ Param = 'automatic_inter_site_topology_generation_enabled'; CmdletParam = 'AutomaticInterSiteTopologyGenerationEnabled' }
    @{ Param = 'automatic_topology_generation_enabled'; CmdletParam = 'AutomaticTopologyGenerationEnabled' }
    @{ Param = 'universal_group_caching_enabled'; CmdletParam = 'UniversalGroupCachingEnabled' }
)

$getProperties = @($propertyMap | ForEach-Object { $_.CmdletParam })

try {
    $existing = Get-ADReplicationSite @adParams -Identity $name -Properties $getProperties
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $existing = $null
}
catch {
    $module.FailJson("Failed to get replication site '$name': $_", $_)
}

Function Get-SiteState {
    param($Site)
    $s = @{}
    foreach ($p in $propertyMap) {
        $s[$p.Param] = $Site.($p.CmdletParam)
    }
    $s
}

if ($state -eq 'present') {
    if (-not $existing) {
        # CREATE
        $module.Diff.before = @{}
        $module.Result.changed = $true

        $newParams = @{}
        foreach ($p in $propertyMap) {
            $val = $module.Params[$p.Param]
            if ($null -ne $val) {
                $newParams[$p.CmdletParam] = $val
            }
        }

        if (-not $module.CheckMode) {
            try {
                New-ADReplicationSite @adParams @newParams -Name $name
            }
            catch {
                $module.FailJson("Failed to create replication site '$name': $_", $_)
            }

            $existing = Get-ADReplicationSite @adParams -Identity $name -Properties $getProperties
            $module.Result.distinguished_name = $existing.DistinguishedName
            $module.Result.description = $existing.Description
        }

        $module.Diff.after = @{ name = $name }
        foreach ($p in $propertyMap) {
            $val = $module.Params[$p.Param]
            if ($null -ne $val) {
                $module.Diff.after[$p.Param] = $val
            }
        }
    }
    else {
        # UPDATE
        $module.Result.distinguished_name = $existing.DistinguishedName
        $module.Result.description = $existing.Description

        $beforeState = Get-SiteState -Site $existing
        $module.Diff.before = @{ name = $existing.Name } + $beforeState

        $setParams = @{}
        foreach ($p in $propertyMap) {
            $desired = $module.Params[$p.Param]
            if ($null -eq $desired) { continue }

            $current = $existing.($p.CmdletParam)
            if ($desired -ne $current) {
                $setParams[$p.CmdletParam] = $desired
            }
        }

        if ($setParams.Count -gt 0) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    Set-ADReplicationSite @adParams -Identity $name @setParams
                }
                catch {
                    $module.FailJson("Failed to update replication site '$name': $_", $_)
                }

                $existing = Get-ADReplicationSite @adParams -Identity $name -Properties $getProperties
                $module.Result.description = $existing.Description
            }
        }

        $afterState = @{ name = $existing.Name }
        foreach ($p in $propertyMap) {
            $desired = $module.Params[$p.Param]
            $afterState[$p.Param] = if ($null -ne $desired) { $desired } else { $existing.($p.CmdletParam) }
        }
        $module.Diff.after = $afterState
    }
}
else {
    # ABSENT
    if ($existing) {
        $beforeState = Get-SiteState -Site $existing
        $module.Diff.before = @{ name = $existing.Name } + $beforeState
        $module.Result.distinguished_name = $existing.DistinguishedName
        $module.Result.description = $existing.Description
        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                Remove-ADReplicationSite @adParams -Identity $name -Confirm:$false
            }
            catch {
                $module.FailJson("Failed to remove replication site '$name': $_", $_)
            }
        }
    }
    $module.Diff.after = @{}
}

$module.ExitJson()
