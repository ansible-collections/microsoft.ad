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
        site = @{
            type = 'str'
        }
        description = @{
            type = 'str'
        }
        location = @{
            type = 'str'
        }
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
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
$module.Result.site = $null
$module.Result.description = $null
$module.Result.location = $null
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
    @{ Param = 'location'; CmdletParam = 'Location' }
    @{ Param = 'site'; CmdletParam = 'Site' }
)

$getProperties = @('Description', 'Location', 'Site')

try {
    $existing = Get-ADReplicationSubnet @adParams -Identity $name -Properties $getProperties
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $existing = $null
}
catch {
    $module.FailJson("Failed to get replication subnet '$name': $_", $_)
}

Function Get-SiteName {
    param($SiteValue)
    if ($null -eq $SiteValue -or $SiteValue -eq '') {
        return $null
    }
    $s = [string]$SiteValue
    if ($s -match '^CN=([^,]+),') {
        return $Matches[1]
    }
    return $s
}

Function Get-SubnetState {
    param($Subnet)
    @{
        description = $Subnet.Description
        location = $Subnet.Location
        site = Get-SiteName -SiteValue $Subnet.Site
    }
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
                New-ADReplicationSubnet @adParams @newParams -Name $name
            }
            catch {
                $module.FailJson("Failed to create replication subnet '$name': $_", $_)
            }

            $existing = Get-ADReplicationSubnet @adParams -Identity $name -Properties $getProperties
            $module.Result.distinguished_name = $existing.DistinguishedName
            $module.Result.description = $existing.Description
            $module.Result.location = $existing.Location
            $module.Result.site = Get-SiteName -SiteValue $existing.Site
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
        $module.Result.location = $existing.Location
        $module.Result.site = Get-SiteName -SiteValue $existing.Site

        $beforeState = Get-SubnetState -Subnet $existing
        $module.Diff.before = @{ name = $name } + $beforeState

        $setParams = @{}
        foreach ($p in $propertyMap) {
            $desired = $module.Params[$p.Param]
            if ($null -eq $desired) { continue }

            $current = $existing.($p.CmdletParam)
            if ($p.Param -eq 'site') {
                $currentSiteName = Get-SiteName -SiteValue $current
                if ($desired -ne $currentSiteName) {
                    $setParams[$p.CmdletParam] = $desired
                }
            }
            else {
                if ($desired -ne $current) {
                    $setParams[$p.CmdletParam] = $desired
                }
            }
        }

        if ($setParams.Count -gt 0) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    Set-ADReplicationSubnet @adParams -Identity $name @setParams
                }
                catch {
                    $module.FailJson("Failed to update replication subnet '$name': $_", $_)
                }

                $existing = Get-ADReplicationSubnet @adParams -Identity $name -Properties $getProperties
                $module.Result.description = $existing.Description
                $module.Result.location = $existing.Location
                $module.Result.site = Get-SiteName -SiteValue $existing.Site
            }
        }

        $afterState = @{ name = $name }
        foreach ($p in $propertyMap) {
            $desired = $module.Params[$p.Param]
            if ($p.Param -eq 'site') {
                $afterState[$p.Param] = if ($null -ne $desired) { $desired } else { Get-SiteName -SiteValue $existing.Site }
            }
            else {
                $afterState[$p.Param] = if ($null -ne $desired) { $desired } else { $existing.($p.CmdletParam) }
            }
        }
        $module.Diff.after = $afterState
    }
}
else {
    # ABSENT
    if ($existing) {
        $beforeState = Get-SubnetState -Subnet $existing
        $module.Diff.before = @{ name = $name } + $beforeState
        $module.Result.distinguished_name = $existing.DistinguishedName
        $module.Result.description = $existing.Description
        $module.Result.location = $existing.Location
        $module.Result.site = Get-SiteName -SiteValue $existing.Site
        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                Remove-ADReplicationSubnet @adParams -Identity $name -Confirm:$false
            }
            catch {
                $module.FailJson("Failed to remove replication subnet '$name': $_", $_)
            }
        }
    }
    $module.Diff.after = @{}
}

$module.ExitJson()
