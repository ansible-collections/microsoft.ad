#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        name = @{
            type = 'str'
        }
        guid = @{
            type = 'str'
        }
        target = @{
            type = 'str'
            required = $true
        }
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
        }
        enabled = @{
            type = 'bool'
        }
        enforced = @{
            type = 'bool'
        }
        order = @{
            type = 'int'
        }
        domain_server = @{
            type = 'str'
        }
    }
    mutually_exclusive = @(, @('name', 'guid'))
    required_one_of = @(, @('name', 'guid'))
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.changed = $false
$module.Diff.before = @{}
$module.Diff.after = @{}

$name = $module.Params.name
$guid = $module.Params.guid
$target = $module.Params.target
$state = $module.Params.state

$gpParams = @{}
if ($module.Params.domain_server) {
    $gpParams.Server = $module.Params.domain_server
}

try {
    Import-Module GroupPolicy -ErrorAction Stop
}
catch {
    $module.FailJson("Failed to import GroupPolicy module: $_", $_)
}

# Resolve the GPO to get both Name and GUID
try {
    if ($guid) {
        $gpo = Get-GPO @gpParams -Guid $guid -ErrorAction Stop
    }
    else {
        $gpo = Get-GPO @gpParams -Name $name -ErrorAction Stop
    }
}
catch {
    $module.FailJson("Failed to find GPO: $_", $_)
}

# Read current link state on the target
try {
    $inheritance = Get-GPInheritance @gpParams -Target $target -ErrorAction Stop
}
catch {
    $module.FailJson("Failed to read GP links on target '$target': $_", $_)
}

$existingLink = $inheritance.GpoLinks | Where-Object { $_.GpoId -eq $gpo.Id }

if ($state -eq 'present') {
    if ($existingLink) {
        $module.Diff.before = @{
            enabled = $existingLink.Enabled
            enforced = $existingLink.Enforced
            order = $existingLink.Order
        }

        $setParams = @{}
        $desiredAfter = @{
            enabled = $existingLink.Enabled
            enforced = $existingLink.Enforced
            order = $existingLink.Order
        }

        if ($null -ne $module.Params.enabled -and $module.Params.enabled -ne $existingLink.Enabled) {
            if ($module.Params.enabled) {
                $setParams.LinkEnabled = 'Yes'
            }
            else {
                $setParams.LinkEnabled = 'No'
            }
            $desiredAfter.enabled = $module.Params.enabled
        }
        if ($null -ne $module.Params.enforced -and $module.Params.enforced -ne $existingLink.Enforced) {
            if ($module.Params.enforced) {
                $setParams.Enforced = 'Yes'
            }
            else {
                $setParams.Enforced = 'No'
            }
            $desiredAfter.enforced = $module.Params.enforced
        }
        if ($null -ne $module.Params.order -and $module.Params.order -ne $existingLink.Order) {
            $setParams.Order = $module.Params.order
            $desiredAfter.order = $module.Params.order
        }

        $module.Diff.after = $desiredAfter

        if ($setParams.Count -gt 0) {
            $module.Result.changed = $true
            try {
                Set-GPLink @gpParams -Guid $gpo.Id -Target $target @setParams `
                    -WhatIf:$module.CheckMode -Confirm:$false -ErrorAction Stop
            }
            catch {
                $module.FailJson("Failed to update GPO link: $_", $_)
            }
        }
    }
    else {
        # Create link
        $module.Result.changed = $true

        $newParams = @{}
        if ($null -ne $module.Params.enabled) {
            if ($module.Params.enabled) {
                $newParams.LinkEnabled = 'Yes'
            }
            else {
                $newParams.LinkEnabled = 'No'
            }
        }
        if ($null -ne $module.Params.enforced) {
            if ($module.Params.enforced) {
                $newParams.Enforced = 'Yes'
            }
            else {
                $newParams.Enforced = 'No'
            }
        }
        if ($null -ne $module.Params.order) {
            $newParams.Order = $module.Params.order
        }

        try {
            New-GPLink @gpParams -Guid $gpo.Id -Target $target @newParams `
                -WhatIf:$module.CheckMode -Confirm:$false -ErrorAction Stop
        }
        catch {
            $module.FailJson("Failed to create GPO link: $_", $_)
        }

        $module.Diff.after = @{
            enabled = if ($null -ne $module.Params.enabled) { $module.Params.enabled } else { $true }
            enforced = if ($null -ne $module.Params.enforced) { $module.Params.enforced } else { $false }
            order = if ($null -ne $module.Params.order) { $module.Params.order } else { $null }
        }
    }
}
else {
    # state = absent
    if ($existingLink) {
        $module.Diff.before = @{
            enabled = $existingLink.Enabled
            enforced = $existingLink.Enforced
            order = $existingLink.Order
        }
        $module.Result.changed = $true

        try {
            Remove-GPLink @gpParams -Guid $gpo.Id -Target $target `
                -WhatIf:$module.CheckMode -Confirm:$false -ErrorAction Stop
        }
        catch {
            $module.FailJson("Failed to remove GPO link: $_", $_)
        }
    }
}

$module.ExitJson()
