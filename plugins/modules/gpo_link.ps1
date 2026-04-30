#!powershell

# Copyright: (c) 2026, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$spec = @{
    options = @{
        gpo_name = @{ type = 'str' }
        gpo_guid = @{ type = 'str' }
        target = @{ type = 'str'; required = $true }
        link_enabled = @{ type = 'bool' }
        enforced = @{ type = 'bool' }
        order = @{ type = 'int' }
        state = @{ type = 'str'; choices = @('absent', 'present'); default = 'present' }
        domain = @{ type = 'str' }
        server = @{ type = 'str' }
    }
    mutually_exclusive = @(
        , @('gpo_name', 'gpo_guid')
    )
    required_one_of = @(
        , @('gpo_name', 'gpo_guid')
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$gpoName = $module.Params.gpo_name
$gpoGuid = $module.Params.gpo_guid
$target = $module.Params.target
$linkEnabled = $module.Params.link_enabled
$enforced = $module.Params.enforced
$order = $module.Params.order
$state = $module.Params.state
$domain = $module.Params.domain
$server = $module.Params.server

# Build common parameters for GP cmdlets
$gpParams = @{}
if ($domain) { $gpParams.Domain = $domain }
if ($server) { $gpParams.Server = $server }

# Ensure the GroupPolicy module is available
try {
    Import-Module GroupPolicy -ErrorAction Stop
} catch {
    $module.FailJson("The GroupPolicy PowerShell module is not available. Install RSAT or the GroupPolicy feature.", $_)
}

# Resolve GPO identity — get both name and GUID for return values
try {
    if ($gpoGuid) {
        $gpoObject = Get-GPO @gpParams -Guid $gpoGuid -ErrorAction Stop
    } else {
        $gpoObject = Get-GPO @gpParams -Name $gpoName -ErrorAction Stop
    }
} catch {
    $identifier = if ($gpoGuid) { $gpoGuid } else { $gpoName }
    $module.FailJson("GPO '$identifier' not found: $_", $_)
}

$resolvedName = $gpoObject.DisplayName
$resolvedGuid = $gpoObject.Id.ToString()

# Set return values that are always present
$module.Result.gpo_name = $resolvedName
$module.Result.gpo_guid = $resolvedGuid
$module.Result.target = $target

# Find existing link
$existingLink = $null
try {
    $inheritance = Get-GPInheritance @gpParams -Target $target -ErrorAction Stop
    $existingLink = $inheritance.GpoLinks | Where-Object {
        $_.GpoId.ToString() -eq $resolvedGuid
    }
} catch {
    if ($state -eq 'present') {
        # Target may not exist — let New-GPLink handle the error
    }
}

# Build diff output
$module.Diff.before = @{}
$module.Diff.after = @{}

if ($existingLink) {
    $module.Diff.before = @{
        gpo_name = $resolvedName
        target = $target
        link_enabled = ($existingLink.Enabled -eq 'Yes')
        enforced = ($existingLink.Enforced -eq 'Yes')
        order = $existingLink.Order
    }
}

if ($state -eq 'absent') {
    # Remove the GPO link
    if ($existingLink) {
        $module.Result.changed = $true
        $module.Diff.after = @{}

        if (-not $module.CheckMode) {
            try {
                Remove-GPLink @gpParams -Guid $resolvedGuid -Target $target -ErrorAction Stop
            } catch {
                $module.FailJson("Failed to remove GPO link: $_", $_)
            }
        }
    }
    # If no existing link, nothing to do — already absent
} else {
    # state=present — create or update the link
    if (-not $existingLink) {
        # Create new link
        $module.Result.changed = $true

        $newLinkParams = @{
            Guid = $resolvedGuid
            Target = $target
            ErrorAction = 'Stop'
        }

        # Set link_enabled (New-GPLink uses -LinkEnabled)
        if ($null -ne $linkEnabled) {
            $newLinkParams.LinkEnabled = if ($linkEnabled) { 'Yes' } else { 'No' }
        } else {
            $newLinkParams.LinkEnabled = 'Yes'
        }

        # Set enforced
        $newEnforced = $false
        if ($null -ne $enforced) {
            $newEnforced = $enforced
        }

        $module.Diff.after = @{
            gpo_name = $resolvedName
            target = $target
            link_enabled = if ($null -ne $linkEnabled) { $linkEnabled } else { $true }
            enforced = $newEnforced
        }

        if (-not $module.CheckMode) {
            try {
                $newLink = New-GPLink @gpParams @newLinkParams

                # Set enforced separately — New-GPLink doesn't have -Enforced
                if ($newEnforced) {
                    Set-GPLink @gpParams -Guid $resolvedGuid -Target $target -Enforced 'Yes' -ErrorAction Stop | Out-Null
                }

                # Set order if specified
                if ($null -ne $order) {
                    Set-GPLink @gpParams -Guid $resolvedGuid -Target $target -Order $order -ErrorAction Stop | Out-Null
                }

                # Fetch final state for return values
                $finalInheritance = Get-GPInheritance @gpParams -Target $target -ErrorAction Stop
                $finalLink = $finalInheritance.GpoLinks | Where-Object {
                    $_.GpoId.ToString() -eq $resolvedGuid
                }
                if ($finalLink) {
                    $module.Diff.after.order = $finalLink.Order
                    $module.Diff.after.enforced = ($finalLink.Enforced -eq 'Yes')
                    $module.Diff.after.link_enabled = ($finalLink.Enabled -eq 'Yes')
                }
            } catch {
                $module.FailJson("Failed to create GPO link: $_", $_)
            }
        }
    } else {
        # Update existing link
        $needsUpdate = $false
        $setParams = @{
            Guid = $resolvedGuid
            Target = $target
            ErrorAction = 'Stop'
        }

        $afterState = @{
            gpo_name = $resolvedName
            target = $target
            link_enabled = ($existingLink.Enabled -eq 'Yes')
            enforced = ($existingLink.Enforced -eq 'Yes')
            order = $existingLink.Order
        }

        if (($null -ne $linkEnabled) -and ($linkEnabled -ne ($existingLink.Enabled -eq 'Yes'))) {
            $setParams.LinkEnabled = if ($linkEnabled) { 'Yes' } else { 'No' }
            $afterState.link_enabled = $linkEnabled
            $needsUpdate = $true
        }

        if (($null -ne $enforced) -and ($enforced -ne ($existingLink.Enforced -eq 'Yes'))) {
            $setParams.Enforced = if ($enforced) { 'Yes' } else { 'No' }
            $afterState.enforced = $enforced
            $needsUpdate = $true
        }

        if (($null -ne $order) -and ($order -ne $existingLink.Order)) {
            $setParams.Order = $order
            $afterState.order = $order
            $needsUpdate = $true
        }

        $module.Diff.after = $afterState

        if ($needsUpdate) {
            $module.Result.changed = $true

            if (-not $module.CheckMode) {
                try {
                    Set-GPLink @gpParams @setParams | Out-Null
                } catch {
                    $module.FailJson("Failed to update GPO link: $_", $_)
                }
            }
        }
    }

    # Populate return values for present state
    $module.Result.link_enabled = $module.Diff.after.link_enabled
    $module.Result.enforced = $module.Diff.after.enforced
    if ($module.Diff.after.ContainsKey('order')) {
        $module.Result.order = $module.Diff.after.order
    }
}

$module.ExitJson()
