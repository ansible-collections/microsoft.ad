#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$ruleSubSpec = @{
    type = 'dict'
    options = @{
        value = @{
            type = 'list'
            elements = 'str'
            required = $true
        }
        update = @{
            type = 'str'
            default = 'set'
            choices = @('set', 'append')
        }
    }
}

$spec = @{
    options = @{
        name = @{
            type = 'str'
            required = $true
        }
        transform_rules = $ruleSubSpec
        authorization_rules = $ruleSubSpec
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
        }
    }
    required_if = @(
        , @('state', 'present', @('transform_rules', 'authorization_rules'), $true)
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false
$module.Result.transform_rules = $null
$module.Result.authorization_rules = $null
$module.Diff.before = @{}
$module.Diff.after = @{}

$name = $module.Params.name
$state = $module.Params.state

try {
    $trust = Get-AdfsRelyingPartyTrust -Name $name -ErrorAction Stop
}
catch {
    $module.FailJson("Failed to retrieve relying party trust '$name': $_", $_)
}

if (-not $trust) {
    $module.FailJson("Relying party trust '$name' not found.")
}

$ruleMap = @(
    @{
        Param = 'transform_rules'
        CmdletParam = 'IssuanceTransformRules'
        TrustProp = 'IssuanceTransformRules'
    }
    @{
        Param = 'authorization_rules'
        CmdletParam = 'IssuanceAuthorizationRules'
        TrustProp = 'IssuanceAuthorizationRules'
    }
)

Function Normalize-RuleString {
    <#
    .SYNOPSIS
    Normalizes a claim rule string for comparison. AD FS reformats
    rules when storing them (adds leading spaces, joins continuation
    lines, changes line breaks). Collapsing all whitespace into
    single spaces produces a canonical form that matches regardless
    of how AD FS chose to format the stored text.
    #>
    param([string]$Value)
    ($Value -replace '\s+', ' ').Trim()
}

$updateParams = @{}

foreach ($rule in $ruleMap) {
    $currentRaw = $trust.($rule.TrustProp)
    if ($null -ne $currentRaw) {
        $current = $currentRaw.Replace("`r`n", "`n").Trim()
    }
    else {
        $current = ''
    }
    $paramValue = $module.Params[$rule.Param]

    if ($state -eq 'absent') {
        $desired = ''
    }
    elseif ($null -ne $paramValue) {
        $joined = ($paramValue.value -join "`n").Trim()

        if ($paramValue.update -eq 'append') {
            $currentNorm = Normalize-RuleString $current
            $joinedNorm = Normalize-RuleString $joined
            if ($currentNorm.Contains($joinedNorm)) {
                $desired = $current
            }
            else {
                $desired = "$current`n$joined"
            }
        }
        else {
            $desired = $joined
        }
    }
    else {
        $module.Result[$rule.Param] = $current
        continue
    }

    $module.Diff.before[$rule.Param] = $current
    $module.Diff.after[$rule.Param] = $desired

    if ((Normalize-RuleString $current) -ne (Normalize-RuleString $desired)) {
        $updateParams[$rule.CmdletParam] = $desired
    }

    $module.Result[$rule.Param] = $desired
}

if ($updateParams.Count -gt 0) {
    $module.Result.changed = $true
    if (-not $module.CheckMode) {
        try {
            Set-AdfsRelyingPartyTrust -TargetName $name @updateParams
        }
        catch {
            $module.FailJson("Failed to set claim rules on '$name': $_", $_)
        }
    }
}

$module.ExitJson()
