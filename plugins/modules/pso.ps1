#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'precedence'
            Option = @{ type = 'int' }
            Attribute = 'Precedence'
        }
        [PSCustomObject]@{
            Name = 'min_password_length'
            Option = @{ type = 'int'; no_log = $false }
            Attribute = 'MinPasswordLength'
        }
        [PSCustomObject]@{
            Name = 'complexity_enabled'
            Option = @{ type = 'bool' }
            Attribute = 'ComplexityEnabled'
        }
        [PSCustomObject]@{
            Name = 'lockout_threshold'
            Option = @{ type = 'int' }
            Attribute = 'LockoutThreshold'
        }
        [PSCustomObject]@{
            Name = 'subjects'
            Option = @{ type = 'list'; elements = 'str' }
        }
    )
    ModuleNoun = 'ADFineGrainedPasswordPolicy'
    ExtraProperties = @('AppliesTo')
    DefaultPath = {
        param($Module, $ADParams)
        $domainNC = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext
        "CN=Password Settings Container,CN=System,$domainNC"
    }
    PreAction = {
        param($Module, $ADParams, $ADObject)

        if (
            $Module.Params.state -eq 'present' -and
            $null -eq $Module.Params.precedence -and
            -not $ADObject
        ) {
            $Module.FailJson("precedence must be set when state=present and the PSO does not exist")
        }

        if (
            $Module.Params.state -eq 'present' -and
            $null -ne $Module.Params.subjects -and
            @($Module.Params.subjects).Count -gt 0
        ) {
            $subjectDNs = @(
                $Module.Params.subjects | ConvertTo-AnsibleADDistinguishedName @ADParams -Module $Module -Context 'subjects'
            )
            foreach ($dn in $subjectDNs) {
                try {
                    $obj = Get-ADObject @ADParams -Identity $dn -Properties objectClass
                }
                catch {
                    $Module.FailJson("PSO subject '$dn' could not be found: $_", $_)
                }

                if ($obj.objectClass -contains 'group') {
                    $group = Get-ADGroup @ADParams -Identity $dn
                    if ($group.GroupScope -ne 'Global') {
                        $Module.FailJson(
                            "PSO subjects must be global security groups or users. '$($group.Name)' is a $($group.GroupScope) group."
                        )
                    }
                }
                elseif ($obj.objectClass -notcontains 'user') {
                    $Module.FailJson("PSO subject '$dn' must be a global security group or user.")
                }
            }
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($Module.Params.state -eq 'present' -and $null -ne $Module.Params.subjects) {
            $desiredSubjects = @($Module.Params.subjects)
            $desiredSorted = @($desiredSubjects | Sort-Object)

            $psoIdentity = $Module.Result.distinguished_name

            $currentDNs = @()
            if ($ADObject -and $null -ne $ADObject.AppliesTo) {
                $currentDNs = @($ADObject.AppliesTo)
            }
            elseif (-not $Module.CheckMode) {
                try {
                    $pso = Get-ADFineGrainedPasswordPolicy @ADParams -Identity $psoIdentity -Properties AppliesTo
                    if ($null -ne $pso.AppliesTo) {
                        $currentDNs = @($pso.AppliesTo)
                    }
                }
                catch {
                    $Module.FailJson("Failed to get PSO subjects for '$psoIdentity': $_", $_)
                }
            }

            $desiredDNs = @(
                $desiredSubjects | ConvertTo-AnsibleADDistinguishedName @ADParams -Module $Module -Context 'subjects'
            )

            $currentNames = @($currentDNs | ForEach-Object {
                    if ($_ -match '^CN=([^,]+),') { $Matches[1] } else { $_ }
                } | Sort-Object)

            $Module.Diff.after['subjects'] = $desiredSorted
            if ($null -ne $Module.Diff.before) {
                $Module.Diff.before['subjects'] = $currentNames
            }

            $currentSorted = @($currentDNs | Sort-Object)
            $desiredDNSorted = @($desiredDNs | Sort-Object)

            $toAdd = @($desiredDNSorted | Where-Object { $_ -notin $currentSorted })
            $toRemove = @($currentSorted | Where-Object { $_ -notin $desiredDNSorted })

            if ($toAdd.Count -gt 0 -or $toRemove.Count -gt 0) {
                $Module.Result.changed = $true

                if (-not ($Module.CheckMode -and -not $ADObject)) {
                    $subjectParams = @{
                        Identity = $psoIdentity
                        WhatIf = $Module.CheckMode
                        Confirm = $false
                    }

                    if ($toAdd.Count) {
                        try {
                            Add-ADFineGrainedPasswordPolicySubject @subjectParams @ADParams -Subjects $toAdd
                        }
                        catch {
                            $Module.FailJson("Failed to add PSO subjects: $_", $_)
                        }
                    }

                    if ($toRemove.Count) {
                        try {
                            Remove-ADFineGrainedPasswordPolicySubject @subjectParams @ADParams -Subjects $toRemove
                        }
                        catch {
                            $Module.FailJson("Failed to remove PSO subjects: $_", $_)
                        }
                    }
                }
            }
        }

    }
}
Invoke-AnsibleADObject @setParams
