# Copyright (c) 2023 Ansible Project
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

Function Compare-AnsibleADAttribute {
    <#
    .SYNOPSIS
    Compares AD attribute values.

    .PARAMETER Name
    The attribute name to compare.

    .PARAMETER ADObject
    The AD object to compare with.

    .PARAMETER Attribute
    The attribute value(s) to add/remove/set.

    .PARAMETER Action
    Set to Add to add the value(s), Remove to remove the value(s), and Set to replace the value(s).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [Parameter()]
        [AllowNull()]
        [Microsoft.ActiveDirectory.Management.ADObject]
        $ADObject,

        [Parameter()]
        [AllowEmptyCollection()]
        [object]
        $Attribute,

        [ValidateSet("Add", "Remove", "Set")]
        [string]
        $Action
    )

    <# Gets all the known types the AD module can return

    DateTime, Guid, SecurityIdentifier are all from readonly properties
    that the AD module alaises of the real LDAP attributes.

    Get-ADObject -LDAPFilter '(objectClass=*)' -Properties * |
        ForEach-Object {
            foreach ($name in $_.PSObject.Properties.Name) {
                if ($name -in @('AddedProperties', 'ModifiedProperties', 'RemovedProperties', 'PropertyNames')) { continue }

                $v = $_.$name
                if ($null -eq $v) { continue }
                if ($v -isnot [System.Collections.IList] -or $v -is [System.Byte[]]) {
                    $v = @(, $v)
                }

                foreach ($value in $v) {
                    $value.GetType()
                }
            }
        } |
        Sort-Object -Unique
    #>
    $getDiffValue = {
        if ($_ -is [System.Byte[]]) {
            [System.Convert]::ToBase64String($_)
        }
        elseif ($_ -is [System.DirectoryServices.ActiveDirectorySecurity]) {
            $_.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        else {
            # Bool, Int32, Int64, String
            $_
        }
    }

    $existingAttributes = [System.Collections.Generic.List[object]]@()
    if ($ADObject -and $ADObject.$Name) {
        $existingValues = $ADObject.$Name
        if ($null -ne $existingValues) {
            if (
                $existingValues -is [System.Collections.IList] -and
                $existingValues -isnot [System.Byte[]]
            ) {
                # Wrap with @() to help pwsh unroll the property value collection
                $existingAttributes.AddRange(@($existingValues))

            }
            else {
                $existingAttributes.Add($existingValues)
            }
        }
    }

    $desiredAttributes = [System.Collections.Generic.List[object]]@()
    if ($null -ne $Attribute -and $Attribute -isnot [System.Collections.IList]) {
        $Attribute = @($Attribute)
    }
    foreach ($attr in $Attribute) {
        if ($attr -is [System.Collections.IDictionary]) {
            if ($attr.Keys.Count -gt 2) {
                $keyList = $attr.Keys -join "', '"
                throw "Attribute '$Name' entry should only contain the 'type' and 'value' keys, found: '$keyList'"
            }

            $type = $attr.type
            $value = $attr.value
        }
        else {
            $type = 'raw'
            $value = $attr
        }

        switch ($type) {
            bytes {
                $desiredAttributes.Add([System.Convert]::FromBase64String($value))
            }
            date_time {
                $dtVal = [DateTime]::ParseExact(
                    "o",
                    $value,
                    [System.Globalization.CultureInfo]::InvariantCulture)
                $desiredAttributes.Add($dtVal.ToFileTimeUtc())
            }
            int {
                $desiredAttributes.Add([Int64]$value)
            }
            security_descriptor {
                $sd = New-Object -TypeName System.DirectoryServices.ActiveDirectorySecurity
                $sd.SetSecurityDescriptorSddlForm($value)
                $desiredAttributes.Add($sd)
            }
            raw {
                $desiredAttributes.Add($value)
            }
            default { throw "Attribute type '$type' must be bytes, date_time, int, security_descriptor, or raw" }
        }
    }

    $diffBefore = @($existingAttributes | ForEach-Object -Process $getDiffValue)
    $diffAfter = [System.Collections.Generic.List[object]]@()
    $value = [System.Collections.Generic.List[object]]@()
    $changed = $false

    # It's a lot easier to compare the string values
    $existing = [string[]]$diffBefore
    $desired = [string[]]@($desiredAttributes | ForEach-Object -Process $getDiffValue)

    if ($Action -eq 'Add') {
        $diffAfter.AddRange($existingAttributes)

        for ($i = 0; $i -lt $desired.Length; $i++) {
            if ($desired[$i] -cnotin $existing) {
                $value.Add($desiredAttributes[$i])
                $diffAfter.Add($desiredAttributes[$i])
                $changed = $true
            }
        }
    }
    elseif ($Action -eq 'Remove') {
        $diffAfter.AddRange($existingAttributes)

        for ($i = $desired.Length - 1; $i -ge 0; $i--) {
            if ($desired[$i] -cin $existing) {
                $value.Add($desiredAttributes[$i])
                $diffAfter.RemoveAt($i)
                $changed = $true
            }
        }
    }
    else {
        $diffAfter.AddRange($desiredAttributes)

        $toAdd = [string[]][System.Linq.Enumerable]::Except($desired, $existing)
        $toRemove = [string[]][System.Linq.Enumerable]::Except($existing, $desired)
        if ($toAdd.Length -or $toRemove.Length) {
            $changed = $true
        }

        if ($changed) {
            $value.AddRange($desiredAttributes)
        }
    }

    [PSCustomObject]@{
        Name = $Name
        Value = $value.ToArray()  # AD cmdlets expect an array here
        Changed = $changed
        DiffBefore = @($diffBefore | Sort-Object)
        DiffAfter = @($diffAfter | ForEach-Object -Process $getDiffValue | Sort-Object)
    }
}

Function Update-AnsibleADSetADObjectParam {
    <#
    .SYNOPSIS
    Updates the Set-AD* parameter splat with the parameters needed to set the
    attributes requested.
    It will output a boolean that indicates whether a change is needed to
    update the attributes.

    .PARAMETER Splat
    The parameter splat to update.

    .PARAMETER Add
    The attributes to add.

    .PARAMETER Remove
    The attributes to remove.

    .PARAMETER Set
    The attributes to set.

    .PARAMETER Diff
    An optional dictionary that can be used to store the diff output value on
    what was changed.

    .PARAMETER ADObject
    The AD object to compare the requested attribute values with.

    .PARAMETER ForNew
    This Splat is used for New-AD* and will update the OtherAttributes
    parameter.
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Collections.IDictionary]
        $Splat,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Add,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Remove,

        [Parameter()]
        [AllowNull()]
        [System.Collections.IDictionary]
        $Set,

        [Parameter()]
        [System.Collections.IDictionary]
        $Diff,

        [Parameter()]
        [AllowNull()]
        [Microsoft.ActiveDirectory.Management.ADObject]
        $ADObject,

        [Parameter()]
        [switch]
        $ForNew
    )

    $diffBefore = @{}
    $diffAfter = @{}

    $addAttributes = @{}
    $removeAttributes = @{}
    $replaceAttributes = @{}
    $clearAttributes = [System.Collections.Generic.List[String]]@()

    if ($Add.Count) {
        foreach ($kvp in $Add.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Add
            if ($val.Changed -and $val.Value.Count) {
                $addAttributes[$kvp.Key] = $val.Value
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }
    # remove doesn't make sense when creating a new object
    if (-not $ForNew -and $Remove.Count) {
        foreach ($kvp in $Remove.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Remove
            if ($val.Changed -and $val.Value.Count) {
                $removeAttributes[$kvp.Key] = $val.Value
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }
    if ($Set.Count) {
        foreach ($kvp in $Set.GetEnumerator()) {
            $val = Compare-AnsibleADAttribute -Name $kvp.Key -ADObject $ADObject -Attribute $kvp.Value -Action Set
            if ($val.Changed) {
                if ($val.Value.Count) {
                    $replaceAttributes[$kvp.Key] = $val.Value
                }
                else {
                    $clearAttributes.Add($kvp.Key)
                }
            }
            $diffBefore[$kvp.Key] = $val.DiffBefore
            $diffAfter[$kvp.Key] = $val.DiffAfter
        }
    }

    $changed = $false
    if ($ForNew) {
        $diffBefore = $null
        $otherAttributes = @{}

        foreach ($kvp in $addAttributes.GetEnumerator()) {
            $otherAttributes[$kvp.Key] = $kvp.Value
        }
        foreach ($kvp in $replaceAttributes.GetEnumerator()) {
            $otherAttributes[$kvp.Key] = $kvp.Value
        }

        if ($otherAttributes.Count) {
            $changed = $true
            $Splat.OtherAttributes = $otherAttributes
        }
    }
    else {
        if ($addAttributes.Count) {
            $changed = $true
            $Splat.Add = $addAttributes
        }
        if ($removeAttributes.Count) {
            $changed = $true
            $Splat.Remove = $removeAttributes
        }
        if ($replaceAttributes.Count) {
            $changed = $true
            $Splat.Replace = $replaceAttributes
        }
        if ($clearAttributes.Count) {
            $changed = $true
            $Splat.Clear = $clearAttributes
        }
    }

    if ($null -ne $Diff.Count) {
        $Diff.after = $diffAfter
        $Diff.before = $diffBefore
    }

    $changed
}

Function Get-AnsibleADAttributeSpec {
    <#
    .SYNOPSIS
    Used by modules to get the argument spec fragment for AnsibleModule that
    want to expose the AD attribute management.

    .EXAMPLE
    $spec = @{
        options = @{}
    }
    $module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-AnsibleADAttributeSpec))

    .NOTES
    The options here are reflected in the doc fragment 'ansible.active_directory.ad_attribute' at
    'plugins/doc_fragments/ad_attribute.py'.
    #>
    @{
        options = @{
            attributes = @{
                default = @{}
                type = 'dict'
                options = @{
                    add = @{
                        default = @{}
                        type = 'dict'
                    }
                    remove = @{
                        default = @{}
                        type = 'dict'
                    }
                    set = @{
                        default = @{}
                        type = 'dict'
                    }
                }
            }
        }
    }
}

$exportMembers = @{
    Function = @(
        "Get-AnsibleADAttributeSpec"
        "Update-AnsibleADSetADObjectParam"
    )
}
Export-ModuleMember @exportMembers
