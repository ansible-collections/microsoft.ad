#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils.ADAttribute
#AnsibleRequires -PowerShell ..module_utils.ADIdentity

$spec = @{
    options = @{
        description = @{
            type = 'str'
        }
        display_name = @{
            type = 'str'
        }
        domain_password = @{
            no_log = $true
            type = 'str'
        }
        domain_server = @{
            type = 'str'
        }
        domain_username = @{
            type = 'str'
        }
        identity = @{
            type = 'str'
        }
        name = @{
            type = 'str'
        }
        path = @{
            type = 'str'
        }
        state = @{
            choices = 'absent', 'present'
            default = 'present'
            type = 'str'
        }
        type = @{
            type = 'str'
        }
    }
    required_if = @(
        , @("state", "present", @("name", "type"))
    )
    required_one_of = @(
        , @("identity", "name")
    )
    required_together = @(, @('domain_username', 'domain_password'))
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec, @(Get-AnsibleADAttributeSpec))

$module.Result.object_guid = $null
$module.Result.distinguished_name = $null

Import-Module -Name ActiveDirectory

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

if ($module.Params.domain_username) {
    $adParams.Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList @(
        $module.Params.domain_username,
        (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.domain_password)
    )
}

[string[]]$requestedProperties = [System.Collections.Generic.HashSet[string]]@(
    'description'
    'displayName'
    'name'
    'objectClass'
    $module.Params.attributes.add.Keys
    $module.Params.attributes.remove.Keys
    $module.Params.attributes.set.Keys
) | Where-Object { $_ }

$defaultNamingContext = (Get-ADRootDSE -Properties defaultNamingContext @adParams).defaultNamingContext
$identity = if ($module.Params.identity) {
    $module.Params.identity
}
else {
    $ouPath = $defaultNamingContext
    if ($module.Params.path) {
        $ouPath = $module.Params.path
    }
    "CN=$($module.Params.name -replace ',', '\,'),$ouPath"
}

$getParams = @{
    Identity = $identity
    Properties = $requestedProperties
}
$adObject = Get-AnsibleADObject @getParams @adParams
if ($adObject) {
    $module.Result.object_guid = $adObject.ObjectGUID
    $module.Result.distinguished_name = $adObject.DistinguishedName

    $module.Diff.before = @{
        attributes = $null
        name = $adObject.Name
        description = $adObject.Description
        display_name = $adObject.DisplayName
        path = @($adObject.DistinguishedName -split '[^\\],', 2)[-1]
        type = $adObject.ObjectClass
    }
}
else {
    $module.Diff.before = $null
}

if ($module.Params.state -eq 'absent') {
    if ($adObject) {
        $removeParams = @{
            Confirm = $false
            WhatIf = $module.CheckMode
        }

        # Remove-ADObject -Recursive fails with access is denied, use this
        # instead to remove the child objects manually
        Get-ADObject -Filter * -Searchbase $adObject.DistinguishedName |
            Sort-Object -Property { $_.DistinguishedName.Length } -Descending |
            Remove-ADObject @removeParams @adParams

        $module.Result.changed = $true
    }

    $module.Diff.after = $null
}
else {
    $attributes = $module.Params.attributes
    $objectDN = $null
    $objectGuid = $null

    if (-not $adObject) {
        $newParams = @{
            Confirm = $false
            Name = $module.Params.name
            Type = $module.Params.type
            WhatIf = $module.CheckMode
            PassThru = $true
        }
        if ($module.Params.description) {
            $newParams.Description = $module.Params.description
        }
        if ($module.Params.display_name) {
            $newParams.DisplayName = $module.Params.display_name
        }

        $objectPath = $null
        if ($module.Params.path) {
            $objectPath = $path
            $newParams.Path = $module.Params.path
        }
        else {
            $objectPath = $defaultNamingContext
        }

        $diffAttributes = @{}
        $null = Update-AnsibleADSetADObjectParam @attributes -Splat $newParams -Diff $diffAttributes -ForNew

        $adObject = New-ADObject @newParams @adParams
        $module.Result.changed = $true

        if ($module.CheckMode) {
            $objectDN = "CN=$($module.Params.name -replace ',', '\,'),$objectPath"
            $objectGuid = [Guid]::Empty  # Dummy value for check mode
        }
        else {
            $objectDN = $adObject.DistinguishedName
            $objectGuid = $adObject.ObjectGUID
        }

        $module.Diff.after = @{
            attributes = $diffAttributes.after
            name = $module.Params.name
            description = $module.Params.description
            display_name = $module.Params.display_name
            path = $objectPath
            type = $module.Params.type
        }
    }
    else {
        $objectDN = $adObject.DistinguishedName
        $objectGuid = $adObject.ObjectGUID

        $commonParams = @{
            Confirm = $false
            Identity = $adObject.ObjectGUID
            PassThru = $true
            WhatIf = $module.CheckMode
        }
        $setParams = @{}

        if ($adObject.ObjectClass -ne $module.Params.type) {
            $msg = -join @(
                "Cannot change object type $($adObject.ObjectClass) of existing object "
                "$($adObject.DistinguishedName) to $($module.Params.type)"
            )
            $module.FailJson($msg)
        }

        $diffAttributes = @{}
        $changed = Update-AnsibleADSetADObjectParam @attributes -Splat $setParams -Diff $diffAttributes -ADObject $adObject
        if ($changed) {
        }

        $description = $adObject.Description
        if ($module.Params.description -and $module.Params.description -cne $description) {
            $description = $module.Params.description
            $setParams.Description = $description
            $changed = $true
        }

        $displayName = $adObject.DisplayName
        if ($module.Params.display_name -and $module.Params.display_name -cne $displayName) {
            $displayName = $module.Params.display_name
            $setParams.DisplayName = $displayName
            $changed = $true
        }

        $objectName = $adObject.Name
        $objectPath = @($objectDN -split '[^\\],', 2)[-1]

        if ($module.Params.name -cne $objectName) {
            $objectName = $module.Params.name
            $adObject = Rename-ADObject @commonParams -NewName $objectName
            $module.Result.changed = $true
        }

        if ($module.Params.path -and $module.Params.path -ne $objectPath) {
            $objectPath = $module.Params.path
            $adObject = Move-ADObject @commonParams -TargetPath $objectPath
            $module.Result.changed = $true
        }

        if ($changed) {
            $adObject = Set-ADObject @commonParams @setParams @adParams
            $module.Result.changed = $true
        }

        if ($module.CheckMode) {
            $objectDN = "CN=$($objectName -replace ',', '\,'),$objectPath"
        }
        else {
            $objectDN = $adObject.DistinguishedName
        }

        $module.Diff.before.attributes = $diffAttributes.before
        $module.Diff.after = @{
            attributes = $diffAttributes.after
            name = $objectName
            description = $description
            display_name = $displayName
            path = $objectPath
            type = $module.Params.type
        }
    }

    # Explicit vars are set when running in check mode as the adObject may not
    # have the desired values set at runtime
    $module.Result.distinguished_name = $objectDN
    $module.Result.object_guid = $objectGuid.Guid
}

$module.ExitJson()
