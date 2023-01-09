# Copyright (c) 2023 Ansible Project
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

Function Get-AnsibleADObject {
    <#
    .SYNOPSIS
    The -Identity params is limited to just objectGuid and distinguishedName
    on Get-ADObject. Try to preparse the value to support more common props
    like sAMAccountName, objectSid, userPrincipalName.

    .PARAMETER Identity
    The Identity to get.

    .PARAMETER Properties
    Extra properties to request on the object

    .PARAMETER Server
    The explicit domain controller to query.

    .PARAMETER Credential
    Custom queries to authenticate with.

    .PARAMETER GetCommand
    The Get-AD* cmdlet to use to get the AD object. Defaults to Get-ADObject
    if not specified.
    #>
    [OutputType([Microsoft.ActiveDirectory.Management.ADObject])]
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Identity,

        [Parameter()]
        [AllowEmptyCollection()]
        [string[]]
        $Properties,

        [string]
        $Server,

        [PSCredential]
        $Credential,

        [System.Management.Automation.CommandInfo]
        $GetCommand = $null

    )

    $getByteFilterValue = {
        @($args[0] | ForEach-Object {
                '\' + [System.BitConverter]::ToString($_).ToLowerInvariant()
            }) -join ''
    }

    $ldapFilter = $null

    $objectGuid = [Guid]::Empty
    if ([System.Guid]::TryParse($Identity, [ref]$objectGuid)) {
        $value = &$getByteFilterValue $objectGuid.ToByteArray()
        $ldapFilter = "(objectGUID=$value)"
    }
    elseif ($Identity -match '^.*\@.*\..*$') {
        $ldapFilter = "(userPrincipalName=$($Matches[0]))"
    }
    elseif ($Identity -match '^(?:[^:*?""<>|\/\\]+\\)?(?<username>[^;:""<>|?,=\*\+\\\(\)]{1,20})$') {
        $ldapFilter = "(sAMAccountName=$($Matches.username))"
    }
    else {
        try {
            $sid = New-Object -TypeName System.Security.Principal.SecurityIdentifier -ArgumentList $Identity
            $sidBytes = New-Object -TypeName System.Byte[] -ArgumentList $sid.BinaryLength
            $sid.GetBinaryForm($sidBytes, 0)
            $value = &$getByteFilterValue $sidBytes
            $ldapFilter = "(objectSid=$value)"
        }
        catch [System.ArgumentException] {
            $ldapFilter = "(distinguishedName=$Identity)"
        }
    }

    $getParms = $PSBoundParameters
    $null = $getParms.Remove('Identity')
    if ($Properties.Count -eq 0) {
        $null = $getParms.Remove('Properties')
    }

    $cmd = if ($GetCommand) {
        $GetCommand
    }
    else {
        Get-Command -Name Get-ADObject -Module ActiveDirectory
    }

    & $cmd @PSBoundParameters -LDAPFilter $ldapFilter | Select-Object -First 1
}

$exportMembers = @{
    Function = @(
        "Get-AnsibleADObject"
    )
}
Export-ModuleMember @exportMembers
