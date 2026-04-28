#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

$cdpSubspec = @{
    options = @{
        uri = @{ type = 'str'; required = $true }
        publish_to_server = @{ type = 'bool'; default = $false }
        publish_delta_to_server = @{ type = 'bool'; default = $false }
        add_to_certificate_cdp = @{ type = 'bool'; default = $false }
        add_to_freshest_crl = @{ type = 'bool'; default = $false }
        add_to_crl_cdp = @{ type = 'bool'; default = $false }
        add_to_crl_idp = @{ type = 'bool'; default = $false }
    }
}

$aiaSubspec = @{
    options = @{
        uri = @{ type = 'str'; required = $true }
        add_to_certificate_aia = @{ type = 'bool'; default = $false }
        add_to_certificate_ocsp = @{ type = 'bool'; default = $false }
    }
}

$spec = @{
    options = @{
        cdp = @{
            type = 'list'
            elements = 'dict'
            options = $cdpSubspec.options
        }
        aia = @{
            type = 'list'
            elements = 'dict'
            options = $aiaSubspec.options
        }
        restart_service = @{
            type = 'bool'
            default = $true
        }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false
$module.Result.reboot_required = $false

# Maps Ansible snake_case param names to cmdlet PascalCase switch names.
# Used for key generation, splat building, and flag extraction.
$cdpFlagMap = [ordered]@{
    publish_to_server = 'PublishToServer'
    publish_delta_to_server = 'PublishDeltaToServer'
    add_to_certificate_cdp = 'AddToCertificateCdp'
    add_to_freshest_crl = 'AddToFreshestCrl'
    add_to_crl_cdp = 'AddToCrlCdp'
    add_to_crl_idp = 'AddToCrlIdp'
}

$aiaFlagMap = [ordered]@{
    add_to_certificate_aia = 'AddToCertificateAia'
    add_to_certificate_ocsp = 'AddToCertificateOcsp'
}

Function Get-EntryKey {
    <#
    .SYNOPSIS
    Builds a normalized string key from a cmdlet output object for set
    comparison. Flag values are read using the PascalCase cmdlet property
    names from the map.
    #>
    param($Entry, $FlagMap)
    $parts = @($Entry.Uri)
    foreach ($cmdletName in $FlagMap.Values) {
        if ([bool]$Entry.$cmdletName) { $parts += '1' } else { $parts += '0' }
    }
    $parts -join '|'
}

Function Get-DesiredEntryKey {
    <#
    .SYNOPSIS
    Builds a normalized string key from an Ansible param dict entry.
    Flag values are read using the snake_case param names from the map.
    #>
    param([hashtable]$Entry, $FlagMap)
    $parts = @($Entry.uri)
    foreach ($paramName in $FlagMap.Keys) {
        if ([bool]$Entry.$paramName) { $parts += '1' } else { $parts += '0' }
    }
    $parts -join '|'
}

Function ConvertTo-CmdletSplat {
    <#
    .SYNOPSIS
    Builds a parameter splat for an Add/Remove cmdlet from an Ansible
    param dict entry. Only includes flags that are true.
    #>
    param([hashtable]$Entry, $FlagMap)
    $splat = @{ Uri = $Entry.uri }
    foreach ($kvp in $FlagMap.GetEnumerator()) {
        if ($Entry[$kvp.Key]) {
            $splat[$kvp.Value] = $true
        }
    }
    $splat
}

Function Sync-CAExtensionList {
    <#
    .SYNOPSIS
    Compares current CA extension entries against a desired list and
    applies additions/removals. Works for both CDP and AIA by accepting
    the cmdlet names and flag map as parameters.
    #>
    param(
        [string]$Label,
        [hashtable[]]$DesiredEntries,
        $FlagMap,
        [string]$GetCmdlet,
        [string]$AddCmdlet,
        [string]$RemoveCmdlet
    )

    try {
        $currentEntries = @(& $GetCmdlet)
    }
    catch {
        $module.FailJson("Failed to get current $Label entries: $_", $_)
    }

    $currentKeys = @($currentEntries | ForEach-Object { Get-EntryKey $_ $FlagMap })
    $desiredKeys = @($DesiredEntries | ForEach-Object { Get-DesiredEntryKey $_ $FlagMap })

    $toRemove = @()
    $toAdd = @()
    if ($currentKeys.Count -eq 0 -and $desiredKeys.Count -eq 0) {
        return
    }
    elseif ($currentKeys.Count -eq 0) {
        $toAdd = $DesiredEntries
    }
    elseif ($desiredKeys.Count -eq 0) {
        $toRemove = $currentEntries
    }
    else {
        $diff = Compare-Object -ReferenceObject $currentKeys -DifferenceObject $desiredKeys
        foreach ($d in $diff) {
            if ($d.SideIndicator -eq '<=') {
                $idx = [array]::IndexOf($currentKeys, $d.InputObject)
                $toRemove += $currentEntries[$idx]
            }
            elseif ($d.SideIndicator -eq '=>') {
                $idx = [array]::IndexOf($desiredKeys, $d.InputObject)
                $toAdd += $DesiredEntries[$idx]
            }
        }
    }

    if ($toRemove.Count -eq 0 -and $toAdd.Count -eq 0) {
        return
    }

    $module.Result.changed = $true

    if (-not $module.CheckMode) {
        foreach ($entry in $toRemove) {
            try {
                $null = & $RemoveCmdlet -Uri $entry.Uri -Force
            }
            catch {
                $module.FailJson("Failed to remove $Label entry '$($entry.Uri)': $_", $_)
            }
        }
        foreach ($entry in $toAdd) {
            $splat = ConvertTo-CmdletSplat $entry $FlagMap
            $splat.Force = $true
            try {
                $null = & $AddCmdlet @splat
            }
            catch {
                $module.FailJson("Failed to add $Label entry '$($entry.uri)': $_", $_)
            }
        }
    }
}

# Handle cdp
if ($null -ne $module.Params.cdp) {
    Sync-CAExtensionList `
        -Label 'CDP' `
        -DesiredEntries $module.Params.cdp `
        -FlagMap $cdpFlagMap `
        -GetCmdlet 'Get-CACrlDistributionPoint' `
        -AddCmdlet 'Add-CACrlDistributionPoint' `
        -RemoveCmdlet 'Remove-CACrlDistributionPoint'
}

# Handle aia
if ($null -ne $module.Params.aia) {
    Sync-CAExtensionList `
        -Label 'AIA' `
        -DesiredEntries $module.Params.aia `
        -FlagMap $aiaFlagMap `
        -GetCmdlet 'Get-CAAuthorityInformationAccess' `
        -AddCmdlet 'Add-CAAuthorityInformationAccess' `
        -RemoveCmdlet 'Remove-CAAuthorityInformationAccess'
}

# Restart CertSvc if changes were made and restart_service is requested
if ($module.Result.changed -and $module.Params.restart_service) {
    if (-not $module.CheckMode) {
        try {
            Restart-Service -Name CertSvc -Force
        }
        catch {
            $module.FailJson("Failed to restart CertSvc service: $_", $_)
        }
    }
}

$module.ExitJson()
