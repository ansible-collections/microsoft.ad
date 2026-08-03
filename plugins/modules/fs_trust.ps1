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
        metadata_url = @{
            type = 'str'
        }
        metadata_file = @{
            type = 'str'
        }
        identifier = @{
            type = 'list'
            elements = 'str'
        }
        saml_endpoint = @{
            type = 'list'
            elements = 'str'
        }
        wsfed_endpoint = @{
            type = 'str'
        }
        enabled = @{
            type = 'bool'
        }
        monitoring_enabled = @{
            type = 'bool'
        }
        auto_update_enabled = @{
            type = 'bool'
        }
        token_lifetime = @{
            type = 'int'
            no_log = $false  # Needed for linter: no-log-needed: Argument 'token_lifetime' in argument_spec could be a secret, though doesn't have `no_log` set
        }
        notes = @{
            type = 'str'
        }
        access_control_policy_name = @{
            type = 'str'
        }
        signature_algorithm = @{
            type = 'str'
            choices = @('rsa_sha1', 'rsa_sha256')
        }
        encrypt_claims = @{
            type = 'bool'
        }
    }
    mutually_exclusive = @(
        , @('metadata_url', 'metadata_file', 'identifier')
    )
    required_if = @(
        , @('state', 'present', @('metadata_url', 'metadata_file', 'identifier'), $true)
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false
$module.Result.identifier = @()
$module.Result.enabled = $null
$module.Result.monitoring_enabled = $null
$module.Result.auto_update_enabled = $null
$module.Result.token_lifetime = $null
$module.Result.notes = $null
$module.Result.access_control_policy_name = $null
$module.Result.signature_algorithm = $null
$module.Result.encrypt_claims = $null
$module.Result.wsfed_endpoint = $null
$module.Result.saml_endpoints = @()

$name = $module.Params.name
$state = $module.Params.state

$signatureAlgorithmMap = @{
    'rsa_sha1' = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    'rsa_sha256' = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
}
# Reverse map so we can report signature_algorithm back in the friendly
# short form rather than the raw XML-DSig URI.
$signatureAlgorithmReverseMap = @{}
ForEach ($kvp in $signatureAlgorithmMap.GetEnumerator()) {
    $signatureAlgorithmReverseMap[$kvp.Value] = $kvp.Name
}

# Properties that can be set both at creation time (via Add-AdfsRelyingPartyTrust)
# and updated afterwards (via Set-AdfsRelyingPartyTrust). Identifier and
# WSFedEndpoint are included here too so drift on those is detected/corrected
# on update, not just applied at creation.
$propertyMap = @(
    @{ Param = 'identifier'; Cmdlet = 'Identifier' }
    @{ Param = 'wsfed_endpoint'; Cmdlet = 'WSFedEndpoint'; Cast = { param($v) [Uri]$v } }
    @{ Param = 'monitoring_enabled'; Cmdlet = 'MonitoringEnabled' }
    @{ Param = 'auto_update_enabled'; Cmdlet = 'AutoUpdateEnabled' }
    @{ Param = 'token_lifetime'; Cmdlet = 'TokenLifetime' }
    @{ Param = 'notes'; Cmdlet = 'Notes' }
    @{ Param = 'access_control_policy_name'; Cmdlet = 'AccessControlPolicyName' }
    @{ Param = 'signature_algorithm'; Cmdlet = 'SignatureAlgorithm'; Cast = { param($v) $signatureAlgorithmMap[$v] } }
    @{ Param = 'encrypt_claims'; Cmdlet = 'EncryptClaims' }
)

# Generic "is this different" check used for both scalars and arrays (e.g.
# Identifier). Compare-Object handles both cleanly when each side is
# wrapped in @(); plain -ne on two arrays does an unintended element-wise
# comparison rather than a whole-collection comparison.
function Test-AdfsValueChanged {
    param($Current, $Desired)
    return [bool](Compare-Object -ReferenceObject @($Current) -DifferenceObject @($Desired))
}

# Builds the desired SAML endpoint collection and applies it via either
# Add-AdfsRelyingPartyTrust (creation) or Set-AdfsRelyingPartyTrust (update).
# When the ADFS module is loaded via implicit remoting, New-AdfsSamlEndpoint
# objects can't cross the proxy boundary, so in that case the endpoint
# creation AND the Add/Set call must happen together inside the same
# Windows PowerShell session.
function Invoke-AdfsTrustSamlEndpoint {
    param(
        [ValidateSet('Add', 'Set')]
        [string]$Operation,
        [string]$Name,
        [string[]]$EndpointUris,
        [hashtable]$AddParams
    )

    $cmd = Get-Command Add-AdfsRelyingPartyTrust -ErrorAction Stop
    $useRemoting = [bool]($cmd.Module.PrivateData.ImplicitRemoting)

    if ($useRemoting) {
        $scriptBlock = {
            param([string]$Operation, [string]$Name, [string[]]$EndpointUris, [hashtable]$AddParams)
            # $eps = [System.Collections.Generic.List[object]]::new()
            # for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
            #     $eps.Add((New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)))
            # }

            $eps = for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
                New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)
            }
            if ($Operation -eq 'Add') {
                $AddParams['SamlEndpoint'] = @($eps)
                Add-AdfsRelyingPartyTrust @AddParams
            }
            else {
                Set-AdfsRelyingPartyTrust -TargetName $Name -SamlEndpoint @($eps) -Confirm:$false
            }
        }

        $winPS = New-PSSession -UseWindowsPowerShell -ErrorAction Stop
        try {
            Invoke-Command -Session $winPS -ScriptBlock $scriptBlock -ArgumentList $Operation, $Name, $EndpointUris, $AddParams -ErrorAction Stop
        }
        finally {
            $winPS | Remove-PSSession -ErrorAction SilentlyContinue
        }
    }
    else {
        # $endpoints = [System.Collections.Generic.List[object]]::new()
        # for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
        #     $endpoints.Add((New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)))
        # }

        $endpoints = for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
            New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)
        }

        if ($Operation -eq 'Add') {
            $AddParams['SamlEndpoint'] = @($endpoints)
            Add-AdfsRelyingPartyTrust @AddParams -ErrorAction Stop
        }
        else {
            Set-AdfsRelyingPartyTrust -TargetName $Name -SamlEndpoint @($endpoints) -Confirm:$false -ErrorAction Stop
        }
    }
}

try {
    $existing = Get-AdfsRelyingPartyTrust -Name $name -ErrorAction Stop
}
catch {
    $module.FailJson("Failed to retrieve relying party trust '$name': $($_.Exception.Message)", $_)
}

if ($state -eq 'present') {
    if (-not $existing) {
        # CREATE
        $addParams = @{
            Name = $name
            Confirm = $false
        }

        if ($module.Params.metadata_url) {
            # No separate reachability pre-check here: Add-AdfsRelyingPartyTrust
            # will itself fail with a clear error if the URL can't be reached,
            # so a second, possibly differently-authenticated request is just
            # an extra point of failure without adding real safety.
            $addParams.MetadataUrl = [Uri]$module.Params.metadata_url
        }
        elseif ($module.Params.metadata_file) {
            if (-not (Test-Path -LiteralPath $module.Params.metadata_file)) {
                $module.FailJson("Metadata file not found: '$($module.Params.metadata_file)'")
            }
            $addParams.MetadataFile = $module.Params.metadata_file
        }
        else {
            $addParams.Identifier = $module.Params.identifier
            if ($module.Params.wsfed_endpoint) {
                $addParams.WSFedEndpoint = [Uri]$module.Params.wsfed_endpoint
            }
        }

        if ($null -ne $module.Params.enabled) {
            $addParams.Enabled = $module.Params.enabled
        }

        ForEach ($prop in $propertyMap) {
            # Identifier/WSFedEndpoint are already handled above for the
            # non-metadata creation path; avoid clobbering/duplicating them.
            if ($prop.Param -in @('identifier', 'wsfed_endpoint')) { continue }

            $val = $module.Params[$prop.Param]
            if ($null -ne $val) {
                if ($prop.Cast) { $val = & $prop.Cast $val }
                $addParams[$prop.Cmdlet] = $val
            }
        }

        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                if ($module.Params.saml_endpoint) {
                    Invoke-AdfsTrustSamlEndpoint -Operation Add -Name $name -EndpointUris @($module.Params.saml_endpoint) -AddParams $addParams
                }
                else {
                    Add-AdfsRelyingPartyTrust @addParams -ErrorAction Stop
                }
            }
            catch {
                $module.FailJson("Failed to create relying party trust '$name': $($_.Exception.Message)", $_)
            }

            try {
                $existing = Get-AdfsRelyingPartyTrust -Name $name -ErrorAction Stop
            }
            catch {
                $module.FailJson("Failed to retrieve newly created trust '$name': $($_.Exception.Message)", $_)
            }
        }
    }
    else {
        # UPDATE
        $updateParams = @{}

        ForEach ($prop in $propertyMap) {
            $desired = $module.Params[$prop.Param]
            if ($null -eq $desired) { continue }

            if ($prop.Cast) { $desired = & $prop.Cast $desired }
            $current = $existing.($prop.Cmdlet)

            if (Test-AdfsValueChanged -Current $current -Desired $desired) {
                $updateParams[$prop.Cmdlet] = $desired
            }
        }

        if ($updateParams.Count -gt 0) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    Set-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false @updateParams -ErrorAction Stop
                }
                catch {
                    $module.FailJson("Failed to update relying party trust '$name': $($_.Exception.Message)", $_)
                }
            }
        }

        # Update SAML endpoints if different from what's currently configured.
        # Set-AdfsRelyingPartyTrust -SamlEndpoint replaces the entire endpoint
        # collection, so saml_endpoint in the playbook must always contain the
        # full desired set, not just the endpoint(s) being added.
        if ($module.Params.saml_endpoint) {
            # Build both lists with .Add() rather than capturing loop/pipeline
            # output into a variable. Capturing a for/foreach/pipeline result
            # directly unwraps a single-item result into a bare object
            # instead of a 1-element array, which broke .Count comparisons
            # (and therefore idempotency) whenever exactly one SAML endpoint
            # was configured.
            # $desiredEndpoints = [System.Collections.Generic.List[object]]::new()
            # for ($i = 0; $i -lt $module.Params.saml_endpoint.Count; $i++) {
            #     $desiredEndpoints.Add([PSCustomObject]@{
            #         Uri = $module.Params.saml_endpoint[$i]
            #         Binding = 'POST'
            #         Protocol = 'SAMLAssertionConsumer'
            #         IsDefault = ($i -eq 0)
            #    })
            # }

            # $currentEndpoints = [System.Collections.Generic.List[object]]::new()
            # ForEach ($endpoint in @($existing.SamlEndpoints)) {
            #     $currentEndpoints.Add([PSCustomObject]@{
            #         Uri = $endpoint.Location.ToString()
            #         Binding = $endpoint.Binding.ToString()
            #         Protocol = $endpoint.Protocol.ToString()
            #         IsDefault = $endpoint.IsDefault
            #     })
            # }

            $desiredEndpoints = @(
                ForEach ($i = 0; $i -lt $module.Params.saml_endpoint.Count; $i++) {
                    [PSCustomObject]@{
                        Uri = $module.Params.saml_endpoint[$i]
                        Binding = 'POST'
                        Protocol = 'SAMLAssertionConsumer'
                        IsDefault = ($i -eq 0)
                    }
                }
            )

            $currentEndpoints = @(
                ForEach ($ep in $existing.SamlEndpoints) {
                    [PSCustomObject]@{
                        Uri = $ep.Location.ToString()
                        Binding = $ep.Binding.ToString()
                        Protocol = $ep.Protocol.ToString()
                        IsDefault = $ep.IsDefault
                    }
                }
            )

            # Compare in original order: order determines which endpoint gets
            # Index 0 / IsDefault. Compare Uri, Binding, Protocol, and
            # IsDefault so a change to any of those is detected, not just a
            # changed Location.
            $samlEndpointChanged = $currentEndpoints.Count -ne $desiredEndpoints.Count
            if (-not $samlEndpointChanged) {
                for ($i = 0; $i -lt $currentEndpoints.Count; $i++) {
                    $c = $currentEndpoints[$i]
                    $d = $desiredEndpoints[$i]
                    if ($c.Uri -ne $d.Uri -or $c.Binding -ne $d.Binding -or $c.Protocol -ne $d.Protocol -or $c.IsDefault -ne $d.IsDefault) {
                        $samlEndpointChanged = $true
                        break
                    }
                }
            }

            if ($samlEndpointChanged) {
                $module.Result.changed = $true

                if (-not $module.CheckMode) {
                    try {
                        Invoke-AdfsTrustSamlEndpoint -Operation Set -Name $name -EndpointUris @($module.Params.saml_endpoint) -AddParams $null
                    }
                    catch {
                        $module.FailJson("Failed to update SAML endpoints for relying party trust '$name': $($_.Exception.Message)", $_)
                    }
                }
            }
        }

        if ($null -ne $module.Params.enabled -and $module.Params.enabled -ne $existing.Enabled) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    if ($module.Params.enabled) {
                        Enable-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false -ErrorAction Stop
                    }
                    else {
                        Disable-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false -ErrorAction Stop
                    }
                }
                catch {
                    $module.FailJson("Failed to set enabled state for relying party trust '$name': $($_.Exception.Message)", $_)
                }
            }
        }

        if ($module.Result.changed -and -not $module.CheckMode) {
            try {
                $existing = Get-AdfsRelyingPartyTrust -Name $name -ErrorAction Stop
            }
            catch {
                $module.FailJson("Failed to retrieve updated trust '$name': $($_.Exception.Message)", $_)
            }
        }
    }

    if ($existing) {
        $module.Result.identifier = @($existing.Identifier)
        $module.Result.enabled = $existing.Enabled
        $module.Result.monitoring_enabled = $existing.MonitoringEnabled
        $module.Result.auto_update_enabled = $existing.AutoUpdateEnabled
        $module.Result.token_lifetime = $existing.TokenLifetime
        $module.Result.notes = $existing.Notes
        $module.Result.access_control_policy_name = $existing.AccessControlPolicyName
        $module.Result.encrypt_claims = $existing.EncryptClaims
        $module.Result.saml_endpoints = @($existing.SamlEndpoints | ForEach-Object { $_.Location.ToString() })

        if ($existing.SignatureAlgorithm -and $signatureAlgorithmReverseMap.ContainsKey($existing.SignatureAlgorithm)) {
            $module.Result.signature_algorithm = $signatureAlgorithmReverseMap[$existing.SignatureAlgorithm]
        }
        else {
            $module.Result.signature_algorithm = $existing.SignatureAlgorithm
        }

        if ($existing.WSFedEndpoint) {
            $module.Result.wsfed_endpoint = $existing.WSFedEndpoint.ToString()
        }
    }
}
else {
    # ABSENT
    if ($existing) {
        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                Remove-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false -ErrorAction Stop
            }
            catch {
                $module.FailJson("Failed to remove relying party trust '$name': $($_.Exception.Message)", $_)
            }
        }
    }
}

$module.ExitJson()
