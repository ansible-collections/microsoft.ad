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
# Identifier). Treats both sides as unordered sets of values - this matches
# ADFS semantics for multi-valued properties like Identifier, and is a no-op
# simplification for scalars. Avoids Compare-Object entirely: passing it a
# genuinely empty array as -ReferenceObject/-DifferenceObject throws
# "Cannot bind argument to parameter 'ReferenceObject' because it is null"
# due to a PowerShell parameter-binding quirk, not because the value is
# actually null.
function Test-AdfsValueChanged {
    param($Current, $Desired)

    $currentArray = @($Current | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    $desiredArray = @($Desired | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })

    if ($currentArray.Count -ne $desiredArray.Count) {
        return $true
    }

    if ($currentArray.Count -eq 0) {
        return $false
    }

    $currentSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$currentArray)
    return -not $currentSet.SetEquals([string[]]$desiredArray)
}

function New-DesiredAdfsSamlEndpoints {
    param(
        [Parameter(Mandatory)]
        [string[]]$EndpointUris
    )

    @(
        for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
            [PSCustomObject]@{
                Uri = $EndpointUris[$i]
                Binding = 'POST'
                Protocol = 'SAMLAssertionConsumer'
                IsDefault = ($i -eq 0)
            }
        }
    )
}

function New-AdfsDesiredState {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$Current
    )

    [PSCustomObject]@{
        Identifier = @($Current.Identifier)
        Enabled = $Current.Enabled
        MonitoringEnabled = $Current.MonitoringEnabled
        AutoUpdateEnabled = $Current.AutoUpdateEnabled
        TokenLifetime = $Current.TokenLifetime
        Notes = $Current.Notes
        AccessControlPolicyName = $Current.AccessControlPolicyName
        SignatureAlgorithm = $Current.SignatureAlgorithm
        EncryptClaims = $Current.EncryptClaims
        WSFedEndpoint = $Current.WSFedEndpoint
        SamlEndpoints = @(
            $Current.SamlEndpoints | ForEach-Object {
                [PSCustomObject]@{
                    Uri = $_.Uri
                    Binding = $_.Binding
                    Protocol = $_.Protocol
                    IsDefault = $_.IsDefault
                }
            }
        )
    }
}

function Set-AdfsModuleResult {
    param(
        [Parameter(Mandatory)]
        [PSCustomObject]$State
    )

    $module.Result.identifier = @($State.Identifier)
    $module.Result.enabled = $State.Enabled
    $module.Result.monitoring_enabled = $State.MonitoringEnabled
    $module.Result.auto_update_enabled = $State.AutoUpdateEnabled
    $module.Result.token_lifetime = $State.TokenLifetime
    $module.Result.notes = $State.Notes
    $module.Result.access_control_policy_name = $State.AccessControlPolicyName
    $module.Result.encrypt_claims = $State.EncryptClaims
    $module.Result.saml_endpoints = @(
        $State.SamlEndpoints | ForEach-Object {
            $_.Uri
        }
    )

    if (
        $State.SignatureAlgorithm -and
        $signatureAlgorithmReverseMap.ContainsKey($State.SignatureAlgorithm)
    ) {
        $module.Result.signature_algorithm =
            $signatureAlgorithmReverseMap[$State.SignatureAlgorithm]
    }
    else {
        $module.Result.signature_algorithm = $State.SignatureAlgorithm
    }

    $module.Result.wsfed_endpoint = $State.WSFedEndpoint
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
            param(
                [string]$Operation,
                [string]$Name,
                [string[]]$EndpointUris,
                [hashtable]$AddParams
            )

            $eps = @(
                for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
                    New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)

                }
            )

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
        $endpoints = @(
            for ($i = 0; $i -lt $EndpointUris.Count; $i++) {
                New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $EndpointUris[$i] -Index $i -IsDefault:($i -eq 0)
            }
        )

        if ($Operation -eq 'Add') {
            $AddParams['SamlEndpoint'] = @($endpoints)
            Add-AdfsRelyingPartyTrust @AddParams -ErrorAction Stop
        }
        else {
            Set-AdfsRelyingPartyTrust -TargetName $Name -SamlEndpoint @($endpoints) -Confirm:$false -ErrorAction Stop
        }
    }
}

# Retrieves a relying party trust and flattens it into a plain PSCustomObject
# before it can cross the WinCompat remoting boundary. Under implicit
# remoting (PowerShell 7+ consuming the ADFS module via WinPS Compatibility),
# nested complex properties - most notably SamlEndpoints - do not survive
# CliXml round-tripping intact: PowerShell's remoting serializer falls back
# to capturing only ToString() once a type exceeds its default serialization
# depth, silently turning e.g. each SamlEndpoint object into the bare string
# "Microsoft.IdentityServer.Management.Resources.SamlEndpoint" with none of
# its real properties (Location, Binding, Protocol, IsDefault) intact. Doing
# the property extraction *inside* the native Windows PowerShell session -
# before anything crosses the proxy - avoids this entirely, mirroring how
# Invoke-AdfsTrustSamlEndpoint already does writes inside the same session
# boundary.
function Get-AdfsRelyingPartyTrustDetail {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    $cmd = Get-Command Get-AdfsRelyingPartyTrust -ErrorAction Stop
    $useRemoting = [bool]($cmd.Module.PrivateData.ImplicitRemoting)

    $scriptBlock = {
        param([string]$Name)

        $rp = Get-AdfsRelyingPartyTrust -Name $Name -ErrorAction Stop

        if (-not $rp) {
            return $null
        }

        $samlEndpoints = @(
            $rp.SamlEndpoints | ForEach-Object {
                [PSCustomObject]@{
                    Uri = $_.Location.ToString()
                    Binding = $_.Binding.ToString()
                    Protocol = $_.Protocol.ToString()
                    IsDefault = $_.IsDefault
                }
            }
        )

        [PSCustomObject]@{
            Identifier = @($rp.Identifier)
            WSFedEndpoint = if ($rp.WSFedEndpoint) {
                $rp.WSFedEndpoint.ToString()
            }
            else {
                $null
            }
            Enabled = $rp.Enabled
            MonitoringEnabled = $rp.MonitoringEnabled
            AutoUpdateEnabled = $rp.AutoUpdateEnabled
            TokenLifetime = $rp.TokenLifetime
            Notes = $rp.Notes
            AccessControlPolicyName = $rp.AccessControlPolicyName
            SignatureAlgorithm = $rp.SignatureAlgorithm
            EncryptClaims = $rp.EncryptClaims
            SamlEndpoints = $samlEndpoints
        }
    }

    if ($useRemoting) {
        $winPS = New-PSSession -UseWindowsPowerShell -ErrorAction Stop

        try {
            return Invoke-Command -Session $winPS -ScriptBlock $scriptBlock -ArgumentList $Name -ErrorAction Stop
        }
        finally {
            $winPS | Remove-PSSession -ErrorAction SilentlyContinue
        }
    }
    else {
        return & $scriptBlock $Name
    }
}

try {
    $existing = Get-AdfsRelyingPartyTrustDetail -Name $name
}
catch {
    $module.FailJson("Failed to retrieve relying party trust '$name': $($_.Exception.Message)", $_)
}

# $desiredState represents the state the module wants ADFS to have.
# In check mode this is returned directly.
# In normal mode it is replaced with the actual state after changes.
$desiredState = $null

if ($existing) {
    $desiredState = New-AdfsDesiredState -Current $existing
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
            if ($prop.Param -in @('identifier', 'wsfed_endpoint')) {
                continue
            }

            $val = $module.Params[$prop.Param]

            if ($null -eq $val) {
                continue
            }

            if ($prop.Cast) {
                $val = & $prop.Cast $val
            }

            $addParams[$prop.Cmdlet] = $val
        }

        # Build the desired state for the object that would be created.
        $desiredState = [PSCustomObject]@{
            Identifier = @($module.Params.identifier)
            Enabled = $module.Params.enabled
            MonitoringEnabled = $module.Params.monitoring_enabled
            AutoUpdateEnabled = $module.Params.auto_update_enabled
            TokenLifetime = $module.Params.token_lifetime
            Notes = $module.Params.notes
            AccessControlPolicyName = $module.Params.access_control_policy_name
            SignatureAlgorithm = $module.Params.signature_algorithm
            EncryptClaims = $module.Params.encrypt_claims
            WSFedEndpoint = $module.Params.wsfed_endpoint
            SamlEndpoints = @()
        }

        if ($module.Params.saml_endpoint) {
            $desiredState.SamlEndpoints =
                New-DesiredAdfsSamlEndpoints -EndpointUris @($module.Params.saml_endpoint)
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
                $existing = Get-AdfsRelyingPartyTrustDetail -Name $name
            }
            catch {
                $module.FailJson("Failed to retrieve newly created trust '$name': $($_.Exception.Message)", $_)
            }

            # Actual state is authoritative after creation.
            $desiredState = New-AdfsDesiredState -Current $existing
        }
    }
    else {
        # UPDATE

        $updateParams = @()

        ForEach ($prop in $propertyMap) {
            $desired = $module.Params[$prop.Param]

            if ($null -eq $desired) {
                continue
            }

            $desiredAdfsValue = $desired

            if ($prop.Cast) {
                $desiredAdfsValue = & $prop.Cast $desiredAdfsValue
            }

            $current = $existing.($prop.Cmdlet)

            if (Test-AdfsValueChanged -Current $current -Desired $desired) {
                $updateParams += @{
                    Cmdlet = $prop.Cmdlet
                    Value  = $desiredAdfsValue
                }

                # Project the requested value into the desired state.
                $desiredState.($prop.Cmdlet) = $desiredAdfsValue
            }
        }

        # SAML endpoint desired state.
        $samlEndpointChanged = $false

        if ($module.Params.saml_endpoint) {
            $desiredSamlEndpoints = New-DesiredAdfsSamlEndpoints -EndpointUris @($module.Params.saml_endpoint)

            $currentSamlEndpoints = @($existing.SamlEndpoints)

            # Compare in original order: order determines which endpoint gets
            # Index 0 / IsDefault. Compare Uri, Binding, Protocol, and
            # IsDefault so a change to any of those is detected, not just a
            # changed Location.
            $samlEndpointChanged = $currentSamlEndpoints.Count -ne $desiredSamlEndpoints.Count

            if (-not $samlEndpointChanged) {
                for ($i = 0; $i -lt $currentSamlEndpoints.Count; $i++) {
                    $currentEndpoint = $currentSamlEndpoints[$i]
                    $desiredEndpoint = $desiredSamlEndpoints[$i]

                    if (
                        $currentEndpoint.Uri -ne $desiredEndpoint.Uri -or
                        $currentEndpoint.Binding -ne $desiredEndpoint.Binding -or
                        $currentEndpoint.Protocol -ne $desiredEndpoint.Protocol -or
                        $currentEndpoint.IsDefault -ne $desiredEndpoint.IsDefault
                    ) {
                        $samlEndpointChanged = $true
                        break
                    }
                }
            }

            if ($samlEndpointChanged) {
                $desiredState.SamlEndpoints = $desiredSamlEndpoints
            }
        }

        # Enabled desired state.
        $enabledChanged = (
            $null -ne $module.Params.enabled -and
            $module.Params.enabled -ne $existing.Enabled
        )

        if ($enabledChanged) {
            $desiredState.Enabled = $module.Params.enabled
        }

        if (
            $updateParams.Count -gt 0 -or
            $samlEndpointChanged -or
            $enabledChanged
        ) {
            $module.Result.changed = $true
        }

        if (-not $module.CheckMode -and $module.Result.changed) {
            try {
                # Apply normal property updates.
                if ($updateParams.Count -gt 0) {
                    $setParams = @{}

                    foreach ($update in $updateParams) {
                        $setParams[$update.Cmdlet] = $update.Value
                    }

                    Set-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false @setParams -ErrorAction Stop
                }

                # Apply SAML endpoint changes.
                if ($samlEndpointChanged) {
                    Invoke-AdfsTrustSamlEndpoint -Operation Set -Name $name -EndpointUris @($module.Params.saml_endpoint) -AddParams $null
                }

                # Apply enabled state.
                if ($enabledChanged) {
                    if ($module.Params.enabled) {
                        Enable-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false -ErrorAction Stop
                    }
                    else {
                        Disable-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false -ErrorAction Stop
                    }
                }
            }
            catch {
                $module.FailJson(
                    "Failed to update relying party trust '$name': $($_.Exception.Message)",
                    $_
                )
            }

            try {
                $existing = Get-AdfsRelyingPartyTrustDetail -Name $name
            }
            catch {
                $module.FailJson(
                    "Failed to retrieve updated trust '$name': $($_.Exception.Message)",
                    $_
                )
            }

            # Actual state is authoritative after a real update.
            $desiredState = New-AdfsDesiredState -Current $existing
        }
    }

    if ($desiredState) {
        Set-AdfsModuleResult -State $desiredState
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
