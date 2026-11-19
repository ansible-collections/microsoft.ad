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

    $currentSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$currentArray)
    $desiredSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$desiredArray)

    return -not $currentSet.SetEquals($desiredSet)
}

# Compare SAML endpoints in their original order.
# Endpoint order matters because Index 0 is the default endpoint.
function Test-AdfsSamlEndpointsChanged {
    param(
        [Parameter(Mandatory)]
        [array]$Current,

        [Parameter(Mandatory)]
        [array]$Desired
    )

    if ($Current.Count -ne $Desired.Count) {
        return $true
    }

    for ($i = 0; $i -lt $Current.Count; $i++) {
        $currentEndpoint = $Current[$i]
        $desiredEndpoint = $Desired[$i]

        if (
            ([string]$currentEndpoint.Uri) -ne ([string]$desiredEndpoint.Uri) -or
            ([string]$currentEndpoint.Binding) -ne ([string]$desiredEndpoint.Binding) -or
            ([string]$currentEndpoint.Protocol) -ne ([string]$desiredEndpoint.Protocol) -or
            ([bool]$currentEndpoint.IsDefault) -ne ([bool]$desiredEndpoint.IsDefault)
        ) {
            return $true
        }
    }

    return $false
}

# Build the desired SAML endpoint collection.
function New-DesiredAdfsSamlEndpoint {
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

# Create a desired-state object from the current ADFS state.
#
# The desired state is used as the projected result in check mode.
# After a real update/create, it is replaced with the actual ADFS state.
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

# Convert a desired/current state object into the Ansible module result.
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
        $module.Result.signature_algorithm = $signatureAlgorithmReverseMap[$State.SignatureAlgorithm]
    }
    else {
        $module.Result.signature_algorithm = $State.SignatureAlgorithm
    }

    $module.Result.wsfed_endpoint = $State.WSFedEndpoint
}

# Builds the desired SAML endpoint collection and applies it via either
# Add-AdfsRelyingPartyTrust (creation) or Set-AdfsRelyingPartyTrust (update).
#
# When the ADFS module is loaded via implicit remoting, New-AdfsSamlEndpoint
# objects cannot cross the proxy boundary. In that case endpoint creation and
# the Add/Set call must happen inside the same Windows PowerShell session.
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
# its real properties (Location, Binding, Protocol, IsDefault) intact.
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
    $module.FailJson("Failed to retrieve relying party trust '$name': $_", $_)
}

# $desiredState is the single representation of the state the module wants.
#
# In check mode:
#   current state -> projected desired state -> result
#
# In normal mode:
#   current state -> projected desired state -> apply -> actual state -> result
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
            # These are already handled above for creation.
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

        # Build the projected desired state.
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
            $desiredState.SamlEndpoints = New-DesiredAdfsSamlEndpoint -EndpointUris @($module.Params.saml_endpoint)
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
                $module.FailJson("Failed to create relying party trust '$name': $_", $_)
            }

            try {
                $existing = Get-AdfsRelyingPartyTrustDetail -Name $name
            }
            catch {
                $module.FailJson("Failed to retrieve newly created trust '$name': $_", $_)
            }

            # Actual ADFS state is authoritative after creation.
            $desiredState = New-AdfsDesiredState -Current $existing
        }
    }
    else {
        # UPDATE

        # Always start from the current ADFS state.
        $desiredState = New-AdfsDesiredState -Current $existing

        $updateParams = @{}
        $samlEndpointChanged = $false
        $enabledChanged = $false

        # Scalar properties
        ForEach ($prop in $propertyMap) {
            $requested = $module.Params[$prop.Param]

            if ($null -eq $requested) {
                continue
            }

            $desiredValue = $requested

            if ($prop.Cast) {
                $desiredValue = & $prop.Cast $desiredValue
            }

            $currentValue = $existing.($prop.Cmdlet)

            if (Test-AdfsValueChanged -Current $currentValue -Desired $desiredValue) {
                $updateParams[$prop.Cmdlet] = $desiredValue

                # Project the requested value into desired state.
                $desiredState.($prop.Cmdlet) = $desiredValue
            }
        }
        # SAML endpoints

        if ($module.Params.saml_endpoint) {
            $desiredSamlEndpoints = New-DesiredAdfsSamlEndpoint -EndpointUris @($module.Params.saml_endpoint)

            $currentSamlEndpoints = @($existing.SamlEndpoints)

            $samlEndpointChanged = Test-AdfsSamlEndpointsChanged -Current $currentSamlEndpoints -Desired $desiredSamlEndpoints

            if ($samlEndpointChanged) {
                # Project requested SAML endpoint state.
                $desiredState.SamlEndpoints = $desiredSamlEndpoints
            }
        }

        # Enabled state
        if (
            $null -ne $module.Params.enabled -and
            $module.Params.enabled -ne $existing.Enabled
        ) {
            $enabledChanged = $true

            # Project requested enabled state.
            $desiredState.Enabled = $module.Params.enabled
        }

        # Determine whether anything changed.
        if (
            $updateParams.Count -gt 0 -or
            $samlEndpointChanged -or
            $enabledChanged
        ) {
            $module.Result.changed = $true
        }

        # Apply changes unless check mode is active.
        if (
            -not $module.CheckMode -and
            $module.Result.changed
        ) {
            try {
                # Apply scalar properties.
                if ($updateParams.Count -gt 0) {
                    Set-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false @updateParams -ErrorAction Stop
                }

                # Apply SAML endpoints.
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
                $module.FailJson("Failed to update relying party trust '$name': $_", $_)
            }

            # Re-read the actual state after applying the changes.
            try {
                $existing = Get-AdfsRelyingPartyTrustDetail -Name $name
            }
            catch {
                $module.FailJson("Failed to retrieve updated trust '$name': $_", $_)
            }

            # Actual ADFS state is authoritative after a real update.
            $desiredState = New-AdfsDesiredState -Current $existing
        }
    }

    # Return either:
    #
    #   - projected desired state in check mode
    #   - actual ADFS state after a real operation
    #
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
                $module.FailJson("Failed to remove relying party trust '$name': $_", $_)
            }
        }
    }
}

$module.ExitJson()
