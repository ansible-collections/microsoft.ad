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
            no_log = $false
        }
        notes = @{
            type = 'str'
        }
        access_control_policy_name = @{
            type = 'str'
        }
        issuance_transform_rules = @{
            type = 'str'
        }
        issuance_authorization_rules = @{
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
$module.Result.name = $module.Params.name
$module.Result.identifier = @()
$module.Result.enabled = $null
$module.Result.monitoring_enabled = $null
$name = $module.Params.name
$state = $module.Params.state

$signatureAlgorithmMap = @{
    'rsa_sha1' = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'
    'rsa_sha256' = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
}

$propertyMap = @(
    @{ Param = 'monitoring_enabled'; Cmdlet = 'MonitoringEnabled' }
    @{ Param = 'auto_update_enabled'; Cmdlet = 'AutoUpdateEnabled' }
    @{ Param = 'token_lifetime'; Cmdlet = 'TokenLifetime' }
    @{ Param = 'notes'; Cmdlet = 'Notes' }
    @{ Param = 'access_control_policy_name'; Cmdlet = 'AccessControlPolicyName' }
    @{ Param = 'issuance_transform_rules'; Cmdlet = 'IssuanceTransformRules' }
    @{ Param = 'issuance_authorization_rules'; Cmdlet = 'IssuanceAuthorizationRules' }
    @{ Param = 'signature_algorithm'; Cmdlet = 'SignatureAlgorithm'; Cast = { param($v) $signatureAlgorithmMap[$v] } }
    @{ Param = 'encrypt_claims'; Cmdlet = 'EncryptClaims' }
)

try {
    $existing = Get-AdfsRelyingPartyTrust -Name $name -ErrorAction Stop
}
catch {
    $module.FailJson("Failed to retrieve relying party trust '$name': $_", $_)
}

if ($state -eq 'present') {
    if (-not $existing) {
        # CREATE
        $addParams = @{
            Name = $name
            Confirm = $false
        }

        if ($module.Params.metadata_url) {
            try {
                $null = Invoke-WebRequest -Uri $module.Params.metadata_url -UseBasicParsing -ErrorAction Stop
            }
            catch {
                $module.FailJson("Cannot reach metadata URL '$($module.Params.metadata_url)': $_", $_)
            }
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

        foreach ($prop in $propertyMap) {
            $val = $module.Params[$prop.Param]
            if ($null -ne $val) {
                if ($prop.Cast) { $val = & $prop.Cast $val }
                $addParams[$prop.Cmdlet] = $val
            }
        }

        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                $cmd = Get-Command Add-AdfsRelyingPartyTrust
                if ($module.Params.saml_endpoint -and $cmd.Module.PrivateData.ImplicitRemoting) {
                    # The ADFS module is loaded via implicit remoting and
                    # SamlEndpoint objects get deserialized crossing the
                    # proxy boundary. Create them inside a WinPS session.
                    $addTrustWithEndpoints = {
                        param([hashtable]$Params, [string[]]$EndpointUris)
                        $eps = foreach ($u in $EndpointUris) {
                            New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $u
                        }
                        $Params['SamlEndpoint'] = @($eps)
                        Add-AdfsRelyingPartyTrust @Params
                    }
                    $winPS = New-PSSession -UseWindowsPowerShell
                    try {
                        Invoke-Command -Session $winPS -ScriptBlock $addTrustWithEndpoints -ArgumentList $addParams, [string[]]$module.Params.saml_endpoint
                    }
                    finally {
                        $winPS | Remove-PSSession
                    }
                }
                else {
                    if ($module.Params.saml_endpoint) {
                        $endpoints = @()
                        foreach ($ep in $module.Params.saml_endpoint) {
                            $endpoints += New-AdfsSamlEndpoint -Binding POST -Protocol SAMLAssertionConsumer -Uri $ep
                        }
                        $addParams.SamlEndpoint = $endpoints
                    }
                    Add-AdfsRelyingPartyTrust @addParams
                }
            }
            catch {
                $module.FailJson("Failed to create relying party trust '$name': $_", $_)
            }

            try {
                $existing = Get-AdfsRelyingPartyTrust -Name $name
            }
            catch {
                $module.FailJson("Failed to retrieve newly created trust '$name': $_", $_)
            }
        }
    }
    else {
        # UPDATE
        $updateParams = @{}

        foreach ($prop in $propertyMap) {
            $desired = $module.Params[$prop.Param]
            if ($null -eq $desired) { continue }

            if ($prop.Cast) { $desired = & $prop.Cast $desired }
            $current = $existing.($prop.Cmdlet)
            if ($desired -ne $current) {
                $updateParams[$prop.Cmdlet] = $desired
            }
        }

        if ($updateParams.Count -gt 0) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    Set-AdfsRelyingPartyTrust -TargetName $name @updateParams
                }
                catch {
                    $module.FailJson("Failed to update relying party trust '$name': $_", $_)
                }
            }
        }

        if ($null -ne $module.Params.enabled -and $module.Params.enabled -ne $existing.Enabled) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    if ($module.Params.enabled) {
                        Enable-AdfsRelyingPartyTrust -TargetName $name
                    }
                    else {
                        Disable-AdfsRelyingPartyTrust -TargetName $name
                    }
                }
                catch {
                    $module.FailJson("Failed to set enabled state for relying party trust '$name': $_", $_)
                }
            }
        }

        if ($module.Result.changed -and -not $module.CheckMode) {
            try {
                $existing = Get-AdfsRelyingPartyTrust -Name $name
            }
            catch {
                $module.FailJson("Failed to retrieve updated trust '$name': $_", $_)
            }
        }
    }

    if ($existing) {
        $module.Result.identifier = @($existing.Identifier)
        $module.Result.enabled = $existing.Enabled
        $module.Result.monitoring_enabled = $existing.MonitoringEnabled
    }
}
else {
    # ABSENT
    if ($existing) {
        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                Remove-AdfsRelyingPartyTrust -TargetName $name -Confirm:$false
            }
            catch {
                $module.FailJson("Failed to remove relying party trust '$name': $_", $_)
            }
        }
    }
}

$module.ExitJson()
