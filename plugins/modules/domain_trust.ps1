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
        direction = @{
            type = 'str'
            choices = @('inbound', 'outbound', 'bidirectional')
        }
        type = @{
            type = 'str'
            choices = @('external', 'forest')
        }
        trust_password = @{
            type = 'str'
            no_log = $true
        }
        selective_authentication = @{
            type = 'bool'
        }
        domain_server = @{
            type = 'str'
        }
    }
    required_if = @(
        , @('state', 'present', @('direction', 'type', 'trust_password'))
    )
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.changed = $false
$module.Result.distinguished_name = $null

$name = $module.Params.name
$state = $module.Params.state

$directionMap = @{
    'inbound' = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Inbound
    'outbound' = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Outbound
    'bidirectional' = [System.DirectoryServices.ActiveDirectory.TrustDirection]::Bidirectional
}

$directionDisplayMap = @{
    'inbound' = 'Inbound'
    'outbound' = 'Outbound'
    'bidirectional' = 'BiDirectional'
}

# Get-ADTrust uses ForestTransitive (bool) to distinguish forest vs external,
# not TrustType (which returns Uplevel/Downlevel/MIT).
Function Get-TrustTypeDisplay {
    param($ADTrust)
    if ($ADTrust.ForestTransitive) { 'Forest' } else { 'External' }
}

Function Test-IsForestTrust {
    param($ADTrust)
    [bool]$ADTrust.ForestTransitive
}

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

try {
    $existing = Get-ADTrust @adParams -Identity $name -ErrorAction SilentlyContinue
}
catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
    $existing = $null
}
catch {
    $module.FailJson("Failed to retrieve trust '$name': $_", $_)
}

if ($state -eq 'present') {
    $desiredDirection = $directionDisplayMap[$module.Params.direction]
    $desiredType = if ($module.Params.type -eq 'forest') { 'Forest' } else { 'External' }
    $trustDirection = $directionMap[$module.Params.direction]

    if (-not $existing) {
        $module.Result.changed = $true
        $module.Diff.before = @{}
        $module.Diff.after = @{
            name = $name
            direction = $desiredDirection
            trust_type = $desiredType
            selective_authentication = [bool]$module.Params.selective_authentication
        }

        if (-not $module.CheckMode) {
            try {
                $null = Resolve-DnsName -Name $name -ErrorAction Stop
            }
            catch {
                $module.FailJson("DNS resolution failed for '$name'. Ensure DNS conditional forwarders are configured before creating a trust: $_", $_)
            }

            try {
                if ($module.Params.type -eq 'forest') {
                    $localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    $localForest.CreateLocalSideOfTrustRelationship($name, $trustDirection, $module.Params.trust_password)
                }
                else {
                    $localDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    $localDomain.CreateLocalSideOfTrustRelationship($name, $trustDirection, $module.Params.trust_password)
                }
            }
            catch {
                $module.FailJson("Failed to create trust '$name': $_", $_)
            }

            if ($module.Params.type -eq 'forest' -and
                $null -ne $module.Params.selective_authentication -and
                $module.Params.selective_authentication) {
                try {
                    $localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    $localForest.SetSelectiveAuthenticationStatus($name, $true)
                }
                catch {
                    $module.FailJson("Trust created but failed to enable selective authentication on '$name': $_", $_)
                }
            }

            try {
                $existing = Get-ADTrust @adParams -Identity $name
            }
            catch {
                $module.FailJson("Trust creation succeeded but validation failed for '$name': $_", $_)
            }

            $module.Result.distinguished_name = $existing.DistinguishedName
        }
    }
    else {
        # UPDATE
        $module.Result.distinguished_name = $existing.DistinguishedName
        $currentType = Get-TrustTypeDisplay $existing

        $module.Diff.before = @{
            name = $name
            direction = [string]$existing.Direction
            trust_type = $currentType
            selective_authentication = [bool]$existing.SelectiveAuthentication
        }

        if ($desiredDirection -ne [string]$existing.Direction) {
            $module.FailJson(
                "Trust '$name' exists with direction '$($existing.Direction)' but '$desiredDirection' was requested. " +
                "Direction cannot be changed in-place. Remove the trust first (state=absent) and recreate it."
            )
        }
        if ($desiredType -ne $currentType) {
            $module.FailJson(
                "Trust '$name' exists with type '$currentType' but '$desiredType' was requested. " +
                "Type cannot be changed in-place. Remove the trust first (state=absent) and recreate it."
            )
        }

        $after = $module.Diff.before.Clone()

        if ($null -ne $module.Params.selective_authentication -and
            $module.Params.selective_authentication -ne [bool]$existing.SelectiveAuthentication) {

            if (-not (Test-IsForestTrust $existing)) {
                $module.FailJson("Selective authentication can only be set on forest trusts, not external trusts.")
            }

            $after.selective_authentication = $module.Params.selective_authentication
            $module.Result.changed = $true

            if (-not $module.CheckMode) {
                try {
                    $localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    $localForest.SetSelectiveAuthenticationStatus($name, $module.Params.selective_authentication)
                }
                catch {
                    $module.FailJson("Failed to update selective authentication on trust '$name': $_", $_)
                }
            }
        }

        $module.Diff.after = $after
    }
}
else {
    # ABSENT
    if ($existing) {
        $currentType = Get-TrustTypeDisplay $existing
        $module.Result.distinguished_name = $existing.DistinguishedName
        $module.Result.changed = $true

        $module.Diff.before = @{
            name = $name
            direction = [string]$existing.Direction
            trust_type = $currentType
            selective_authentication = [bool]$existing.SelectiveAuthentication
        }
        $module.Diff.after = @{}

        if (-not $module.CheckMode) {
            try {
                if (Test-IsForestTrust $existing) {
                    $localForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
                    $localForest.DeleteLocalSideOfTrustRelationship($name)
                }
                else {
                    $localDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
                    $localDomain.DeleteLocalSideOfTrustRelationship($name)
                }
            }
            catch {
                $module.FailJson("Failed to remove trust '$name': $_", $_)
            }
        }
    }
}

$module.ExitJson()
