#!powershell

# Copyright (c) 2026 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic

using namespace System.Management.Automation

$spec = @{
    options = @{
        name = @{
            type = 'str'
            required = $true
        }
        display_name = @{
            type = 'str'
        }
        state = @{
            type = 'str'
            default = 'present'
            choices = @('present', 'absent')
        }
        source_template = @{
            type = 'str'
        }
        key_size = @{
            type = 'int'
        }
        extended_key_usages = @{
            type = 'list'
            elements = 'str'
        }
        key_usage = @{
            type = 'list'
            elements = 'str'
        }
        validity_period_days = @{
            type = 'int'
        }
        renewal_period_days = @{
            type = 'int'
        }
        enrollment_flag = @{
            type = 'list'
            elements = 'str'
        }
        private_key_flag = @{
            type = 'list'
            elements = 'str'
            no_log = $false
        }
        certificate_name_flag = @{
            type = 'list'
            elements = 'str'
        }
        schema_version = @{
            type = 'int'
            choices = @(2, 3, 4)
        }
        publish_to_ca = @{
            type = 'list'
            elements = 'str'
        }
        domain_server = @{
            type = 'str'
        }
    }
    supports_check_mode = $true
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)

$module.Result.changed = $false
$module.Result.distinguished_name = $null
$module.Result.template_oid = $null

$name = $module.Params.name
$displayName = if ($module.Params.display_name) { $module.Params.display_name } else { $name }
$state = $module.Params.state
$sourceTemplate = $module.Params.source_template

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

# Name-Value Maps

$ekuMap = @{
    'server_authentication'     = '1.3.6.1.5.5.7.3.1'
    'client_authentication'     = '1.3.6.1.5.5.7.3.2'
    'code_signing'              = '1.3.6.1.5.5.7.3.3'
    'secure_email'              = '1.3.6.1.5.5.7.3.4'
    'ip_security_end_system'    = '1.3.6.1.5.5.7.3.5'
    'ip_security_tunnel'        = '1.3.6.1.5.5.7.3.6'
    'ip_security_user'          = '1.3.6.1.5.5.7.3.7'
    'time_stamping'             = '1.3.6.1.5.5.7.3.8'
    'ocsp_signing'              = '1.3.6.1.5.5.7.3.9'
    'smart_card_logon'          = '1.3.6.1.4.1.311.20.2.2'
    'certificate_request_agent' = '1.3.6.1.4.1.311.20.2.1'
    'encrypting_file_system'    = '1.3.6.1.4.1.311.10.3.4'
    'file_recovery'             = '1.3.6.1.4.1.311.10.3.4.1'
    'key_recovery'              = '1.3.6.1.4.1.311.10.3.11'
    'key_recovery_agent'        = '1.3.6.1.4.1.311.21.6'
    'document_signing'          = '1.3.6.1.4.1.311.10.3.12'
    'remote_desktop'            = '1.3.6.1.4.1.311.54.1.2'
    'kdc_authentication'        = '1.3.6.1.5.2.3.5'
}

$enrollmentFlagMap = @{
    'include_symmetric_algorithms'            = 0x00000001
    'pend_all_requests'                       = 0x00000002
    'publish_to_kra_container'                = 0x00000004
    'publish_to_ds'                           = 0x00000008
    'auto_enrollment_check_user_ds_certificate' = 0x00000010
    'auto_enrollment'                         = 0x00000020
    'previous_approval_validate_reenrollment' = 0x00000040
}

$privateKeyFlagMap = @{
    'require_private_key_archival'          = 0x00000001
    'exportable_key'                        = 0x00000010
    'strong_key_protection_required'        = 0x00000020
    'require_alternate_signature_algorithm' = 0x00000040
    'require_same_key_renewal'              = 0x00000080
    'use_legacy_provider'                   = 0x00000100
    'ek_trust_on_use'                       = 0x00000200
    'ek_validate_cert'                      = 0x00000400
    'ek_validate_key'                       = 0x00000800
    'attest_preferred'                      = 0x00001000
    'attest_required'                       = 0x00002000
    'attestation_without_policy'            = 0x00004000
    'hello_logon_key'                       = 0x00200000
}

$certNameFlagMap = @{
    'enrollee_supplies_subject'          = 0x00000001
    'enrollee_supplies_subject_alt_name' = 0x00010000
    'subject_alt_require_domain_dns'     = 0x00400000
    'subject_alt_require_spn'            = 0x00800000
    'subject_alt_require_directory_guid' = 0x01000000
    'subject_alt_require_upn'            = 0x02000000
    'subject_alt_require_email'          = 0x04000000
    'subject_alt_require_dns'            = 0x08000000
    'subject_require_dns_as_cn'          = 0x10000000
    'subject_require_email'              = 0x20000000
    'subject_require_common_name'        = 0x40000000
    'subject_require_directory_path'     = 0x80000000
}

# pKIKeyUsage is a byte array using ASN.1 BIT STRING encoding (bits reversed
# within each byte). Byte 0 holds the first 8 usages, byte 1 holds decipher_only.
$keyUsageMap = @{
    'digital_signature' = @{ Byte = 0; Bit = 0x80 }
    'non_repudiation'   = @{ Byte = 0; Bit = 0x40 }
    'key_encipherment'  = @{ Byte = 0; Bit = 0x20 }
    'data_encipherment' = @{ Byte = 0; Bit = 0x10 }
    'key_agreement'     = @{ Byte = 0; Bit = 0x08 }
    'key_cert_sign'     = @{ Byte = 0; Bit = 0x04 }
    'crl_sign'          = @{ Byte = 0; Bit = 0x02 }
    'encipher_only'     = @{ Byte = 0; Bit = 0x01 }
    'decipher_only'     = @{ Byte = 1; Bit = 0x80 }
}

$intProperties = @(
    'flags'
    'revision'
    'pKIDefaultKeySpec'
    'pKIMaxIssuingDepth'
    'msPKI-RA-Signature'
    'msPKI-Enrollment-Flag'
    'msPKI-Private-Key-Flag'
    'msPKI-Certificate-Name-Flag'
    'msPKI-Minimal-Key-Size'
    'msPKI-Template-Schema-Version'
    'msPKI-Template-Minor-Revision'
)

# Collection (multi-valued string) properties
$collectionProperties = @(
    'pKIExtendedKeyUsage'
    'pKICriticalExtensions'
    'pKIDefaultCSPs'
    'msPKI-Certificate-Application-Policy'
    'msPKI-RA-Application-Policies'
)

# Byte-array properties
$byteProperties = @(
    'pKIExpirationPeriod'
    'pKIOverlapPeriod'
    'pKIKeyUsage'
)

$allTemplateProperties = $intProperties + $collectionProperties + $byteProperties

# Maps module params to LDAP attributes with type casting and comparison logic.
# Used for both create (override cloned values) and update (idempotent set).
# Flag params use Resolve-FlagList; EKU uses Resolve-EkuList; key_usage and
# period bytes are handled separately in the code.

$overrideMap = @(
    @{
        Param = 'key_size'
        Attr = 'msPKI-Minimal-Key-Size'
        Cast = { param($v) [int]$v }
    }
    @{
        Param = 'schema_version'
        Attr = 'msPKI-Template-Schema-Version'
        Cast = { param($v) [int]$v }
    }
    @{
        Param = 'enrollment_flag'
        Attr = 'msPKI-Enrollment-Flag'
        Cast = { param($v) [int](Resolve-FlagList $v $enrollmentFlagMap 'enrollment_flag') }
    }
    @{
        Param = 'private_key_flag'
        Attr = 'msPKI-Private-Key-Flag'
        Cast = { param($v) [int](Resolve-FlagList $v $privateKeyFlagMap 'private_key_flag') }
    }
    @{
        Param = 'certificate_name_flag'
        Attr = 'msPKI-Certificate-Name-Flag'
        Cast = { param($v) [int](Resolve-FlagList $v $certNameFlagMap 'certificate_name_flag') }
    }
    @{
        Param = 'extended_key_usages'
        Attr = 'pKIExtendedKeyUsage'
        Cast = { param($v) , [string[]](Resolve-EkuList $v) }
    }
    @{
        Param = 'validity_period_days'
        Attr = 'pKIExpirationPeriod'
        Cast = { param($v) , [byte[]](ConvertTo-PeriodByte -Days $v) }
    }
    @{
        Param = 'renewal_period_days'
        Attr = 'pKIOverlapPeriod'
        Cast = { param($v) , [byte[]](ConvertTo-PeriodByte -Days $v) }
    }
)

# Helper functions

Function Resolve-FlagList {
    param(
        [object[]]$Values,
        [hashtable]$FlagMap,
        [string]$ParamName
    )
    $result = 0
    foreach ($flag in $Values) {
        $flagInt = 0
        if ($FlagMap.ContainsKey([string]$flag)) {
            $flagInt = $FlagMap[[string]$flag]
        }
        elseif ([LanguagePrimitives]::TryConvertTo($flag, [int], [ref]$flagInt)) {
            # raw int or hex string parsed successfully
        }
        else {
            $valid = ($FlagMap.Keys | Sort-Object) -join ", "
            $module.FailJson("Invalid ${ParamName} value '${flag}'. Valid names: ${valid}, or an integer.")
        }
        $result = $result -bor $flagInt
    }
    $result
}

Function Resolve-EkuList {
    param([object[]]$Values)
    foreach ($v in $Values) {
        $s = [string]$v
        if ($ekuMap.ContainsKey($s)) { $ekuMap[$s] } else { $s }
    }
}

Function Resolve-KeyUsageByte {
    param([object[]]$Values)
    $bytes = [byte[]]::new(2)
    foreach ($v in $Values) {
        $s = [string]$v
        if (-not $keyUsageMap.ContainsKey($s)) {
            $valid = ($keyUsageMap.Keys | Sort-Object) -join ", "
            $module.FailJson("Invalid key_usage value '${s}'. Valid names: ${valid}.")
        }
        $entry = $keyUsageMap[$s]
        $bytes[$entry.Byte] = $bytes[$entry.Byte] -bor $entry.Bit
    }
    , $bytes
}

Function Compare-KeyUsageByte {
    param([byte[]]$Current, [byte[]]$Desired)
    if ($null -eq $Current) { return $true }
    $currentPadded = [byte[]]::new(2)
    [Array]::Copy($Current, $currentPadded, [Math]::Min($Current.Length, 2))
    ($currentPadded[0] -ne $Desired[0]) -or ($currentPadded[1] -ne $Desired[1])
}

# AD stores pKIExpirationPeriod / pKIOverlapPeriod as 8-byte little-endian
# negative FILETIME intervals (100-nanosecond units).
# 864000000000 = 1 day in 100ns units (24 * 60 * 60 * 10,000,000).
Function ConvertTo-PeriodByte {
    <#
    .SYNOPSIS
    Converts days to the 8-byte negative FILETIME interval used by
    pKIExpirationPeriod and pKIOverlapPeriod.
    #>
    param([int]$Days)
    [System.BitConverter]::GetBytes([Int64](-$Days * 864000000000))
}

Function ConvertFrom-PeriodByte {
    <#
    .SYNOPSIS
    Converts pKIExpirationPeriod / pKIOverlapPeriod bytes back to days.
    #>
    param([byte[]]$Bytes)
    if ($null -eq $Bytes -or $Bytes.Length -ne 8) { return $null }
    $ticks = [System.BitConverter]::ToInt64($Bytes, 0)
    [Math]::Round(-$ticks / 864000000000)
}

Function New-TemplateOID {
    <#
    .SYNOPSIS
    Generates a unique OID and CN for a new certificate template,
    using the forest base OID from the OID container.
    #>
    param(
        [hashtable]$ADParams,
        [string]$ConfigNC
    )

    $oidPath = "CN=OID,CN=Public Key Services,CN=Services,$ConfigNC"
    $forestOID = Get-ADObject @ADParams -Identity $oidPath -Properties 'msPKI-Cert-Template-OID' |
        Select-Object -ExpandProperty 'msPKI-Cert-Template-OID'

    do {
        $part1 = Get-Random -Minimum 10000000 -Maximum 99999999
        $part2 = Get-Random -Minimum 10000000 -Maximum 99999999
        $hex = -join ((1..32) | ForEach-Object {
            '{0:X}' -f (Get-Random -Minimum 0 -Maximum 16)
        })
        $templateOID = "$forestOID.$part1.$part2"
        $oidCN = "$part2.$hex"

        $existing = Get-ADObject @ADParams `
            -SearchBase $oidPath `
            -Filter { cn -eq $oidCN -and msPKI-Cert-Template-OID -eq $templateOID }
    } until ($null -eq $existing)

    @{
        TemplateOID = $templateOID
        OIDCN = $oidCN
    }
}

try {
    $configNC = (Get-ADRootDSE @adParams).configurationNamingContext
}
catch {
    $module.FailJson("Failed to get AD configuration: $_", $_)
}

$templatePath = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"

try {
    $existingTemplate = Get-ADObject @adParams `
        -SearchBase $templatePath `
        -LDAPFilter "(&(objectClass=pKICertificateTemplate)(cn=$name))" `
        -Properties ($allTemplateProperties + @('displayName', 'msPKI-Cert-Template-OID'))
}
catch {
    $module.FailJson("Failed to search for existing template '$name': $_", $_)
}

if ($state -eq 'present') {
    if (-not $existingTemplate) {
        # CREATE
        if (-not $sourceTemplate) {
            $module.FailJson("source_template is required when creating a new certificate template.")
        }

        try {
            $source = Get-ADObject @adParams `
                -SearchBase $templatePath `
                -LDAPFilter "(&(objectClass=pKICertificateTemplate)(displayName=$sourceTemplate))" `
                -Properties ($allTemplateProperties + @('displayName'))
        }
        catch {
            $module.FailJson("Failed to find source template '$sourceTemplate': $_", $_)
        }
        if (-not $source) {
            $module.FailJson("Source template '$sourceTemplate' not found in $templatePath.")
        }

        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            try {
                $oid = New-TemplateOID -ADParams $adParams -ConfigNC $configNC
            }
            catch {
                $module.FailJson("Failed to generate template OID: $_", $_)
            }

            # Create the OID registration object
            $oidPath = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
            $oidAttrs = @{
                'DisplayName' = $displayName
                'flags' = [int]1
                'msPKI-Cert-Template-OID' = $oid.TemplateOID
            }
            try {
                New-ADObject @adParams -Path $oidPath -OtherAttributes $oidAttrs `
                    -Name $oid.OIDCN -Type 'msPKI-Enterprise-Oid'
            }
            catch {
                $module.FailJson("Failed to create OID object: $_", $_)
            }

            # Clone source attributes, extracting raw .NET types from AD wrappers
            $templateAttrs = @{
                'msPKI-Cert-Template-OID' = $oid.TemplateOID
            }
            foreach ($prop in $intProperties) {
                $raw = $source.$prop
                if ($null -ne $raw) {
                    $templateAttrs[$prop] = [int]$raw
                }
            }
            foreach ($prop in $collectionProperties) {
                $val = [string[]]@($source.$prop | Where-Object { $_ })
                if ($val.Count -gt 0) {
                    $templateAttrs[$prop] = $val
                }
            }
            foreach ($prop in $byteProperties) {
                $raw = $source.$prop
                if ($null -ne $raw) {
                    $templateAttrs[$prop] = [byte[]]$raw
                }
            }

            # Apply user overrides (flags, EKUs, periods, key_size, schema_version)
            foreach ($o in $overrideMap) {
                $val = $module.Params[$o.Param]
                if ($null -ne $val) {
                    $templateAttrs[$o.Attr] = & $o.Cast $val
                }
            }

            # key_usage override (byte-level, outside overrideMap)
            if ($null -ne $module.Params.key_usage) {
                $templateAttrs['pKIKeyUsage'] = Resolve-KeyUsageByte $module.Params.key_usage
            }

            try {
                New-ADObject @adParams -Path $templatePath -OtherAttributes $templateAttrs `
                    -Name $name -DisplayName $displayName -Type 'pKICertificateTemplate'
            }
            catch {
                $module.FailJson("Failed to create certificate template '$name': $_", $_)
            }

            $existingTemplate = Get-ADObject @adParams `
                -SearchBase $templatePath `
                -LDAPFilter "(&(objectClass=pKICertificateTemplate)(cn=$name))" `
                -Properties ($allTemplateProperties + @('displayName', 'msPKI-Cert-Template-OID'))

            $module.Result.distinguished_name = $existingTemplate.DistinguishedName
            $module.Result.template_oid = $oid.TemplateOID
        }
    }
    else {
        # UPDATE
        $module.Result.distinguished_name = $existingTemplate.DistinguishedName
        $module.Result.template_oid = $existingTemplate.'msPKI-Cert-Template-OID'

        $replaceAttrs = @{}

        if ($displayName -ne $existingTemplate.DisplayName -and $module.Params.display_name) {
            $replaceAttrs['displayName'] = $displayName
        }

        foreach ($o in $overrideMap) {
            $desired = $module.Params[$o.Param]
            if ($null -eq $desired) { continue }

            $current = $existingTemplate.($o.Attr)
            $resolvedDesired = & $o.Cast $desired
            $needsUpdate = switch ($o.Param) {
                'extended_key_usages' {
                    $resolvedOids = [string[]]$resolvedDesired
                    [bool](Compare-Object -ReferenceObject @($current | Sort-Object) -DifferenceObject @($resolvedOids | Sort-Object))
                }
                { $_ -in 'validity_period_days', 'renewal_period_days' } {
                    $desired -ne (ConvertFrom-PeriodByte -Bytes $current)
                }
                default {
                    $resolvedDesired -ne $current
                }
            }

            if ($needsUpdate) {
                $replaceAttrs[$o.Attr] = $resolvedDesired
            }
        }

        # key_usage comparison (byte-level)
        if ($null -ne $module.Params.key_usage) {
            $desiredKU = Resolve-KeyUsageByte $module.Params.key_usage
            if (Compare-KeyUsageByte -Current $existingTemplate.pKIKeyUsage -Desired $desiredKU) {
                $replaceAttrs['pKIKeyUsage'] = $desiredKU
            }
        }

        if ($replaceAttrs.Count -gt 0) {
            $module.Result.changed = $true
            if (-not $module.CheckMode) {
                try {
                    Set-ADObject @adParams -Identity $existingTemplate.DistinguishedName -Replace $replaceAttrs
                }
                catch {
                    $module.FailJson("Failed to update certificate template '$name': $_", $_)
                }
            }
        }
    }

    # Publish the template to the requested CAs
    if ($null -ne $module.Params.publish_to_ca) {
        $enrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
        try {
            $allCAs = @(Get-ADObject @adParams -SearchBase $enrollmentPath `
                    -SearchScope OneLevel -Filter * -Properties certificateTemplates)
        }
        catch {
            $module.FailJson("Failed to enumerate Certificate Authorities: $_", $_)
        }

        $desiredCANames = @($module.Params.publish_to_ca)

        foreach ($ca in $allCAs) {
            $currentTemplates = @($ca.certificateTemplates)
            $isPublished = $currentTemplates -contains $name
            $shouldBePublished = $desiredCANames -contains $ca.Name

            if ($shouldBePublished -and -not $isPublished) {
                $module.Result.changed = $true
                if (-not $module.CheckMode) {
                    try {
                        Set-ADObject @adParams -Identity $ca.DistinguishedName `
                            -Add @{ certificateTemplates = $name }
                    }
                    catch {
                        $module.FailJson("Failed to publish template to CA '$($ca.Name)': $_", $_)
                    }
                }
            }
            elseif (-not $shouldBePublished -and $isPublished) {
                $module.Result.changed = $true
                if (-not $module.CheckMode) {
                    try {
                        Set-ADObject @adParams -Identity $ca.DistinguishedName `
                            -Remove @{ certificateTemplates = $name }
                    }
                    catch {
                        $module.FailJson("Failed to unpublish template from CA '$($ca.Name)': $_", $_)
                    }
                }
            }
        }

        # Validate that all requested CAs exist
        $knownCANames = @($allCAs | ForEach-Object { $_.Name })
        foreach ($caName in $desiredCANames) {
            if ($knownCANames -notcontains $caName) {
                $module.Warn("Certificate Authority '$caName' was not found in Enrollment Services.")
            }
        }
    }
}
else {
    # Remove the template if it exists
    if ($existingTemplate) {
        $module.Result.distinguished_name = $existingTemplate.DistinguishedName
        $module.Result.template_oid = $existingTemplate.'msPKI-Cert-Template-OID'
        $module.Result.changed = $true

        if (-not $module.CheckMode) {
            # Unpublish from all CAs
            $enrollmentPath = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configNC"
            try {
                $allCAs = @(Get-ADObject @adParams -SearchBase $enrollmentPath `
                        -SearchScope OneLevel -Filter * -Properties certificateTemplates)
            }
            catch {
                $module.FailJson("Failed to enumerate CAs for unpublishing: $_", $_)
            }

            foreach ($ca in $allCAs) {
                if (@($ca.certificateTemplates) -contains $name) {
                    try {
                        Set-ADObject @adParams -Identity $ca.DistinguishedName `
                            -Remove @{ certificateTemplates = $name }
                    }
                    catch {
                        $module.FailJson("Failed to unpublish template from CA '$($ca.Name)': $_", $_)
                    }
                }
            }

            # Remove the template object
            try {
                Remove-ADObject @adParams -Identity $existingTemplate.DistinguishedName -Confirm:$false
            }
            catch {
                $module.FailJson("Failed to remove certificate template '$name': $_", $_)
            }

            # Remove the OID object
            $templateOID = $existingTemplate.'msPKI-Cert-Template-OID'
            if ($templateOID) {
                $oidPath = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
                try {
                    $oidObj = Get-ADObject @adParams -SearchBase $oidPath `
                        -LDAPFilter "(msPKI-Cert-Template-OID=$templateOID)"
                    if ($oidObj) {
                        Remove-ADObject @adParams -Identity $oidObj.DistinguishedName -Confirm:$false
                    }
                }
                catch {
                    $module.Warn("Failed to remove OID object for template '$name': $_")
                }
            }
        }
    }
}

$module.ExitJson()
