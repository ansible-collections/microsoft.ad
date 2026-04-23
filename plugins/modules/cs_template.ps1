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
            type = 'int'
        }
        private_key_flag = @{
            type = 'int'
            no_log = $false
        }
        certificate_name_flag = @{
            type = 'int'
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
$module.Result.display_name = $null
$module.Result.key_size = $null
$module.Result.schema_version = $null
$module.Result.enrollment_flag = $null
$module.Result.private_key_flag = $null
$module.Result.certificate_name_flag = $null
$module.Result.extended_key_usages = @()
$module.Result.validity_period_days = $null
$module.Result.renewal_period_days = $null

$name = $module.Params.name
$displayName = if ($module.Params.display_name) { $module.Params.display_name } else { $name }
$state = $module.Params.state
$sourceTemplate = $module.Params.source_template

$adParams = @{}
if ($module.Params.domain_server) {
    $adParams.Server = $module.Params.domain_server
}

# Integer properties on the template that we clone and can override
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
$overrideMap = @(
    @{
        Param = 'key_size'
        Attr = 'msPKI-Minimal-Key-Size'
        Cast = { param($v) [System.Int32]$v }
    }
    @{
        Param = 'schema_version'
        Attr = 'msPKI-Template-Schema-Version'
        Cast = { param($v) [System.Int32]$v }
    }
    @{
        Param = 'enrollment_flag'
        Attr = 'msPKI-Enrollment-Flag'
        Cast = { param($v) [System.Int32]$v }
    }
    @{
        Param = 'private_key_flag'
        Attr = 'msPKI-Private-Key-Flag'
        Cast = { param($v) [System.Int32]$v }
    }
    @{
        Param = 'certificate_name_flag'
        Attr = 'msPKI-Certificate-Name-Flag'
        Cast = { param($v) [System.Int32]$v }
    }
    @{
        Param = 'extended_key_usages'
        Attr = 'pKIExtendedKeyUsage'
        Cast = { param($v) , [string[]]$v }
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

Function Set-ResultFromTemplate {
    param($Module, $ADObject)
    $Module.Result.distinguished_name = $ADObject.DistinguishedName
    $Module.Result.template_oid = $ADObject.'msPKI-Cert-Template-OID'
    $Module.Result.display_name = $ADObject.DisplayName
    $Module.Result.key_size = $ADObject.'msPKI-Minimal-Key-Size'
    $Module.Result.schema_version = $ADObject.'msPKI-Template-Schema-Version'
    $Module.Result.enrollment_flag = $ADObject.'msPKI-Enrollment-Flag'
    $Module.Result.private_key_flag = $ADObject.'msPKI-Private-Key-Flag'
    $Module.Result.certificate_name_flag = $ADObject.'msPKI-Certificate-Name-Flag'
    $Module.Result.extended_key_usages = @($ADObject.pKIExtendedKeyUsage)
    $Module.Result.validity_period_days = ConvertFrom-PeriodByte -Bytes $ADObject.pKIExpirationPeriod
    $Module.Result.renewal_period_days = ConvertFrom-PeriodByte -Bytes $ADObject.pKIOverlapPeriod
}

# AD stores pKIExpirationPeriod / pKIOverlapPeriod as 8-byte little-endian
# negative FILETIME intervals (100-nanosecond units). These helpers convert
# between that encoding and a human-readable day count.
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
        $hex = -join ((1..32) | ForEach-Object { '{0:X}' -f (Get-Random -Minimum 0 -Maximum 16) })
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
        # --- CREATE ---
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
                'flags' = [System.Int32]1
                'msPKI-Cert-Template-OID' = $oid.TemplateOID
            }
            try {
                New-ADObject @adParams -Path $oidPath -OtherAttributes $oidAttrs `
                    -Name $oid.OIDCN -Type 'msPKI-Enterprise-Oid'
            }
            catch {
                $module.FailJson("Failed to create OID object: $_", $_)
            }

            # Clone source attributes into a clean hashtable.
            # Get-ADObject wraps values in ADPropertyValueCollection; we must
            # extract raw .NET types or New-ADObject rejects them.
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

            # Apply user overrides before creation
            foreach ($o in $overrideMap) {
                $val = $module.Params[$o.Param]
                if ($null -ne $val) {
                    $templateAttrs[$o.Attr] = & $o.Cast $val
                }
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

            Set-ResultFromTemplate -Module $module -ADObject $existingTemplate
        }
    }
    else {
        # Update the template if the display name or any of the properties have changed
        Set-ResultFromTemplate -Module $module -ADObject $existingTemplate

        $replaceAttrs = @{}

        if ($displayName -ne $existingTemplate.DisplayName -and $module.Params.display_name) {
            $replaceAttrs['displayName'] = $displayName
        }
        foreach ($o in $overrideMap) {
            $desired = $module.Params[$o.Param]
            if ($null -eq $desired) { continue }

            $current = $existingTemplate.($o.Attr)
            $needsUpdate = switch ($o.Param) {
                'extended_key_usages' {
                    [bool](Compare-Object -ReferenceObject @($current | Sort-Object) -DifferenceObject @($desired | Sort-Object))
                }
                { $_ -in 'validity_period_days', 'renewal_period_days' } {
                    $desired -ne (ConvertFrom-PeriodByte -Bytes $current)
                }
                default {
                    $desired -ne $current
                }
            }

            if ($needsUpdate) {
                $replaceAttrs[$o.Attr] = & $o.Cast $desired
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

                $existingTemplate = Get-ADObject @adParams `
                    -SearchBase $templatePath `
                    -LDAPFilter "(&(objectClass=pKICertificateTemplate)(cn=$name))" `
                    -Properties ($allTemplateProperties + @('displayName', 'msPKI-Cert-Template-OID'))

                Set-ResultFromTemplate -Module $module -ADObject $existingTemplate
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
        Set-ResultFromTemplate -Module $module -ADObject $existingTemplate
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
