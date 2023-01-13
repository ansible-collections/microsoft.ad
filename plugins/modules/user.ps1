#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.AccessToken
#AnsibleRequires -CSharpUtil Ansible.Basic
#AnsibleRequires -PowerShell ..module_utils._ADObject

Function Test-Credential {
    param(
        [String]$Username,
        [String]$Password,
        [String]$Domain = $null
    )
    if (($Username.ToCharArray()) -contains [char]'@') {
        # UserPrincipalName
        $Domain = $null # force $Domain to be null, to prevent undefined behaviour, as a domain name is already included in the username
    }
    elseif (($Username.ToCharArray()) -contains [char]'\') {
        # Pre Win2k Account Name
        $Domain = ($Username -split '\\')[0]
        $Username = ($Username -split '\\', 2)[-1]
    } # If no domain provided, so maybe local user, or domain specified separately.

    try {
        ([Ansible.AccessToken.TokenUtil]::LogonUser($Username, $Domain, $Password, "Network", "Default")).Dispose()
        return $true
    }
    catch [Ansible.AccessToken.Win32Exception] {
        # following errors indicate the creds are correct but the user was
        # unable to log on for other reasons, which we don't care about
        $success_codes = @(
            0x0000052F, # ERROR_ACCOUNT_RESTRICTION
            0x00000530, # ERROR_INVALID_LOGON_HOURS
            0x00000531, # ERROR_INVALID_WORKSTATION
            0x00000569  # ERROR_LOGON_TYPE_GRANTED
        )
        $failed_codes = @(
            0x0000052E, # ERROR_LOGON_FAILURE
            0x00000532, # ERROR_PASSWORD_EXPIRED
            0x00000773, # ERROR_PASSWORD_MUST_CHANGE
            0x00000533  # ERROR_ACCOUNT_DISABLED
        )

        if ($_.Exception.NativeErrorCode -in $failed_codes) {
            return $false
        }
        elseif ($_.Exception.NativeErrorCode -in $success_codes) {
            return $true
        }
        else {
            # an unknown failure, reraise exception
            throw $_
        }
    }
}

$setParams = @{
    PropertyInfo = @(
        [PSCustomObject]@{
            Name = 'account_locked'
            Option = @{
                choices = @(, $false)
                type = 'bool'
            }
            Attribute = 'LockedOut'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                if ($ADObject.LockedOut) {
                    Unlock-ADAccount @ADParams -Identity $ADObject.ObjectGUID -WhatIf:$Module.CheckMode
                    $Module.Result.changed = $true
                }

                $Module.Diff.after.account_locked = $false
            }
        }

        [PSCustomObject]@{
            Name = 'city'
            Option = @{ type = 'str' }
            Attribute = 'City'
        }

        [PSCustomObject]@{
            Name = 'company'
            Option = @{ type = 'str' }
            Attribute = 'company'
        }

        [PSCustomObject]@{
            Name = 'country'
            Option = @{ type = 'str' }
            Attribute = 'Country'
        }

        [PSCustomObject]@{
            Name = 'delegates'
            Option = @{
                aliases = 'principals_allowed_to_delegate'
                type = 'list'
                elements = 'str'
            }
            Attribute = 'PrincipalsAllowedToDelegateToAccount'
            CaseInsensitive = $true
        }

        [PSCustomObject]@{
            Name = 'email'
            Option = @{ type = 'str' }
            Attribute = 'EmailAddress'
        }

        [PSCustomObject]@{
            Name = 'enabled'
            Option = @{ type = 'bool' }
            Attribute = 'Enabled'
        }

        [PSCustomObject]@{
            Name = 'firstname'
            Option = @{ type = 'str' }
            Attribute = 'givenName'
        }

        [PSCustomObject]@{
            Name = 'groups'
            Option = @{
                elements = 'str'
                type = 'list'
            }
        }

        [PSCustomObject]@{
            Name = 'groups_action'
            Option = @{
                choices = 'add', 'remove', 'set'
                default = 'set'
                type = 'str'
            }
        }

        [PSCustomObject]@{
            Name = 'groups_missing_behaviour'
            Option = @{
                choices = 'fail', 'ignore', 'warn'
                default = 'fail'
                type = 'str'
            }
        }

        [PSCustomObject]@{
            Name = 'password'
            Option = @{
                no_log = $true
                type = 'str'
            }
            New = {
                param($Module, $ADParams, $NewParams)

                $NewParams.AccountPassword = (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.password)
                $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
            }
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                $Module.Diff.before.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'

                $changed = switch ($Module.Params.update_password) {
                    always { $true }
                    on_create { $false }
                    when_changed {
                        # Try and use the UPN but fallback to msDS-PrincipalName if none is defined
                        $username = $ADObject.UserPrincipalName
                        if (-not $username) {
                            $username = $ADObject['msDS-PrincipalName']
                        }

                        -not (Test-Credential -Username $username -Password $module.Params.password)
                    }
                }

                if (-not $changed) {
                    $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER'
                    return
                }

                # -WhatIf was broken until Server 2016 and will set the
                # password. Just avoid calling this in check mode.
                if (-not $Module.CheckMode) {
                    $setParams = @{
                        Identity = $ADObject.ObjectGUID
                        Reset = $true
                        Confirm = $false
                        NewPassword = (ConvertTo-SecureString -AsPlainText -Force -String $module.Params.password)
                    }
                    Set-ADAccountPassword @setParams @ADParams
                }

                $Module.Diff.after.password = 'VALUE_SPECIFIED_IN_NO_LOG_PARAMETER - changed'
                $Module.Result.changed = $true
            }
        }

        [PSCustomObject]@{
            Name = 'password_expired'
            Option = @{ type = 'bool' }
            Attribute = 'PasswordExpired'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                if ($ADObject.PasswordExpired -ne $Module.Params.password_expired) {
                    $SetParams.ChangePasswordAtLogon = $Module.Params.password_expired
                }

                $Module.Diff.after.password_expired = $Module.Params.password_expired
            }
        }

        [PSCustomObject]@{
            Name = 'password_never_expires'
            Option = @{ type = 'bool' }
            Attribute = 'PasswordNeverExpires'
        }

        [PSCustomObject]@{
            Name = 'postal_code'
            Option = @{ type = 'str' }
            Attribute = 'PostalCode'
        }

        [PSCustomObject]@{
            Name = 'sam_account_name'
            Option = @{ type = 'str' }
            Attribute = 'sAMAccountName'
        }

        [PSCustomObject]@{
            Name = 'spn'
            Option = @{
                type = 'list'
                elements = 'str'
                aliases = 'spns'
            }
            Attribute = 'servicePrincipalNames'
            Set = {
                param($Module, $ADParams, $SetParams, $ADObject)

                [string[]]$existing = @($ADObject.servicePrincipalNames.Value)
                [string[]]$desired = @($Module.Params.spn)

                $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase

                [string[]]$toAdd = @()
                [string[]]$toRemove = @()
                [string[]]$diffAfter = @()
                switch ($Module.Params.spn_action) {
                    add {
                        $toAdd = [System.Linq.Enumerable]::Except($desired, $existing, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Union($desired, $existing, $ignoreCase)
                    }
                    remove {
                        $toRemove = [System.Linq.Enumerable]::Intersect($desired, $existing, $ignoreCase)
                        $diffAfter = [System.Linq.Enumerable]::Except($existing, $desired, $ignoreCase)
                    }
                    set {
                        $toAdd = [System.Linq.Enumerable]::Except($desired, $existing, $ignoreCase)
                        $toRemove = [System.Linq.Enumerable]::Except($existing, $desired, $ignoreCase)
                        $diffAfter = $desired
                    }
                }

                $spnValue = @{}
                if ($toAdd) {
                    # For whatever reason the Set-ADUser doesn't like a tainted
                    # [string[]] typed array, use ForEach-Object to bypass this
                    $spnValue.Add = $toAdd | ForEach-Object { "$_" }
                }
                if ($toRemove) {
                    $spnValue.Remove = $toRemove | ForEach-Object { "$_" }
                }

                if ($spnValue.Count) {
                    $SetParams.ServicePrincipalNames = $spnValue
                }

                $Module.Diff.after.spn = @($diffAfter | Sort-Object)
            }
        }

        [PSCustomObject]@{
            Name = 'spn_action'
            Option = @{
                choices = 'add', 'remove', 'set'
                default = 'set'
                type = 'str'
            }
        }

        [PSCustomObject]@{
            Name = 'state_province'
            Option = @{ type = 'str' }
            Attribute = 'State'
        }

        [PSCustomObject]@{
            Name = 'street'
            Option = @{ type = 'str' }
            Attribute = 'StreetAddress'
        }

        [PSCustomObject]@{
            Name = 'surname'
            Option = @{
                aliases = 'lastname'
                type = 'str'
            }
            Attribute = 'Surname'
        }

        [PSCustomObject]@{
            Name = 'update_password'
            Option = @{
                choices = 'always', 'on_create', 'when_changed'
                default = 'always'
                type = 'str'
            }
        }

        [PSCustomObject]@{
            Name = 'upn'
            Option = @{ type = 'str' }
            Attribute = 'userPrincipalName'
        }

        [PSCustomObject]@{
            Name = 'user_cannot_change_password'
            Option = @{ type = 'bool' }
            Attribute = 'CannotChangePassword'
        }
    )
    ModuleNoun = 'ADUser'
    DefaultPath = {
        param($Module, $ADParams)

        $GUID_USERS_CONTAINER_W = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        $defaultNamingContext = (Get-ADRootDSE @ADParams -Properties defaultNamingContext).defaultNamingContext

        Get-ADObject @ADParams -Identity $defaultNamingContext -Properties wellKnownObjects |
            Select-Object -ExpandProperty wellKnownObjects |
            Where-Object { $_.StartsWith("B:32:$($GUID_USERS_CONTAINER_W):") } |
            ForEach-Object Substring 38
    }
    ExtraProperties = @(
        # Used for password when checking if the password is valid
        'msDS-PrincipalName'
    )
    PreAction = {
        param ($Module, $ADParams, $ADObject)

        if (
            $Module.Params.state -eq 'present' -and
            $null -eq $ADObject -and
            $null -eq $Module.Params.enabled
        ) {
            $Module.Params.enabled = -not ([String]::IsNullOrWhiteSpace($Module.Params.password))
        }
    }
    PostAction = {
        param($Module, $ADParams, $ADObject)

        if ($ADObject) {
            $Module.Result.sid = $ADObject.SID.Value
        }
        elseif ($Module.Params.state -eq 'present') {
            # Use dummy value for check mode when creating a new user
            $Module.Result.sid = 'S-1-5-0000'
        }

        if ($null -eq $Module.Params.groups -or $Module.Params.state -eq 'absent') {
            return
        }

        [string[]]$desiredGroups = @(
            foreach ($group in $Module.Params.groups) {
                try {
                    (Get-ADGroup -Identity $group @ADParams).DistinguishedName
                }
                catch {
                    if ($Module.Params.groups_missing_behaviour -eq "fail") {
                        $module.FailJson("Failed to locate group $($group): $($_.Exception.Message)", $_)
                    }
                    elseif ($Module.Params.groups_missing_behaviour -eq "warn") {
                        $module.Warn("Failed to locate group $($group) but continuing on: $($_.Exception.Message)")
                    }
                }
            }
        )

        [string[]]$existingGroups = @(
            # In check mode the ADObject won't be given
            if ($ADObject) {
                try {
                    Get-ADPrincipalGroupMembership -Identity $ADObject.ObjectGUID @ADParams -ErrorAction Stop |
                        Select-Object -ExpandProperty DistinguishedName
                }
                catch {
                    $module.Warn("Failed to enumerate user groups but continuing on: $($_.Exception.Message)")
                }
            }
        )

        if ($Module.Diff.before) {
            $Module.Diff.before.groups = @($existingGroups | Sort-Object)
        }

        $ignoreCase = [System.StringComparer]::OrdinalIgnoreCase
        [string[]]$toAdd = @()
        [string[]]$toRemove = @()
        [string[]]$diffAfter = @()
        switch ($Module.Params.groups_action) {
            add {
                $toAdd = [System.Linq.Enumerable]::Except($desiredGroups, $existingGroups, $ignoreCase)
                $diffAfter = [System.Linq.Enumerable]::Union($desiredGroups, $existingGroups, $ignoreCase)
            }
            remove {
                $toRemove = [System.Linq.Enumerable]::Intersect($desiredGroups, $existingGroups, $ignoreCase)
                $diffAfter = [System.Linq.Enumerable]::Except($existingGroups, $desiredGroups, $ignoreCase)
            }
            set {
                $toAdd = [System.Linq.Enumerable]::Except($desiredGroups, $existingGroups, $ignoreCase)
                $toRemove = [System.Linq.Enumerable]::Except($existingGroups, $desiredGroups, $ignoreCase)
                $diffAfter = $desiredGroups
            }
        }

        $Module.Diff.after.groups = $diffAfter
        $commonParams = @{
            Confirm = $false
            WhatIf = $Module.CheckMode
        }
        foreach ($member in $toAdd) {
            if ($ADObject) {
                Add-ADGroupMember -Identity $member -Members $ADObject.ObjectGUID @ADParams @commonParams
            }
            $Module.Result.changed = $true
        }
        foreach ($member in $toRemove) {
            if ($ADObject) {
                try {
                    Remove-ADGroupMember -Identity $member -Members $ADObject.ObjectGUID @ADParams @commonParams
                }
                catch [Microsoft.ActiveDirectory.Management.ADException] {
                    if ($_.Exception.ErrorCode -eq 0x0000055E) {
                        # ERROR_MEMBERS_PRIMARY_GROUP - win_domain_user didn't
                        # fail in this scenario. To preserve compatibility just
                        # display a warning.
                        $Module.Warn("Cannot remove group '$member' as it's the primary group of the user, skipping: $($_.Exception.Message)")
                        $Module.Diff.after.groups = @($Module.Diff.after.groups; $member)
                    }
                    else {
                        throw
                    }
                }
            }
            $Module.Result.changed = $true
        }

        # Ensure it's in alphabetical order to match before state as much as possible
        $Module.Diff.after.groups = @($Module.Diff.after.groups | Sort-Object)
    }
}
Invoke-AnsibleADObject @setParams
