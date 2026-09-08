#!powershell

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

#AnsibleRequires -CSharpUtil Ansible.Basic
#Requires -Module Ansible.ModuleUtils.Legacy
#Requires -Module Ansible.ModuleUtils.SID

$spec = @{
    options = @{
        object = @{ type = "str"; required = $true; aliases = "path" }
        principal = @{ type = "str"; required = $true; aliases = "user" }
        rights = @{ type = "str"; required = $true }
        object_type = @{ type = "str"; aliases = "rights_attr" }
        type = @{ type = "str"; required = $true; choices = "allow", "deny" }
        inherit = @{ type = "str"; default = "None" }
        inherited_object_type = @{ type = "str" }
        state = @{ type = "str"; default = "present"; choices = "absent", "present" }
    }
}

$module = [Ansible.Basic.AnsibleModule]::Create($args, $spec)
$module.Result.changed = $false

Try {
    Import-Module ActiveDirectory
}
Catch {
    $module.FailJson("Error importing module ActiveDirectory")
}

$object = $module.Params.object
$principal = $module.Params.principal
$state = $module.Params.state
$type = $module.Params.type
$rights = $module.Params.rights
$object_type = $module.Params.object_type
$inherit = $module.Params.inherit
$inherited_object_type = $module.Params.inherited_object_type

$user_sid = Convert-ToSID -account_name $principal

$guidmap = @{}
Get-ADObject -SearchBase ((Get-ADRootDSE).SchemaNamingContext) -LDAPFilter "(schemaidguid=*)" -Properties lDAPDisplayName, schemaIDGUID |
    ForEach-Object { $guidmap[$_.lDAPDisplayName] = [System.GUID]$_.schemaIDGUID }

if ($rights_attr) {
    if ($guidmap.Contains($object_type)) {
        $objGUID = $guidmap[$object_type]
    }
    Else {
        $module.FailJson("LDAP attribute $rights_attr does not exist")
    }
}
Else {
    $objGUID = [guid]::empty
}

if ($inherited_object_type) {
    if ($guidmap.Contains($inherited_object_type)) {
        $inheritGUID = $guidmap[$inherited_object_type]
    }
    Else {
        $module.FailJson("LDAP attribute $inherited_object_type does not exist")
    }
}
Else {
    $inheritGUID = [guid]::empty
}

Try {
    $objRights = [System.DirectoryServices.ActiveDirectoryRights]$rights
    $InheritanceFlag = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$inherit

    If ($type -eq "allow") {
        $objType = [System.Security.AccessControl.AccessControlType]::Allow
    }
    Else {
        $objType = [System.Security.AccessControl.AccessControlType]::Deny
    }

    $objUser = New-Object System.Security.Principal.SecurityIdentifier($user_sid)
    $objACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($objUser, $objRights, $objType, $objGUID, $InheritanceFlag, $inheritGUID)
    $objACL = Get-ACL -Path "AD:\$($object)"

    $match = $false
    ForEach ($rule in $objACL.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
        If (
            ($rule.ActiveDirectoryRights -eq $objACE.ActiveDirectoryRights) -And
            ($rule.InheritanceType -eq $objACE.InheritanceType) -And
            ($rule.ObjectType -eq $objACE.ObjectType) -And
            ($rule.InheritedObjectType -eq $objACE.InheritedObjectType) -And
            ($rule.ObjectFlags -eq $objACE.ObjectFlags) -And
            ($rule.AccessControlType -eq $objACE.AccessControlType) -And
            ($rule.IdentityReference -eq $objACE.IdentityReference) -And
            ($rule.IsInherited -eq $objACE.IsInherited) -And
            ($rule.InheritanceFlags -eq $objACE.InheritanceFlags) -And
            ($rule.PropagationFlags -eq $objACE.PropagationFlags)
        ) {
            $match = $true
            Break
        }
    }

    If ($state -eq "present" -And $match -eq $false) {
        Try {
            $objACL.AddAccessRule($objACE)
            Set-ACL -Path "AD:\$($object)" -AclObject $objACL
            $module.Result.changed = $true
        }
        Catch {
            $module.FailJson("an exception occurred when adding the specified rule - $($_.Exception.Message)")
        }
    }
    ElseIf ($state -eq "absent" -And $match -eq $true) {
        Try {
            $objACL.RemoveAccessRule($objACE)
            Set-ACL -Path "AD:\$($object)" -AclObject $objACL
            $module.Result.changed = $true
        }
        Catch {
            $module.FailJson("an exception occurred when removing the specified rule - $($_.Exception.Message)")
        }
    }
    Else {
        # A rule was attempting to be added but already exists
        If ($match -eq $true) {
            $module.Result.msg = "the specified rule already exists"
            $module.ExitJson()
        }
        # A rule didn't exist that was trying to be removed
        Else {
            $module.Result.msg = "the specified rule does not exist"
            $module.ExitJson()
        }
    }

}
Catch {
    $module.FailJson("an error occurred when attempting to $type $rights permission(s) on $object for $principal - $($_.Exception.Message)")
}

$module.ExitJson()
