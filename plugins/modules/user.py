#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: user
short_description: Manage Active Directory users
description:
- Manages Active Directory users and their attributes.
options:
  account_locked:
    description:
    - C(no) will unlock the user account if locked.
    - Note that there is not a way to lock an account as an administrator.
    - Accounts are locked due to user actions; as an admin, you may only unlock a locked account.
    - If you wish to administratively disable an account, set I(enabled) to C(no).
    choices:
    - false
    type: bool
  city:
    description:
    - Configures the user's city.
    - This is the value set on the C(l) LDAP attribute.
    type: str
  company:
    description:
    - Configures the user's company name.
    - This is the value set on the C(company) LDAP attribute.
    type: str
  country:
    description:
    - Configures the user's country code.
    - Note that this is a two-character ISO 3166 code.
    - This is the value set on the C(c) LDAP attribute.
    type: str
  delegates:
    description:
    - Specifies an array of principal objects the user is allowed to act on
      behalf for delegation.
    - Must be specified as a distinguished name C(CN=shenetworks,CN=Users,DC=ansible,DC=test)
    - This is the value set on the C(msDS-AllowedToActOnBehalfOfOtherIdentity)
      LDAP attribute.
    - This is a highly sensitive attribute.
    aliases:
    - principals_allowed_to_delegate
    type: list
    elements: str
  description:
    description:
    - The description of the AD object to set.
    - This is the value set on the C(description) LDAP attribute.
    type: str
  display_name:
    description:
    - The display name of the AD object to set.
    - This is the value of the C(displayName) LDAP attribute.
    type: str
  email:
    description:
    - Configures the user's email address.
    - This is a record in AD and does not do anything to configure any email
      servers or systems.
    - This is the value set on the C(mail) LDAP attribute.
    type: str
  enabled:
    description:
    - C(yes) will enable the user account.
    - C(no) will disable the account.
    - The default when creating a new is C(yes) if I(password) is specified. If
      no I(password) is specified then the user will not be enabled.
    type: bool
  firstname:
    description:
    - Configures the user's first name (given name).
    - This is the value set on the C(givenName) LDAP attribute.
    type: str
  groups:
    description:
    - Adds or removes the user from this list of groups, depending on the value
      of I(groups_action).
    - To remove all but the Principal Group, set
      C(groups=<principal group name>) and C(groups_action=set).
    - Note that users cannot be removed from their principal group (for
      example, "Domain Users"). Attempting to do so will display a warning.
    type: list
    elements: str
  groups_action:
    description:
    - If C(add), the user is added to each group in I(groups) where not already
      a member.
    - If C(remove), the user is removed from each group in I(groups).
    - If C(set), the user is added as a member of each group in I(groups)
      and removed from any other groups.
    choices:
    - add
    - remove
    - set
    default: set
    type: str
  groups_missing_behaviour:
    description:
    - Controls what happens when a group specified by C(groups) is an invalid
      group name.
    - C(fail) is the default and will return an error any groups do not exist.
    - C(ignore) will ignore any groups that does not exist.
    - C(warn) will display a warning for any groups that do not exist but will
      continue without failing.
    choices:
    - fail
    - ignore
    - warn
    default: fail
    type: str
  password:
    description:
    - Optionally set the user's password to this (plain text) value.
    - To enable an account - I(enabled) - a password must already be
      configured on the account, or you must provide a password here.
    - Use the I(update_password) option to control how a password is checked
      for idempotency.
    type: str
  password_expired:
    description:
    - C(yes) will require the user to change their password at next login.
    - C(no) will clear the expired password flag.
    - This is mutually exclusive with I(password_never_expires).
    type: bool
  password_never_expires:
    description:
    - C(yes) will set the password to never expire.
    - C(no) will allow the password to expire.
    - This is mutually exclusive with I(password_expired).
    type: bool
  postal_code:
    description:
    - Configures the user's postal code / zip code.
    - This is the value set on the C(postalcode) LDAP attribute.
    type: str
  sam_account_name:
    description:
    - The C(sAMAccountName) value to set for the user.
    - If omitted, the I(name) value is used when creating a new user.
    type: str
  spn:
    description:
    - Specifies the service principal name(s) for the account. This parameter
      sets the ServicePrincipalNames property of the account.
    - This is the value set on the C(servicePrincipalName) LDAP attribute.
    aliases:
    - spns
    type: list
    elements: str
  spn_action:
    description:
    - If C(add), the SPNs are added to the user.
    - If C(remove), the SPNs are removed from the user.
    - If C(set), the defined set of SPN's overwrite the current set of SPNs.
    choices:
    - add
    - remove
    - set
    default: set
    type: str
  state_province:
    description:
    - Configures the user's state.
    - This is the value set on the C(state) LDAP attribute.
    type: str
  street:
    description:
    - Configures the user's street address.
    - This is the value set on the C(streetaddress) LDAP attribute.
    type: str
  surname:
    description:
    - Configures the user's last name (surname).
    - This is the value set on the C(sn) LDAP attribute.
    aliases:
    - lastname
    type: str
  update_password:
    description:
    - C(always) will always update passwords.
    - C(on_create) will only set the password for newly created users.
    - C(when_changed) will only set the password when changed.
    - Using C(when_changed) will not work if the account is not enabled.
    choices:
    - always
    - on_create
    - when_changed
    default: always
    type: str
  upn:
    description:
    - Configures the User Principal Name (UPN) for the account.
    - This is not required, but is best practice to configure for modern
      versions of Active Directory.
    - The format is C(<username>@<domain>).
    - This is the value set on the C(userPrincipalName) LDAP attribute.
    type: str
  user_cannot_change_password:
    description:
    - C(yes) will prevent the user from changing their password.
    - C(no) will allow the user to change their password.
    type: bool
extends_documentation_fragment:
- ansible.active_directory.ad_object
- ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
  platform:
    platforms:
    - windows
seealso:
- module: ansible.active_directory.domain
- module: ansible.active_directory.domain_controller
- module: ansible.active_directory.object
- module: ansible.active_directory.object_info
- module: community.windows.win_domain_computer
- module: community.windows.win_domain_group
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Ensure user bob is present with address information
  ansible.active_directory.user:
    name: bob
    firstname: Bob
    surname: Smith
    company: BobCo
    password: B0bP4ssw0rd
    state: present
    groups:
    - Domain Admins
    street: 123 4th St.
    city: Sometown
    state_province: IN
    postal_code: 12345
    country: US
    attributes:
      set:
        telephoneNumber: 555-123456

- name: Ensure user bob is created and use custom credentials to create the user
  ansible.active_directory.user:
    name: bob
    firstname: Bob
    surname: Smith
    password: B0bP4ssw0rd
    state: present
    domain_username: DOMAIN\admin-account
    domain_password: SomePas2w0rd
    domain_server: domain@DOMAIN.COM

- name: Ensure user bob is present in OU ou=test,dc=domain,dc=local
  ansible.active_directory.user:
    name: bob
    password: B0bP4ssw0rd
    state: present
    path: ou=test,dc=domain,dc=local
    groups:
    - Domain Admins
    - Domain Users

- name: Ensure user bob is absent
  ansible.active_directory.user:
    name: bob
    state: absent

- name: Ensure user has spn's defined
  ansible.active_directory.user:
    name: liz.kenyon
    spn:
    - MSSQLSvc/us99db-svr95:1433
    - MSSQLSvc/us99db-svr95.vmware.com:1433

- name: Ensure user has spn added
  ansible.active_directory.user:
    name: liz.kenyon
    spn_action: add
    spn:
    - MSSQLSvc/us99db-svr95:2433

- name: Ensure user is created with delegates and spn's defined
  ansible.active_directory.user:
    name: shmemmmy
    password: The3rubberducki33!
    state: present
    groups:
    - Domain Admins
    - Domain Users
    - Enterprise Admins
    delegates:
    - CN=shenetworks,CN=Users,DC=ansible,DC=test
    - CN=mk.ai,CN=Users,DC=ansible,DC=test
    - CN=jessiedotjs,CN=Users,DC=ansible,DC=test
    spn:
    - MSSQLSvc/us99db-svr95:2433
"""

RETURN = r"""
object_guid:
  description:
  - The C(objectGUID) of the AD object that was created, removed, or edited.
  - If a new object was created in check mode, a GUID of 0s will be returned.
  returned: always
  type: str
  sample: d84a141f-2b99-4f08-9da0-ed2d26864ba1
distinguished_name:
  description:
  - The C(distinguishedName) of the AD object that was created, removed, or edited.
  returned: always
  type: str
  sample: CN=TestUser,CN=Users,DC=domain,DC=test
sid:
  description:
  - The Security Identifier (SID) of the account managed.
  - If a new user was created in check mode, the SID will be C(S-1-5-0000).
  returned: always
  type: str
  sample: S-1-5-21-4151808797-3430561092-2843464588-1104
"""
