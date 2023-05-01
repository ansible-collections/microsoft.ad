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
    - The principal objects that the current AD object can trust for
      delegation to either add, remove or set.
    - The values for each sub option must be specified as a distinguished name
      C(CN=shenetworks,CN=Users,DC=ansible,DC=test)
    - This is the value set on the C(msDS-AllowedToActOnBehalfOfOtherIdentity)
      LDAP attribute.
    - This is a highly sensitive attribute as it allows the principals
      specified to impersonate any account when authenticating with the AD
      computer object being managed.
    - To clear all principals, use I(set) with an empty list.
    - See R(Setting list option values,ansible_collections.microsoft.ad.docsite.guide_list_values)
      for more information on how to add/remove/set list options.
    aliases:
    - principals_allowed_to_delegate
    type: dict
    suboptions:
      add:
        description:
        - The AD objects by their C(DistinguishedName) to add as a principal
          allowed to delegate.
        - Any existing principals not specified by I(add) will be untouched
          unless specified by I(remove) or not in I(set).
        type: list
        elements: str
      remove:
        description:
        - The AD objects by their C(DistinguishedName) to remove as a principal
          allowed to delegate.
        - Any existing principals not specified by I(remove) will be untouched
          unless I(set) is defined.
        type: list
        elements: str
      set:
        description:
        - The AD objects by their C(DistinguishedName) to set as the only
          principals allowed to delegate.
        - This will remove any existing principals if not specified in this
          list.
        - Specify an empty list to remove all principals allowed to delegate.
        type: list
        elements: str
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
    - Specifies the group membership the user is added, removed, or set to.
    - To clear all group memberships, use I(set) with an empty list.
    - Note that users cannot be removed from their principal group (for
      example, "Domain Users"). Attempting to do so will display a warning.
    - See R(Setting list option values,ansible_collections.microsoft.ad.docsite.guide_list_values)
      for more information on how to add/remove/set list options.
    type: dict
    suboptions:
      add:
        description:
        - The groups to add the user to.
        type: list
        elements: str
      remove:
        description:
        - The groups to remove the user from.
        type: list
        elements: str
      set:
        description:
        - The only groups the user is a member of.
        - This will clear out any existing groups if not in the specified list.
        - Set to an empty list to clear all group membership of the user.
        type: list
        elements: str
      missing_behaviour:
        description:
        - Controls what happens when a group specified by C(groups) is an
          invalid group name.
        - C(fail) is the default and will return an error any groups do not
          exist.
        - C(ignore) will ignore any groups that does not exist.
        - C(warn) will display a warning for any groups that do not exist but
          will continue without failing.
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
    - Specifies the service principal name(s) for the account to add, remove or
      set.
    - This is the value set on the C(servicePrincipalName) LDAP attribute.
    - To clear all service principal names, use I(set) with an empty list.
    - See R(Setting list option values,ansible_collections.microsoft.ad.docsite.guide_list_values)
      for more information on how to add/remove/set list options.
    aliases:
    - spns
    type: dict
    suboptions:
      add:
        description:
        - The SPNs to add to C(servicePrincipalName).
        type: list
        elements: str
      remove:
        description:
        - The SPNs to remove from C(servicePrincipalName).
        type: list
        elements: str
      set:
        description:
        - The SPNs to set as the only values in C(servicePrincipalName).
        - This will clear out any existing SPNs if not in the specified list.
        - Set to an empty list to clear all SPNs on the AD object.
        type: list
        elements: str
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
notes:
- See R(win_domain_user migration,ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_user)
  for help on migrating from M(community.windows.win_domain_user) to this module.
extends_documentation_fragment:
- microsoft.ad.ad_object
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
- module: microsoft.ad.domain
- module: microsoft.ad.domain_controller
- module: microsoft.ad.group
- module: microsoft.ad.object
- module: microsoft.ad.object_info
- module: microsoft.ad.computer
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_user>
  description: This module replaces C(community.windows.win_domain_user). See the migration guide for details.
- module: community.windows.win_domain_user
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Ensure user bob is present with address information
  microsoft.ad.user:
    name: bob
    firstname: Bob
    surname: Smith
    company: BobCo
    password: B0bP4ssw0rd
    state: present
    groups:
      set:
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
  microsoft.ad.user:
    name: bob
    firstname: Bob
    surname: Smith
    password: B0bP4ssw0rd
    state: present
    domain_username: DOMAIN\admin-account
    domain_password: SomePas2w0rd
    domain_server: domain@DOMAIN.COM

- name: Ensure user bob is present in OU ou=test,dc=domain,dc=local
  microsoft.ad.user:
    name: bob
    password: B0bP4ssw0rd
    state: present
    path: ou=test,dc=domain,dc=local
    groups:
      set:
      - Domain Admins
      - Domain Users

- name: Ensure user bob is absent
  microsoft.ad.user:
    name: bob
    state: absent

- name: Ensure user has only these spn's defined
  microsoft.ad.user:
    name: liz.kenyon
    spn:
      set:
      - MSSQLSvc/us99db-svr95:1433
      - MSSQLSvc/us99db-svr95.vmware.com:1433

- name: Ensure user has spn added
  microsoft.ad.user:
    name: liz.kenyon
    spn:
      add:
      - MSSQLSvc/us99db-svr95:2433

- name: Ensure user is created with delegates and spn's defined
  microsoft.ad.user:
    name: shmemmmy
    password: The3rubberducki33!
    state: present
    groups:
      set:
      - Domain Admins
      - Domain Users
      - Enterprise Admins
    delegates:
      set:
      - CN=shenetworks,CN=Users,DC=ansible,DC=test
      - CN=mk.ai,CN=Users,DC=ansible,DC=test
      - CN=jessiedotjs,CN=Users,DC=ansible,DC=test
    spn:
      set:
      - MSSQLSvc/us99db-svr95:2433

# The name option is the name of the AD object as seen in dsa.msc and not the
# sAMAccountName. For example, this will change the sAMAccountName of the user
# CN=existing_user,CN=Users,DC=domain,DC=com to 'new_sam_name'.
# E.g. This will change
- name: Change the user's sAMAccountName
  microsoft.ad.user:
    name: existing_user
    sam_account_name: new_sam_name
    state: present

# This will rename the AD object that is specified by identity to 'new_name'.
# The identity value can be the object's GUID, SecurityIdentifier, or
# sAMAccountName. It is important to use the identity value when renaming or
# moving a user object to ensure the object is moved/renamed rather than a new
# one being created.
- name: Rename user LDAP name
  microsoft.ad.user:
    name: new_name
    identity: '{{ user_obj.object_guid }}'
    state: present

# Like changing the name example above, the identity option is needed to ensure
# the existing user object specified is moved rather than a new one created at
# the path specified.
- name: Move user object to different OU
  microsoft.ad.user:
    name: user
    path: OU=Admins,DC=domain,DC=com
    identity: '{{ user_obj.sid }}'
    state: present
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
