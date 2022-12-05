#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: object
short_description: Manage Active Directory objects
description:
- Manages Active Directory objects and their attributes.
requirements:
- C(ActiveDirectory) PowerShell module
options:
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
  domain_password:
    description:
    - The password for I(domain_username).
    type: str
  domain_server:
    description:
    - Specified the Active Directory Domain Services instance to connect to.
    - Can be in the form of an FQDN or NetBIOS name.
    - If not specified then the value is based on the default domain of the computer running PowerShell.
    type: str
  domain_username:
    description:
    - The username to use when interacting with AD.
    - If this is not set then the user that is used for authentication will be the connection user.
    - Ansible will be unable to use the connection user unless auth is Kerberos with credential delegation or CredSSP,
      or become is used on the task.
    type: str
  identity:
    description:
    - The identity of the AD object used to find the AD object to manage.
    - Must be specified if I(name) is not set, when trying to rename the object
      with a new I(name), or when trying to move the object into a different
      I(path).
    - The identity can be in the form of a GUID representing the C(objectGUID)
      value, the C(userPrincipalName), C(sAMAccountName), C(objectSid), or
      C(distinguishedName).
    - If omitted, the AD object to managed is selected by the
      C(distinguishedName) using the format C(CN={{ name }},{{ path }}). If
      I(path) is not defined, the C(defaultNamingContext) is used instead.
    type: str
  name:
    description:
    - The C(name) of the AD object to manage.
    - If I(identity) is specified, and the name of the object it found does not
      match this value, the object will be renamed.
    - This must be set when I(state=present) or if I(identity) is not set.
    type: str
  path:
    description:
    - The path of the OU or the container where the new object should exist in.
    - If no path is specified, the default is the C(defaultNamingContext) of
      domain.
    type: str
  state:
    description:
    - Set to C(present) to ensure the AD object exists.
    - Set to C(absent) to remove the AD object if it exists.
    - The option I(name) must be set when I(state=present).
    choices:
    - absent
    - present
    default: present
    type: str
  type:
    description:
    - The object type of the AD object.
    - This corresponds to the C(objectClass) of the AD object.
    - Some examples of a type are C(user), C(computer), C(group), C(subnet),
      C(contact), C(container).
    - This is required when I(state=present).
    type: str
notes:
- This is a generic module used to create and manage any object type in Active
  Directory. It will not validate all the correct defaults are set for each
  type when it is created. If a type specific module is available to manage
  that AD object type it is recommend to use that.
- Some LDAP attributes can have only a single value set while others can have
  multiple. Some attributes are also read only and cannot be changed. It is
  recommened to look at the schema metadata for an attribute where
  C(System-Only) are read only values and C(Is-Single-Value) are attributes
  with only 1 value.
- Attempting to set multiple values to a C(Is-Single-Value) attribute results
  in undefined behaviour.
extends_documentation_fragment:
- ansible.active_directory.ad_attribute
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
- module: ansible.active_directory.object_info
- module: community.windows.win_domain_computer
- module: community.windows.win_domain_group
- module: community.windows.win_domain_user
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
# Use this to get all valid types in a domain environment
# (Get-ADObject -SearchBase (Get-ADRootDSE).subschemaSubentry -Filter * -Properties objectClasses).objectClasses |
#     Select-String -Pattern "Name\s+'(\w+)'" |
#     ForEach-Object { $_.Matches.Groups[1].Value } |
#     Sort-Object

- name: Create a contact object
  ansible.active_directory.object:
    name: MyContact
    description: My Contact Description
    type: contact
    state: present

- name: Rename a contact object
  ansible.active_directory.object:
    identity: '{{ contact_obj.object_guid }}'
    name: RenamedContact
    type: contact
    state: present

- name: Move a contact object
  ansible.active_directory.object:
    identity: '{{ contact_object.object_guid }}'
    name: MyContact
    path: OU=Contacts,DC=domain,DC=test
    type: contact
    state: present

- name: Remove a contact object in default path
  ansible.active_directory.object:
    name: MyContact
    state: absent

- name: Remove a contact object in custom path
  ansible.active_directory.object:
    name: MyContact
    path: OU=Contacts,DC=domain,DC=test
    state: absent

- name: Remove a contact by identity
  ansible.active_directory.object:
    identity: '{{ contact_obj.object_guid }}'
    state: absent

- name: Create container object with custom attributes
  ansible.active_directory.object:
    name: App
    attributes:
      set:
        wWWHomePage: https://ansible.com
    type: container
    state: present

- name: Clear attribute of any value
  ansible.active_directory.object:
    name: App
    attributes:
      set:
        wWWHomePage: ~
    type: container
    state: present

- name: Edit object security with Everyone Allow All access
  ansible.active_directory.object:
    name: App
    attributes:
      add:
        nTSecurityDescriptor:
          type: security_descriptor
          value: O:DAG:DAD:PAI(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
    type: container
    state: present

- name: Ensure multiple values are present in attribute
  ansible.active_directory.object:
    name: App
    attributes:
      add:
        extensionName:
        - value 1
        - value 2
    type: container
    state: present

- name: Ensure multiple values are not present in attribute
  ansible.active_directory.object:
    name: App
    attributes:
      remove:
        extensionName:
        - value 1
        - value 3
    type: container
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
"""
