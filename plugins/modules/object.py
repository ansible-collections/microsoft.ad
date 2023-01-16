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
options:
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
- module: microsoft.ad.object_info
- module: microsoft.ad.user
- module: microsoft.ad.computer
- module: microsoft.ad.group
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
  microsoft.ad.object:
    name: MyContact
    description: My Contact Description
    type: contact
    state: present

- name: Rename a contact object
  microsoft.ad.object:
    identity: '{{ contact_obj.object_guid }}'
    name: RenamedContact
    type: contact
    state: present

- name: Move a contact object
  microsoft.ad.object:
    identity: '{{ contact_object.object_guid }}'
    name: MyContact
    path: OU=Contacts,DC=domain,DC=test
    type: contact
    state: present

- name: Remove a contact object in default path
  microsoft.ad.object:
    name: MyContact
    state: absent

- name: Remove a contact object in custom path
  microsoft.ad.object:
    name: MyContact
    path: OU=Contacts,DC=domain,DC=test
    state: absent

- name: Remove a contact by identity
  microsoft.ad.object:
    identity: '{{ contact_obj.object_guid }}'
    state: absent

- name: Create container object with custom attributes
  microsoft.ad.object:
    name: App
    attributes:
      set:
        wWWHomePage: https://ansible.com
    type: container
    state: present

- name: Clear attribute of any value
  microsoft.ad.object:
    name: App
    attributes:
      set:
        wWWHomePage: ~
    type: container
    state: present

- name: Edit object security with Everyone Allow All access
  microsoft.ad.object:
    name: App
    attributes:
      add:
        nTSecurityDescriptor:
          type: security_descriptor
          value: O:DAG:DAD:PAI(A;CI;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)
    type: container
    state: present

- name: Ensure multiple values are present in attribute
  microsoft.ad.object:
    name: App
    attributes:
      add:
        extensionName:
        - value 1
        - value 2
    type: container
    state: present

- name: Ensure multiple values are not present in attribute
  microsoft.ad.object:
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
