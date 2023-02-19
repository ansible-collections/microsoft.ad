#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: group
short_description: Manage Active Directory group objects
description:
- Manages Active Directory group objects and their attributes.
options:
  category:
    description:
    - The category of the group.
    - If a new group is created then C(security) will be used by default.
    - A C(security) group can be associated with access control lists whereas
      C(distribution) groups are typically associated with mailing distribution
      lists.
    - This is the value set on the C(groupType) LDAP attributes.
    choices:
    - distribution
    - security
    type: str
  homepage:
    description:
    - The homepage of the group.
    - This is the value set on the C(wWWHomePage) LDAP attribute.
    type: str
  managed_by:
    description:
    - The user or group that manages the group.
    - The value can be in the form of a C(distinguishedName), C(objectGUID),
      C(objectSid), or C(sAMAccountName).
    - This is the value set on the C(managedBy) LDAP attribute.
    type: str
  members:
    description:
    - The members of the group to set.
    - The value is a dictionary that contains 3 keys, I(add), I(remove), and
      I(set).
    - Each subkey is set to a list of AD principal objects to add, remove or
      set as the members of this AD group respectively. A principal can be in
      the form of a C(distinguishedName), C(objectGUID), C(objectSid), or
      C(sAMAccountName).
    - The module will fail if it cannot find any of the members referenced.
    type: dict
    suboptions:
      add:
        description:
        - Adds the principals specified as members of the group, keeping the
          existing membership if they are not specified.
        type: list
        elements: str
      remove:
        description:
        - Removes the principals specified as members of the group, keeping the
          existing membership if they are not specified.
        type: list
        elements: str
      set:
        description:
        - Sets only the principals specified as members of the group.
        - Any other existing member will be removed from the group membership
          if not specified in this list.
        - Set this to an empty list to remove all members from a group.
        type: list
        elements: str
  sam_account_name:
    description:
    - The C(sAMAccountName) value to set for the group.
    - If omitted, the I(name) value is used when creating a new group.
    type: str
  scope:
    description:
    - The scope of the group.
    - This is required when I(state=present) and the group does not already
      exist.
    - See
      L(Group scope,https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755692%28v=ws.10%29)
      for more information on the various domain group scopes.
    - This is the value set on the C(groupType) LDAP attributes.
    choices:
    - domainlocal
    - global
    - universal
    type: str
notes:
- See R(win_group migration,ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group)
  for help on migrating from M(community.windows.win_domain_group) to this
  module.
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
- module: microsoft.ad.membership
- module: microsoft.ad.object_info
- module: microsoft.ad.object
- module: microsoft.ad.user
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_group>
  description: This module replaces C(community.windows.win_domain_group). See the migration guide for details.
- module: community.windows.win_domain_group
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Ensure a group exists
  microsoft.ad.group:
    name: Cow
    scope: global

- name: Remove a group
  microsoft.ad.group:
    name: Cow
    state: absent

- name: Create a group in a custom path
  microsoft.ad.group:
    name: Cow
    scope: global
    path: OU=groups,DC=ansible,DC=local
    state: present

- name: Remove a group in a custom path
  microsoft.ad.group:
    name: Cow
    path: OU=groups,DC=ansible,DC=local
    state: absent

- name: Create group with delete protection enabled and custom attributes
  microsoft.ad.group:
    name: Ansible Users
    scope: domainlocal
    category: security
    homepage: www.ansible.com
    attributes:
      set:
        mail: helpdesk@ansible.com
    protect_from_deletion: true

- name: Change the path of a group
  microsoft.ad.group:
    name: MyGroup
    scope: global
    identity: S-1-5-21-2171456218-3732823212-122182344-1189
    path: OU=groups,DC=ansible,DC=local

- name: Add managed_by user
  microsoft.ad.group:
    name: Group Name Here
    scope: global
    managed_by: Domain Admins

- name: Add group and specify the AD domain services to use for the create
  microsoft.ad.group:
    name: Test Group
    domain_username: user@CORP.ANSIBLE.COM
    domain_password: Password01!
    domain_server: corp-DC12.corp.ansible.com
    scope: domainlocal

- name: Add members to the group, preserving existing membership
  microsoft.ad.group:
    name: Test Group
    scope: domainlocal
    members:
      add:
      - Domain Admins
      - Domain Users

- name: Remove members from the group, preserving existing membership
  microsoft.ad.group:
    name: Test Group
    scope: domainlocal
    members:
      remove:
      - Domain Admins
      - Domain Users

- name: Replace entire membership of group
  microsoft.ad.group:
    name: Test Group
    scope: domainlocal
    members:
      set:
      - Domain Admins
      - Domain Users
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
  sample: CN=MyGroup,CN=Users,,DC=domain,DC=test
sid:
  description:
  - The Security Identifier (SID) of the group managed.
  - If a new group was created in check mode, the SID will be C(S-1-5-0000).
  returned: always
  type: str
  sample: S-1-5-21-4151808797-3430561092-2843464588-1104
"""
