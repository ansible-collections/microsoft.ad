#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: computer
short_description: Manage Active Directory computer objects
description:
- Manages Active Directory computer objects and their attributes.
options:
  dns_hostname:
    description:
    - Specifies the fully qualified domain name (FQDN) of the computer.
    - This is the value set on the C(dNSHostName) LDAP attribute.
    type: str
  enabled:
    description:
    - C(yes) will enable the group.
    - C(no) will disable the group.
    type: bool
  managed_by:
    description:
    - The user or group that manages the object.
    - The value can be in the form of a C(distinguishedName), C(objectGUID),
      C(objectSid), or sAMAccountName).
    - This is the value set on the C(managedBy) LDAP attribute.
    type: str
  sam_account_name:
    description:
    - The C(sAMAccountName) value to set for the group.
    - If omitted, the I(name) value is used when creating a new group.
    - It has a maximum of 256 characters, 15 is advised for older
      operating systems compatibility.
    - If ommitted the value is the same as C(name$) when the computer is
      created.
    - Note that all computer C(sAMAccountName) values need to end with a C($).
    - If C($) is omitted, it will be added to the end.
    type: str
notes:
- See R(win_domain_computer migration,ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer)
  for help on migrating from M(microsoft.ad.computer) to this module.
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
- module: microsoft.ad.offline_join
- module: community.windows.win_domain_group
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Add linux computer to Active Directory OU using a windows machine
  microsoft.ad.computer:
    name: one_linux_server
    sam_account_name: linux_server$
    dns_hostname: one_linux_server.my_org.local
    path: OU=servers,DC=my_org,DC=local
    description: Example of linux server
    enabled: yes
    state: present

- name: Remove linux computer from Active Directory using a windows machine
  microsoft.ad.computer:
    name: one_linux_server
    state: absent
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
  sample: CN=MyComputer,CN=Computers,DC=domain,DC=test
sid:
  description:
  - The Security Identifier (SID) of the account managed.
  - If a new computer was created in check mode, the SID will be C(S-1-5-0000).
  returned: always
  type: str
  sample: S-1-5-21-4151808797-3430561092-2843464588-1104
"""
