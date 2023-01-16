#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: ou
short_description: Manage Active Directory organizational units
description:
- Manages Active Directory organizational units and their attributes.
options:
  city:
    description:
    - Configures the user's city.
    - This is the value set on the C(l) LDAP attribute.
    type: str
  country:
    description:
    - Configures the user's country code.
    - Note that this is a two-character ISO 3166 code.
    - This is the value set on the C(c) LDAP attribute.
    type: str
  managed_by:
    description:
    - The user or group that manages the object.
    - The value can be in the form of a C(distinguishedName), C(objectGUID),
      C(objectSid), or sAMAccountName).
    - This is the value set on the C(managedBy) LDAP attribute.
    type: str
  postal_code:
    description:
    - Configures the user's postal code / zip code.
    - This is the value set on the C(postalcode) LDAP attribute.
    type: str
  state_province:
    description:
    - Configures the user's state.
    - This is the value set on the C(state) LDAP attribute.
    type: str
  street:
    description:
    - Configures the user's street address.
    - This is the value set on the C(street) LDAP attribute.
    type: str
notes:
- When an OU is created, I(protect_from_deletion) defaults to C(True) if not
  specified.
- See R(win_domain_ou migration,ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou)
  for help on migrating from M(community.windows.win_domain_ou) to this module.
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
- module: microsoft.ad.object_info
- module: microsoft.ad.user
- module: microsoft.ad.computer
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_ou>
  description: This module replaces C(community.windows.win_domain_ou). See the migration guide for details.
- module: community.windows.win_domain_ou
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Ensure OU is present & protected
  microsoft.ad.ou:
    name: AnsibleFest
    state: present

- name: Ensure OU is present & protected
  microsoft.ad.ou:
    name: EUC Users
    path: DC=euc,DC=vmware,DC=lan
    state: present
    protect_from_deletion: true

- name: Ensure OU is absent
  microsoft.ad.ou:
    name: EUC Users
    path: DC=euc,DC=vmware,DC=lan
    state: absent

- name: Ensure OU is present with specific properties
  microsoft.ad.ou:
    name: WS1Users
    path: CN=EUC Users,DC=euc,DC=vmware,DC=lan
    protect_from_deletion: true
    description: EUC Business Unit
    city: Sandy Springs
    country: US
    state_province: Georgia
    street: 1155 Perimeter Center West
    postal_code: 30189

- name: Ensure OU updated with new properties
  microsoft.ad.ou:
    name: WS1Users
    path: DC=euc,DC=vmware,DC=lan
    protected: false
    managed_by: jzollo@vmware.com
    attributes:
      set:
        comment: A comment for the OU
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
