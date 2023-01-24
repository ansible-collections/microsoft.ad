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
        - Any existing pricipals not specified by I(remove) will be untouched
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
  kerberos_encryption_types:
    description:
    - Specifies the Kerberos encryption types supported the AD computer
      account.
    - This is the value set on the C(msDS-SupportedEncryptionTypes) LDAP
      attribute.
    - Avoid using C(rc4) or C(des) as they are older an insecure encryption
      protocols.
    - To clear all encryption types, use I(set) with an empty list.
    - See R(Setting list option values,ansible_collections.microsoft.ad.docsite.guide_list_values)
      for more information on how to add/remove/set list options.
    type: dict
    suboptions:
      add:
        description:
        - The encryption types to add to the existing set.
        - Any existing encryption types not specified by I(add) will be
          untouched unless specified by I(remove) or not in I(set).
        choices:
        - aes128
        - aes256
        - des
        - rc4
        type: list
        elements: str
      remove:
        description:
        - The encryption types to remove from the existing set.
        - Any existing encryption types not specified by I(remove) will be
          untouched unless I(set) is defined.
        choices:
        - aes128
        - aes256
        - des
        - rc4
        type: list
        elements: str
      set:
        description:
        - The encryption types to set as the only encryption types allowed
          by the AD computer.
        - This will remove any existing encryption types if not specified in
          this list.
        - Specify an empty list to remove all encryption types.
        choices:
        - aes128
        - aes256
        - des
        - rc4
        type: list
        elements: str
  location:
    description:
    - Sets the location of the computer account.
    - This is the value set on the C(location) LDAP attribute.
    type: str
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
  trusted_for_delegation:
    description:
    - Specifies whether an account is trusted for Kerberos delegation.
    - This is also known as unconstrained Kerberos delegation.
    - This sets the C(ADS_UF_TRUSTED_FOR_DELEGATION) flag in the
      C(userAccountControl) LDAP attribute.
    type: bool
  upn:
    description:
    - Configures the User Principal Name (UPN) for the account.
    - The format is C(<username>@<domain>).
    - This is the value set on the C(userPrincipalName) LDAP attribute.
    type: str
notes:
- See R(win_domain_computer migration,ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer)
  for help on migrating from M(community.windows.win_domain_computer) to this
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
- module: microsoft.ad.offline_join
- module: microsoft.ad.group
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_computer>
  description: This module replaces C(community.windows.win_domain_computer). See the migration guide for details.
- module: community.windows.win_domain_computer
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

- name: Add SPNs to computer
  microsoft.ad.computer:
    name: TheComputer
    spn:
      add:
      - HOST/TheComputer
      - HOST/TheComputer.domain.test
      - HOST/TheComputer.domain.test:1234

- name: Remove SPNs on the computer
  microsoft.ad.computer:
    name: TheComputer
    spn:
      remove:
      - HOST/TheComputer
      - HOST/TheComputer.domain.test
      - HOST/TheComputer.domain.test:1234

- name: Set the principals the computer trusts for delegation from
  microsoft.ad.computer:
    name: TheComputer
    delegates:
      set:
      - CN=FileShare,OU=Computers,DC=domain,DC=test
      - CN=DC,OU=Domain Controllers,DC=domain,DC=test
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
