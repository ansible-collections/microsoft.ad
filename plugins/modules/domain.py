#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: domain
short_description: Ensures the existence of a Windows domain
description:
- Ensure that the domain named by I(dns_domain_name) exists and is reachable.
- If the domain is not reachable, the domain is created in a new forest on the target Windows Server 2012+ host.
- This module may require subsequent use of the M(ansible.windows.win_reboot) action if changes are made.
options:
  create_dns_delegation:
    description:
    - Whether to create a DNS delegation that references the new DNS server that you install along with the domain controller.
    - Valid for Active Directory-integrated DNS only.
    - The default is computed automatically based on the environment.
    type: bool
  database_path:
    description:
    - The path to a directory on a fixed disk of the Windows host where the
      domain database will be created.
    - If not set then the default path is C(%SYSTEMROOT%\NTDS).
    type: path
  dns_domain_name:
    description:
    - The DNS name of the domain which should exist and be reachable or reside on the target Windows host.
    type: str
    required: yes
  domain_mode:
    description:
    - Specifies the domain functional level of the first domain in the creation of a new forest.
    - The domain functional level cannot be lower than the forest functional level, but it can be higher.
    - The default is automatically computed and set.
    - Current known modes are C(Win2003), C(Win2008), C(Win2008R2), C(Win2012), C(Win2012R2), or C(WinThreshold).
    type: str
  domain_netbios_name:
    description:
    - The NetBIOS name for the root domain in the new forest.
    - For NetBIOS names to be valid for use with this parameter they must be single label names of 15 characters or less, if not it will fail.
    - If this parameter is not set, then the default is automatically computed from the value of the I(domain_name) parameter.
    type: str
  forest_mode:
    description:
    - Specifies the forest functional level for the new forest.
    - The default forest functional level in Windows Server is typically the same as the version you are running.
    - Current known modes are C(Win2003), C(Win2008), C(Win2008R2), C(Win2012), C(Win2012R2), or C(WinThreshold).
    type: str
  install_dns:
    description:
    - Whether to install the DNS service when creating the domain controller.
    type: bool
    default: true
  log_path:
    description:
    - Specifies the fully qualified, non-UNC path to a directory on a fixed disk of the local computer where the log file for this operation is written.
    - If not set then the default path is C(%SYSTEMROOT%\NTDS).
    type: path
  reboot:
    description:
    - If C(true), this will reboot the host if a reboot was required to configure the domain.
    - If C(false), this will not reboot the host if a reboot was required and instead sets the I(reboot_required) return value to C(true).
    - Multiple reboots may occur if the host required a reboot before the domain promotion.
    - This cannot be used with async mode.
    - To use this parameter, ensure the fully qualified module name is used in the task or the I(collections) keyword includes this collection.
    type: bool
    default: false
  safe_mode_password:
    description:
    - Safe mode password for the domain controller.
    type: str
    required: true
  sysvol_path:
    description:
    - The path to a directory on a fixed disk of the Windows host where the
      Sysvol file will be created.
    - If not set then the default path is C(%SYSTEMROOT%\SYSVOL).
    type: path
extends_documentation_fragment:
- ansible.builtin.action_common_attributes
- ansible.builtin.action_common_attributes.flow
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms:
    - windows
  action:
    support: full
  async:
    support: partial
    details: Supported for all scenarios except with I(reboot=True).
  bypass_host_loop:
    support: none
seealso:
- module: microsoft.ad.domain_controller
- module: microsoft.ad.group
- module: microsoft.ad.membership
- module: microsoft.ad.user
- module: microsoft.ad.computer
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain>
  description: This module replaces C(ansible.windows.win_domain). See the migration guide for details.
- module: ansible.windows.win_domain
author:
- Matt Davis (@nitzmahone)
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Create new domain in a new forest on the target host and reboot
  microsoft.ad.domain:
    dns_domain_name: ansible.vagrant
    safe_mode_password: password123!
    reboot: true

- name: Create new Windows domain in a new forest with specific parameters and reboot in post task
  microsoft.ad.domain:
    create_dns_delegation: false
    database_path: C:\Windows\NTDS
    dns_domain_name: ansible.vagrant
    domain_mode: Win2012R2
    domain_netbios_name: ANSIBLE
    forest_mode: Win2012R2
    safe_mode_password: password123!
    sysvol_path: C:\Windows\SYSVOL
  register: domain_install

- name: Reboot host if install requires it
  ansible.windows.win_reboot:
  when: domain_install.reboot_required
"""

RETURN = r"""
reboot_required:
  description: True if changes were made that require a reboot.
  returned: always
  type: bool
  sample: true
"""
