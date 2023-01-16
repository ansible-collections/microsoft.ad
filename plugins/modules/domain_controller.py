#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: domain_controller
short_description: Manage domain controller/member server state for a Windows host
description:
- Ensure that a Windows Server 2012+ host is configured as a domain controller or demoted to member server.
- This module may require subsequent use of the M(ansible.windows.win_reboot) action if changes are made.
options:
  database_path:
    description:
    - The path to a directory on a fixed disk of the Windows host where the
      domain database will be created..
    - If not set then the default path is C(%SYSTEMROOT%\NTDS).
    type: path
  dns_domain_name:
    description:
    - When I(state=domain_controller), the DNS name of the domain for which the targeted Windows host should be a DC.
    type: str
  domain_admin_user:
    description:
    - Username of a domain admin for the target domain (necessary to promote or demote a domain controller).
    type: str
    required: true
  domain_admin_password:
    description:
    - Password for the specified I(domain_admin_user).
    type: str
    required: true
  domain_log_path:
    description:
    - Specified the fully qualified, non-UNC path to a directory on a fixed disk of the local computer that will
      contain the domain log files.
    type: path
  install_dns:
    description:
    - Whether to install the DNS service when creating the domain controller.
    - If not specified then the C(-InstallDns) option is not supplied to C(Install-ADDSDomainController) command,
      see L(Install-ADDSDomainController,https://learn.microsoft.com/en-us/powershell/module/addsdeployment/install-addsdomaincontroller).
    type: bool
  install_media_path:
    description:
    - The path to a directory on a fixed disk of the Windows host where the Install From Media C(IFC) data will be used.
    - See the L(Install using IFM guide,https://social.technet.microsoft.com/wiki/contents/articles/8630.active-directory-step-by-step-guide-to-install-an-additional-domain-controller-using-ifm.aspx) for more information. # noqa
    type: path
  local_admin_password:
    description:
    - Password to be assigned to the local C(Administrator) user (required when I(state=member_server)).
    type: str
  read_only:
    description:
    - Whether to install the domain controller as a read only replica for an existing domain.
    type: bool
    default: no
  reboot:
    description:
    - If C(true), this will reboot the host if a reboot was required to configure the server.
    - If C(false), this will not reboot the host if a reboot was required and instead sets the I(reboot_required) return value to C(true).
    - Multiple reboots may occur if the host required a reboot before the domain promotion.
    - This cannot be used with async mode.
    - To use this parameter, ensure the fully qualified module name is used in the task or the I(collections) keyword includes this collection.
    type: bool
    default: false
  safe_mode_password:
    description:
    - Safe mode password for the domain controller (required when I(state=domain_controller)).
    type: str
  site_name:
    description:
    - Specifies the name of an existing site where you can place the new domain controller.
    - This option is required when I(read_only=true).
    type: str
  state:
    description:
    - Whether the target host should be a domain controller or a member server.
    type: str
    choices:
    - domain_controller
    - member_server
    required: yes
  sysvol_path:
    description:
    - The path to a directory on a fixed disk of the Windows host where the
      Sysvol folder will be created.
    - If not set then the default path is C(%SYSTEMROOT%\SYSVOL).
    type: path
notes:
- It is highly recommended to set I(reboot=true) to have Ansible manage the host reboot phase as the actions done by
  this module puts the host in a state where it may not be possible for Ansible to reconnect in a subsequent task
  without a reboot.
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
- module: microsoft.ad.computer
- module: microsoft.ad.domain
- module: microsoft.ad.group
- module: microsoft.ad.membership
- module: microsoft.ad.user
- ref: Migration guide <ansible_collections.microsoft.ad.docsite.guide_migration.migrated_modules.win_domain_controller>
  description: This module replaces C(ansible.windows.win_domain_controller). See the migration guide for details.
- module: ansible.windows.win_domain_controller
author:
- Matt Davis (@nitzmahone)
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Ensure a server is a domain controller
  microsoft.ad.domain_controller:
    dns_domain_name: ansible.vagrant
    domain_admin_user: testguy@ansible.vagrant
    domain_admin_password: password123!
    safe_mode_password: password123!
    state: domain_controller
    reboot: true

- name: Ensure a server is not a domain controller
  microsoft.ad.domain_controller:
    domain_admin_user: testguy@ansible.vagrant
    domain_admin_password: password123!
    local_admin_password: password123!
    state: member_server
    reboot: true

- name: Promote server as a read only domain controller
  microsoft.ad.domain_controller:
    dns_domain_name: ansible.vagrant
    domain_admin_user: testguy@ansible.vagrant
    domain_admin_password: password123!
    safe_mode_password: password123!
    state: domain_controller
    read_only: yes
    site_name: London
    reboot: true

# This scenario is not recommended, use reboot: true when possible
- name: Promote server with custom paths with manual reboot task
  microsoft.ad.domain_controller:
    dns_domain_name: ansible.vagrant
    domain_admin_user: testguy@ansible.vagrant
    domain_admin_password: password123!
    safe_mode_password: password123!
    state: domain_controller
    sysvol_path: D:\SYSVOL
    database_path: D:\NTDS
    domain_log_path: D:\NTDS
  register: dc_promotion

- name: Reboot after promotion
  microsoft.ad.win_reboot:
  when: dc_promotion.reboot_required
"""

RETURN = r"""
reboot_required:
  description: True if changes were made that require a reboot.
  returned: always
  type: bool
  sample: true
"""
