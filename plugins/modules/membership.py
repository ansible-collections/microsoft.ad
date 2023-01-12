#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2022 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: membership
short_description: Manage domain/workgroup membership for a Windows host
description:
- Manages domain membership or workgroup membership for a Windows host. Also supports hostname changes.
- This module may require subsequent use of the M(ansible.windows.win_reboot) action if changes are made.
options:
  dns_domain_name:
    description:
    - When I(state=domain), this is the DNS name of the domain to which the targeted Windows host should be joined.
    type: str
  domain_admin_user:
    description:
    - Username of a domain admin for the target domain (required to join or leave the domain).
    required: true
    type: str
  domain_admin_password:
    description:
    - Password for the specified C(domain_admin_user).
    required: true
    type: str
  domain_ou_path:
    description:
    - The desired OU path for adding the computer object.
    - This is only used when adding the target host to a domain, if it is already a member then it is ignored.
    type: str
  hostname:
    description:
    - The desired hostname for the Windows host.
    type: str
  reboot:
    description:
    - If C(true), this will reboot the host if a reboot was required to configure the domain.
    - If C(false), this will not reboot the host if a reboot was required and instead sets the I(reboot_required) return value to C(true).
    - If changing from a domain to workgroup, the connection account must be a local user that can connect to the host
      after it has unjoined the domain.
    - This cannot be used with async mode.
    - To use this parameter, ensure the fully qualified module name is used in the task or the I(collections) keyword includes this collection.
    type: bool
    default: false
  state:
    description:
    - Whether the target host should be a member of a domain or workgroup.
    - When I(state=domain), I(dns_domain_name), I(domain_admin_user), and I(domain_admin_password) must be set.
    - When I(state=workgroup), I(workgroup_name) must be set.
    choices:
    - domain
    - workgroup
    required: true
    type: str
  workgroup_name:
    description:
    - When I(state=workgroup), this is the name of the workgroup that the Windows host should be in.
    type: str
extends_documentation_fragment:
- ansible.builtin.action_common_attributes
- ansible.builtin.action_common_attributes.flow
attributes:
  check_mode:
    support: full
  diff_mode:
    support: full
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
- module: ansible.active_directory.domain
- module: ansible.active_directory.domain_controller
- module: ansible.active_directory.user
- module: community.windows.win_domain_computer
- module: community.windows.win_domain_group
- module: ansible.windows.win_group
- module: ansible.windows.win_group_membership
- module: ansible.windows.win_user
author:
- Matt Davis (@nitzmahone)
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: join host to ansible.vagrant with automatic reboot
  ansible.active_directory.membership:
    dns_domain_name: ansible.vagrant
    hostname: mydomainclient
    domain_admin_user: testguy@ansible.vagrant
    domain_admin_password: password123!
    domain_ou_path: "OU=Windows,OU=Servers,DC=ansible,DC=vagrant"
    state: domain
    reboot: true

- name: join host to workgroup with manual reboot in later task
  ansible.active_directory.membership:
    workgroup_name: mywg
    domain_admin_user: '{{ win_domain_admin_user }}'
    domain_admin_password: '{{ win_domain_admin_password }}'
    state: workgroup
  register: workgroup_res

- name: reboot host after joining workgroup
  ansible.windows.win_reboot:
  when: workgroup_res.reboot_required
"""

RETURN = r"""
reboot_required:
  description: True if changes were made that require a reboot.
  returned: always
  type: bool
  sample: true
"""
