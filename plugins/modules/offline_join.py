#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: offline_join
short_description: Get the Offline Domain Join BLOB
description:
- Used to get the Offline Domain Join BLOB.
- This BLOB is used to join computers to a domain without any network access.
requirements:
- C(ActiveDirectory) PowerShell module
options:
  blob_path:
    description:
    - If set, will store the blob bytes into a file at this path.
    - This will not create the parent directory specified if it does not exist.
    - The existence of this file is also used as an idempotency check, if the
      file already exists the blob will not be regenerated.
    - If specified the module return value I(blob) will be null.
    type: str
  domain_server:
    description:
    - Specified the Active Directory Domain Services instance to connect to.
    - Can be in the form of an FQDN or NetBIOS name.
    - If not specified then the value is based on the default domain of the
      computer running PowerShell.
    type: str
  identity:
    description:
    - The identity of the computer object used to generate the offline join
      blob for.
    - This is mutually exclusive with I(name) and (path).
    - The identity can be in the form of a GUID representing the C(objectGUID)
      value, C(sAMAccountName), C(objectSid), or C(distinguishedName).
    - This option or I(name) must be specified.
    type: str
  name:
    description:
    - The name of the computer object used to generate the offline join blob
      for.
    - This is mutually exclusive with I(identity).
    - The name is combined with I(path) to find the AD computer object that
      matches the DistinguishedName C(CN={{ name}},{{ path }}).
    - This option or I(identity) must be specified.
    type: str
  path:
    description:
    - The path where the computer object specified by C(name) is stored.
    - By default the default computer path defined in AD is used, for example
      C(CN=Computers,DC=domain,DC=com).
    type: str
  provision_root_ca_certs:
    description:
    - Adds all the root Certificate Authority certificates on the local machine
      and adds them to the blob.
    type: bool
    default: false
extends_documentation_fragment:
- ansible.builtin.action_common_attributes
attributes:
  check_mode:
    support: full
  diff_mode:
    support: none
  platform:
    platforms:
    - windows
notes:
- For more information on Offline Domain Join see
  L(the step-by-step guide,https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd392267%28v=ws.10%29).
- There is no way to specify specific credentials to communicate with the
  domain controller when creating the blob. Use C(become) with net credentials
  if the current user cannot authenticate itself and bypass the double hop
  problem.
- The data returned by this module is very sensitive. If not using I(blob_path)
  then C(no_log=True) should be used on the task to avoid the data being
  leaked.
- This module will always report a change unless I(blob_path) is specified. If
  the path is specified then then the existence of that path will act as the
  idempotency check.
- Generating a new blob will reset the password of the computer object, take
  care that this isn't called under a computer account that has already been
  joined.
seealso:
- module: microsoft.ad.domain
- module: microsoft.ad.membership
- module: microsoft.ad.computer
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: create computer object
  microsoft.ad.computer:
    name: MyComputer
    state: present
  register: computer_obj

- name: create offline blob
  microsoft.ad.offline_join:
    identity: '{{ computer_obj.object_guid }}'
  when: computer_obj is changed
  register: offline_blob
  no_log: true

- name: join host by offline blob
  microsoft.ad.membership:
    offline_join_blob: '{{ offline_blob.blob }}'
    state: domain
    reboot: true
  delegate_to: member-host

- name: create blob and store it in a file on the target host
  microsoft.ad.offline_join:
    name: MyComputer
    path: OU=Production,DC=domain,DC=com
    blob_path: C:\Windows\TEMP\offline_blob
"""

RETURN = r"""
blob:
  description:
  - The blob as a base64 string.
  - This value is empty when running in check mode.
  - This value is null when I(blob_path) is specified.
  - This value is highly sensitive as it contains the credentials and other
    authentication data needed for an offline join.
  returned: always
  type: str
  sample: ARAIAMzMzMygCAAAAAAAAAAAAgABAAAA
"""
