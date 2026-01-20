# -*- coding: utf-8 -*-

# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


class ModuleDocFragment:

    # Common options for ansible_collections.microsoft.ad.plugins.module_utils._ADObject Initialize-ADConnection
    # If you need other functions from the _ADObject util, extend the ad_object fragment instead.
    DOCUMENTATION = r"""
requirements:
- C(ActiveDirectory) PowerShell module
options:
  domain_credentials:
    description:
    - Specifies the credentials that should be used when using the server
      specified by I(name).
    - To specify credentials for the default domain server, use an entry
      without the I(name) key or use the I(domain_username) and
      I(domain_password) option.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    - See R(AD authentication in modules,ansible_collections.microsoft.ad.docsite.guide_ad_module_authentication)
      for more information.
    default: []
    type: list
    elements: dict
    suboptions:
      name:
        description:
        - The name of the server these credentials are for.
        - This value should correspond to the value used in other options that
          specify a custom server to use, for example an option that references
          an AD identity located on a different AD server.
        - This key can be omitted in one entry to specify the default
          credentials to use when a server is not specified instead of using
          I(domain_username) and I(domain_password).
        type: str
      username:
        description:
        - The username to use when connecting to the server specified by
          I(name).
        type: str
        required: true
      password:
        description:
        - The password to use when connecting to the server specified by
          I(name).
        type: str
        required: true
  domain_password:
    description:
    - The password for I(domain_username).
    - The I(domain_credentials) sub entry without a I(name) key can also be
      used to specify the credentials for the default domain authentication.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
  domain_server:
    description:
    - Specified the Active Directory Domain Services instance to connect to.
    - Can be in the form of an FQDN or NetBIOS name.
    - If not specified then the value is based on the default domain of the computer running PowerShell.
    - Custom credentials can be specified under a I(domain_credentials) entry
      without a I(name) key or through I(domain_username) and
      I(domain_password).
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
  domain_username:
    description:
    - The username to use when interacting with AD.
    - If this is not set then the user that is used for authentication will be the connection user.
    - Ansible will be unable to use the connection user unless auth is Kerberos with credential delegation or CredSSP,
      or become is used on the task.
    - The I(domain_credentials) sub entry without a I(name) key can also be
      used to specify the credentials for the default domain authentication.
    - This can be set under the R(play's module defaults,module_defaults_groups)
      under the C(group/microsoft.ad.domain) group.
    type: str
notes:
- If running on a server that is not a Domain Controller, credential
  delegation through CredSSP or Kerberos with delegation must be used or the
  I(domain_username), I(domain_password) must be set.
"""
