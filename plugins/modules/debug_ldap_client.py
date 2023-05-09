#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: debug_ldap_client
short_description: Get host information for debugging LDAP connections
description:
- Get information about the current Ansible host to debug LDAP connections and
  their capabilities.
version_added: 1.1.0
options: {}
notes:
- See R(LDAP connection help,ansible_collections.microsoft.ad.docsite.guide_ldap_connection)
  for more information about LDAP connections.
- The return values are not part of any contract and can change in the future.
  It is meant to give a snapshot of the Ansible host that can help debug LDAP
  connection issues and not be used as part of a normal playbook.
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
    - posix
  action:
    support: full
  async:
    support: full
  bypass_host_loop:
    support: none
author:
- Jordan Borean (@jborean93)
"""

EXAMPLES = r"""
- name: Get information about the Ansible host's LDAP capabilities
  microsoft.ad.debug_ldap_client:
"""

RETURN = r"""
dns:
  description:
  - Details about the SRV LDAP server lookup.
  - The values will only be populated if dnspython is installed.
  returned: always
  type: complex
  contains:
    default_port:
      description:
      - The default port of the SRV record chosen.
      returned: dnspython is installed
      type: int
      sample: 389
    default_server:
      description:
      - The default hostname of the SRV record chosen.
      returned: dnspython is installed
      type: str
      sample: dc01.domain.com
    exception:
      description:
      - Any exceptions that occurred when getting the SRV records.
      returned: dnspython is installed
      type: str
      sample: ""
    records:
      description:
      - The SRV records that were found during the LDAP server lookup.
      returned: dnspython is installed
      type: list
      contains:
        port:
          description:
          - The port of this SRV record.
          returned: dnspython is installed and default_realm is found
          type: int
          sample: 389
        priority:
          description:
          - The record priority value.
          returned: dnspython is installed and default_realm is found
          type: int
          sample: 0
        target:
          description:
          - The target name of the SRV record.
          returned: dnspython is installed and default_realm is found
          type: str
          sample: dc01.domain.com.
        weight:
          description:
          - The record weight value.
          returned: dnspython is installed and default_realm is found
          type: int
          sample: 100
kerberos:
  description:
  - Details about the host Kerberos setup.
  - The values will only be populated if krb5 is installed.
  returned: always
  type: complex
  contains:
    default_cc:
      description:
      - Details about the default Kerberos credential cache.
      returned: krb5 is installed
      type: complex
      contains:
        creds:
          description:
          - A list of credentials that is stored in the ccache.
          - This requires C(krb5 >= 0.5.0) to be populated.
          returned: krb5 is installed
          type: complex
          contains:
            client:
              description:
              - The client principal name the credential is for.
              returned: krb5 >= 0.5.0 is installed
              type: str
              sample: username@DOMAIN.COM
            server:
              description:
              - The server principal name the credential is for.
              returned: krb5 >= 0.5.0 is installed
              type: str
              sample: krbtgt/DOMAIN.COM@DOMAIN.COM
        exception:
          description:
          - Any exceptions that occurred when getting the ccache information.
          returned: krb5 is installed
          type: str
          sample: ""
        name:
          description:
          - The default ccache type and name.
          returned: krb5 is installed
          type: str
          sample: FILE:/tmp/krb5cc_1000
        principal:
          description:
          - The default principal of the ccache
          returned: krb5 is installed
          type: str
          sample: username@DOMAIN.COM
    default_realm:
      description:
      - The default_realm as reported by Kerberos.
      - This value is used for the automatic server lookup.
      returned: krb5 is installed
      type: str
      sample: domain.com
    exception:
      description:
      - Exception details if the default realm could not be retrieved.
      returned: krb5 is installed
      type: str
      sample: ""
packages:
  description:
  - All the packages used by this collection for LDAP connections and their
    installed versions.
  - If the package is not installed, or failed to import, the value is the
    traceback from the import process.
  - This can be used to determine the availability of optional features like
    Kerberos authentication or server lookups.
  returned: always
  type: complex
  contains:
    dnspython:
      description:
      - The installed version of C(dnspython) or the import error if not
        installed.
      returned: always
      type: str
      sample: '2.3.0'
    dpapi_ng:
      description:
      - The installed version of C(dpapi-ng) or the import error if not
        installed.
      returned: always
      type: str
      sample: '0.1.0'
    krb5:
      description:
      - The installed version of C(krb5) or the import error if not
        installed.
      returned: always
      type: str
      sample: '0.5.0'
    pyspnego:
      description:
      - The installed version of C(pyspnego) or the import error if not
        installed.
      returned: always
      type: str
      sample: '0.8.0'
    sansldap:
      description:
      - The installed version of C(sansldap) or the import error if not
        installed.
      returned: always
      type: str
      sample: '0.1.0'
"""
