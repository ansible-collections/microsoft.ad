# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
name: laps_password
author: Jordan Borean (@jborean93)
short_description: Retrieves the LAPS password for a server
description:
- This lookup returns the LAPS password set for a server from the Active Directory database.
options:
  _terms:
    description:
    - The host name to retrieve the LAPS password for.
    - This corresponds to the C(sAMAccountName) of the computer to lookup.
    - If the value does not end with C($), it is automatically added during the
      lookup.
    required: True
    type: str
  search_base:
    description:
    - Changes the search based used when searching for the computer object.
    - Defaults to the C(defaultNamingContext) of the Active Directory server
      if not specified.
    - If searching a larger Active Directory database, it is recommended to
      narrow the search base to speed up the queries.
    type: str
extends_documentation_fragment:
- microsoft.ad.ldap_connection
"""

EXAMPLES = """
"""

RETURN = """
_raw:
  description:
  - The LAPS password(s) for the host(s) requested.
  type: str
"""

from ansible.errors import AnsibleLookupError
from ansible.module_utils.basic import missing_required_lib
from ansible.plugins.lookup import LookupBase

try:
    import sansldap
    from ..plugin_utils import _ldap as ldap

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


class LookupModule(LookupBase):
    def run(self, terms, variables=None, **kwargs):
        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap",
                url="https://pypi.org/project/sansldap/",
                reason="for ldap lookups",
            )
            raise AnsibleLookupError(f"{msg}: {LDAP_IMP_ERR}") from LDAP_IMP_ERR

        self.set_options(var_options=variables, direct=kwargs)

        with ldap.create_connection(**self.get_options()) as client:

            host_filter = sansldap.FilterOr(filters=[])

            hosts = []
            for t in terms:
                host = str(t)
                if not host.endswith("$"):
                    host = f"{host}$"

                hosts.append(host)
                host_filter.filters.append(sansldap.FilterEquality("sAMAccountName", host.encode("utf-8")))

            ldap_filter = sansldap.FilterAnd(filters=[sansldap.FilterEquality("objectClass", b"computer"), host_filter])

            result = client.search(
                ldap_filter,
                ["sAMAccountName", "ms-Mcs-AdmPwd"],
                search_base=self.get_option("search_base"),
            )
            sam_results = {
                r["sAMAccountName"][0].decode("utf-8").upper(): r.get("ms-Mcs-AdmPwd", None) for r in result.values()
            }

            laps_passwords = []
            for host in hosts:
                upper_host = host.upper()
                if upper_host not in sam_results:
                    raise AnsibleLookupError(f"Failed to find the server '{host}'")

                password = sam_results[upper_host]
                if not password:
                    raise AnsibleLookupError(f"The server '{host}' did not have the LAPS attribute 'ms-Mcs-AdmPwd'")

                laps_passwords.append(password[0].decode("utf-8"))

            return laps_passwords
