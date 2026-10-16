# Copyright: (c) 2024, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
name: laps
author: Nico Ohnezat (@no-12)
short_description: Inventory plugin for Active Directory
version_added: 2.2.0
description:
- Lookup plugin that retrieves the LAPS password information for multiple hosts from an Active Directory server.
options:
  _terms:
    description:
    - One or multiple C(CommonName) of the computer objects to search for.
    required: True
  laps:
    description:
    - The LAPS password type to retrieve.
    - Defaults to the C(auto).
    - This will attempt to retrieve the LAPS password in the following order C(windows_encrypted), C(windows_plain_text), C(legacy_microsoft).
    type: str
    choices:
    - auto
    - windows_encrypted
    - windows_plain_text
    - legacy_microsoft
    default: auto
  search_base:
    description:
    - The LDAP search base to find the computer objects in.
    - Defaults to the C(defaultNamingContext) of the Active Directory server
      if not specified.
    - If searching a larger Active Directory database, it is recommended to
      narrow the search base to speed up the queries.
    type: str
  search_scope:
    description:
    - The scope of the LDAP search to perform.
    - C(base) will search only the current path or object specified by
      I(search_base). This is typically not useful for inventory plugins.
    - C(one_level) will search only the immediate child objects in
      I(search_base).
    - C(subtree) will search the immediate child objects and any nested
      objects in I(search_base).
    choices:
    - base
    - one_level
    - subtree
    default: subtree
    type: str
notes:
- This plugin is a tech preview and the module options are subject to change
  based on feedback received.
extends_documentation_fragment:
- microsoft.ad.ldap_connection
"""

import json

from ansible.errors import AnsibleError
from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_bytes
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from ansible.utils.unsafe_proxy import wrap_var

try:
    import sansldap

    from ..plugin_utils._ldap import create_ldap_connection
    from ..plugin_utils._ldap.laps import LAPSDecryptor
    from ..filter.ldap_converters import as_datetime

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


display = Display()


def _parse_value(values, parser=wrap_var):
    if values:
        return parser(values[0])
    return None


def _create_error_result(cn, laps, error_msg):
    return {"failed": True, "cn": cn, "laps": laps, "error_msg": error_msg}


def _create_result(cn, laps, username, password, expiration_time_raw):
    return {
        "failed": False,
        "cn": cn,
        "laps": laps,
        "laps_username": username,
        "laps_password": password,
        "laps_password_expiration_time": _parse_value(
            values=expiration_time_raw,
            parser=as_datetime,
        ),
    }


class LookupModule(LookupBase):
    NAME = "microsoft.ad.laps"

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap and pyspnego",
                url="https://pypi.org/project/sansldap/ and https://pypi.org/project/pyspnego/",
                reason="for ldap lookups",
            )
            raise AnsibleError(f"{msg}: {LDAP_IMP_ERR}") from LDAP_IMP_ERR

        search_base = self.get_option("search_base")
        search_scope = self.get_option("search_scope")
        ldap_search_scope = {
            "base": sansldap.SearchScope.BASE,
            "one_level": sansldap.SearchScope.ONE_LEVEL,
            "subtree": sansldap.SearchScope.SUBTREE,
        }[search_scope]

        computer_filter = sansldap.FilterEquality("objectClass", b"computer")
        cn_filter = sansldap.FilterOr(
            filters=[sansldap.FilterEquality("cn", to_bytes(t)) for t in terms]
        )
        final_filter = sansldap.FilterAnd(filters=[computer_filter, cn_filter])

        attributes = [
            "cn",
            "mslaps-encryptedpassword",
            "mslaps-password",
            "mslaps-passwordexpirationtime",
            "ms-mcs-admpwd",
            "ms-mcs-admpwdexpirationtime",
        ]

        connection_options = self.get_options()
        self.laps_decryptor = LAPSDecryptor(**connection_options)

        with create_ldap_connection(**connection_options) as client:
            return [
                self._get_laps_credentials(dn, info)
                for dn, info in client.search(
                    filter=final_filter,
                    attributes=attributes,
                    search_base=search_base,
                    search_scope=ldap_search_scope,
                ).items()
            ]

    def _get_laps_credentials(self, dn, info):
        display.v(f"Get LAPS credentials for {dn}")
        laps = self.get_option("laps")
        insensitive_info = {k.lower(): v for k, v in info.items()}
        cn = _parse_value(insensitive_info.get("cn"))

        if (
            laps in ["auto", "windows_encrypted"]
            and "mslaps-encryptedpassword" in insensitive_info
        ):
            return self._get_windows_encrypted(cn=cn, insensitive_info=insensitive_info)

        if (
            laps in ["auto", "windows_plain_text"]
            and "mslaps-password" in insensitive_info
        ):
            return self._get_windows_plain_text(
                cn=cn, insensitive_info=insensitive_info
            )

        if laps in ["auto", "legacy_microsoft"] and "ms-mcs-admpwd" in insensitive_info:
            return self._get_windows_plain_text(
                cn=cn, insensitive_info=insensitive_info
            )

        return _create_error_result(
            cn=cn,
            laps=laps,
            error_msg="No LAPS password found for the specified computer",
        )

    def _get_windows_encrypted(self, cn, insensitive_info):
        laps = "windows_encrypted"
        parsed_mslaps_password = _parse_value(
            values=insensitive_info.get("mslaps-encryptedpassword"),
            parser=self.laps_decryptor.decrypt,
        )

        debug_message = parsed_mslaps_password.get("debug")
        if debug_message:
            return _create_error_result(cn=cn, laps=laps, error_msg=debug_message)

        value = parsed_mslaps_password.get("value")
        if not value:
            return _create_error_result(
                cn=cn, laps=laps, error_msg="Failed to parse decrypted LAPS password"
            )

        return _create_result(
            cn=cn,
            laps=laps,
            username=value.get("n"),
            password=value.get("p"),
            expiration_time_raw=insensitive_info.get("mslaps-passwordexpirationtime"),
        )

    def _get_windows_plain_text(self, cn, insensitive_info):
        raw_mslaps_password = _parse_value(insensitive_info.get("mslaps-password"))
        parsed_mslaps_password = json.loads(raw_mslaps_password)
        return _create_result(
            cn=cn,
            laps="windows_plain_text",
            username=parsed_mslaps_password.get("n"),
            password=parsed_mslaps_password.get("p"),
            expiration_time_raw=insensitive_info.get("mslaps-passwordexpirationtime"),
        )

    def _get_legacy_microsoft(self, cn, insensitive_info):
        return _create_result(
            cn=cn,
            laps="legacy_microsoft",
            username="Administrator",
            password=_parse_value(insensitive_info.get("ms-mcs-admpwd")),
            expiration_time_raw=insensitive_info.get("ms-mcs-admpwdexpirationtime"),
        )
