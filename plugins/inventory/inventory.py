# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import annotations

DOCUMENTATION = """
name: inventory
author: Jordan Borean (@jborean93)
short_description: Inventory plugin for Active Directory
description:
- Inventory plugin for Active Directory or other LDAP sources.
- Uses a YAML configuration file that ends with C(microsoft.ad.{yml|yaml}).
options:
  attributes:
    description:
    - The LDAP attributes to retrieve.
    - Attributes that are denoted as single value in the LDAP schema ar
      returned as that single value, multi values attributes are returned as a
      list of values.
    - The type of the attribute value is dependent on the LDAP schema
      definition.
    default: []
    type: list
    elements: str
  filter:
    description:
    - The LDAP filter string used to query the computer objects
    default: '(objectClass=computer)'
    type: str
  hostvars_prefix:
    description:
    - The prefix used for host variables.
    - This prefix is applied to all variables set by this inventory plugin.
    default: ""
    type: str
  hostvars_suffix:
    description:
    - The suffix used for host variables.
    - This suffix is applied to all variables set by this inventory plugin.
    default: ""
    type: str
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
extends_documentation_fragment:
- constructed
- microsoft.ad.ldap_connection
"""

EXAMPLES = """
"""

import typing as t

from ansible.errors import AnsibleError
from ansible.inventory.data import InventoryData
from ansible.module_utils.basic import missing_required_lib
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable

try:
    import sansldap
    from ..plugin_utils import _ldap as ldap

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "microsoft.ad.inventory"

    def verify_file(self, path: str) -> bool:
        if super().verify_file(path):
            return path.endswith(("microsoft.ad.yml", "microsoft.ad.yaml"))

        return False

    def parse(
        self,
        inventory: InventoryData,
        loader: DataLoader,
        path: str,
        cache: bool,
    ) -> None:
        super().parse(inventory, loader, path, cache)
        self.set_options()
        self._read_config_data(path)

        if not HAS_LDAP:
            msg = missing_required_lib(
                "sansldap and pyspnego",
                url="https://pypi.org/project/sansldap/ and https://pypi.org/project/pyspnego/",
                reason="for ldap lookups",
            )
            raise AnsibleError(f"{msg}: {LDAP_IMP_ERR}") from LDAP_IMP_ERR

        compose = self.get_option("compose")
        groups = self.get_option("groups")
        keyed_groups = self.get_option("keyed_groups")
        search_base = self.get_option("search_base")
        search_scope = self.get_option("search_scope")
        strict = self.get_option("strict")
        vars_prefix = self.get_option("hostvars_prefix")
        vars_suffix = self.get_option("hostvars_suffix")

        ldap_search_scope = {
            "base": sansldap.SearchScope.BASE,
            "one_level": sansldap.SearchScope.ONE_LEVEL,
            "subtree": sansldap.SearchScope.SUBTREE,
        }[search_scope]

        ldap_filter = sansldap.LDAPFilter.from_string(self.get_option("filter"))

        custom_attributes = self.get_option("attributes")
        attributes = {"name", "dnshostname"}.union([c.lower() for c in custom_attributes])
        with ldap.create_connection(**self.get_options()) as client:
            schema = ldap.LDAPSchema.load_schema(client)

            for info in client.search(
                filter=ldap_filter,
                attributes=list(attributes),
                search_base=search_base,
                search_scope=ldap_search_scope,
            ).values():
                insenstive_info = {k.lower(): v for k, v in info.items()}

                host_name = insenstive_info["name"][0].decode("utf-8")
                inventory.add_host(host_name)

                dns_host_name = insenstive_info.get("dnshostname", None)
                if dns_host_name:
                    inventory.set_variable(host_name, "ansible_host", dns_host_name[0].decode("utf-8"))

                host_vars: t.Dict[str, t.Any] = {}
                for name in custom_attributes:
                    values = schema.cast_object(name, insenstive_info.get(name.lower(), []))
                    var_name = f"{vars_prefix}{name}{vars_suffix}"

                    host_vars[var_name] = values
                    inventory.set_variable(host_name, var_name, values)

                self._set_composite_vars(compose, host_vars, host_name, strict=strict)
                self._add_host_to_composed_groups(groups, host_vars, host_name, strict=strict)
                self._add_host_to_keyed_groups(keyed_groups, host_vars, host_name, strict=strict)
