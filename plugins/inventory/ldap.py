# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = """
name: ldap
author: Jordan Borean (@jborean93)
short_description: Inventory plugin for Active Directory
description:
- Inventory plugin for Active Directory or other LDAP sources.
- Uses a YAML configuration file that ends with C(microsoft.ad.{yml|yaml}).
- Each host that is added will set the C(inventory_hostname) to the C(name) of
  the LDAP computer object and C(ansible_hostname) to the value of the
  C(dNSHostName) LDAP attribute if set. If the C(dNSHostName) attribute is not
  set on the computer object then C(ansible_hostname) is not set.
- Any other fact that is needed, needs to be defined in the I(attributes)
  option.
options:
  attributes:
    description:
    - The LDAP attributes to retrieve.
    - The keys specified are the LDAP attributes requested and the values for
      each attribute is a dictionary that reflects what host var to set it to
      and how.
    - Each key of the inner dictionary value is the host variable name to set
      and the value is the template to use to derive the value. If no value is
      explicitly set then it will use the coerced value as returned from the
      LDAP attribute.
    - Attributes that are denoted as single value in the LDAP schema are
      returned as that single value, multi values attributes are returned as a
      list of values.
    - See R(LDAP inventory attributes,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory.attributes)
      for more information.
    default: {}
    type: dict
  filter:
    description:
    - The LDAP filter string used to query the computer objects.
    - This will be combined with the filter "(objectClass=computer)".
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
notes:
- See R(LDAP inventory,ansible_collections.microsoft.ad.docsite.guide_ldap_inventory)
  for more details on how to use this inventory plugin.
extends_documentation_fragment:
- constructed
- microsoft.ad.ldap_connection
"""

EXAMPLES = """
"""

import base64
import typing as t

from ansible.errors import AnsibleError
from ansible.inventory.data import InventoryData
from ansible.module_utils.basic import missing_required_lib
from ansible.parsing.dataloader import DataLoader
from ansible.plugins.inventory import BaseInventoryPlugin, Constructable
from ansible.utils.unsafe_proxy import wrap_var

try:
    import sansldap

    from ..plugin_utils._ldap import create_ldap_connection
    from ..plugin_utils._ldap.schema import LDAPSchema

    HAS_LDAP = True
    LDAP_IMP_ERR = None
except Exception as e:
    HAS_LDAP = False
    LDAP_IMP_ERR = e


class InventoryModule(BaseInventoryPlugin, Constructable):
    NAME = "microsoft.ad.ldap"

    def verify_file(self, path: str) -> bool:
        if super().verify_file(path):
            return path.endswith(("microsoft.ad.ldap.yml", "microsoft.ad.ldap.yaml"))

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
        ldap_filter = self.get_option("filter")
        search_base = self.get_option("search_base")
        search_scope = self.get_option("search_scope")
        strict = self.get_option("strict")

        ldap_search_scope = {
            "base": sansldap.SearchScope.BASE,
            "one_level": sansldap.SearchScope.ONE_LEVEL,
            "subtree": sansldap.SearchScope.SUBTREE,
        }[search_scope]

        computer_filter = sansldap.FilterEquality("objectClass", b"computer")
        final_filter: sansldap.LDAPFilter
        if ldap_filter:
            final_filter = sansldap.FilterAnd(
                filters=[
                    computer_filter,
                    sansldap.LDAPFilter.from_string(ldap_filter),
                ]
            )
        else:
            final_filter = computer_filter

        custom_attributes = self._get_custom_attributes()
        attributes = {"name", "dnshostname"}.union([a.lower() for a in custom_attributes.keys()])

        with create_ldap_connection(**self.get_options()) as client:
            schema = LDAPSchema.load_schema(client)

            for info in client.search(
                filter=final_filter,
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
                for name, var_info in custom_attributes.items():
                    raw_values = insenstive_info.get(name.lower(), [])
                    values = schema.cast_object(name, raw_values)

                    host_vars["raw"] = wrap_var([base64.b64encode(r).decode() for r in raw_values])
                    host_vars["this"] = wrap_var(values)

                    for n, v in var_info.items():
                        try:
                            composite = self._compose(v, host_vars)
                        except Exception as e:
                            if strict:
                                raise AnsibleError(f"Could not set {n} for host {host_name}: {e}") from e
                            continue

                        host_vars[n] = composite
                        inventory.set_variable(host_name, n, composite)

                    host_vars.pop("raw")
                    host_vars.pop("this")

                self._set_composite_vars(compose, host_vars, host_name, strict=strict)
                self._add_host_to_composed_groups(groups, host_vars, host_name, strict=strict)
                self._add_host_to_keyed_groups(keyed_groups, host_vars, host_name, strict=strict)

    def _get_custom_attributes(self) -> t.Dict[str, t.Dict[str, str]]:
        custom_attributes = self.get_option("attributes")

        processed_attributes: t.Dict[str, t.Dict[str, str]] = {}
        for name, info in custom_attributes.items():
            if not info:
                info = {name.replace("-", "_"): "this"}
            elif isinstance(info, str):
                info = {name.replace("-", "_"): info}
            elif not isinstance(info, dict):
                raise AnsibleError(f"Attribute {name} value was {type(info).__name__} but was expecting a dictionary")

            for var_name in list(info.keys()):
                var_template = info[var_name]
                if not var_template:
                    info[var_name] = "this"

                elif not isinstance(var_template, str):
                    raise AnsibleError(
                        f"Attribute {name}.{var_name} template value was {type(var_template).__name__} but was expecting a string"
                    )

            processed_attributes[name] = info

        return processed_attributes
