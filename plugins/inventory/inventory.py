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
      default:
      - distinguishedName
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
extends_documentation_fragment:
- constructed
- microsoft.ad.ldap_connection
"""

EXAMPLES = """
"""

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

        vars_prefix = self.get_option("hostvars_prefix")
        vars_suffix = self.get_option("hostvars_suffix")

        inventory.add_group("windows")
        ldap_filter = sansldap.LDAPFilter.from_string(self.get_option("filter"))

        attributes = {"name"}.union(self.get_option("attributes"))
        with ldap.create_connection(**self.get_options()) as client:
            for info in client.search(ldap_filter, list(attributes)).values():
                host_name = info["name"][0].decode("utf-8")
                insenstive_info = {k.lower(): v for k, v in info.items()}

                inventory.add_host(host_name, group="windows")
                for name in attributes:
                    if name == "name":
                        continue

                    values = [v.decode("utf-8") for v in insenstive_info.get(name.lower(), [])]
                    inventory.set_variable(host_name, f"{vars_prefix}{name}{vars_suffix}", values)

        return
