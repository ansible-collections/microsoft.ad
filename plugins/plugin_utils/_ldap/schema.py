# Copyright: (c) 2023, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within this collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import annotations

import base64
import typing as t

import sansldap

from .client import SyncLDAPClient


class LDAPSchema:
    def __init__(
        self,
        attribute_types: t.Dict[str, sansldap.schema.AttributeTypeDescription],
    ) -> None:
        self.attribute_types = attribute_types

    @classmethod
    def load_schema(cls, client: SyncLDAPClient) -> LDAPSchema:
        root_dse = client.root_dse
        attribute_types = list(
            client.search(
                filter=sansldap.FilterPresent("objectClass"),
                attributes=["attributeTypes"],
                search_base=root_dse.subschema_subentry,
                search_scope=sansldap.SearchScope.BASE,
            ).values()
        )[0]["attributeTypes"]

        attribute_info: t.Dict[str, sansldap.schema.AttributeTypeDescription] = {}
        for info in attribute_types:
            type_description = sansldap.schema.AttributeTypeDescription.from_string(info.decode("utf-8"))
            if type_description.names:
                attribute_info[type_description.names[0].lower()] = type_description

        return LDAPSchema(attribute_info)

    def cast_object(
        self,
        attribute: str,
        values: t.List[bytes],
    ) -> t.Any:
        info = self.attribute_types.get(attribute.lower(), None)
        if not info or not info.syntax:
            return values

        # FIXME: See what other types are used in AD and if they need to be here.
        caster: t.Callable[[bytes], t.Any] = {
            "1.3.6.1.4.1.1466.115.121.1.27": lambda v: int(v),
            "1.3.6.1.4.1.1466.115.121.1.40": lambda v: base64.b64encode(v).decode(),
            "1.2.840.113556.1.4.906": lambda v: int(v),
            "1.2.840.113556.1.4.907": lambda v: base64.b64encode(v).decode(),
            "OctetString": lambda v: base64.b64encode(v).decode(),
        }.get(info.syntax, lambda v: v.decode("utf-8", errors="surrogateescape"))

        casted_values: t.List = []
        for v in values:
            casted_values.append(caster(v))

        if info.single_value:
            return casted_values[0] if casted_values else None
        else:
            return casted_values
