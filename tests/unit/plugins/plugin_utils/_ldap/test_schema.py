# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import uuid

import pytest

sansldap = pytest.importorskip("sansldap")

from ansible_collections.microsoft.ad.plugins.plugin_utils._ldap.schema import LDAPSchema


def test_cast_from_objectsid() -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["objectSid"],
        syntax="foo",
        single_value=True,
    )
    schema = LDAPSchema({"objectsid": type_desc})

    actual = schema.cast_object("objectSid", [b"\x01\x01\x00\x00\x00\x00\x00\x05\x13\x00\x00\x00"])
    assert actual == "S-1-5-19"


def test_cast_from_objectguid() -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["objectGuid"],
        syntax="bar",
        single_value=True,
    )
    schema = LDAPSchema({"objectguid": type_desc})

    value = uuid.uuid4()
    actual = schema.cast_object("objectGuid", [value.bytes_le])
    assert actual == str(value)


@pytest.mark.parametrize("single_value", [True, False])
def test_from_bool(single_value: bool) -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax="1.3.6.1.4.1.1466.115.121.1.7",
        single_value=single_value,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [b"TRUE", b"FALSE"])
    if single_value:
        assert actual is True
    else:
        assert actual == [True, False]


@pytest.mark.parametrize(
    "single_value, syntax",
    [
        (True, "1.3.6.1.4.1.1466.115.121.1.27"),
        (False, "1.3.6.1.4.1.1466.115.121.1.27"),
        (True, "1.2.840.113556.1.4.906"),
        (False, "1.2.840.113556.1.4.906"),
    ],
)
def test_from_int(single_value: bool, syntax: str) -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax=syntax,
        single_value=single_value,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [b"1", b"2345678910"])
    if single_value:
        assert actual == 1
    else:
        assert actual == [1, 2345678910]


@pytest.mark.parametrize(
    "single_value, syntax",
    [
        (True, "1.3.6.1.4.1.1466.115.121.1.40"),
        (False, "1.3.6.1.4.1.1466.115.121.1.40"),
        (True, "1.2.840.113556.1.4.907"),
        (False, "1.2.840.113556.1.4.907"),
        (True, "OctetString"),
        (False, "OctetString"),
    ],
)
def test_from_bytes(single_value: bool, syntax: str) -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax=syntax,
        single_value=single_value,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [b"\x00", b"\x00\x01"])
    if single_value:
        assert actual == "AA=="
    else:
        assert actual == ["AA==", "AAE="]


@pytest.mark.parametrize("single_value", [True, False])
def test_from_string(single_value: bool) -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax="Something",
        single_value=single_value,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [b"caf\xc3\xa9\xFF", b"\x00\x7E\xDF\xFF"])
    if single_value:
        assert actual == "café\uDCFF"
    else:
        assert actual == ["café\uDCFF", "\u0000~\uDCDF\uDCFF"]


def test_from_string_no_type_desc() -> None:
    schema = LDAPSchema({})

    actual = schema.cast_object("myAttr", [b"caf\xc3\xa9\xFF", b"\x00\x7E\xDF\xFF"])
    assert actual == ["café\uDCFF", "\u0000~\uDCDF\uDCFF"]


def test_single_value_empty_input() -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax="OctetString",
        single_value=True,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [])
    assert actual is None


def test_multi_value_empty_input() -> None:
    type_desc = sansldap.schema.AttributeTypeDescription(
        "1.0",
        names=["myAttr"],
        syntax="OctetString",
        single_value=False,
    )
    schema = LDAPSchema({"myattr": type_desc})

    actual = schema.cast_object("myAttr", [])
    assert actual == []
