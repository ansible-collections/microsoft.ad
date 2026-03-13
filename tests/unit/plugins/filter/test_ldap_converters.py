# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import base64
import typing as t
import uuid

import pytest

from ansible.errors import AnsibleFilterError
from ansible_collections.microsoft.ad.plugins.filter.ldap_converters import (
    as_sid,
    as_guid,
    as_datetime,
    dn_escape,
    parse_dn,
    split_dn,
)


@pytest.mark.parametrize("type", ["int", "str", "bytes"])
def test_as_datetime(type: str) -> None:
    # Last digit is too precise for datetime so will be ignored.
    filetime = 133220025750000011

    value: t.Union[int, str, bytes]
    if type == "int":
        value = filetime
    elif type == "str":
        value = str(filetime)
    else:
        value = str(filetime).encode()

    actual = as_datetime(value)
    assert actual == "2023-02-27T20:16:15.000001+0000"


def test_as_datetime_with_format() -> None:
    filetime = 133220025750000000

    actual = as_datetime(filetime, format="%Y")
    assert actual == "2023"


def test_as_datetime_from_list() -> None:
    actual = as_datetime([133220025750000000, 133220025751000020])
    assert actual == [
        "2023-02-27T20:16:15.000000+0000",
        "2023-02-27T20:16:15.100002+0000",
    ]


@pytest.mark.parametrize("type", ["str", "bytes"])
def test_as_guid(type: str) -> None:
    input_uuid = uuid.uuid4()

    value: t.Union[str, bytes]
    if type == "str":
        value = base64.b64encode(input_uuid.bytes_le).decode()
    else:
        value = input_uuid.bytes_le

    actual = as_guid(value)
    assert actual == str(input_uuid)


def test_as_guid_from_list() -> None:
    input_uuids = [uuid.uuid4(), uuid.uuid4()]

    actual = as_guid([v.bytes_le for v in input_uuids])
    assert actual == [str(input_uuids[0]), str(input_uuids[1])]


@pytest.mark.parametrize("type", ["str", "bytes"])
def test_as_sid(type: str) -> None:
    raw_sid = "AQUAAAAAAAUVAAAAMS9koSf9FmVJIPcjUAQAAA=="

    value: t.Union[str, bytes]
    if type == "str":
        value = raw_sid
    else:
        value = base64.b64decode(raw_sid)

    actual = as_sid(value)
    assert actual == "S-1-5-21-2707697457-1696005415-603398217-1104"


def test_as_sid_from_list() -> None:
    input_sids = ["AQUAAAAAAAUVAAAAHZN390Q1esyM03upUAQAAA==", "AQEAAAAAAAUTAAAA"]

    actual = as_sid(input_sids)
    assert actual == ["S-1-5-21-4151808797-3430561092-2843464588-1104", "S-1-5-19"]


def test_as_sid_too_little_data_auth_count() -> None:
    with pytest.raises(
        AnsibleFilterError, match="Raw SID bytes must be at least 8 bytes long"
    ):
        as_sid(b"\x00\x00\x00\x00")


def test_as_sid_too_little_data_sub_authorities() -> None:
    with pytest.raises(AnsibleFilterError, match="Not enough data to unpack SID"):
        as_sid(b"\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")


@pytest.mark.parametrize(
    "value, expected",
    [
        ("Sue, Grabbit and Runn", "Sue\\, Grabbit and Runn"),
        ("Before\rAfter", "Before\\0DAfter"),
        ("Docs, Adatum", "Docs\\, Adatum"),
        ("foo,bar", "foo\\,bar"),
        ("foo+bar", "foo\\+bar"),
        ('foo"bar', 'foo\\"bar'),
        ("foo\\bar", "foo\\\\bar"),
        ("foo<bar", "foo\\<bar"),
        ("foo>bar", "foo\\>bar"),
        ("foo;bar", "foo\\;bar"),
        (" foo bar", "\\ foo bar"),
        ("#foo bar", "\\#foo bar"),
        ("# foo bar", "\\# foo bar"),
        ("foo bar ", "foo bar\\ "),
        ("foo bar  ", "foo bar \\ "),
        ("foo bar #", "foo bar #"),
        ("foo\00bar", "foo\\00bar"),
        ("foo\nbar", "foo\\0Abar"),
        ("foo\rbar", "foo\\0Dbar"),
        ("foo=bar", "foo\\3Dbar"),
        ("foo/bar", "foo\\2Fbar"),
    ],
)
def test_dn_escape(value: str, expected: str) -> None:
    actual = dn_escape(value)
    assert actual == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        (
            "",
            [],
        ),
        (
            "CN=foo",
            [["CN", "foo"]],
        ),
        (
            r"CN=foo,DC=bar",
            [["CN", "foo"], ["DC", "bar"]],
        ),
        (
            r"CN=foo, DC=bar",
            [["CN", "foo"], ["DC", "bar"]],
        ),
        (
            r"CN=foo , DC=bar",
            [["CN", "foo"], ["DC", "bar"]],
        ),
        (
            r"CN=foo  ,  DC=bar",
            [["CN", "foo"], ["DC", "bar"]],
        ),
        (
            r"UID=jsmith,DC=example,DC=net",
            [["UID", "jsmith"], ["DC", "example"], ["DC", "net"]],
        ),
        (
            r"OU=Sales+CN=J.  Smith,DC=example,DC=net",
            [["OU", "Sales", "CN", "J.  Smith"], ["DC", "example"], ["DC", "net"]],
        ),
        (
            r"OU=Sales + CN=J.  Smith,DC=example,DC=net",
            [["OU", "Sales", "CN", "J.  Smith"], ["DC", "example"], ["DC", "net"]],
        ),
        (
            r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
            [["CN", 'James "Jim" Smith, III'], ["DC", "example"], ["DC", "net"]],
        ),
        (
            r"CN=Before\0dAfter,DC=example,DC=net",
            [["CN", "Before\rAfter"], ["DC", "example"], ["DC", "net"]],
        ),
        (
            r"1.3.6.1.4.1.1466.0=#FE04024869",
            [["1.3.6.1.4.1.1466.0", "\udcfe\x04\x02Hi"]],
        ),
        (
            r"1.3.6.1.4.1.1466.0 = #FE04024869",
            [["1.3.6.1.4.1.1466.0", "\udcfe\x04\x02Hi"]],
        ),
        (
            r"CN=Lu\C4\8Di\C4\87",
            [["CN", "Lučić"]],
        ),
    ],
)
def test_parse_dn(value: str, expected: t.List[str]) -> None:
    actual = parse_dn(value)

    assert actual == expected


def test_parse_dn_invalid_attribute_type() -> None:
    expected = "Expecting attribute type in RDN entry from 'foo_invalid=test'"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn("foo_invalid=test")


def test_parse_dn_no_attribute_value() -> None:
    expected = "Expecting attribute value in RDN entry from ''"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn("foo=")


def test_parse_dn_no_value_after_ava_delimiter() -> None:
    expected = "Expecting attribute type in RDN entry from ''"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn("foo=bar+")


def test_parse_dn_unescaped_hash() -> None:
    expected = "Found leading # for attribute value but does not match hexstring format at '#bar'"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn("foo=#bar")


@pytest.mark.parametrize("c", ["\00", '"', ";", "<", ">"])
def test_parse_dn_unescaped_special_char(c: str) -> None:
    expected = f"Found unescaped character '{c}' in attribute value at '{c}value'"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn(f"foo=test{c}value")


def test_parse_dn_invalid_attr_value_escape() -> None:
    expected = r"Found invalid escape sequence in attribute value at '\\1z"
    with pytest.raises(AnsibleFilterError, match=expected):
        parse_dn("foo=bar \\1z")


@pytest.mark.parametrize(
    "value, expected",
    [
        ("", ""),
        ("CN=foo", "CN=foo"),
        (r"CN=foo,DC=bar", "CN=foo"),
        (r"CN=foo, DC=bar", "CN=foo"),
        (r"CN=foo , DC=bar", "CN=foo"),
        (r"CN=foo  ,  DC=bar", "CN=foo"),
        (r"UID=jsmith,DC=example,DC=net", "UID=jsmith"),
        (r"OU=Sales+CN=J.  Smith,DC=example,DC=net", "OU=Sales+CN=J.  Smith"),
        (r"OU=Sales + CN=J.  Smith,DC=example,DC=net", "OU=Sales+CN=J.  Smith"),
        (
            r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
            r"CN=James \"Jim\" Smith\, III",
        ),
        (r"CN=Before\0dAfter,DC=example,DC=net", r"CN=Before\0DAfter"),
        (r"1.3.6.1.4.1.1466.0=#FE04024869", "1.3.6.1.4.1.1466.0=\udcfe\x04\x02Hi"),
        (r"1.3.6.1.4.1.1466.0 = #FE04024869", "1.3.6.1.4.1.1466.0=\udcfe\x04\x02Hi"),
        (r"CN=Lu\C4\8Di\C4\87", "CN=Lučić"),
    ],
)
def test_split_dn_leaf(value: str, expected: str) -> None:
    actual = split_dn(value)
    assert actual == expected


@pytest.mark.parametrize(
    "value, expected",
    [
        ("", ""),
        ("CN=foo", ""),
        (r"CN=foo,DC=bar", "DC=bar"),
        (r"CN=foo, DC=bar", "DC=bar"),
        (r"CN=foo , DC=bar", "DC=bar"),
        (r"CN=foo  ,  DC=bar", "DC=bar"),
        (r"UID=jsmith,DC=example,DC=net", "DC=example,DC=net"),
        (r"OU=Sales+CN=J.  Smith,DC=example,DC=net", "DC=example,DC=net"),
        (r"OU=Sales + CN=J.  Smith,DC=example,DC=net", "DC=example,DC=net"),
        (
            r"CN=James \"Jim\" Smith\, III,DC=example,DC=net",
            r"DC=example,DC=net",
        ),
        (r"CN=Before\0dAfter,DC=example,DC=net", r"DC=example,DC=net"),
        (r"1.3.6.1.4.1.1466.0=#FE04024869", ""),
        (r"1.3.6.1.4.1.1466.0 = #FE04024869", ""),
        (r"CN=Lu\C4\8Di\C4\87", ""),
        (
            r"CN=foo,DC=bar+C=US\, test+OU=Fake\+Test,DC=end",
            r"DC=bar+C=US\, test+OU=Fake\+Test,DC=end",
        ),
    ],
)
def test_split_dn_parent(value: str, expected: str) -> None:
    actual = split_dn(value, "parent")
    assert actual == expected
