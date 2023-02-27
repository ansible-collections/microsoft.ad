# Copyright (c) 2023 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

import base64
import typing as t
import uuid

import pytest

from ansible.errors import AnsibleFilterError
from ansible_collections.microsoft.ad.plugins.filter.ldap_converters import as_sid, as_guid, as_datetime


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
    assert actual == ["2023-02-27T20:16:15.000000+0000", "2023-02-27T20:16:15.100002+0000"]


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
    with pytest.raises(AnsibleFilterError, match="Raw SID bytes must be at least 8 bytes long"):
        as_sid(b"\x00\x00\x00\x00")


def test_as_sid_too_little_data_sub_authorities() -> None:
    with pytest.raises(AnsibleFilterError, match="Not enough data to unpack SID"):
        as_sid(b"\x01\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
