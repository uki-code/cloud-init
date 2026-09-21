# This file is part of cloud-init. See LICENSE file for license information.

import pytest

from cloudinit.distros import pfsense_utils as pf_utils

BASE_CONFIG = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pfsense</hostname>
  </system>
  <interfaces>
    <wan>
      <if>vtnet0</if>
      <descr>WAN</descr>
    </wan>
    <lan>
      <if>vtnet1</if>
      <descr>LAN</descr>
    </lan>
  </interfaces>
  <gateways></gateways>
</pfsense>
"""


@pytest.fixture
def config_path(tmp_path):
    path = tmp_path / "config.xml"
    path.write_text(BASE_CONFIG)
    return str(path)


class TestGetConfigElements:
    def test_returns_list_of_dicts(self, config_path):
        ifaces = pf_utils.get_config_elements(
            "/pfsense/interfaces", fp=config_path
        )
        assert ifaces == [
            {
                "wan": {"if": "vtnet0", "descr": "WAN"},
                "lan": {"if": "vtnet1", "descr": "LAN"},
            }
        ]

    def test_missing_path_returns_empty_list(self, config_path):
        assert (
            pf_utils.get_config_elements("/pfsense/laggs/lagg", fp=config_path)
            == []
        )


class TestAppendConfigElement:
    def test_appends_new_child(self, config_path):
        pf_utils.append_config_element(
            "/pfsense/interfaces/opt1",
            {"if": "vtnet2", "descr": "OPT1"},
            fp=config_path,
        )
        ifaces = pf_utils.get_config_elements(
            "/pfsense/interfaces", fp=config_path
        )
        assert ifaces[0]["opt1"] == {"if": "vtnet2", "descr": "OPT1"}
        # existing siblings are untouched
        assert ifaces[0]["wan"] == {"if": "vtnet0", "descr": "WAN"}

    def test_raises_on_missing_parent(self, config_path):
        with pytest.raises(IndexError):
            pf_utils.append_config_element(
                "/pfsense/nosuchparent/child", "value", fp=config_path
            )


class TestRemoveConfigElement:
    def test_removes_all_matches_when_no_key(self, config_path):
        pf_utils.remove_config_element(
            "/pfsense/interfaces/wan", fp=config_path
        )
        ifaces = pf_utils.get_config_elements(
            "/pfsense/interfaces", fp=config_path
        )
        assert "wan" not in ifaces[0]
        assert "lan" in ifaces[0]

    def test_removes_only_matching_key_value(self, config_path):
        # regression test: remove_config_element's keyed-removal branch
        # used to index with the literal string "key" instead of the
        # `key` variable (and call dict-style __getitem__ on an
        # lxml.Element, which only supports int indices) -- this is dead
        # code today unless fixed, so this pins the fix down.
        pf_utils.remove_config_element(
            "/pfsense/interfaces/*", "if", "vtnet0", fp=config_path
        )
        ifaces = pf_utils.get_config_elements(
            "/pfsense/interfaces", fp=config_path
        )
        assert "wan" not in ifaces[0]
        assert ifaces[0]["lan"] == {"if": "vtnet1", "descr": "LAN"}

    def test_no_match_leaves_document_untouched(self, config_path):
        pf_utils.remove_config_element(
            "/pfsense/interfaces/*", "if", "doesnotexist", fp=config_path
        )
        ifaces = pf_utils.get_config_elements(
            "/pfsense/interfaces", fp=config_path
        )
        assert set(ifaces[0]) == {"wan", "lan"}


class TestGetSetConfigValue:
    def test_get_config_values(self, config_path):
        values = pf_utils.get_config_values(
            "/pfsense/interfaces/wan/if", fp=config_path
        )
        assert values == ["vtnet0"]

    def test_set_config_value_updates_existing_node(self, config_path):
        pf_utils.set_config_value(
            "/pfsense/interfaces/wan/if", "vtnet9", fp=config_path
        )
        assert pf_utils.get_config_values(
            "/pfsense/interfaces/wan/if", fp=config_path
        ) == ["vtnet9"]

    def test_set_config_value_creates_missing_node_under_existing_parent(
        self, config_path
    ):
        # regression test: set_config_value's create-branch used to call
        # the nonexistent ET.element(tag) instead of ET.Element(tag).
        pf_utils.set_config_value(
            "/pfsense/interfaces/wan/mtu", "9000", fp=config_path
        )
        assert pf_utils.get_config_values(
            "/pfsense/interfaces/wan/mtu", fp=config_path
        ) == ["9000"]

    def test_set_config_value_raises_on_missing_parent(self, config_path):
        # regression test: this used to raise IndexError from inside the
        # create-branch with no clear error, for a parent path that also
        # doesn't exist.
        with pytest.raises(ValueError):
            pf_utils.set_config_value(
                "/pfsense/nosuchparent/child", "value", fp=config_path
            )
