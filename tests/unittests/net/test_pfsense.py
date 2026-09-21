# This file is part of cloud-init. See LICENSE file for license information.

"""
End-to-end tests for the pfSense network renderer's reconciliation
behaviour: merging cloud-init's desired interfaces into a persistent,
learner-mutable config.xml across boot-to-boot transitions, rather than
wiping and rebuilding <interfaces> from scratch every render.
"""

from unittest import mock

from cloudinit.distros import pfsense_utils as pf_utils
from cloudinit.net import network_state, pfsense, pfsense_state

BASE_CONFIG = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pfsense</hostname>
    <earlyshellcmd></earlyshellcmd>
  </system>
  <interfaces></interfaces>
  <gateways></gateways>
  <staticroutes></staticroutes>
</pfsense>
"""

WAN = ("eth-wan", "52:54:00:00:00:01", "203.0.113.10/24", None)
LAN = ("eth-lan", "52:54:00:00:00:02", "192.168.1.1/24", None)
OPT1 = ("eth-opt1", "52:54:00:00:00:03", "10.0.0.1/24", "10.0.0.254")
OPT2 = ("eth-opt2", "52:54:00:00:00:04", "10.0.1.1/24", None)

# A real pfSense image never ships with an empty <interfaces/> the way
# BASE_CONFIG above does -- the installer wizard always assigns at least
# wan/lan to something before first boot. Used for the bootstrap test
# below, where cloud-init's net_config targets those same factory-assigned
# devices by MAC on its first-ever render (no prior tracked state).
FACTORY_CONFIG = """<?xml version="1.0"?>
<pfsense>
  <system>
    <hostname>pfsense</hostname>
    <earlyshellcmd></earlyshellcmd>
  </system>
  <interfaces>
    <wan><if>vtnet0</if><descr>WAN</descr></wan>
    <lan><if>vtnet1</if><descr>LAN</descr></lan>
  </interfaces>
  <gateways></gateways>
  <staticroutes></staticroutes>
</pfsense>
"""

VTNET0 = ("vtnet0", "52:54:00:00:00:01", "203.0.113.10/24", None)
VTNET1 = ("vtnet1", "52:54:00:00:00:02", "192.168.1.1/24", None)


def _v2_config(entries):
    ethernets = {}
    for config_id, mac, address, gateway4 in entries:
        cfg = {
            "match": {"macaddress": mac},
            "set-name": config_id,
            "addresses": [address],
        }
        if gateway4:
            cfg["gateway4"] = gateway4
        ethernets[config_id] = cfg
    return {"version": 2, "ethernets": ethernets}


def _mac_map(entries):
    return {mac: config_id for config_id, mac, _, _ in entries}


def _render(config_path, entries):
    mac_map = _mac_map(entries)
    net_config = _v2_config(entries)

    with mock.patch(
        "cloudinit.net.network_state.get_interfaces_by_mac",
        return_value=mac_map,
    ):
        ns = network_state.parse_net_config_data(net_config)

    renderer = pfsense.Renderer(
        config={"config_path": str(config_path), "postcmds": False}
    )
    with mock.patch(
        "cloudinit.net.get_interfaces_by_mac", return_value=mac_map
    ), mock.patch("cloudinit.net.pfsense.subp.subp"), mock.patch(
        "cloudinit.distros.pfsense_utils.subp.subp"
    ):
        renderer.render_network_state(ns)
    return renderer


def _ifaces(config_path):
    elems = pf_utils.get_config_elements(
        "/pfsense/interfaces", fp=str(config_path)
    )
    return elems[0] if elems else {}


def _state(config_path):
    return pfsense_state.load_state(fp=str(config_path))


def _rec_for(config_path, config_id):
    for rec in _state(config_path)["interfaces"].values():
        if rec.get("devname") == config_id:
            return rec
    return None


class TestPfsenseInterfaceReconciliation:
    def test_first_boot_positional_assignment(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)

        _render(config_path, [WAN, LAN, OPT1])

        ifaces = _ifaces(config_path)
        assert ifaces["wan"]["if"] == "eth-wan"
        assert ifaces["wan"]["ipaddr"] == "203.0.113.10"
        assert ifaces["lan"]["if"] == "eth-lan"
        assert ifaces["opt1"]["if"] == "eth-opt1"

        state = _state(config_path)
        assert state["next_opt_index"] == 2
        assert _rec_for(config_path, "eth-wan")["friendly"] == "wan"
        assert _rec_for(config_path, "eth-opt1")["friendly"] == "opt1"

    def test_idempotent_rerender(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)

        _render(config_path, [WAN, LAN, OPT1])
        first_pass = config_path.read_text()

        _render(config_path, [WAN, LAN, OPT1])
        second_pass = config_path.read_text()

        assert first_pass == second_pass

    def test_shrink_cascades_removed_interface_and_its_gateway(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)

        _render(config_path, [WAN, LAN, OPT1])
        assert "opt1" in _ifaces(config_path)
        assert pf_utils.get_config_elements(
            '/pfsense/gateways/gateway_item[interface="opt1"]',
            fp=str(config_path),
        )

        # opt1's NIC disappears from the hypervisor/operator's netconfig
        _render(config_path, [WAN, LAN])

        ifaces = _ifaces(config_path)
        assert "opt1" not in ifaces
        assert "wan" in ifaces and "lan" in ifaces
        assert not pf_utils.get_config_elements(
            '/pfsense/gateways/gateway_item[interface="opt1"]',
            fp=str(config_path),
        )
        assert not pf_utils.get_config_elements(
            "/pfsense/staticroutes/route", fp=str(config_path)
        )
        assert _rec_for(config_path, "eth-opt1") is None

    def test_regrow_never_reuses_a_freed_slug(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)

        _render(config_path, [WAN, LAN, OPT1])
        _render(config_path, [WAN, LAN])  # opt1 freed via cascade

        _render(config_path, [WAN, LAN, OPT2])  # a different, new NIC

        ifaces = _ifaces(config_path)
        assert "opt1" not in ifaces
        assert ifaces["opt2"]["if"] == "eth-opt2"

    def test_learner_added_interface_is_never_touched(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        pf_utils.append_config_element(
            "/pfsense/interfaces/opt3",
            {"if": "em5", "descr": "LEARNER_MADE_THIS"},
            fp=str(config_path),
        )

        _render(config_path, [WAN, LAN])

        ifaces = _ifaces(config_path)
        assert ifaces["opt3"] == {"if": "em5", "descr": "LEARNER_MADE_THIS"}
        assert _rec_for(config_path, "em5") is None

    def test_lagg_enslavement_then_reclaim(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN, OPT1])

        # learner unassigns opt1, then builds a LAGG using its device
        pf_utils.remove_config_element(
            "/pfsense/interfaces/opt1", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs", "", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs/lagg",
            {"laggif": "lagg0", "members": "eth-opt1,em9"},
            fp=str(config_path),
        )

        # operator's netconfig is unchanged -- still describes eth-opt1
        _render(config_path, [WAN, LAN, OPT1])

        assert "opt1" not in _ifaces(config_path)
        rec = _rec_for(config_path, "eth-opt1")
        assert rec["owned"] is False
        assert rec["friendly"] == "opt1"

        # learner tears the LAGG down
        pf_utils.remove_config_element(
            "/pfsense/laggs/lagg", fp=str(config_path)
        )

        _render(config_path, [WAN, LAN, OPT1])

        ifaces = _ifaces(config_path)
        assert ifaces["opt1"]["if"] == "eth-opt1"
        rec = _rec_for(config_path, "eth-opt1")
        assert rec["owned"] is True
        assert rec["friendly"] == "opt1"

    def test_plain_field_edit_is_reasserted_not_preserved(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN])

        pf_utils.set_config_value(
            "/pfsense/interfaces/wan/ipaddr", "9.9.9.9", fp=str(config_path)
        )

        _render(config_path, [WAN, LAN])

        assert _ifaces(config_path)["wan"]["ipaddr"] == "203.0.113.10"

    def test_reclaim_self_heals_on_slug_collision(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN, OPT1])

        pf_utils.remove_config_element(
            "/pfsense/interfaces/opt1", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs", "", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs/lagg",
            {"laggif": "lagg0", "members": "eth-opt1"},
            fp=str(config_path),
        )
        _render(config_path, [WAN, LAN, OPT1])  # owned flips False

        # something else claims "opt1" while it's vacant (e.g. pfSense's
        # own webUI gap-fill assigning an unrelated NIC)
        pf_utils.append_config_element(
            "/pfsense/interfaces/opt1",
            {"if": "em9", "descr": "SOMEONE_ELSES_NIC"},
            fp=str(config_path),
        )

        # learner tears the LAGG down -- reclaim should not clobber em9
        pf_utils.remove_config_element(
            "/pfsense/laggs/lagg", fp=str(config_path)
        )
        _render(config_path, [WAN, LAN, OPT1])

        ifaces = _ifaces(config_path)
        assert ifaces["opt1"]["if"] == "em9"
        reclaimed_slugs = [
            slug
            for slug, iface in ifaces.items()
            if isinstance(iface, dict) and iface.get("if") == "eth-opt1"
        ]
        assert len(reclaimed_slugs) == 1
        assert reclaimed_slugs[0] != "opt1"

    def test_wan_floor_violation_promotes_an_optional_interface(
        self, tmp_path
    ):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN, OPT1])

        # wan's NIC disappears entirely
        _render(config_path, [LAN, OPT1])

        ifaces = _ifaces(config_path)
        assert "opt1" not in ifaces
        assert ifaces["wan"]["if"] == "eth-opt1"
        assert ifaces["lan"]["if"] == "eth-lan"
        assert _rec_for(config_path, "eth-opt1")["friendly"] == "wan"

    def test_wan_floor_violation_refuses_when_no_candidate(self, tmp_path):
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN])

        # wan's NIC disappears, and there's no optional interface to
        # promote -- must refuse rather than leave the box with no wan
        _render(config_path, [LAN])

        ifaces = _ifaces(config_path)
        assert ifaces["wan"]["if"] == "eth-wan"  # untouched, not force-deleted
        rec = _rec_for(config_path, "eth-wan")
        assert rec is not None
        assert rec["owned"] is True
        assert rec["friendly"] == "wan"

    def test_wan_floor_violation_refuses_to_clobber_reclaimed_slug(
        self, tmp_path
    ):
        # Regression test: a removal deferred by LAGG-enslavement can open a
        # window where something else (pfSense's own webUI gap-fill, or a
        # learner directly) legitimately claims the now-vacant wan/lan slug
        # before cloud-init's next render. The floor-violation promotion
        # path used to clobber whatever it found there unconditionally --
        # it must instead recognize the slug no longer belongs to the
        # device it's removing, and leave the new occupant alone.
        config_path = tmp_path / "config.xml"
        config_path.write_text(BASE_CONFIG)
        _render(config_path, [WAN, LAN, OPT1])

        # learner enslaves wan's NIC into a LAGG
        pf_utils.remove_config_element(
            "/pfsense/interfaces/wan", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs", "", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/laggs/lagg",
            {"laggif": "lagg0", "members": "eth-wan"},
            fp=str(config_path),
        )

        # cloud-init is told to stop wanting eth-wan while it's enslaved --
        # hands-off, so nothing happens yet
        _render(config_path, [LAN, OPT1])
        assert "wan" not in _ifaces(config_path)

        # something else claims "wan" while it's vacant, with a NIC
        # unrelated to eth-wan
        pf_utils.remove_config_element(
            "/pfsense/laggs/lagg", fp=str(config_path)
        )
        pf_utils.append_config_element(
            "/pfsense/interfaces/wan",
            {"if": "em9", "descr": "SOMEONE_ELSES_WAN"},
            fp=str(config_path),
        )

        # cloud-init still doesn't want eth-wan -- must not clobber em9
        _render(config_path, [LAN, OPT1])

        ifaces = _ifaces(config_path)
        assert ifaces["wan"] == {"if": "em9", "descr": "SOMEONE_ELSES_WAN"}
        assert ifaces["opt1"]["if"] == "eth-opt1"  # never promoted away
        assert _rec_for(config_path, "eth-wan") is None

    def test_bootstrap_takes_over_factory_assigned_wan_lan(self, tmp_path):
        # Regression test: a real pfSense image never ships with an empty
        # <interfaces/> -- the installer always assigns wan/lan to
        # something first. Cloud-init's first-ever render (no prior
        # tracked state) must recognize that its desired devices already
        # sit at "wan"/"lan" and take over those slugs in place, not mint
        # fresh opt slots and leave the same device assigned under two
        # slugs at once.
        config_path = tmp_path / "config.xml"
        config_path.write_text(FACTORY_CONFIG)

        _render(config_path, [VTNET0, VTNET1])

        ifaces = _ifaces(config_path)
        assert ifaces["wan"]["if"] == "vtnet0"
        assert ifaces["wan"]["ipaddr"] == "203.0.113.10"
        assert ifaces["lan"]["if"] == "vtnet1"
        assert ifaces["lan"]["ipaddr"] == "192.168.1.1"
        # No duplicate opt slot for either device.
        assert "opt1" not in ifaces
        assert "opt2" not in ifaces

        assert _rec_for(config_path, "vtnet0")["friendly"] == "wan"
        assert _rec_for(config_path, "vtnet1")["friendly"] == "lan"

    def test_bootstrap_takes_over_factory_slug_across_a_rename(
        self, tmp_path
    ):
        # Regression test: when a device's set-name differs from its
        # current kernel name, bsd.py's _ifconfig_entries() renames it
        # live -- e.g. `ifconfig vtnet0 name control-net` -- *before*
        # config.xml is ever read this render. The bootstrap "take over
        # an existing slug" fix must still recognize the device by its
        # pre-rename name (config.xml hasn't caught up yet), not just its
        # new name, or "wan" is left referencing a devname ("vtnet0")
        # that no longer exists the moment the rename takes effect, while
        # the renamed device gets wrongly duplicated under a fresh opt
        # slot instead of taking over "wan" in place.
        #
        # Deliberately doesn't use the shared _render() helper above --
        # its _mac_map()/_v2_config() both derive the mocked "current
        # kernel name" and the net_config's set-name from the same
        # string, so cur_name == device_name always and the rename
        # branch in _ifconfig_entries() is never actually exercised.
        config_path = tmp_path / "config.xml"
        config_path.write_text(FACTORY_CONFIG)  # wan=vtnet0, lan=vtnet1

        mac_map = {
            "52:54:00:00:00:01": "vtnet0",  # current kernel name
            "52:54:00:00:00:02": "vtnet1",
        }
        net_config = {
            "version": 2,
            "ethernets": {
                "control-net": {
                    "match": {"macaddress": "52:54:00:00:00:01"},
                    "set-name": "control-net",  # differs from "vtnet0"
                    "addresses": ["10.10.0.101/24"],
                },
                "lan-net": {
                    "match": {"macaddress": "52:54:00:00:00:02"},
                    "set-name": "lan-net",  # differs from "vtnet1"
                    "addresses": ["192.168.1.1/24"],
                },
            },
        }

        with mock.patch(
            "cloudinit.net.network_state.get_interfaces_by_mac",
            return_value=mac_map,
        ):
            ns = network_state.parse_net_config_data(net_config)

        renderer = pfsense.Renderer(
            config={"config_path": str(config_path), "postcmds": False}
        )
        with mock.patch(
            "cloudinit.net.get_interfaces_by_mac", return_value=mac_map
        ), mock.patch("cloudinit.net.pfsense.subp.subp"), mock.patch(
            "cloudinit.distros.pfsense_utils.subp.subp"
        ):
            renderer.render_network_state(ns)

        ifaces = _ifaces(config_path)
        assert ifaces["wan"]["if"] == "control-net"
        assert ifaces["wan"]["ipaddr"] == "10.10.0.101"
        assert ifaces["lan"]["if"] == "lan-net"
        assert ifaces["lan"]["ipaddr"] == "192.168.1.1"
        # No duplicate opt slot for either renamed device.
        assert "opt1" not in ifaces
        assert "opt2" not in ifaces
