# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import functools
import ipaddress
import logging
import re
import shlex

import cloudinit.net.bsd
from cloudinit import subp, util
from cloudinit.distros import pfsense_utils as pf_utils
from cloudinit.net import pfsense_cascade, pfsense_state

LOG = logging.getLogger(__name__)


class Renderer(cloudinit.net.bsd.BSDRenderer):

    static_routes_node = "/pfsense/staticroutes/route"
    gateways_node = "/pfsense/gateways/gateway_item"
    interfaces_node = "/pfsense/interfaces"
    earlyshellcmd_node = "/pfsense/system/earlyshellcmd"
    upstream_dns_node = "/pfsense/system/dnsserver"

    def __init__(self, config=None):
        config = config or {}
        super(Renderer, self).__init__(config)
        # NOTE: deliberately not named `interface_routes` -- BSDRenderer
        # declares that class attribute as a str (`""`), and openbsd.py
        # relies on that string type (it concatenates rendered config
        # text onto it). This is a different, list-of-tuples bookkeeping
        # structure private to this renderer's own route handling.
        self.pending_static_routes = []
        self.config_path = config.get("config_path", "/cf/conf/config.xml")

    def _string_escape(self, string):
        return re.sub("[^a-zA-Z0-9_]+", "_", string).upper()

    def _get_config_ifaces(self):
        # pfSense stores interfaces within a top-level <interfaces> element
        # with each interface as a child element, keyed by its assigned
        # slug (wan, lan, opt1, opt2, ...) as the element tag.
        # This function returns a list of all interface elements, with the
        # slug stashed under "_slug" since it isn't otherwise recoverable
        # once the elements are flattened to dicts.
        c_ifaces = pf_utils.get_config_elements(
            Renderer.interfaces_node, fp=self.config_path
        )
        # An <interfaces/> element with no children at all flattens to
        # None (not {}) via _element_to_dict, not just an empty list.
        if not c_ifaces or not isinstance(c_ifaces[0], dict):
            return []
        ifaces = []
        for slug in c_ifaces[0]:
            iface = c_ifaces[0][slug]
            if not isinstance(iface, dict):
                continue
            iface["_slug"] = slug
            ifaces.append(iface)
        return ifaces

    def _build_iface_fields(self, device_name):
        # Build the fields cloud-init owns on an <interfaces>/<slug>
        # element for the given device. NOTE: <if> is the key value in
        # the xml structure and MUST match the hardware interface name.
        iface = {}
        iface["if"] = device_name
        iface["descr"] = self._string_escape(device_name)
        iface["enable"] = ""

        # Check if we have ipv4 configuration for this interface
        if device_name in self.interface_configurations:
            v = self.interface_configurations[device_name]

            if isinstance(v, dict):
                if v.get("address"):
                    iface["ipaddr"] = v.get("address")

                if v.get("netmask"):
                    iface["subnet"] = str(
                        ipaddress.IPv4Network(
                            f"0.0.0.0/{v.get('netmask')}"
                        ).prefixlen
                    )

                if v.get("mtu"):
                    iface["mtu"] = v.get("mtu")
            elif isinstance(v, str):
                if v == "DHCP":
                    iface["ipaddr"] = "dhcp"

        # Check if we have ipv6 configuration for this interface
        if device_name in self.interface_configurations_ipv6:
            v = self.interface_configurations_ipv6[device_name]

            if isinstance(v, dict):

                if v.get("address"):
                    iface["ipaddrv6"] = v.get("address")

                if v.get("prefix"):
                    iface["subnetv6"] = str(
                        ipaddress.IPv6Network(
                            f"::/{v.get('prefix')}"
                        ).prefixlen
                    )

                # ipv6 MTU takes precedence over ipv4
                # - relaistically, only should be on one or the other
                # - but if both, we'll use the ipv6 mtu
                if v.get("mtu"):
                    iface["mtu"] = v.get("mtu")

            elif isinstance(v, str):
                if v == "DHCP":
                    iface["ipaddrv6"] = "dhcp6"

        return iface

    def _build_desired_ifaces(self):
        # Generate list of devices, preserving assignment order
        # NOTE: set union (`|`) does not preserve order, so dedupe with
        # dict.fromkeys() instead - slug assignment depends on devices
        # being in a deterministic order
        devices = list(
            dict.fromkeys(
                list(self.interface_configurations.keys())
                + list(self.interface_configurations_ipv6.keys())
            )
        )

        desired = {}
        for device_name in devices:
            identity = self.interface_identities.get(device_name, {})
            logical_id = pfsense_state.compute_logical_id(
                identity.get("mac_address"),
                identity.get("config_id"),
                device_name,
            )
            fields = self._build_iface_fields(device_name)
            fields["mac"] = identity.get("mac_address")
            fields["config_id"] = identity.get("config_id")
            # Bookkeeping only -- not in OWNED_FIELDS, so owned_fields_from()
            # never writes this to config.xml. Lets reconcile() recognize a
            # device config.xml already has a slug for under its pre-rename
            # name (e.g. pfSense's own factory wan/lan assignment) even
            # though this render already renamed it before config.xml was
            # ever read.
            fields["prior_devname"] = identity.get("prior_devname")
            desired[logical_id] = fields
        return desired

    def _write_iface_config(self):
        desired = self._build_desired_ifaces()
        live_by_slug = {c["_slug"]: c for c in self._get_config_ifaces()}
        state = pfsense_state.load_state(fp=self.config_path)
        is_claimed = functools.partial(
            pfsense_cascade.is_claimed_by_other_construct, fp=self.config_path
        )

        result = pfsense_state.reconcile(
            state, live_by_slug, desired, set(live_by_slug), is_claimed
        )

        if result.writes and not pf_utils.get_config_elements(
            Renderer.interfaces_node, fp=self.config_path
        ):
            # Base image is assumed to always ship an <interfaces/>
            # container, but don't crash if it's ever missing.
            pf_utils.append_config_element(
                Renderer.interfaces_node, "", fp=self.config_path
            )

        for write in result.writes:
            path = Renderer.interfaces_node + f"/{write['slug']}"
            # Remove-then-append is safe whether or not the slug already
            # exists: removing zero matches is a harmless no-op.
            pf_utils.remove_config_element(path, fp=self.config_path)
            pf_utils.append_config_element(
                path, write["element"], fp=self.config_path
            )

        for removal in result.pending_removals:
            pfsense_cascade.remove_interface_cascade(
                result.new_state,
                removal,
                result.floor_violations,
                fp=self.config_path,
            )

        pfsense_state.save_state(result.new_state, fp=self.config_path)

    def _resolve_conf(self, settings):
        # Get current upstream DNS servers
        # NOTE: pfSense default configuration uses the local resolver
        # before attempting remote DNS servers
        upstream_dns = pf_utils.get_config_values(
            Renderer.upstream_dns_node, fp=self.config_path
        )

        # Discover nameservers from interface configuration
        nameservers = settings.dns_nameservers
        for iface in settings.iter_interfaces():
            for subnet in iface.get("subnets", []):
                nameservers.extend(subnet.get("dns_nameservers", []))

        # Add nameservers to config if not already present
        for ns in nameservers:
            if ns not in upstream_dns:
                pf_utils.append_config_element(
                    Renderer.upstream_dns_node, ns, fp=self.config_path
                )

        # Apply resolvconf
        pf_utils.sync_resolvconf()

    def _create_gateway(self, gateway):

        # Check if gateway already exists
        gateways = pf_utils.get_config_elements(
            Renderer.gateways_node, fp=self.config_path
        )
        for g in gateways:
            if g["gateway"] == gateway:
                return g["name"]

        # Find interface for gateway
        c_ifaces = self._get_config_ifaces()
        gw_iface_slug = None
        ipprotocol = None
        for c_iface in c_ifaces:
            iface_ip = None
            iface_mask = None
            if c_iface.get("ipaddr"):
                iface_ip = c_iface.get("ipaddr")
                iface_mask = c_iface.get("subnet")
                ipprotocol = "inet"
            elif c_iface.get("ipaddrv6"):
                iface_ip = c_iface.get("ipaddrv6")
                iface_mask = c_iface.get("subnetv6")
                ipprotocol = "inet6"

            if (
                iface_ip is None
                or iface_mask is None
                or iface_ip in ["dhcp", "dhcp6"]
            ):
                continue

            if ipaddress.ip_address(gateway) in ipaddress.ip_network(
                f"{iface_ip}/{iface_mask}", strict=False
            ):
                # gateway_item/interface stores the assigned interface
                # slug (wan/lan/optN), not the physical device name
                gw_iface_slug = c_iface["_slug"]
                break
            else:
                continue
        if gw_iface_slug is None:
            LOG.warning("No interface found for gateway %s", gateway)
            return False

        # Create new gateway
        gateway = {
            "name": "GW_" + self._string_escape(gateway),
            "gateway": gateway,
            "interface": gw_iface_slug,
            "weight": "1",
            "ipprotocol": ipprotocol,
            "descr": f"Gateway for {gateway} on {gw_iface_slug}",
        }

        pf_utils.append_config_element(
            Renderer.gateways_node, gateway, fp=self.config_path
        )
        return gateway["name"]

    def _write_route_config(self):
        for network, netmask, gateway in self.pending_static_routes:
            # Check if route exists
            routes = pf_utils.get_config_elements(
                Renderer.static_routes_node, fp=self.config_path
            )
            route_exists = False
            for r in routes:
                if r["network"] == f"{network}/{netmask}":
                    route_exists = True
                    break

            # Skip itteration if route exists
            if route_exists:
                LOG.info(
                    "Route %s already exists - skipping",
                    f"{network}/{netmask}",
                )
                continue

            # Create gateway if it doesn't exist
            # - If exists, returns gateway name
            gw_name = self._create_gateway(gateway)
            if not gw_name:
                LOG.warning(
                    "Failed to create static route %s via %s",
                    f"{network}/{netmask}",
                    gateway,
                )
                continue

            # Create new route
            route = {
                "network": f"{network}/{netmask}",
                "gateway": gw_name,
                "descr": f"Route to {network}/{netmask} via {gateway}",
            }

            # Write the route to the config
            pf_utils.append_config_element(
                Renderer.static_routes_node, route, fp=self.config_path
            )

    def set_route(self, network, netmask, gateway):
        # Deferr adding routes until we write the config
        # - We need the name of a gateway (or create if note exist)
        #   prior to creating the route entry

        # Reformat the netmask for pfSense
        if ipaddress.ip_address(network).version == 4:
            netmask = str(
                ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
            )
        else:
            netmask = str(ipaddress.IPv6Network(f"::/{netmask}").prefixlen)

        self.pending_static_routes.append((network, netmask, gateway))

    def rename_interface(self, cur_name, device_name):

        # Generate interface rename commnad
        rename_cmd = f"ifconfig {cur_name} name {device_name}"

        # Perform rename to allow immediate effect
        subp.subp(shlex.split(rename_cmd), capture=True, rcs=[0])

        # Check if rename command already exists in  an <earlyshellcmd>
        earlyshellcmds = pf_utils.get_config_values(
            Renderer.earlyshellcmd_node, fp=self.config_path
        )
        for cmd in earlyshellcmds:
            if cmd == rename_cmd:
                return

        # Add rename command to earlyshellcmds
        pf_utils.append_config_element(
            Renderer.earlyshellcmd_node, rename_cmd, fp=self.config_path
        )

    def dhcp_interfaces(self):
        raise NotImplementedError()

    def start_services(self, run=False):
        if not run:
            LOG.debug("pfsense generate postcmd disabled")
            return

        # Reload pfSense config
        pf_utils.reload_config()

    def write_config(self, target=None):
        self._write_iface_config()
        self._write_route_config()


def available(target=None):
    return util.is_PFSense()
