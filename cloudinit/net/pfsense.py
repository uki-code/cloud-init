# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging
import re
import ipaddress
import shlex

import cloudinit.net.bsd
from cloudinit import util, subp
from cloudinit.distros import pfsense_utils as pf_utils

LOG = logging.getLogger(__name__)

class Renderer(cloudinit.net.bsd.BSDRenderer):

    static_routes_node = "/pfsense/staticroutes/route"
    gateways_node = "/pfsense/gateways/gateway_item"
    interfaces_node = "/pfsense/interfaces"
    earlyshellcmd_node = "/pfsense/system/earlyshellcmd"
    upstream_dns_node = "/pfsense/system/dnsserver"

    def __init__(self, config=None):
        super(Renderer, self).__init__()
        self.interface_routes = []

    def _string_escape(self, string):
        return re.sub('[^a-zA-Z0-9_]+', '_', string).upper()

    def _get_config_ifaces(self):
        # pfSense stores interfaces within a top-level <interfaces> element
        # with each interface as a child element with the interface name as # the element tag.
        # This function returns a list of all interface elements.
        c_ifaces = pf_utils.get_config_elements(Renderer.interfaces_node)
        return [c_ifaces[0][c_iface] for c_iface in c_ifaces[0]]

    def _resolve_conf(self, settings):
        # Get current upstream DNS servers
        # NOTE: pfSense default configuration uses the local resolver
        # before attempting remote DNS servers
        upstream_dns = pf_utils.get_config_values(Renderer.upstream_dns_node)

        # Discover nameservers from interface configuration
        nameservers = settings.dns_nameservers
        for iface in settings.iter_interfaces():
            for subnet in iface.get("subnets", []):
                nameservers.extend(subnet.get("dns_nameservers", []))

        # Add nameservers to config if not already present
        for ns in nameservers:
            if ns not in upstream_dns:
                pf_utils.append_config_element(Renderer.upstream_dns_node, ns)

        # Apply resolvconf
        pf_utils.sync_resolvconf()

    def _write_iface_config(self):
        # Remove existing interface configuration
        # Can't iterate through straight-up interfaces list
        # because <if> name might not necessarily match the node name
        pf_utils.remove_config_element(Renderer.interfaces_node, None, None)
        pf_utils.append_config_element(Renderer.interfaces_node, "")

        # Generate list of devices
        devices = (self.interface_configurations.keys() | self.interface_configurations_ipv6.keys()) or []

        for device_name in devices:
            # Set basic interface properties
            # NOTE: <if> is the key value in the xml structure
            # MUST match the hardware interface name
            # The parent XML tag is set to this value for consistency
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
                        iface["subnet"] = str(ipaddress.IPv4Network(f"0.0.0.0/{v.get('netmask')}").prefixlen)

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
                        iface["subnetv6"] = str(ipaddress.IPv6Network(f"::/{v.get('prefix')}").prefixlen)

                    # ipv6 MTU takes precedence over ipv4
                    # - relaistically, only should be on one or the other
                    # - but if both, we'll use the ipv6 mtu
                    if v.get("mtu"):
                        iface["mtu"] = v.get("mtu")

                elif isinstance(v, str):
                    if v == "DHCP":
                        iface["ipaddrv6"] = "dhcp6"

            # Add the interface to the config
            pf_utils.append_config_element(Renderer.interfaces_node + f"/{device_name}", iface)

    def _create_gateway(self, gateway):

        # Check if gateway already exists
        gateways = pf_utils.get_config_elements(Renderer.gateways_node)
        for g in gateways:
            if g["gateway"] == gateway:
                return g["name"]

        # Find interface for gateway
        c_ifaces = self._get_config_ifaces()
        gw_iface_name = None
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

            if iface_ip is None or iface_mask is None or iface_ip in ["dhcp", "dhcp6"]:
                continue

            if ipaddress.ip_address(gateway) in ipaddress.ip_network(f"{iface_ip}/{iface_mask}", strict=False):
                gw_iface_name = c_iface["if"]
                break
            else:
                continue
        if gw_iface_name is None:
            LOG.warning("No interface found for gateway %s", gateway)
            return False

        # Create new gateway
        gateway = {
            "name": "GW_" + self._string_escape(gateway),
            "gateway": gateway,
            "interface": gw_iface_name,
            "weight": "1",
            "ipprotocol": ipprotocol,
            "descr": f"Gateway for {gateway} on {gw_iface_name}",
        }

        pf_utils.append_config_element(Renderer.gateways_node, gateway)
        return gateway["name"]

    def _write_route_config(self):
        for network, netmask, gateway in self.interface_routes:
            # Check if route exists
            routes = pf_utils.get_config_elements(Renderer.static_routes_node)
            route_exists = False
            for r in routes:
                if r["network"] == f"{network}/{netmask}":
                    route_exists = True
                    break

            # Skip itteration if route exists
            if route_exists:
                LOG.info("Route %s already exists - skipping", f"{network}/{netmask}")
                continue

            # Create gateway if it doesn't exist
            # - If exists, returns gateway name
            gw_name = self._create_gateway(gateway)
            if not gw_name:
                LOG.warning("Failed to create static route %s via %s", f"{network}/{netmask}", gateway)
                continue

            # Create new route
            route = {
                "network": f"{network}/{netmask}",
                "gateway": gw_name,
                "descr": f"Route to {network}/{netmask} via {gateway}",
            }

            # Write the route to the config
            pf_utils.append_config_element(Renderer.static_routes_node, route)

    def set_route(self, network, netmask, gateway):
        # Deferr adding routes until we write the config
        # - We need the name of a gateway (or create if note exist)
        #   prior to creating the route entry

        # Reformat the netmask for pfSense
        if ipaddress.ip_address(network).version == 4:
            netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen)
        else:
            netmask = str(ipaddress.IPv6Network(f"::/{netmask}").prefixlen)

        self.interface_routes.append((network, netmask, gateway))

    def rename_interface(self, cur_name, device_name):

        # Generate interface rename commnad
        rename_cmd = f"ifconfig {cur_name} name {device_name}"

        # Perform rename to allow immediate effect
        subp.subp(shlex.split(rename_cmd), capture=True, rcs=[0])

        # Check if rename command already exists in  an <earlyshellcmd>
        earlyshellcmds = pf_utils.get_config_values(Renderer.earlyshellcmd_node)
        for cmd in earlyshellcmds:
            if cmd == rename_cmd:
                return

        # Add rename command to earlyshellcmds
        pf_utils.append_config_element(Renderer.earlyshellcmd_node, rename_cmd)

    def dhcp_interfaces(self):
        raise NotImplementedError()

    def start_services(self, run=False):
        if not run:
            LOG.debug("pfsense generate postcmd disabled")
            return

        # Reload pfSense config
        pf_utils.reload_config()

    def write_config(self):
        self._write_iface_config()
        self._write_route_config()

def available(target=None):
    return util.is_PFSense()