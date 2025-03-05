# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import logging
import os
import operator
import csv
import ipaddress

from cloudinit import subp, util, net
from cloudinit.net import renderer
from cloudinit.net.network_state import NetworkState

LOG = logging.getLogger(__name__)

class Renderer(renderer.Renderer):
    def __init__(self, config=None):
        if not config:
            config = {}
        self.config =config
        self.config_obj = {}
        self.props_path = config.get("rs_props_path", "data/persist.properties")
        self.routes_base_path = config.get("rs_routes_path", "data/route-")

    def _decomment(self, file):
        """Reads in a file, removing lines that start with an octothorpe"""
        for row in file:
            raw = row.split('#')[0].strip()
            if raw: yield raw

    def _read_properties(self, filename):
        """Reads a given properties file with each line of the format key=value.  Returns a dictionary containing the pairs."""
        with open(filename, "r") as config_file:
            reader = csv.reader(self._decomment(config_file), delimiter='=', escapechar='\\', quoting=csv.QUOTE_NONE)
            for row in reader:
                if len(row) != 2:
                    raise csv.Error("Too many fields on row with contents: "+str(row))
                self.config_obj[row[0]] = row[1]

    def _write_properties(self, filename):
        """Writes the provided dictionary in key-sorted order to a properties file with each line of the format key=value"""
        with open(filename, "w", encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile, delimiter='=', escapechar='\\', lineterminator='\n', quoting=csv.QUOTE_NONE)
            for key, value in sorted(self.config_obj.items(), key=operator.itemgetter(0)):
                    writer.writerow([ key, value])

    def _clear_properties(self, substrs):
        """ Given a list of substrings, clear config values with a corresponding key"""
        to_remove = []
        for obj in self.config_obj.keys():
            if any(substr in obj for substr in substrs):
                to_remove.append(obj)

        # Can't modify dict in middle of loop
        for obj in to_remove:
            del self.config_obj[obj]

    def _render_routes(self, settings, route_base):
        """Populate config object with route-related configuration values"""

        # Clear out any existing route options
        iface_configs = ["SRM_DEFAULT_GATEWAY", "SRM_DEFAULT_GATEWAY_IFACE"]
        self._clear_properties(iface_configs)

        routes = list(settings.iter_routes())

        # Parse out routes from config
        ifname_by_mac = net.get_interfaces_by_mac()
        for interface in settings.iter_interfaces():
            device_name = ifname_by_mac[interface.get("mac_address")]
            subnets = interface.get("subnets", [])

            # Clear any previous routes (/data/route-IFACE)
            iface_static_route_config = f"{route_base}{device_name}"
            if os.path.exists(iface_static_route_config):
                os.remove(iface_static_route_config)

            for subnet in subnets:
                # Support legacy "gateway" parameter
                if subnet.get("type") == "static":
                    gateway = subnet.get("gateway")
                    if gateway and len(gateway.split(".")) == 4:
                        routes.append(
                            {
                                "network": "0.0.0.0",
                                "netmask": "0.0.0.0",
                                "gateway": gateway,
                                "interface": device_name
                            }
                        )
                elif subnet.get("type") == "static6":
                    gateway = subnet.get("gateway")
                    if gateway and len(gateway.split(":")) > 1:
                        routes.append(
                            {
                                "network": "::",
                                "prefix": "0",
                                "gateway": gateway,
                                "interface": device_name
                            }
                        )
                else:
                    continue

                # Handle explicitly defined static routes
                for route in subnet.get("routes", []):
                    route_obj = {
                        "network": route["network"],
                        "prefix": route["prefix"],
                        "gateway": route["gateway"],
                        "interface": device_name
                    }
                    LOG.debug("Appending route to %s: %s", device_name, route_obj)
                    routes.append(route_obj)

        default_routes_set = 0

        for route in routes:
            network = route.get("network")
            gateway = route.get("gateway")
            device_name = route.get("interface")
            if not (network and gateway and device_name):
                LOG.debug("Skipping a bad route entry")
                continue

            # Handle default routes
            if network in ["0.0.0.0", "::"]:

                LOG.debug("Setting default gateway interface to %s", device_name)
                self.config_obj["SRM_DEFAULT_GATEWAY"] = gateway
                self.config_obj["SRM_DEFAULT_GATEWAY_IFACE"] = device_name
                default_routes_set += 1

                # TODO: Test and implement weighted default routes (if possible)
                if default_routes_set > 2:
                    raise NotImplementedError("Multiple default routes are not supported by RedSeal")

            # Handle static routes
            else:
                iface_static_route_config = f"{route_base}{device_name}"
                netmask = (
                    route.get("netmask")
                    if route.get("netmask")
                    else route.get("prefix")
                )
                static_route = f"{network}/{netmask} via {gateway} dev {device_name}"
                LOG.debug("Appending route to %s config: %s", device_name, static_route)

                # Append route to appropriate file
                with open(iface_static_route_config, "a", encoding="utf-8", newline='') as fp:
                    fp.write(static_route)

                # Call "ifup-route" to apply route
                LOG.debug("Applying route to %s", device_name)
                route_cmd = f"/etc/sysconfig/network-scripts/ifup-routes {device_name}"
                subp.subp(["bash", "-s", route_cmd])

    def _render_ifaces(self, settings):
        """Populate config object with iface-related configuration values"""

        # Clear out any existing config options
        iface_configs = ["ENABLE_INTERFACE_", "SRM_IPADDR_", "SRM_NETMASK_", "IFACE_ROLE_"]
        self._clear_properties(iface_configs)

        # Iterate through by MAC to ensure we have interface
        # name after any renaming has been done
        ifname_by_mac = net.get_interfaces_by_mac()
        for interface in settings.iter_interfaces():
            device_name = ifname_by_mac[interface.get("mac_address")]

            # TODO: Move this to a redseal-specific module
            # set interface as an admin and model interface to support SSH and WebGUI
            self.config_obj[f"IFACE_ROLE_{device_name}"] = "server-admin,model-admin"

            for subnet in interface.get("subnets", []):

                # Configure IPv4 IP settings
                if subnet.get("type") == "static":
                    if not subnet.get("netmask"):
                        LOG.debug(
                            "Skipping IP %s, because there is no netmask",
                            subnet.get("address"),
                        )
                        continue

                    # Convert from netmask to cidr
                    parsed_netmask = str(ipaddress.IPv4Network(f"0.0.0.0/{subnet.get('netmask')}").prefixlen)
                    LOG.debug(
                        "Configuring dev %s with %s / %s",
                        device_name,
                        subnet.get("address"),
                        parsed_netmask,
                    )
                    self.config_obj[f"ENABLE_INTERFACE_{device_name}"] = "true"
                    self.config_obj[f"SRM_IPADDR_{device_name}"] = subnet.get("address")
                    self.config_obj[f"SRM_NETMASK_{device_name}"] = parsed_netmask

                # Configure IPv6 IP settings
                elif subnet.get("type") == "static6":
                    if not subnet.get("prefix"):
                        LOG.debug(
                            "Skipping IP %s, because there is no prefix",
                            subnet.get("address"),
                        )
                        continue

                    # Convert from netmask to cidr
                    parsed_prefix = str(ipaddress.IPv6Network(f"::/{subnet.get('prefix')}").prefixlen)
                    LOG.debug(
                        "Configuring dev %s with %s / %s",
                        device_name,
                        subnet.get("address"),
                        parsed_prefix
                    )
                    self.config_obj[f"ENABLE_INTERFACE_{device_name}"] = "true"
                    self.config_obj[f"SRM_IPADDR_{device_name}"] = subnet.get("address")
                    self.config_obj[f"SRM_NETMASK_{device_name}"] = parsed_prefix

                # Configure interface for DHCP
                elif (
                    subnet.get("type") == "dhcp"
                    or subnet.get("type") == "dhcp4"
                ):
                    self.config_obj[f"SRM_IPADDR_{device_name}"] = "dhcp"

    def _render_dns(self, settings):
        """Populate config object with dns-related configuration values"""

        # Clear out any existing dns options
        iface_configs = ["SRM_DNS_NAME"]
        self._clear_properties(iface_configs)

        nameservers = settings.dns_nameservers
        for interface in settings.iter_interfaces():
            for subnet in interface.get("subnets", []):
                if "dns_nameservers" in subnet:
                    nameservers.extend(subnet["dns_nameservers"])

        for idx, server in enumerate(nameservers):
            self.config_obj[f"SRM_DNS_NAME{idx+1}"] = server

    def render_network_state(
        self,
        network_state: NetworkState,
        templates=None,
        target=None,
    ) -> None:

        # Summary: apply network config to RedSeal's persistent config file
        # which are picked up and applied via the `rsinit.service` systemd unit
        # This assumes that `rsinit.service` runs after `cloud-init-main` has run
        # (may require modifications to systemd config)

        # Read in existing RedSeal config file to preserve existing config values
        rs_prop = subp.target_path(target, self.props_path)
        rs_route_base = subp.target_path(target, self.routes_base_path)
        util.ensure_dir(os.path.dirname(rs_prop))
        self._read_properties(rs_prop)

        # Append network config values to config structure
        self._render_ifaces(settings=network_state)
        self._render_routes(settings=network_state, route_base=rs_route_base)
        self._render_dns(settings=network_state)

        # Write config file to disk
        self._write_properties(rs_prop)

def available(target=None):
    return util.is_RedSeal()
