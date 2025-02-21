# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import configparser
import logging
import os

from typing import Optional

from cloudinit import subp, util, net

from cloudinit.net import renderers, renderer

from cloudinit.net.network_state import NetworkState

LOG = logging.getLogger(__name__)

class Renderer(renderer.Renderer):
    def __init__(self, config=None):
        parent_renderer_list =  ['eni', 'netplan', 'network-manager', 'sysconfig', 'networkd']
        self.config = config
        self.config_parser = configparser.ConfigParser(allow_unnamed_section=True)
        self.config_parser.optionxform = str
        self.props_path = config.get("rs_props_path", "data/persist.properties")
        _, self.parent_renderer = renderers.select(priority=parent_renderer_list)

    def _render_routes(self, settings):

        conf_obj = self.config_parser['UNNAMED SECTION']

        routes = list(settings.iter_routes())
        ifname_by_mac = net.get_interfaces_by_mac()
        for interface in settings.iter_interfaces():
            device_name = ifname_by_mac[interface.get("mac_address")]
            subnets = interface.get("subnets", [])
            for subnet in subnets:
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
                routes += [route.update({"interface": device_name}) for route in subnet.get("routes", [])]

        routes_set = 0
        for route in routes:
            network = route.get("network")
            if not network:
                LOG.debug("Skipping a bad route entry")
                continue
            netmask = (
                route.get("netmask")
                if route.get("netmask")
                else route.get("prefix")
            )
            gateway = route.get("gateway")

            # TODO: Test and implement general network routes
            if not network in ["0.0.0.0", "::"]:
                LOG.warning("Non-default route was provided - Not yet implemented in RedSeal, Skipping")
                continue
                #raise NotImplementedError("Non-default network routes are not supported by RedSeal")

            conf_obj["SRM_DEFAULT_GATEWAY"] = gateway
            conf_obj["SRM_DEFAULT_GATEWAY_IFACE"] = route.interface
            routes_set += 1

            # TODO: Test and implement weighted default routes, if possible
            if routes_set > 2:
                raise NotImplementedError("Multiple default routes are not supported by RedSeal")

    def _render_ifaces(self, settings):

        conf_obj = self.config_parser['UNNAMED SECTION']

        # Iterate through by MAC to ensure we have interface
        # name after any renaming has been done
        ifname_by_mac = net.get_interfaces_by_mac()
        for interface in settings.iter_interfaces():
            device_name = ifname_by_mac[interface.get("mac_address")]
            for subnet in interface.get("subnets", []):

                # Configure IPv4 IP settings
                if subnet.get("type") == "static":
                    if not subnet.get("netmask"):
                        LOG.debug(
                            "Skipping IP %s, because there is no netmask",
                            subnet.get("address"),
                        )
                        continue
                    LOG.debug(
                        "Configuring dev %s with %s / %s",
                        device_name,
                        subnet.get("address"),
                        subnet.get("netmask"),
                    )
                    conf_obj[f"ENABLE_INTERFACE_{device_name}"] = "true"
                    conf_obj[f"SRM_IPADDR_{device_name}"] = subnet.get("address")
                    conf_obj[f"SRM_NETMASK_{device_name}"] = subnet.get("netmask")

                # Configure IPv6 IP settings
                # Untested
                elif subnet.get("type") == "static6":
                    if not subnet.get("prefix"):
                        LOG.debug(
                            "Skipping IP %s, because there is no prefix",
                            subnet.get("address"),
                        )
                        continue
                    LOG.debug(
                        "Configuring dev %s with %s / %s",
                        device_name,
                        subnet.get("address"),
                        subnet.get("prefix"),
                    )
                    conf_obj[f"ENABLE_INTERFACE_{device_name}"] = "true"
                    conf_obj[f"SRM_IPADDR_{device_name}"] = subnet.get("address")
                    conf_obj[f"SRM_NETMASK_{device_name}"] = subnet.get("prefix")

                # Configure interface for DHCP
                # Untested - unimplemented
                elif (
                    subnet.get("type") == "dhcp"
                    or subnet.get("type") == "dhcp4"
                ):
                    raise NotImplementedError("Setting RedSeal interface with DHCP is not yet supported")

    def _render_dns(self, settings):

        conf_obj = self.config_parser['UNNAMED SECTION']

        nameservers = settings.dns_nameservers
        for interface in settings.iter_interfaces():
            for subnet in interface.get("subnets", []):
                if "dns_nameservers" in subnet:
                    nameservers.extend(subnet["dns_nameservers"])

        for idx, server in enumerate(nameservers):
            conf_obj[f"SRM_DNS_NAME{idx+1}"] = server

    def render_network_state(
        self,
        network_state: NetworkState,
        templates: Optional[dict] = None,
        target=None,
    ) -> None:

        # Apply network config to OS itself, based on supported renderers
        self.parent_renderer.render_network_state(network_state, templates, target)

        # Read in existing RedSeal config file to preserve existing config values
        fp_rs_prop = subp.target_path(target, self.props_path)
        util.ensure_dir(os.path.dirname(fp_rs_prop))
        self.config_parser.read_file(open(fp_rs_prop))

        # Append network config values to config structure
        self._render_ifaces(settings=network_state)
        self._render_routes(settings=network_state)
        self._render_dns(settings=network_state)

        # Write config file to disk
        self.config_parser.write(open(fp_rs_prop, 'w', encoding='utf-8'), space_around_delimiters=False)
