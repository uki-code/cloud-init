# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

"""
Cascade deletion for pfSense interfaces cloud-init previously owned but
that have genuinely disappeared (the backing physical device is no longer
present), plus the LAGG-membership check that decides whether cloud-init
should be managing an interface at all.

Schema notes verified against pfSense's own PHP source
(github.com/pfsense/pfsense, src/etc/inc/interfaces.inc and
src/usr/local/www/interfaces_*.php) rather than assumed by analogy:
  - LAGG members are raw device names (interfaces.inc:1082,
    `ifconfig <laggif> laggport <member>`).
  - Bridge members, PPP link "ports", and interface-group members are
    assigned friendly names, not raw device names.
  - GIF/GRE's parent field is a "devname|ipaddr" composite
    (interfaces_gif_edit.php) -- matched with startswith, not equality.
"""

import logging

from cloudinit.distros import pfsense_utils as pf_utils
from cloudinit.net import pfsense_state

LOG = logging.getLogger(__name__)

INTERFACES_NODE = "/pfsense/interfaces"

# Devname-keyed constructs (raw physical/pseudo device names).
LAGGS_NODE = "/pfsense/laggs/lagg"
VLANS_NODE = "/pfsense/vlans/vlan"
QINQS_NODE = "/pfsense/qinqs/qinqentry"
WIRELESS_NODE = "/pfsense/wireless/clone"

# Friendly-slug-keyed constructs.
BRIDGES_NODE = "/pfsense/bridges/bridged"
GIFS_NODE = "/pfsense/gifs/gif"
GRES_NODE = "/pfsense/gres/gre"
PPPS_NODE = "/pfsense/ppps/ppp"
IFGROUPS_NODE = "/pfsense/ifgroups/ifgroup"
SHAPER_NODE = "/pfsense/shaper"
FILTER_NODE = "/pfsense/filter/rule"
NAT_RULE_NODE = "/pfsense/nat/rule"
NAT_OUTBOUND_RULE_NODE = "/pfsense/nat/outbound/rule"
NAT_ONETOONE_NODE = "/pfsense/nat/onetoone"
DHCPD_NODE = "/pfsense/dhcpd"
DHCPDV6_NODE = "/pfsense/dhcpdv6"
OPENVPN_SERVER_NODE = "/pfsense/openvpn/openvpn-server"
OPENVPN_CLIENT_NODE = "/pfsense/openvpn/openvpn-client"
IPSEC_PHASE1_NODE = "/pfsense/ipsec/phase1"
GATEWAYS_NODE = "/pfsense/gateways/gateway_item"
STATICROUTES_NODE = "/pfsense/staticroutes/route"


def _contains_predicate(field, token, separator=","):
    """
    XPath 1.0 idiom for "does this delimited list field contain this exact
    token" -- works identically whether the field holds a single value or
    a delimited list, so the same helper covers both.
    """
    return (
        f'contains(concat("{separator}", {field}, "{separator}"), '
        f'"{separator}{token}{separator}")'
    )


def _delete_matching(tree_path, field, value, fp):
    if not value:
        return
    pf_utils.remove_config_element(f'{tree_path}[{field}="{value}"]', fp=fp)


def _delete_matching_prefix(tree_path, field, prefix, fp):
    """
    For fields stored as a "value|extra" composite (GIF/GRE's parent
    field, which embeds the parent's IP alongside its identity).
    """
    if not prefix:
        return
    pf_utils.remove_config_element(
        f'{tree_path}[starts-with({field}, "{prefix}|")]', fp=fp
    )


def _trim_or_delete_list_member(
    container_tree_path, member_field, own_if_field, target, separator, fp
):
    """
    For the element at container_tree_path whose member_field (a
    separator-delimited list) contains target: remove target from the
    list. If the list becomes empty, delete the element entirely and
    return its own produced ifname (own_if_field) for recursive
    processing; if it survives, return None.
    """
    predicate = f"[{_contains_predicate(member_field, target, separator)}]"
    matched_path = container_tree_path + predicate
    values = pf_utils.get_config_values(
        f"{matched_path}/{member_field}", fp=fp
    )
    if not values:
        return None

    members = [m for m in values[0].split(separator) if m and m != target]
    if members:
        pf_utils.set_config_value(
            f"{matched_path}/{member_field}",
            separator.join(members),
            fp=fp,
        )
        LOG.warning(
            "pfsense cascade: trimmed %s from %s (remaining: %s)",
            target,
            container_tree_path,
            members,
        )
        return None

    produced = None
    if own_if_field:
        produced_values = pf_utils.get_config_values(
            f"{matched_path}/{own_if_field}", fp=fp
        )
        produced = produced_values[0] if produced_values else None

    pf_utils.remove_config_element(matched_path, fp=fp)
    LOG.warning(
        "pfsense cascade: %s emptied by removing %s, deleting entirely",
        container_tree_path,
        target,
    )
    return produced


def _find_slug_for_devname(devname, fp):
    parents = pf_utils.get_config_elements(INTERFACES_NODE, fp=fp)
    if not parents:
        return None
    for slug, iface in parents[0].items():
        if isinstance(iface, dict) and iface.get("if") == devname:
            return slug
    return None


def _delete_slug_dependents(slug, fp):
    """
    Delete/trim everything referencing `slug`, in an order that never
    deletes a referent while something still points at it: routes ->
    filter -> NAT -> DHCP -> OpenVPN -> IPsec -> shaper -> interface
    groups -> GIF/GRE -> PPP -> bridges -> the gateway_item(s) themselves
    last (routes that depended on them are already gone by then).
    """
    gateway_names = pf_utils.get_config_values(
        f'{GATEWAYS_NODE}[interface="{slug}"]/name', fp=fp
    )
    for gw_name in gateway_names:
        pf_utils.remove_config_element(
            f'{STATICROUTES_NODE}[gateway="{gw_name}"]', fp=fp
        )
        LOG.warning(
            "pfsense cascade: removed static routes via gateway %s", gw_name
        )

    # Filter/NAT rules: single-interface and floating (comma-list) rules
    # are both handled by the same contains-based trim, since a
    # single-value field trimmed to empty is exactly "delete the rule".
    _trim_or_delete_list_member(FILTER_NODE, "interface", None, slug, ",", fp)
    _trim_or_delete_list_member(
        NAT_RULE_NODE, "interface", None, slug, ",", fp
    )
    _delete_matching(NAT_OUTBOUND_RULE_NODE, "interface", slug, fp)
    _delete_matching(NAT_ONETOONE_NODE, "interface", slug, fp)

    # dhcpd/dhcpdv6: the slug IS the tag, same pattern as <interfaces>.
    pf_utils.remove_config_element(f"{DHCPD_NODE}/{slug}", fp=fp)
    pf_utils.remove_config_element(f"{DHCPDV6_NODE}/{slug}", fp=fp)

    _delete_matching(OPENVPN_SERVER_NODE, "interface", slug, fp)
    _delete_matching(OPENVPN_CLIENT_NODE, "interface", slug, fp)
    _delete_matching(IPSEC_PHASE1_NODE, "interface", slug, fp)

    # Traffic shaper queues: best-effort match anywhere under the shaper
    # tree, since its nested queue schema isn't fully modeled here.
    pf_utils.remove_config_element(
        f'{SHAPER_NODE}//*[interface="{slug}"]', fp=fp
    )

    # Interface groups: space-separated membership (interfaces.inc:5818,
    # `explode(" ", $groupname['members'])`), unlike the comma-separated
    # lists everywhere else.
    _trim_or_delete_list_member(IFGROUPS_NODE, "members", None, slug, " ", fp)

    _delete_matching_prefix(GIFS_NODE, "if", slug, fp)
    _delete_matching_prefix(GRES_NODE, "if", slug, fp)

    _trim_or_delete_list_member(PPPS_NODE, "ports", None, slug, ",", fp)

    produced = _trim_or_delete_list_member(
        BRIDGES_NODE, "members", "bridgeif", slug, ",", fp
    )
    if produced:
        _process_devname(produced, fp, visited=set())

    # Gateways last: anything that depended on them (routes, above) is
    # already gone.
    _delete_matching(GATEWAYS_NODE, "interface", slug, fp)


def _process_devname(devname, fp, visited):
    if devname is None or devname in visited:
        return
    visited.add(devname)

    slug = _find_slug_for_devname(devname, fp)
    if slug:
        _delete_slug_dependents(slug, fp)
        pf_utils.remove_config_element(f"{INTERFACES_NODE}/{slug}", fp=fp)
        LOG.warning(
            "pfsense cascade: removed interface assignment %s (device %s)",
            slug,
            devname,
        )

    produced = _trim_or_delete_list_member(
        LAGGS_NODE, "members", "laggif", devname, ",", fp
    )
    if produced:
        _process_devname(produced, fp, visited)

    for tree_path, own_if_field in (
        (VLANS_NODE, "vlanif"),
        (QINQS_NODE, "vlanif"),
    ):
        produced_values = pf_utils.get_config_values(
            f'{tree_path}[if="{devname}"]/{own_if_field}', fp=fp
        )
        if produced_values:
            pf_utils.remove_config_element(
                f'{tree_path}[if="{devname}"]', fp=fp
            )
            LOG.warning(
                "pfsense cascade: removed %s parented on %s",
                tree_path,
                devname,
            )
            for produced_devname in produced_values:
                _process_devname(produced_devname, fp, visited)

    produced_values = pf_utils.get_config_values(
        f'{WIRELESS_NODE}[if="{devname}"]/cloneif', fp=fp
    )
    if produced_values:
        pf_utils.remove_config_element(
            f'{WIRELESS_NODE}[if="{devname}"]', fp=fp
        )
        for produced_devname in produced_values:
            _process_devname(produced_devname, fp, visited)


def is_claimed_by_other_construct(devname, fp):
    """
    The only ownership-flip trigger: LAGG membership. Every other
    construct that can reference a devname or slug (bridge, GIF/GRE, PPP,
    OpenVPN/IPsec, filter/NAT/DHCP, gateways) depends on cloud-init
    continuing to manage the interface correctly -- see the plan/chat
    discussion for the per-construct verification against pfSense's
    source. Cloud-init never writes to <laggs> itself, so a hit here is
    unambiguously learner-originated.
    """
    if not devname:
        return False
    predicate = _contains_predicate("members", devname, ",")
    members = pf_utils.get_config_values(
        f"{LAGGS_NODE}[{predicate}]/members",
        fp=fp,
    )
    return bool(members)


def _select_promotion_candidate(state, exclude):
    candidates = [
        rec
        for rec in pfsense_state.list_owned_optional_slugs(state)
        if rec["logical_id"] not in exclude
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda rec: int(rec["friendly"][3:]))
    return candidates[0]


def _promote(candidate, target_slug, fp):
    old_slug = candidate["friendly"]
    LOG.warning(
        "pfsense cascade: promoting %s to %s (destroying %s's own "
        "dependents first)",
        old_slug,
        target_slug,
        old_slug,
    )
    _delete_slug_dependents(old_slug, fp)
    pf_utils.remove_config_element(f"{INTERFACES_NODE}/{old_slug}", fp=fp)
    owned = dict(candidate.get("applied") or {})
    # target_slug's own node is still present and stale at this point --
    # its backing device vanished, but _process_devname for that removal
    # hasn't run yet (promotion happens first). Clear it before creating
    # the promoted replacement, or both would coexist as same-tag
    # siblings and collapse into a list on the next read.
    pf_utils.remove_config_element(f"{INTERFACES_NODE}/{target_slug}", fp=fp)
    pf_utils.append_config_element(
        f"{INTERFACES_NODE}/{target_slug}", owned, fp=fp
    )
    candidate["friendly"] = target_slug


def remove_interface_cascade(state, removal, floor_violations, fp):
    logical_id = removal["logical_id"]
    slug = removal["friendly"]
    devname = removal["devname"]

    if slug in ("wan", "lan") and slug in floor_violations:
        candidate = _select_promotion_candidate(state, exclude={logical_id})
        if candidate is None:
            LOG.error(
                "pfsense cascade: refusing to remove mandatory interface "
                "%s (device %s) -- no eligible optional interface "
                "available to promote; will retry next render",
                slug,
                devname,
            )
            return
        _promote(candidate, slug, fp)

    LOG.warning(
        "pfsense cascade: begin removal -- logical_id=%s friendly=%s "
        "devname=%s mac=%s",
        logical_id,
        slug,
        devname,
        removal.get("mac"),
    )
    _process_devname(devname, fp, visited=set())
    LOG.warning("pfsense cascade: complete for logical_id %s", logical_id)
    pfsense_state.confirm_removed(state, logical_id)
