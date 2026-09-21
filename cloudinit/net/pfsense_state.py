# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

"""
Reconciliation state for the pfSense network renderer.

pfSense's config.xml is a persistent document that a learner can also edit
live via the GUI between boots (build a LAGG, a bridge, a VPN, firewall
rules), and the set of physical interfaces the hypervisor presents can
change across boots. This module tracks, across boots, which interfaces
cloud-init has assigned a friendly name (wan/lan/optN) to, so a render can
merge into that document instead of wiping and rebuilding it from scratch.
"""

import copy
import json
from dataclasses import dataclass, field

from cloudinit.distros import pfsense_utils as pf_utils

# pfSense's own sanctioned subtree for third-party/package-owned data --
# every actual pfSense package stashes its own settings here, and it
# round-trips through write_config()/backup-restore the same way real
# package config does.
STATE_PARENT_NODE = "/pfsense/installedpackages/cloudinit"
STATE_NODE = STATE_PARENT_NODE + "/state"

# The only fields cloud-init ever writes/overwrites on an
# <interfaces>/<slug> element. Everything else on that element (blockpriv,
# blockbogons, gateway, media, mediaopt, dhcp6-duid, ...) is left alone.
OWNED_FIELDS = (
    "if",
    "descr",
    "enable",
    "ipaddr",
    "subnet",
    "mtu",
    "ipaddrv6",
    "subnetv6",
)


@dataclass
class ReconcileResult:
    writes: list = field(default_factory=list)
    pending_removals: list = field(default_factory=list)
    floor_violations: list = field(default_factory=list)
    new_state: dict = field(default_factory=dict)


def compute_logical_id(mac_address, config_id, device_name):
    """
    The stable identity for an interface, MAC-primary: the hypervisor
    injects real interfaces every boot, and MAC is the one property that's
    actually about the hardware -- config_id is just an operator-chosen
    label. config_id and device_name are still recorded on the state entry
    for readability, just never used as the primary key when a MAC is
    available.
    """
    if mac_address:
        return f"mac:{mac_address}"
    if config_id:
        return f"cid:{config_id}"
    return f"name:{device_name}"


def owned_fields_from(desired):
    """
    Extract just the fields cloud-init owns from a fully-built desired
    interface dict (which also carries "mac"/"config_id" metadata that
    should never be written to config.xml).
    """
    return {k: v for k, v in desired.items() if k in OWNED_FIELDS}


def _merge_owned_fields(live, owned):
    """
    Merge `owned` onto a copy of the live element: every OWNED_FIELDS key
    ends up exactly matching `owned` (including being removed if `owned`
    doesn't have it -- a full reassert, not an additive merge), while
    everything else on the live element (learner-added fields, or entire
    sibling elements this function never sees) is left untouched.
    """
    merged = {k: v for k, v in live.items() if k != "_slug"}
    for f in OWNED_FIELDS:
        if f in owned:
            merged[f] = owned[f]
        else:
            merged.pop(f, None)
    return merged


def _bootstrap_state():
    return {"version": 1, "next_opt_index": 1, "interfaces": {}}


def load_state(fp):
    values = pf_utils.get_config_values(STATE_NODE, fp=fp)
    if not values or not values[0]:
        return _bootstrap_state()
    return json.loads(values[0])


def save_state(state, fp):
    """
    Persist state under <installedpackages>/cloudinit/state. Handles the
    node not existing yet at either level -- the config.xml may already
    have an empty <installedpackages/> skeleton, or (defensively) may not.
    """
    json_string = json.dumps(state)

    if pf_utils.get_config_elements(STATE_PARENT_NODE, fp=fp):
        pf_utils.set_config_value(STATE_NODE, json_string, fp=fp)
        return

    installedpackages_node = STATE_PARENT_NODE.rsplit("/", 1)[0]
    if not pf_utils.get_config_elements(installedpackages_node, fp=fp):
        pf_utils.append_config_element(installedpackages_node, "", fp=fp)

    pf_utils.append_config_element(
        STATE_PARENT_NODE, {"state": json_string}, fp=fp
    )


def allocate_slugs(state, new_logical_ids, occupied_slugs):
    """
    Assign a friendly slug (wan, lan, opt1, opt2, ...) to each logical_id
    in new_logical_ids, in order. next_opt_index is a monotonic high-water
    mark that's never handed back out, even across a freed slot -- see the
    plan/chat discussion for why this diverges from pfSense's own native
    gap-fill behavior (that gap-fill only ever runs after a human has
    satisfied pfSense's own delete-time refusals; our cascade is
    unattended, and our dependency graph can't be proven exhaustive
    against pfSense's full schema).
    """
    live_opt_numbers = [
        int(s[3:])
        for s in occupied_slugs
        if s.startswith("opt") and s[3:].isdigit()
    ]
    state["next_opt_index"] = max(
        [state["next_opt_index"]] + [n + 1 for n in live_opt_numbers]
    )

    candidates = ["wan", "lan"] + [
        f"opt{n}"
        for n in range(
            state["next_opt_index"],
            state["next_opt_index"] + len(new_logical_ids),
        )
    ]
    available = [s for s in candidates if s not in occupied_slugs]

    assignments = {}
    for logical_id, slug in zip(new_logical_ids, available):
        assignments[logical_id] = slug
        if slug.startswith("opt"):
            state["next_opt_index"] = max(
                state["next_opt_index"], int(slug[3:]) + 1
            )
    return assignments


def list_owned_optional_slugs(state):
    """
    Owned, currently-optN entries -- the candidate pool for promoting into
    a violated wan/lan floor. Note: this doesn't exclude a candidate that
    happens to also be in this same render's pending_removals batch (a
    rare double-removal edge case); callers that care should filter by
    logical_id themselves.
    """
    return [
        rec
        for rec in state["interfaces"].values()
        if rec.get("owned") and (rec.get("friendly") or "").startswith("opt")
    ]


def confirm_removed(state, logical_id):
    """
    Call only after a cascade delete of `logical_id`'s slug (and
    everything downstream of it) is fully complete. Until this is called,
    the next render re-derives the identical pending_removals entry and
    retries -- crash-safe by construction, no transaction log needed.
    """
    state["interfaces"].pop(logical_id, None)


def reconcile(
    state,
    live_by_slug,
    desired_by_logical_id,
    occupied_slugs,
    is_claimed_by_other_construct,
):
    """
    The three-way merge: (state we track) x (what's actually in config.xml
    right now) x (what this render's netconfig wants). Pure function, no
    I/O -- deliberately the testable seam.

    `owned` is resolved first for every already-tracked logical_id, fully
    independent of and prior to the desired/live branching -- keeping
    these two questions as separate, sequential steps is what makes
    "reclaimed, but the NIC is also gone by now" and "reclaimed while
    something else has since taken its old slug number" both fall out
    naturally, without any special-casing.
    """
    new_state = copy.deepcopy(state)
    writes = []
    pending_removals = []
    floor_violations = []
    needs_slug = []

    for logical_id, rec in list(new_state["interfaces"].items()):
        desired = desired_by_logical_id.get(logical_id)

        # Always check ownership against the freshest devname available
        # this render, not the one last recorded -- _ifconfig_entries
        # refreshes it every render regardless of owned status, so a
        # rename that happened while enslaved must not be missed.
        current_devname = (
            desired["if"] if desired is not None else rec.get("devname")
        )
        rec["devname"] = current_devname

        claimed = (
            is_claimed_by_other_construct(current_devname)
            if current_devname
            else False
        )
        rec["owned"] = not claimed

        if not rec["owned"]:
            # Fully hands-off while enslaved: no write, no removal-cascade
            # consideration, nothing else evaluated for this logical_id.
            continue

        if desired is None:
            slug = rec.get("friendly")
            live = live_by_slug.get(slug) if slug else None
            # Identity guard, mirroring the one below for the
            # still-desired case: a removal can be deferred across
            # renders (e.g. while enslaved in a LAGG), which opens a
            # window for something else -- pfSense's own webUI gap-fill,
            # or a learner directly -- to legitimately claim this slug
            # before we get back to it. If so, it's not ours to cascade
            # or (for wan/lan) promote over; our own device is already
            # gone from everywhere that matters, so just drop our stale
            # tracking for it and leave the new occupant alone.
            if live is not None and live.get("if") == rec.get("devname"):
                pending_removals.append(
                    {
                        "logical_id": logical_id,
                        "friendly": slug,
                        "devname": rec.get("devname"),
                        "mac": rec.get("mac"),
                    }
                )
                if slug in ("wan", "lan"):
                    floor_violations.append(slug)
            else:
                del new_state["interfaces"][logical_id]
            continue

        # owned, and still desired this render.
        slug = rec.get("friendly")
        if slug is not None:
            live = live_by_slug.get(slug)
            if live is not None and live.get("if") != current_devname:
                # Identity guard: this slug number no longer legitimately
                # refers to our device (something else -- e.g. pfSense's
                # own webUI gap-fill -- claimed it while we had no XML
                # node to hold our claim). Don't clobber whoever's there
                # now; self-heal by getting a fresh slug instead.
                slug = None
                rec["friendly"] = None

        if slug is None:
            needs_slug.append(logical_id)
        else:
            owned = owned_fields_from(desired)
            live = live_by_slug.get(slug)
            element = _merge_owned_fields(live, owned) if live else dict(owned)
            writes.append({"slug": slug, "element": element})
            rec["applied"] = owned

    # Devices already sitting at a slug in config.xml, even though
    # cloud-init never tracked them -- e.g. the pfSense installer's own
    # factory wan/lan assignment, present before cloud-init ever runs.
    # Consulted below so a first-ever render takes over that slug in
    # place instead of minting a fresh opt slot and leaving the same
    # device assigned under two slugs at once.
    devname_to_live_slug = {
        live.get("if"): slug
        for slug, live in live_by_slug.items()
        if isinstance(live, dict) and live.get("if")
    }

    # Logical ids never tracked before.
    new_ids = [
        lid
        for lid in desired_by_logical_id
        if lid not in new_state["interfaces"]
    ]
    for lid in new_ids:
        desired = desired_by_logical_id[lid]
        devname = desired["if"]
        already_claimed = is_claimed_by_other_construct(devname)
        existing_slug = None
        if not already_claimed:
            existing_slug = devname_to_live_slug.get(devname)
            if existing_slug is None:
                # This render may have already renamed the device (e.g.
                # pfSense's factory wan/lan assignment) before config.xml
                # was ever read this render -- config.xml still reflects
                # the pre-rename name, so the lookup above misses on the
                # current name alone.
                prior_devname = desired.get("prior_devname")
                if prior_devname and prior_devname != devname:
                    existing_slug = devname_to_live_slug.get(prior_devname)
        new_state["interfaces"][lid] = {
            "logical_id": lid,
            "mac": desired.get("mac"),
            "config_id": desired.get("config_id"),
            "friendly": existing_slug,
            "devname": devname,
            "owned": not already_claimed,
            "applied": None,
        }
        if already_claimed:
            continue
        if existing_slug:
            owned = owned_fields_from(desired)
            live = live_by_slug.get(existing_slug)
            element = _merge_owned_fields(live, owned) if live else dict(owned)
            writes.append({"slug": existing_slug, "element": element})
            new_state["interfaces"][lid]["applied"] = owned
        else:
            needs_slug.append(lid)

    assignments = allocate_slugs(new_state, needs_slug, occupied_slugs)
    for lid in needs_slug:
        desired = desired_by_logical_id[lid]
        slug = assignments[lid]
        owned = owned_fields_from(desired)
        writes.append({"slug": slug, "element": dict(owned)})
        new_state["interfaces"][lid]["friendly"] = slug
        new_state["interfaces"][lid]["applied"] = owned

    return ReconcileResult(
        writes=writes,
        pending_removals=pending_removals,
        floor_violations=floor_violations,
        new_state=new_state,
    )
