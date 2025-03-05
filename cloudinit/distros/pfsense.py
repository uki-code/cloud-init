# Copyright (C) 2025 Alex Luehm
#
# Author: Alex Luehm <alex@luehm.com>
#
# This file is part of cloud-init. See LICENSE file for license information.

import bcrypt
import logging
from datetime import datetime

import cloudinit.distros.freebsd
from cloudinit import subp
import cloudinit.distros.pfsense_utils as pf_utils

LOG = logging.getLogger(__name__)

class Distro(cloudinit.distros.freebsd.Distro):
    """
    Distro subclass for pfSense
    """

    user_node = "/pfsense/system/user"
    group_node = "/pfsense/system/group"
    next_uid_node = "/pfsense/system/nextuid"
    next_gid_node = "/pfsense/system/nextgid"
    hostname_node = "/pfsense/system/hostname"
    domain_node = "/pfsense/system/domain"

    def __init__(self, name, cfg, paths):
        super().__init__(name, cfg, paths)
        self.renderer_configs = {
            "pfsense": {
                "postcmds": "True"
            }
        }

    def create_group(self, name, members=None):
        """
        Create a new group
        Groups are stored within the pfsense/system element as a new group entry
        """

        # Check if name is empty
        if name in [None, ""]:
            LOG.info("Unable to create group, name cannot be empty")
            return False

        # Check if group already exists
        groups = pf_utils.get_config_elements(Distro.group_node)
        if [g for g in groups if g["name"] == name]:
            LOG.info("Group %s already exists, skipping.", name)
            return False

        # Get next available gid
        # - Take the first element, there should only be one
        gid = pf_utils.get_config_values(Distro.next_gid_node)[0]

        # Create new group
        group = {}
        group["name"] = name
        group["description"] = name
        group["gid"] = gid
        group["scope"] = "system"

        # Increment next gid tracker
        pf_utils.set_config_value(Distro.next_gid_node, str(int(gid) + 1))

        # Restructure provided members as a list
        if not members:
            members = []
        elif not isinstance(members, list):
            members = [members]

        # Add group members which currently exist on system
        group["member"] = []
        existing_users = pf_utils.get_config_elements(Distro.user_node)
        existing_names = [u["name"] for u in existing_users]
        for member in members:
            if member not in existing_names:
                LOG.warning("Unable to add group member '%s' to group '%s'; user does not exist.", member, name)
                continue

            group["member"].append(existing_users[existing_names.index(member)]["uid"])

        # Add group to system element
        pf_utils.append_config_element(Distro.group_node, group)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()

    def _add_user_to_group(self, user_id, group_name):
        """
        Add a user to a group
        """

        # Check if group exists
        groups = pf_utils.get_config_elements(Distro.group_node)
        group = None
        for g in groups:
            if g["name"] == group_name:
                group = g
                break

        # If group does not exist, return
        if group is None:
            return False

        # Restructure group members as a list
        if not "member" in group:
            group["member"] = []

        if not isinstance(group["member"], list):
            group["member"] = [group["member"]]

        # If user is already in group, return
        if user_id in group["member"]:
            LOG.info("User %s already in group %s", user_id, group_name)
            return True

        # Add user to group
        group["member"].append(user_id)
        pf_utils.replace_config_element(Distro.group_node, "name", group_name, group)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        return True

    def _add_ssh_key(self, user, key):
        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        raise NotImplementedError()

    def _write_hostname(self, hostname, filename=None):

        # if hostname is a fqdn, split it
        if "." in hostname:
            hostname, fqdn = hostname.split(".", 1)
            # Set domain  `
            pf_utils.set_config_value(Distro.domain_node, fqdn)

        # Set hostname
        pf_utils.set_config_value(Distro.hostname_node, hostname)

    def _apply_hostname(self, hostname):
        pf_utils.sync_hostname()

    def _read_hostname(self, filename, default=None):
        # FQDN is split accross hostname and domain elements
        # in the config.xml
        # Only return hostname for comparision

        return pf_utils.get_config_values(Distro.hostname_node)[0]

    def update_etc_hosts(self, hostname, fqdn):
        pf_utils.sync_hosts()

    def set_passwd(self, user, passwd, hashed=False):
        """
        Set the password for a user
        Stored as bcrypt has in config.xml
        """

        # Check if name is empty
        if user in [None, ""]:
            LOG.info("Unable to set password, user name cannot be empty")
            return False

        # Check if user exists
        users = pf_utils.get_config_elements(Distro.user_node)
        node = None
        for u in users:
            if u["name"] == user:
                node = u
                break
        if node is None:
            LOG.info("User %s does not exist", user)
            return False

        # Set password
        if hashed:
            # Check if password is bcrypt format
            if passwd.startswith("$2"):
                node["bcrypt-hash"] = passwd
                pf_utils.replace_config_element(Distro.user_node, "name", user, node)
            else:
                LOG.info("Invalid bcrypt hash for user %s, skipping", user)
                return False
        else:
            # Generate bcrypt hash of user password
            node["bcrypt-hash"] = bcrypt.hashpw(str(passwd).encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

            pf_utils.replace_config_element(Distro.user_node, "name", user, node)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        return True

    def chpasswd(self, plist_in, hashed):
        name, password = plist_in
        self.set_passwd(name, password, hashed)

    def lock_passwd(self, name):
        """
        Lock a user's password, effectively disabling the account.
        Implemented on pfSense by the <disabled> element in the user's configuration
        """

        # Check if name is empty
        if name in [None, ""]:
            LOG.info("Unable to lock passwd, user name cannot be empty")
            return False

        # Check if user exists
        users = pf_utils.get_config_elements(Distro.user_node)
        node = None
        for u in users:
            if u["name"] == name:
                node = u
                break

        if node is None:
            LOG.info("User %s does not exist", name)
            return False

        # Lock user password
        node["disabled"] = ""
        pf_utils.replace_config_element(Distro.user_node, "name", name, node)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        return True

    def expire_passwd(self, user):
        self.lock_passwd(user)

    def unlock_passwd(self, name):
        """
        Unlock a user's password, effectively enabling the account.
        Implemented on pfSense by removing the <disabled> element from the user's configuration
        """

        # Check if name is empty
        if name in [None, ""]:
            LOG.info("Unable to unlock passwd, user name cannot be empty")
            return False

        # Check if user exists and is locked
        users = pf_utils.get_config_elements(Distro.user_node)
        node = None
        for u in users:
            if u["name"] == name and u.get("disabled"):
                node = u
                break

        if node is None:
            LOG.info("User %s does not exist or is not locked.", name)
            return False

        # Unlock user password
        del node["disabled"]
        pf_utils.replace_config_element(Distro.user_node, "name", name, node)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        return True

    def add_user(self, name, **kwargs):
        """
        Add a user to the system
        Users are stored within the pfsense/system element as a new user entry

        Supported user properties:
        - gecos: User description
        - lock_passwd: Lock user password
        - expiredate: User expiration date (YYYY-MM-DD)
        - groups: List of groups to add user to
        - name: User name
        - groups[list]: List of groups to add user to
        - plain_text_passwd: Plaintext password
        - hashed_passwd: bcrypt hashed password
        - passwd bcrypt hashed password

        Pending:
        - ssh_authorized_keys
        """

        # Check if name is empty
        if name in [None, ""]:
            LOG.info("Unable to create user, name cannot be empty")
            return False

        # Check if user already exists
        users = pf_utils.get_config_elements(Distro.user_node)
        if [u for u in users if u["name"] == name]:
            LOG.info("User %s already exists, skipping.", name)
            return False

        # Get next available uid
        # - Take the first element, there should only be one
        uid = pf_utils.get_config_values(Distro.next_uid_node)[0]

        # Create new user
        user = {}
        user["name"] = name
        user["uid"] = uid
        user["scope"] = "user"

        # Increment next uid tracker
        pf_utils.set_config_value(Distro.next_uid_node, str(int(uid) + 1))

        # Parse user properties
        for key, val in kwargs.items():
            if key == "gecos":
                user["descr"] = val
            elif key == "expiredate":
                date_obj= datetime.strptime(val, "%Y-%m-%d")
                formatted_date = date_obj.strftime("%d/%m/%Y")
                user["expires"] = formatted_date

        # Add user to system element
        pf_utils.append_config_element(Distro.user_node, user)

        # Parse remaining user properties
        for key, val in kwargs.items():
            if key == "groups":
                if not isinstance(val, list):
                    val = [val]
                for group in val:
                    if not self._add_user_to_group(uid, group):
                        LOG.warning("Unable to add user '%s' to group '%s - group does not exist'", name, group)
            elif key == "passwd":

                # This doesn't seem to be implemented in the
                # Distro class - handling here
                self.set_passwd(name, val, hashed=True)

        # Write users and groups from config to system
        pf_utils.sync_users_groups()
        return True
