# This file is part of cloud-init. See LICENSE file for license information.

"""
Tests for cloudinit/distros/pfsense.py's user/group/password/hostname
management. This talks to pfSense's config.xml exclusively through
cloudinit.distros.pfsense_utils (pf_utils), which is mocked wholesale here
rather than exercised against a real file -- pfsense.Distro doesn't (yet)
thread a config path through the way cloudinit.net.pfsense.Renderer does,
so these are unit tests of the Distro's own logic, not integration tests
of the XML round-trip (that's covered separately for pf_utils itself).
"""

from unittest import mock

import pytest

from tests.unittests.distros import _get_distro


@pytest.fixture
def distro():
    return _get_distro("pfsense")


@pytest.fixture
def pf_utils(mocker):
    return mocker.patch("cloudinit.distros.pfsense.pf_utils")


class TestCreateGroup:
    def test_empty_name_returns_false(self, distro, pf_utils):
        assert distro.create_group("") is False
        pf_utils.get_config_elements.assert_not_called()

    def test_existing_group_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "admins", "gid": "2000"}
        ]
        assert distro.create_group("admins") is False
        pf_utils.set_config_value.assert_not_called()

    def test_creates_new_group_with_no_members(self, distro, pf_utils):
        pf_utils.get_config_elements.side_effect = [
            [],  # existing groups check -> none
            [],  # existing users lookup
        ]
        pf_utils.get_config_values.return_value = ["2000"]

        distro.create_group("admins")

        pf_utils.set_config_value.assert_called_once_with(
            "/pfsense/system/nextgid", "2001"
        )
        appended_group = pf_utils.append_config_element.call_args[0][1]
        assert appended_group == {
            "name": "admins",
            "description": "admins",
            "gid": "2000",
            "scope": "system",
            "member": [],
        }
        pf_utils.sync_users_groups.assert_called_once()

    def test_only_existing_members_are_added(self, distro, pf_utils, caplog):
        pf_utils.get_config_elements.side_effect = [
            [],
            [{"name": "alice", "uid": "2001"}, {"name": "bob", "uid": "2002"}],
        ]
        pf_utils.get_config_values.return_value = ["2000"]

        distro.create_group("admins", members=["alice", "ghost"])

        appended_group = pf_utils.append_config_element.call_args[0][1]
        assert appended_group["member"] == ["2001"]
        assert "ghost" in caplog.text

    def test_single_member_string_is_normalized_to_list(
        self, distro, pf_utils
    ):
        pf_utils.get_config_elements.side_effect = [
            [],
            [{"name": "alice", "uid": "2001"}],
        ]
        pf_utils.get_config_values.return_value = ["2000"]

        distro.create_group("admins", members="alice")

        appended_group = pf_utils.append_config_element.call_args[0][1]
        assert appended_group["member"] == ["2001"]


class TestAddUserToGroup:
    def test_group_missing_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = []
        assert distro._add_user_to_group("2001", "admins") is False
        pf_utils.replace_config_element.assert_not_called()

    def test_adds_new_member(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "admins", "member": "2002"}
        ]
        assert distro._add_user_to_group("2001", "admins") is True
        node = pf_utils.replace_config_element.call_args[0][3]
        assert node["member"] == ["2002", "2001"]
        pf_utils.sync_users_groups.assert_called_once()

    def test_group_with_no_member_key_starts_empty(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [{"name": "admins"}]
        distro._add_user_to_group("2001", "admins")
        node = pf_utils.replace_config_element.call_args[0][3]
        assert node["member"] == ["2001"]

    def test_already_a_member_is_a_noop(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "admins", "member": ["2001"]}
        ]
        assert distro._add_user_to_group("2001", "admins") is True
        pf_utils.replace_config_element.assert_not_called()
        pf_utils.sync_users_groups.assert_not_called()


class TestAddSshKey:
    def test_raises_not_implemented(self, distro, pf_utils):
        with pytest.raises(NotImplementedError):
            distro._add_ssh_key("alice", "ssh-ed25519 AAAA...")


class TestHostname:
    def test_write_hostname_plain(self, distro, pf_utils):
        distro._write_hostname("pfsense-box")
        pf_utils.set_config_value.assert_called_once_with(
            "/pfsense/system/hostname", "pfsense-box"
        )

    def test_write_hostname_fqdn_splits_domain(self, distro, pf_utils):
        distro._write_hostname("pfsense-box.lab.example.com")
        assert pf_utils.set_config_value.call_args_list == [
            mock.call("/pfsense/system/domain", "lab.example.com"),
            mock.call("/pfsense/system/hostname", "pfsense-box"),
        ]

    def test_apply_hostname_syncs(self, distro, pf_utils):
        distro._apply_hostname("pfsense-box")
        pf_utils.sync_hostname.assert_called_once()

    def test_read_hostname(self, distro, pf_utils):
        pf_utils.get_config_values.return_value = ["pfsense-box"]
        assert distro._read_hostname("unused") == "pfsense-box"

    def test_update_etc_hosts_syncs(self, distro, pf_utils):
        distro.update_etc_hosts("pfsense-box", "pfsense-box.lab")
        pf_utils.sync_hosts.assert_called_once()


class TestSetPasswd:
    def test_empty_user_returns_false(self, distro, pf_utils):
        assert distro.set_passwd("", "hunter2") is False
        pf_utils.get_config_elements.assert_not_called()

    def test_missing_user_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = []
        assert distro.set_passwd("alice", "hunter2") is False

    def test_hashed_with_valid_bcrypt_prefix(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001"}
        ]
        assert (
            distro.set_passwd("alice", "$2b$12$abcdefg", hashed=True) is True
        )
        node = pf_utils.replace_config_element.call_args[0][3]
        assert node["bcrypt-hash"] == "$2b$12$abcdefg"
        pf_utils.sync_users_groups.assert_called_once()

    def test_hashed_with_invalid_prefix_fails(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001"}
        ]
        assert distro.set_passwd("alice", "plaintext", hashed=True) is False
        pf_utils.replace_config_element.assert_not_called()
        pf_utils.sync_users_groups.assert_not_called()

    def test_unhashed_generates_bcrypt_hash(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001"}
        ]
        assert distro.set_passwd("alice", "hunter2") is True
        node = pf_utils.replace_config_element.call_args[0][3]
        assert node["bcrypt-hash"].startswith("$2")
        pf_utils.sync_users_groups.assert_called_once()

    def test_chpasswd_delegates_to_set_passwd(self, distro, mocker):
        m_set = mocker.patch.object(distro, "set_passwd")
        distro.chpasswd(("alice", "hunter2"), True)
        m_set.assert_called_once_with("alice", "hunter2", True)


class TestLockUnlockPasswd:
    def test_lock_empty_name_returns_false(self, distro, pf_utils):
        assert distro.lock_passwd("") is False

    def test_lock_missing_user_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = []
        assert distro.lock_passwd("alice") is False

    def test_lock_existing_user(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001"}
        ]
        assert distro.lock_passwd("alice") is True
        node = pf_utils.replace_config_element.call_args[0][3]
        assert node["disabled"] == ""
        pf_utils.sync_users_groups.assert_called_once()

    def test_expire_passwd_delegates_to_lock_passwd(self, distro, mocker):
        m_lock = mocker.patch.object(distro, "lock_passwd")
        distro.expire_passwd("alice")
        m_lock.assert_called_once_with("alice")

    def test_unlock_empty_name_returns_false(self, distro, pf_utils):
        assert distro.unlock_passwd("") is False

    def test_unlock_user_not_disabled_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001"}
        ]
        assert distro.unlock_passwd("alice") is False
        pf_utils.replace_config_element.assert_not_called()

    def test_unlock_disabled_user(self, distro, pf_utils):
        # regression test: "disabled" is a boolean-flag-style element,
        # same convention as "enable" -- an empty <disabled></disabled>
        # tag deserializes to None via _element_to_dict, not a truthy
        # value, so unlock_passwd must check for the key's *presence*,
        # not the truthiness of its value.
        pf_utils.get_config_elements.return_value = [
            {"name": "alice", "uid": "2001", "disabled": None}
        ]
        assert distro.unlock_passwd("alice") is True
        node = pf_utils.replace_config_element.call_args[0][3]
        assert "disabled" not in node
        pf_utils.sync_users_groups.assert_called_once()


class TestAddUser:
    def test_empty_name_returns_false(self, distro, pf_utils):
        assert distro.add_user("") is False
        pf_utils.get_config_elements.assert_not_called()

    def test_existing_user_returns_false(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = [{"name": "alice"}]
        assert distro.add_user("alice") is False
        pf_utils.set_config_value.assert_not_called()

    def test_creates_user_with_uid_increment(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]

        assert distro.add_user("alice") is True

        pf_utils.set_config_value.assert_called_once_with(
            "/pfsense/system/nextuid", "2002"
        )
        appended_user = pf_utils.append_config_element.call_args[0][1]
        assert appended_user == {
            "name": "alice",
            "uid": "2001",
            "scope": "user",
        }
        pf_utils.sync_users_groups.assert_called_once()

    def test_gecos_sets_description(self, distro, pf_utils):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]

        distro.add_user("alice", gecos="Alice Example")

        appended_user = pf_utils.append_config_element.call_args[0][1]
        assert appended_user["descr"] == "Alice Example"

    def test_expiredate_is_reformatted_to_pfsense_convention(
        self, distro, pf_utils
    ):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]

        distro.add_user("alice", expiredate="2030-01-15")

        appended_user = pf_utils.append_config_element.call_args[0][1]
        assert appended_user["expires"] == "15/01/2030"

    def test_groups_kwarg_as_single_string_is_normalized(
        self, distro, pf_utils, mocker
    ):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]
        m_add_to_group = mocker.patch.object(
            distro, "_add_user_to_group", return_value=True
        )

        distro.add_user("alice", groups="admins")

        m_add_to_group.assert_called_once_with("2001", "admins")

    def test_missing_group_logs_warning_but_user_creation_still_succeeds(
        self, distro, pf_utils, mocker, caplog
    ):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]
        mocker.patch.object(distro, "_add_user_to_group", return_value=False)

        assert distro.add_user("alice", groups=["ghosts"]) is True
        assert "ghosts" in caplog.text

    def test_passwd_kwarg_sets_hashed_password(self, distro, pf_utils, mocker):
        pf_utils.get_config_elements.return_value = []
        pf_utils.get_config_values.return_value = ["2001"]
        m_set_passwd = mocker.patch.object(distro, "set_passwd")

        distro.add_user("alice", passwd="$2b$12$abcdefg")

        m_set_passwd.assert_called_once_with(
            "alice", "$2b$12$abcdefg", hashed=True
        )
