"""Tests for tools/render-template"""

import sys

import pytest

from cloudinit import subp, templater, util
from tests.helpers import cloud_init_project_dir

# TODO(Look to align with tools.render-template or cloudinit.distos.OSFAMILIES)
DISTRO_VARIANTS = [
    "amazon",
    "arch",
    "azurelinux",
    "centos",
    "debian",
    "eurolinux",
    "fedora",
    "freebsd",
    "gentoo",
    "mariner",
    "netbsd",
    "openbsd",
    "pfsense",
    "photon",
    "rhel",
    "suse",
    "ubuntu",
    "unknown",
]


@pytest.mark.allow_subp_for(sys.executable)
class TestRenderCloudCfg:
    cmd = [sys.executable, cloud_init_project_dir("tools/render-template")]
    tmpl_path = cloud_init_project_dir("config/cloud.cfg.tmpl")
    init_path = cloud_init_project_dir("sysvinit/freebsd/dsidentify.tmpl")

    def test_variant_sets_distro_in_cloud_cfg_subp(self, tmpdir):
        outfile = tmpdir.join("outcfg").strpath

        subp.subp(self.cmd + ["--variant", "ubuntu", self.tmpl_path, outfile])
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())
        assert system_cfg["system_info"]["distro"] == "ubuntu"

    def test_variant_pfsense_accepted_by_cli_subp(self, tmpdir):
        """Regression test: tools/render-template's own --variant choices
        list must stay in sync with OSFAMILIES/_get_variant() -- pfsense
        was previously missing here and failed with 'invalid choice',
        even though it's a real, recognized variant everywhere else.
        setup.py's render_tmpl() shells out to this CLI at package-install
        time, so this is the one path the templater.render_template()
        based tests below don't exercise.
        """
        outfile = tmpdir.join("outcfg").strpath

        subp.subp(
            self.cmd + ["--variant", "pfsense", self.tmpl_path, outfile]
        )
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())
        assert system_cfg["system_info"]["distro"] == "pfsense"

    def test_variant_sets_prefix_in_cloud_cfg_subp(self, tmpdir):
        outfile = tmpdir.join("outcfg").strpath

        subp.subp(
            self.cmd
            + [
                "--variant",
                "freebsd",
                "--prefix",
                "/usr/local",
                self.init_path,
                outfile,
            ]
        )
        with open(outfile) as stream:
            init_cfg = stream.readlines()
        assert 'command="/usr/local/lib/cloud-init/ds-identify"\n' in init_cfg

    @pytest.mark.parametrize("variant", (DISTRO_VARIANTS))
    def test_variant_sets_distro_in_cloud_cfg(self, variant, tmpdir):
        """Testing parametrized inputs with imported function saves ~0.5s per
        call versus calling as subp
        """
        outfile = tmpdir.join("outcfg").strpath

        templater.render_template(
            variant, self.tmpl_path, outfile, is_yaml=True
        )
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())
        if variant == "unknown":
            variant = "ubuntu"  # Unknown is defaulted to ubuntu
        assert system_cfg["system_info"]["distro"] == variant

    @pytest.mark.parametrize("variant", (DISTRO_VARIANTS))
    def test_variant_sets_default_user_in_cloud_cfg(self, variant, tmpdir):
        """Testing parametrized inputs with imported function saves ~0.5s per
        call versus calling as subp
        """
        outfile = tmpdir.join("outcfg").strpath
        templater.render_template(
            variant, self.tmpl_path, outfile, is_yaml=True
        )
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())

        default_user_exceptions = {
            "amazon": "ec2-user",
            "rhel": "cloud-user",
            "centos": "cloud-user",
            "unknown": "ubuntu",
        }
        default_user = system_cfg["system_info"]["default_user"]["name"]
        assert default_user == default_user_exceptions.get(variant, variant)

    @pytest.mark.parametrize("variant", (DISTRO_VARIANTS))
    def test_variant_sets_disable_root_in_cloud_cfg(self, variant, tmpdir):
        """Testing parametrized inputs with imported function saves ~0.5s per
        call versus calling as subp
        """
        outfile = tmpdir.join("outcfg").strpath
        templater.render_template(
            variant, self.tmpl_path, outfile, is_yaml=True
        )
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())

        disable_root_false_variants = {"freebsd", "photon", "pfsense"}
        expected = variant not in disable_root_false_variants
        assert system_cfg["disable_root"] == expected

    @pytest.mark.parametrize(
        "variant,renderers",
        (
            ("freebsd", ["freebsd"]),
            ("netbsd", ["netbsd"]),
            ("openbsd", ["openbsd"]),
            ("pfsense", ["pfsense"]),
            ("ubuntu", ["netplan", "eni", "sysconfig"]),
        ),
    )
    def test_variant_sets_network_renderer_priority_in_cloud_cfg(
        self, variant, renderers, tmpdir
    ):
        """Testing parametrized inputs with imported function saves ~0.5s per
        call versus calling as subp
        """
        outfile = tmpdir.join("outcfg").strpath
        templater.render_template(
            variant, self.tmpl_path, outfile, is_yaml=True
        )
        with open(outfile) as stream:
            system_cfg = util.load_yaml(stream.read())

        assert renderers == system_cfg["system_info"]["network"]["renderers"]
