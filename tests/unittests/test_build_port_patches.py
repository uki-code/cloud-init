# This file is part of cloud-init. See LICENSE file for license information.

"""
Regression guard for build-port/'s FreeBSD packaging patches (see the
"UKI cloud-init fork: versioning, _PACKAGED_VERSION, and a pfSense-
installable pkg" plan): if setup.py, cloudinit/settings.py, or
cloudinit/netinfo.py ever change in a way that shifts the context these
patches expect, this catches it here -- the actual pkg build can't be
exercised by this test suite directly, since it needs a real FreeBSD ports
framework/build jail.
"""

import os
import shutil
import subprocess

import pytest

from tests.helpers import cloud_init_project_dir

PATCH_TARGETS = [
    ("patch-setup.py", "setup.py"),
    ("patch-cloudinit_settings.py", "cloudinit/settings.py"),
    ("extra-cloudinit_netinfo.py", "cloudinit/netinfo.py"),
]


@pytest.mark.parametrize("patch_name,target", PATCH_TARGETS)
def test_build_port_patch_applies_cleanly(patch_name, target, tmp_path):
    patch_file = cloud_init_project_dir(f"build-port/files/{patch_name}")
    source_file = cloud_init_project_dir(target)

    staged = tmp_path / target
    staged.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy(source_file, staged)

    result = subprocess.run(
        ["patch", "--dry-run", "-p0", "-i", patch_file],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"{patch_name} no longer applies cleanly to {target} -- "
        f"build-port/ needs updating alongside this change.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


def test_build_port_makefile_referenced_files_exist():
    """
    Sanity-check the handful of paths build-port/Makefile references
    directly (license files, man pages, shebang'd tools) still exist --
    catches drift without needing to parse/run the Makefile itself.
    """
    referenced = [
        "LICENSE-Apache2.0",
        "LICENSE-GPLv3",
        "doc/man/cloud-id.1",
        "doc/man/cloud-init-per.1",
        "doc/man/cloud-init.1",
        "tools/hook-hotplug",
        "tools/read-dependencies",
        "tools/read-version",
        "tools/validate-yaml.py",
        "config/cloud.cfg.d/05_logging.cfg",
    ]
    missing = [
        path
        for path in referenced
        if not os.path.exists(cloud_init_project_dir(path))
    ]
    assert (
        not missing
    ), f"build-port/Makefile references missing paths: {missing}"
