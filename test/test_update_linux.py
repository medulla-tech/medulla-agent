#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests cibles pour la selection des paquets noyau Linux.

file : test/test_update_linux.py

L'objectif est de verrouiller le scenario observe en production : un paquet
``linux-image-*`` residuel en etat ``rc`` ou un paquet encore installe mais
sans candidat APT ne doit pas etre passe a ``apt-get --only-upgrade`` dans la
politique ``kernel-only``.

Execution :
    python3 -m unittest discover -s test -p 'test_update_linux.py' -v
"""

from pathlib import Path
import sys
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "pulse_xmpp_agent"))

sys.modules.setdefault("distro", types.ModuleType("distro"))

lib_module = sys.modules.setdefault("lib", types.ModuleType("lib"))

uuid_module = types.ModuleType("lib.uuid_deterministic")


class _DeterministicUUID:
    @staticmethod
    def get_deterministic_uuid():
        return "test-uuid"


uuid_module.DeterministicUUID = _DeterministicUUID
utils_module = types.ModuleType("lib.utils")
utils_module.serialnumbermachine = lambda: "test-serial"

setattr(lib_module, "uuid_deterministic", uuid_module)
setattr(lib_module, "utils", utils_module)
sys.modules["lib.uuid_deterministic"] = uuid_module
sys.modules["lib.utils"] = utils_module

from pulse_xmpp_agent.lib.update_linux import DebianSystem


class DummyDebianSystem(DebianSystem):
    """Double de test minimal pour piloter les sorties shell."""

    def __init__(self, outputs=None):
        self.outputs = outputs or {}
        self.commands = []
        self.system_info = {}
        self.dry_run = False
        self.intranet_security = False
        self.sources_name = None

    def _run(self, cmd: str) -> str:
        self.commands.append(cmd)
        if cmd not in self.outputs:
            raise AssertionError(f"Commande inattendue en test: {cmd}")
        return self.outputs[cmd]

    def _apt_base_opts(self) -> str:
        return ""

    def _apt_dry_run_opts(self) -> str:
        return ""


class TestKernelPackageSelection(unittest.TestCase):
    def test_installed_kernel_packages_ignore_residual_configs(self):
        system = DummyDebianSystem(
            {
                "dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\\n'": (
                    "ii\tlinux-image-6.1.0-51-amd64\n"
                    "rc\tlinux-image-6.1.0-32-amd64\n"
                    "ii\tlinux-headers-6.1.0-51-amd64\n"
                    "ii\tbash\n"
                )
            }
        )

        self.assertEqual(
            system._installed_kernel_packages(),
            ["linux-headers-6.1.0-51-amd64", "linux-image-6.1.0-51-amd64"],
        )

    def test_packages_with_apt_candidate_excludes_none_candidate(self):
        system = DummyDebianSystem(
            {
                "apt-cache policy linux-image-6.1.0-51-amd64": (
                    "linux-image-6.1.0-51-amd64:\n"
                    "  Installed: 6.1.177-1\n"
                    "  Candidate: 6.1.180-1\n"
                ),
                "apt-cache policy linux-image-6.1.0-49-amd64": (
                    "linux-image-6.1.0-49-amd64:\n"
                    "  Installed: 6.1.170-1\n"
                    "  Candidate: (none)\n"
                ),
            }
        )

        self.assertEqual(
            system._packages_with_apt_candidate(
                ["linux-image-6.1.0-51-amd64", "linux-image-6.1.0-49-amd64"]
            ),
            ["linux-image-6.1.0-51-amd64"],
        )

    def test_kernel_only_update_uses_only_eligible_packages(self):
        system = DummyDebianSystem(
            {
                "apt-get -qq update ": "",
                "dpkg-query -W -f='${db:Status-Abbrev}\t${binary:Package}\\n'": (
                    "ii\tlinux-image-6.1.0-51-amd64\n"
                    "rc\tlinux-image-6.1.0-32-amd64\n"
                    "ii\tlinux-headers-6.1.0-49-amd64\n"
                ),
                "apt-cache policy linux-headers-6.1.0-49-amd64": (
                    "linux-headers-6.1.0-49-amd64:\n"
                    "  Installed: 6.1.170-1\n"
                    "  Candidate: (none)\n"
                ),
                "apt-cache policy linux-image-6.1.0-51-amd64": (
                    "linux-image-6.1.0-51-amd64:\n"
                    "  Installed: 6.1.177-1\n"
                    "  Candidate: 6.1.180-1\n"
                ),
                (
                    "apt-get -qq install --only-upgrade linux-image-6.1.0-51-amd64 -y  "
                    "-o APT::Get::Only-Upgrade=true "
                ): "",
            }
        )

        system.update("kernel-only")

        self.assertIn(
            "apt-get -qq install --only-upgrade linux-image-6.1.0-51-amd64 -y  -o APT::Get::Only-Upgrade=true ",
            system.commands,
        )


if __name__ == "__main__":
    unittest.main()
