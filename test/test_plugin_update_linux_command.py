#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests cibles pour le code retour du plugin update_linux_command.

file : test/test_plugin_update_linux_command.py

Execution :
    python3 -m unittest discover -s test -p 'test_plugin_update_linux_command.py' -v
"""

from pathlib import Path
import sys
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "pulse_xmpp_agent"))

lib_module = sys.modules.setdefault("lib", types.ModuleType("lib"))
utils_module = types.ModuleType("lib.utils")


def _identity_decorator(function):
    return function


utils_module.set_logging_level = _identity_decorator
setattr(lib_module, "utils", utils_module)
sys.modules["lib.utils"] = utils_module

from pulse_xmpp_agent.pluginsmachine.plugin_update_linux_command import _result_return_code


class TestPluginUpdateLinuxCommandReturnCode(unittest.TestCase):
    def test_returns_error_when_requested_update_action_failed(self):
        result = {
            "section": "update",
            "requested_actions": ["kernel"],
            "unknown_actions": [],
            "applied": [
                {
                    "distribution": "debian",
                    "actions": ["kernel"],
                    "applied": [],
                    "failed": [{"action": "kernel", "error": "apt failed"}],
                }
            ],
        }

        self.assertEqual(_result_return_code(result), 255)

    def test_returns_success_for_policy_update_with_applied_result(self):
        result = {
            "section": "update",
            "requested_actions": [],
            "unknown_actions": [],
            "applied": [{"policy": "kernel-only"}],
        }

        self.assertEqual(_result_return_code(result), 0)

    def test_returns_error_for_incomplete_update_payload(self):
        result = {
            "section": "update",
            "requested_actions": [],
            "unknown_actions": [],
            "applied": [],
            "message": "No supported linux_actions found for update section",
        }

        self.assertEqual(_result_return_code(result), 255)

    def test_returns_error_for_unsupported_section(self):
        result = {
            "section": "unknown",
            "requested_actions": [],
            "unknown_actions": [],
            "applied": [],
            "message": "Unsupported section or empty payload",
        }

        self.assertEqual(_result_return_code(result), 255)


if __name__ == "__main__":
    unittest.main()
