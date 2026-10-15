#!/usr/bin/python3
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Tests cibles pour updateagent et replicator.

file : test/test_updateagent_replicator.py

Execution :
    python3 -m unittest discover -s test -p 'test_updateagent_replicator.py' -v
"""

from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import types
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "pulse_xmpp_agent"))

lib_module = sys.modules.setdefault("lib", types.ModuleType("lib"))
utils_module = types.ModuleType("lib.utils")
update_remote_agent_module = types.ModuleType("lib.update_remote_agent")


def _identity_decorator(function):
    return function


utils_module.set_logging_level = _identity_decorator
setattr(lib_module, "utils", utils_module)
setattr(lib_module, "update_remote_agent", update_remote_agent_module)
sys.modules["lib.utils"] = utils_module
sys.modules["lib.update_remote_agent"] = update_remote_agent_module

from pulse_xmpp_agent.plugins_common import plugin_updateagent
from pulse_xmpp_agent import replicator


class _FakeRemoteAgent:
    def __init__(self, directory):
        self.directory = directory

    def get_fingerprint_agent_base(self):
        return "img-fingerprint"


class _FakeXmppObject:
    def __init__(self, img_agent, descriptor_master=None):
        self.img_agent = img_agent
        self.descriptor_master = descriptor_master
        self.reinstall_calls = 0

    def reinstall_agent(self):
        self.reinstall_calls += 1


class TestUpdateAgent(unittest.TestCase):
    def setUp(self):
        self.original_remote_agent = getattr(
            plugin_updateagent.update_remote_agent,
            "Update_Remote_Agent",
            None,
        )
        plugin_updateagent.update_remote_agent.Update_Remote_Agent = _FakeRemoteAgent

    def tearDown(self):
        if self.original_remote_agent is None:
            delattr(plugin_updateagent.update_remote_agent, "Update_Remote_Agent")
        else:
            plugin_updateagent.update_remote_agent.Update_Remote_Agent = self.original_remote_agent

    def test_dump_file_in_img_tolerates_missing_descriptor_master(self):
        with TemporaryDirectory() as temp_dir:
            img_agent = Path(temp_dir)
            (img_agent / "lib").mkdir()
            xmpp_object = _FakeXmppObject(str(img_agent), descriptor_master=None)

            plugin_updateagent.dump_file_in_img(
                xmpp_object,
                "linux_major_upgrade.py",
                b"print('ok')\n",
                "lib_agent",
            )

            self.assertEqual(xmpp_object.reinstall_calls, 0)
            self.assertEqual(
                (img_agent / "lib" / "linux_major_upgrade.py").read_bytes(),
                b"print('ok')\n",
            )


class TestReplicator(unittest.TestCase):
    def test_prepare_folder_rollback_replaces_previous_snapshot(self):
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            agent_dir = root / "agent"
            rollback_dir = root / "rollback"
            agent_dir.mkdir()
            rollback_dir.mkdir()
            (agent_dir / "agentversion").write_text("5.6.5\n", encoding="utf-8")
            (agent_dir / "launcher.py").write_text("launcher\n", encoding="utf-8")
            (agent_dir / "agentxmpp.py").write_text("agentxmpp\n", encoding="utf-8")
            (agent_dir / "connectionagent.py").write_text("connectionagent\n", encoding="utf-8")
            (agent_dir / "replicator.py").write_text("replicator\n", encoding="utf-8")
            (agent_dir / "lib").mkdir()
            (agent_dir / "script").mkdir()
            (agent_dir / "lib" / "module.py").write_text("module\n", encoding="utf-8")
            (rollback_dir / "stale.txt").write_text("obsolete\n", encoding="utf-8")

            replicator.prepare_folder_rollback(str(rollback_dir), str(agent_dir))

            self.assertFalse((rollback_dir / "stale.txt").exists())
            self.assertEqual(
                (rollback_dir / "agentversion").read_text(encoding="utf-8"),
                "5.6.5\n",
            )
            self.assertEqual(
                (rollback_dir / "lib" / "module.py").read_text(encoding="utf-8"),
                "module\n",
            )

    def test_safe_rmtree_ignores_missing_directory(self):
        with TemporaryDirectory() as temp_dir:
            missing_dir = Path(temp_dir) / "missing"
            replicator.safe_rmtree(str(missing_dir))
            self.assertFalse(missing_dir.exists())


if __name__ == "__main__":
    unittest.main()
