#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
import subprocess
import tempfile
import unittest

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TOOL = os.path.join(BASE, "contrib", "parameters-ca", "parameters-ca.sh")
PUBLISH = os.path.join(BASE, "scripts_installer", "publish-revocations.sh")


class TestPublishRevocations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = os.path.join(cls.directory.name, "root")
        cls.other_root = os.path.join(cls.directory.name, "other-root")
        for root in (cls.root, cls.other_root):
            subprocess.run(["bash", TOOL, "init", "--dir=" + root, "--test"], check=True, capture_output=True)

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = directory.name
        self.server = os.path.join(self.work, "server")
        self.output = os.path.join(self.work, "output")
        for tag in ("tag-a", "tag-b"):
            os.makedirs(os.path.join(self.output, tag))
            open(os.path.join(self.output, tag, "parameters.tar"), "w").close()
        os.makedirs(os.path.join(self.output, "no-parameters"))

    def signed_list(self, version, root=None):
        source = tempfile.mkdtemp(dir=self.work)
        path = os.path.join(source, "revocations.json")
        with open(path, "w") as output:
            json.dump({"version": version, "revoked": []}, output)
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-sign", os.path.join(root or self.root, "root.key"),
             "-out", os.path.join(source, "revocations.sig"), path],
            check=True,
        )
        return source

    def publish(self, source):
        return subprocess.run(
            ["bash", PUBLISH, "--source=" + source, "--root=" + os.path.join(self.root, "root.crt"),
             "--revocations-dir=" + self.server, "--output=" + self.output],
            capture_output=True, text=True,
        )

    def version(self, *path):
        with open(os.path.join(*path, "revocations.json")) as content:
            return json.load(content)["version"]

    def assertFails(self, result, message):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_list_is_published_for_every_organisation(self):
        result = self.publish(self.signed_list(2))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("2 organisation(s)", result.stdout)
        self.assertEqual(self.version(self.server), 2)
        self.assertEqual(self.version(self.output, "tag-a"), 2)
        self.assertEqual(self.version(self.output, "tag-b"), 2)

    def test_folder_without_parameters_is_left_alone(self):
        self.publish(self.signed_list(2))
        self.assertEqual(os.listdir(os.path.join(self.output, "no-parameters")), [])

    def test_no_temporary_file_is_left(self):
        self.publish(self.signed_list(2))
        self.assertEqual(
            sorted(os.listdir(self.server)), ["revocations.json", "revocations.sig"]
        )

    def test_list_of_another_root_is_refused(self):
        self.assertFails(self.publish(self.signed_list(2, self.other_root)), "not signed by the root")
        self.assertFalse(os.path.exists(self.server))

    def test_modified_list_is_refused(self):
        source = self.signed_list(2)
        with open(os.path.join(source, "revocations.json"), "w") as output:
            json.dump({"version": 2, "revoked": ["abc"]}, output)
        self.assertFails(self.publish(source), "not signed by the root")

    def test_older_list_is_refused(self):
        self.publish(self.signed_list(3))
        self.assertFails(self.publish(self.signed_list(2)), "older than 3")
        self.assertEqual(self.version(self.server), 3)

    def test_same_version_is_accepted(self):
        source = self.signed_list(3)
        self.publish(source)
        self.assertEqual(self.publish(source).returncode, 0)

    def test_missing_list_is_refused(self):
        source = self.signed_list(2)
        os.remove(os.path.join(source, "revocations.sig"))
        self.assertFails(self.publish(source), "Cannot read the revocation list")


if __name__ == "__main__":
    unittest.main()
