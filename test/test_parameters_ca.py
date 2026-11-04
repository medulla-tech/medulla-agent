#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest

from cryptography import x509

from pulse_xmpp_agent.lib.signed_parameters import ParametersRefused, verify_parameters

BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
TOOL = os.path.join(BASE, "contrib", "parameters-ca", "parameters-ca.sh")
SIGN = os.path.join(BASE, "scripts_installer", "sign-client-parameters.sh")
SERVER = "medulla.example.test"
ORGANISATION = "client-a"
CONFIG_FILES = (
    "agentconf.ini",
    "agentconf.ini.tpl",
    "manage_scheduler_machine.ini",
    "inventory.ini",
    "start_machine.ini",
    "startupdate.ini",
    "updateopenssh.ini",
    "updatetightvnc.ini",
    "updatebackupclient.ini",
    "am___server_tcpip.ini",
)
CERTIFICATE_FILES = ("medulla-rootca.cert.pem", "medulla-ca-chain.cert.pem")


class TestParametersCa(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        cls.work = cls.directory.name
        cls.root = os.path.join(cls.work, "root")
        cls.intermediate = os.path.join(cls.work, "intermediate")
        cls.run_tool("init", "--dir=" + cls.root, "--test")
        cls.run_tool("intermediate", "--dir=" + cls.root, "--ca-dir=" + cls.intermediate, "--test")

    @classmethod
    def run_tool(cls, *arguments):
        result = subprocess.run(["bash", TOOL] + list(arguments), capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)
        return result

    def tool_fails(self, message, *arguments):
        result = subprocess.run(["bash", TOOL] + list(arguments), capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def path(self, *names):
        return os.path.join(self.work, *names)

    def read(self, *names):
        with open(self.path(*names), "rb") as content:
            return content.read()

    def new_server(self, label, name=SERVER):
        key_dir = self.path(label)
        self.run_tool("request", "--server=" + name, "--key-dir=" + key_dir)
        self.run_tool(
            "sign",
            "--ca-dir=" + self.intermediate,
            "--csr=" + os.path.join(key_dir, "server.csr"),
            "--out=" + os.path.join(key_dir, "server.crt"),
        )
        return key_dir

    def sign_parameters(self, key_dir):
        config = os.path.join(key_dir, "config")
        os.mkdir(config)
        for name in CONFIG_FILES + CERTIFICATE_FILES:
            with open(os.path.join(config, name), "w") as output:
                output.write(name)
        subprocess.run(
            ["bash", SIGN, "--organisation=" + ORGANISATION, "--config-dir=" + config,
             "--certificates-dir=" + config, "--key=" + os.path.join(key_dir, "server.key"),
             "--certificate=" + os.path.join(key_dir, "server.crt"),
             "--output=" + os.path.join(key_dir, "output")],
            check=True, capture_output=True,
        )

    def agent_verifies(self, label):
        published = (label, "output", ORGANISATION)
        return verify_parameters(
            self.read("root", "root.crt"),
            self.read(*published, "server.crt"),
            self.read(*published, "parameters.tar"),
            self.read(*published, "parameters.sig"),
            self.read("root", "revocations.json"),
            self.read("root", "revocations.sig"),
            SERVER,
            ORGANISATION,
        )

    def test_whole_chain_is_accepted_by_the_agent(self):
        self.sign_parameters(self.new_server("accepted"))
        self.assertEqual(self.agent_verifies("accepted")["version"], 1)

    def test_revoked_server_is_refused_by_the_agent(self):
        key_dir = self.new_server("revoked")
        self.sign_parameters(key_dir)
        self.run_tool(
            "revoke", "--dir=" + self.root, "--certificate=" + os.path.join(key_dir, "server.crt")
        )
        with self.assertRaisesRegex(ParametersRefused, "is revoked"):
            self.agent_verifies("revoked")

    def test_revoked_intermediate_is_refused_by_the_agent(self):
        root, intermediate = self.path("root2"), self.path("intermediate2")
        self.run_tool("init", "--dir=" + root, "--test")
        self.run_tool("intermediate", "--dir=" + root, "--ca-dir=" + intermediate, "--test")
        key_dir = self.path("under-revoked")
        self.run_tool("request", "--server=" + SERVER, "--key-dir=" + key_dir)
        self.run_tool(
            "sign", "--ca-dir=" + intermediate, "--csr=" + os.path.join(key_dir, "server.csr"),
            "--out=" + os.path.join(key_dir, "server.crt"),
        )
        self.sign_parameters(key_dir)
        self.run_tool(
            "revoke", "--dir=" + root, "--certificate=" + os.path.join(intermediate, "ca.crt")
        )
        published = ("under-revoked", "output", ORGANISATION)
        with self.assertRaisesRegex(ParametersRefused, "This intermediate is revoked"):
            verify_parameters(
                self.read("root2", "root.crt"),
                self.read(*published, "server.crt"),
                self.read(*published, "parameters.tar"),
                self.read(*published, "parameters.sig"),
                self.read("root2", "revocations.json"),
                self.read("root2", "revocations.sig"),
                SERVER,
                ORGANISATION,
            )

    def test_signing_does_not_need_the_root_key(self):
        copy = self.path("offline")
        os.mkdir(copy)
        for name in ("ca.key", "ca.crt"):
            shutil.copy(os.path.join(self.intermediate, name), copy)
        key_dir = self.path("no-root")
        self.run_tool("request", "--server=" + SERVER, "--key-dir=" + key_dir)
        self.run_tool(
            "sign", "--ca-dir=" + copy, "--csr=" + os.path.join(key_dir, "server.csr"),
            "--out=" + os.path.join(key_dir, "server.crt"),
        )
        self.sign_parameters(key_dir)
        self.assertEqual(self.agent_verifies("no-root")["version"], 1)

    def test_intermediate_is_an_authority_limited_to_one_level(self):
        with open(os.path.join(self.intermediate, "ca.crt"), "rb") as content:
            certificate = x509.load_pem_x509_certificate(content.read())
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertTrue(constraints.value.ca)
        self.assertEqual(constraints.value.path_length, 0)

    def test_existing_intermediate_is_never_overwritten(self):
        self.tool_fails(
            "already exists", "intermediate", "--dir=" + self.root,
            "--ca-dir=" + self.intermediate, "--test",
        )

    def test_revocation_raises_the_list_version(self):
        before = json.loads(self.read("root", "revocations.json"))["version"]
        key_dir = self.new_server("version")
        self.run_tool(
            "revoke", "--dir=" + self.root, "--certificate=" + os.path.join(key_dir, "server.crt")
        )
        self.assertEqual(json.loads(self.read("root", "revocations.json"))["version"], before + 1)

    def test_root_key_is_private(self):
        mode = stat.S_IMODE(os.stat(self.path("root", "root.key")).st_mode)
        self.assertEqual(mode, 0o600)

    def test_server_key_is_private(self):
        key_dir = self.new_server("private")
        mode = stat.S_IMODE(os.stat(os.path.join(key_dir, "server.key")).st_mode)
        self.assertEqual(mode, 0o600)

    def test_test_root_is_marked_as_test(self):
        root = x509.load_pem_x509_certificate(self.read("root", "root.crt"))
        self.assertIn("TEST", root.subject.rfc4514_string())

    def test_server_certificate_is_not_an_authority(self):
        key_dir = self.new_server("leaf")
        with open(os.path.join(key_dir, "server.crt"), "rb") as content:
            certificate = x509.load_pem_x509_certificate(content.read())
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
        self.assertFalse(constraints.value.ca)

    def test_existing_root_is_never_overwritten(self):
        before = self.read("root", "root.key")
        self.tool_fails("already exists", "init", "--dir=" + self.root, "--test")
        self.assertEqual(self.read("root", "root.key"), before)

    def test_existing_server_key_is_never_overwritten(self):
        key_dir = self.new_server("overwrite")
        self.tool_fails("already exists", "request", "--server=" + SERVER, "--key-dir=" + key_dir)

    def test_invalid_server_name_is_refused(self):
        self.tool_fails(
            "Invalid server name", "request", "--server=../evil", "--key-dir=" + self.path("bad")
        )

    def test_invalid_request_is_refused(self):
        request = self.path("garbage.csr")
        with open(request, "w") as output:
            output.write("garbage")
        self.tool_fails(
            "Invalid request", "sign", "--ca-dir=" + self.intermediate, "--csr=" + request,
            "--out=" + self.path("garbage.crt"),
        )

    def test_certificate_of_another_root_cannot_be_revoked(self):
        other_root = self.path("other-root")
        self.run_tool("init", "--dir=" + other_root, "--test")
        self.tool_fails(
            "was not issued by this root", "revoke", "--dir=" + self.root,
            "--certificate=" + os.path.join(other_root, "root.crt"),
        )


if __name__ == "__main__":
    unittest.main()
