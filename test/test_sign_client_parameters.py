#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import os
import subprocess
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

SCRIPT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "scripts_installer", "sign-client-parameters.sh"
)
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


class TestSignClientParameters(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.work = directory.name
        self.config = self.path("config")
        self.certificates = self.path("certificates")
        self.output = self.path("output")
        os.mkdir(self.config)
        os.mkdir(self.certificates)
        for name in CONFIG_FILES:
            self.write(os.path.join(self.config, name), name)
        for name in CERTIFICATE_FILES:
            self.write(os.path.join(self.certificates, name), name)
        self.key, self.certificate = self.new_certificate("server", "medulla.example.test")

    def path(self, *names):
        return os.path.join(self.work, *names)

    def write(self, path, content):
        with open(path, "w") as output:
            output.write(content)

    def new_certificate(self, prefix, common_name):
        key, certificate = self.path(prefix + ".key"), self.path(prefix + ".crt")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
             "-subj", "/CN=" + common_name, "-keyout", key, "-out", certificate],
            check=True, capture_output=True,
        )
        return key, certificate

    def sign(self, organisation="client-a", key=None, certificate=None, download_tag=""):
        return subprocess.run(
            ["bash", SCRIPT, "--organisation=" + organisation, "--download-tag=" + download_tag,
             "--config-dir=" + self.config,
             "--certificates-dir=" + self.certificates, "--key=" + (key or self.key),
             "--certificate=" + (certificate or self.certificate), "--output=" + self.output],
            capture_output=True, text=True,
        )

    def published(self, name, organisation="client-a"):
        return os.path.join(self.output, organisation, name)

    def manifest(self, organisation="client-a"):
        with tarfile.open(self.published("parameters.tar", organisation)) as tar:
            return json.load(tar.extractfile("manifest.json"))

    def assertFails(self, result, message):
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(message, result.stderr)

    def test_three_files_are_published(self):
        self.assertEqual(self.sign().returncode, 0)
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.output, "client-a"))),
            ["parameters.sig", "parameters.tar", "server.crt"],
        )

    def test_manifest_describes_the_server_and_the_organisation(self):
        self.sign()
        self.assertEqual(
            self.manifest(),
            {"server": "medulla.example.test", "organisation": "client-a", "version": 1},
        )

    def test_archive_holds_all_the_parameters(self):
        self.sign()
        with tarfile.open(self.published("parameters.tar")) as tar:
            names = tar.getnames()
        # Exact names: the agent refuses a member with a path, even "./"
        self.assertEqual(sorted(names), sorted(CONFIG_FILES + CERTIFICATE_FILES + ("manifest.json",)))

    def test_signature_matches_the_certificate(self):
        self.sign()
        public = self.path("public.pem")
        with open(public, "w") as output:
            subprocess.run(
                ["openssl", "x509", "-in", self.published("server.crt"), "-noout", "-pubkey"],
                check=True, stdout=output,
            )
        subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", public, "-signature",
             self.published("parameters.sig"), self.published("parameters.tar")],
            check=True, capture_output=True,
        )

    def test_version_goes_up_at_each_signature(self):
        self.sign()
        self.sign()
        self.assertEqual(self.manifest()["version"], 2)

    def test_each_organisation_has_its_own_version(self):
        self.sign("client-a")
        self.sign("client-a")
        self.sign("client-b")
        self.assertEqual(self.manifest("client-a")["version"], 2)
        self.assertEqual(self.manifest("client-b")["version"], 1)

    def test_parameters_are_published_under_the_download_tag(self):
        self.sign("client-a", download_tag="7f3c-tag")
        self.assertEqual(os.listdir(self.output), ["7f3c-tag"])
        self.assertEqual(self.manifest("7f3c-tag")["organisation"], "client-a")

    def test_version_follows_the_download_tag(self):
        self.sign("client-a", download_tag="7f3c-tag")
        self.sign("client-a", download_tag="7f3c-tag")
        self.assertEqual(self.manifest("7f3c-tag")["version"], 2)

    def test_download_tag_that_could_escape_the_directory_is_refused(self):
        self.assertFails(self.sign(download_tag="../evil"), "Invalid download tag")
        self.assertFalse(os.path.exists(self.output))

    def test_whole_certificate_chain_is_published(self):
        with open(self.certificate) as source:
            chain = source.read()
        with open(self.certificate, "a") as output:
            output.write(chain)
        self.assertEqual(self.sign().returncode, 0)
        with open(self.published("server.crt")) as published:
            self.assertEqual(published.read().count("BEGIN CERTIFICATE"), 2)

    def test_no_temporary_directory_is_left(self):
        self.sign()
        self.assertEqual(os.listdir(self.output), ["client-a"])

    def test_organisation_that_could_escape_the_directory_is_refused(self):
        self.assertFails(self.sign("../evil"), "Invalid organisation")
        self.assertFalse(os.path.exists(self.output))

    def test_key_of_another_certificate_is_refused(self):
        other_key, _ = self.new_certificate("other", "other.example.test")
        self.assertFails(self.sign(key=other_key), "does not match")

    def test_expired_certificate_is_refused(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "medulla.example.test")])
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        expired = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=30))
            .not_valid_after(now - timedelta(days=1))
            .sign(key, hashes.SHA256())
        )
        key_file, certificate_file = self.path("expired.key"), self.path("expired.crt")
        with open(key_file, "wb") as output:
            output.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        with open(certificate_file, "wb") as output:
            output.write(expired.public_bytes(serialization.Encoding.PEM))
        self.assertFails(self.sign(key=key_file, certificate=certificate_file), "has expired")

    def test_missing_key_is_refused(self):
        self.assertFails(self.sign(key=self.path("missing.key")), "Cannot read the signing key")

    def test_missing_parameter_file_publishes_nothing(self):
        os.remove(os.path.join(self.config, "inventory.ini"))
        self.assertFails(self.sign(), "Missing file inventory.ini")
        self.assertFalse(os.path.exists(os.path.join(self.output, "client-a")))

    def test_unreadable_published_version_is_refused(self):
        self.sign()
        self.write(self.published("parameters.tar"), "garbage")
        self.assertFails(self.sign(), "Cannot read the version")


if __name__ == "__main__":
    unittest.main()
