#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import io
import json
import os
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from pulse_xmpp_agent.lib.signed_parameters import (
    ParametersRefused,
    extract_parameters,
    verify_parameters,
)

SERVER = "medulla.example.test"
ORGANISATION = "client-a"


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def certificate(
    subject, issuer, public_key, signing_key, ca=False, days=(-1, 365), algorithm=hashes.SHA256
):
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    return (
        x509.CertificateBuilder()
        .subject_name(name(subject))
        .issuer_name(name(issuer))
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + timedelta(days=days[0]))
        .not_valid_after(now + timedelta(days=days[1]))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .sign(signing_key, algorithm())
    )


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def sign(key, data):
    return key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def tar_of(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as tar:
        for filename, content in files.items():
            info = tarfile.TarInfo(filename)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return output.getvalue()


def parameters(server=SERVER, organisation=ORGANISATION, version=5):
    manifest = {"server": server, "organisation": organisation, "version": version}
    return tar_of(
        {
            "manifest.json": json.dumps(manifest).encode(),
            "agentconf.ini": b"[connection]\nserver = medulla.example.test\n",
        }
    )


class TestVerifyParameters(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root_key = new_key()
        cls.root = certificate("Root", "Root", cls.root_key.public_key(), cls.root_key, ca=True)
        cls.intermediate_key = new_key()
        cls.intermediate = certificate(
            "Intermediate", "Root", cls.intermediate_key.public_key(), cls.root_key, ca=True
        )
        cls.server_key = new_key()
        cls.server = certificate(
            SERVER, "Intermediate", cls.server_key.public_key(), cls.intermediate_key
        )

    def revocations(self, revoked=(), version=1):
        content = json.dumps({"version": version, "revoked": list(revoked)}).encode()
        return content, sign(self.root_key, content)

    def verify(
        self, archive=None, signature=None, server=None, intermediate=None, revocations=None, **options
    ):
        archive = parameters() if archive is None else archive
        signature = sign(self.server_key, archive) if signature is None else signature
        revocation_list, revocation_signature = revocations or self.revocations()
        arguments = {"expected_server": SERVER, "expected_organisation": ORGANISATION}
        arguments.update(options)
        return verify_parameters(
            pem(self.root),
            pem(server or self.server) + pem(intermediate or self.intermediate),
            archive,
            signature,
            revocation_list,
            revocation_signature,
            **arguments,
        )

    def assertRefused(self, reason, **arguments):
        with self.assertRaisesRegex(ParametersRefused, reason):
            self.verify(**arguments)

    def test_valid_parameters_are_accepted(self):
        manifest = self.verify(installed_version=4)
        self.assertEqual(manifest["version"], 5)
        self.assertEqual(manifest["organisation"], ORGANISATION)
        self.assertEqual(manifest["revocation_version"], 1)

    def test_same_version_is_accepted_for_a_reinstallation(self):
        self.assertEqual(self.verify(installed_version=5)["version"], 5)

    def test_modified_parameters_are_refused(self):
        archive = parameters()
        self.assertRefused(
            "signature is invalid",
            archive=archive + b"x",
            signature=sign(self.server_key, archive),
        )

    def test_fake_root_with_the_same_name_is_refused(self):
        pirate_key = new_key()
        fake_intermediate = certificate(
            "Intermediate", "Root", pirate_key.public_key(), pirate_key, ca=True
        )
        fake_server = certificate(SERVER, "Intermediate", pirate_key.public_key(), pirate_key)
        archive = parameters()
        self.assertRefused(
            "intermediate certificate is not signed by the root",
            archive=archive,
            signature=sign(pirate_key, archive),
            server=fake_server,
            intermediate=fake_intermediate,
        )

    def test_server_signed_by_another_key_is_refused(self):
        pirate_key = new_key()
        fake = certificate(SERVER, "Intermediate", pirate_key.public_key(), pirate_key)
        self.assertRefused("server certificate is not signed by the intermediate", server=fake)

    def test_server_signed_directly_by_the_root_is_refused(self):
        direct = certificate(SERVER, "Root", self.server_key.public_key(), self.root_key)
        self.assertRefused("not issued by the intermediate", server=direct)

    def test_chain_without_intermediate_is_refused(self):
        archive = parameters()
        revocation_list, revocation_signature = self.revocations()
        with self.assertRaisesRegex(ParametersRefused, "must hold the server and the intermediate"):
            verify_parameters(
                pem(self.root), pem(self.server), archive, sign(self.server_key, archive),
                revocation_list, revocation_signature, SERVER, ORGANISATION,
            )

    def test_certificate_with_a_weak_hash_is_refused(self):
        weak = certificate(
            SERVER, "Intermediate", self.server_key.public_key(), self.intermediate_key,
            algorithm=hashes.SHA224,
        )
        self.assertRefused("server certificate uses a weak hash algorithm", server=weak)

    def test_intermediate_that_is_not_an_authority_is_refused(self):
        leaf = certificate("Intermediate", "Root", self.intermediate_key.public_key(), self.root_key)
        self.assertRefused("must be an authority", intermediate=leaf)

    def test_expired_intermediate_is_refused(self):
        expired = certificate(
            "Intermediate", "Root", self.intermediate_key.public_key(), self.root_key,
            ca=True, days=(-30, -1),
        )
        self.assertRefused("intermediate certificate is not valid at this date", intermediate=expired)

    def test_revoked_intermediate_is_refused(self):
        serial = format(self.intermediate.serial_number, "x")
        self.assertRefused("This intermediate is revoked", revocations=self.revocations([serial]))

    def test_certificate_from_another_issuer_is_refused(self):
        pirate_key = new_key()
        fake = certificate(SERVER, "Pirate", pirate_key.public_key(), pirate_key)
        self.assertRefused("not issued by the intermediate", server=fake)

    def test_parameters_of_another_server_are_refused(self):
        self.assertRefused("not for server", expected_server="other.example.test")

    def test_manifest_of_another_server_is_refused(self):
        self.assertRefused("not for server", archive=parameters(server="other.example.test"))

    def test_parameters_of_another_organisation_are_refused(self):
        # Same server, valid signature: the case of a shared SaaS server
        self.assertRefused("not for organisation", archive=parameters(organisation="client-b"))

    def test_older_parameters_are_refused(self):
        self.assertRefused("older than 6", installed_version=6)

    def test_revoked_server_is_refused(self):
        serial = format(self.server.serial_number, "x")
        self.assertRefused("This server is revoked", revocations=self.revocations([serial]))

    def test_other_servers_are_not_affected_by_a_revocation(self):
        self.assertEqual(self.verify(revocations=self.revocations(["abc123"]))["version"], 5)

    def test_tampered_revocation_list_is_refused(self):
        serial = format(self.server.serial_number, "x")
        _, signature = self.revocations([serial])
        tampered = json.dumps({"version": 1, "revoked": []}).encode()
        self.assertRefused("not signed by the root", revocations=(tampered, signature))

    def test_older_revocation_list_is_refused(self):
        self.assertRefused(
            "Revocation list version 1 is older than 2", installed_revocation_version=2
        )

    def test_expired_certificate_is_refused(self):
        expired = certificate(
            SERVER, "Intermediate", self.server_key.public_key(), self.intermediate_key, days=(-30, -1)
        )
        self.assertRefused("server certificate is not valid at this date", server=expired)

    def test_authority_certificate_is_refused_as_server(self):
        authority = certificate(
            SERVER, "Intermediate", self.server_key.public_key(), self.intermediate_key, ca=True
        )
        self.assertRefused("must not be an authority", server=authority)

    def test_unreadable_certificate_is_refused(self):
        with self.assertRaisesRegex(ParametersRefused, "not readable"):
            revocation_list, revocation_signature = self.revocations()
            verify_parameters(
                pem(self.root), b"-----BEGIN CERTIFICATE-----x-----END CERTIFICATE-----" * 2, b"", b"", revocation_list, revocation_signature,
                SERVER, ORGANISATION,
            )

    def test_signed_archive_without_manifest_is_refused(self):
        self.assertRefused("manifest is not readable", archive=tar_of({"agentconf.ini": b""}))

    def test_signed_archive_that_is_not_a_tar_is_refused(self):
        self.assertRefused("manifest is not readable", archive=b"not a tar archive")

    def test_version_that_is_not_an_integer_is_refused(self):
        self.assertRefused("version is not readable", archive=parameters(version="9"))
        self.assertRefused("version is not readable", archive=parameters(version=True))


class TestExtractParameters(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)

    def path(self, filename):
        return os.path.join(self.directory.name, filename)

    def test_files_are_written_without_the_manifest(self):
        self.assertEqual(extract_parameters(parameters(), self.directory.name), ["agentconf.ini"])
        self.assertTrue(os.path.exists(self.path("agentconf.ini")))
        self.assertFalse(os.path.exists(self.path("manifest.json")))

    def test_existing_file_is_replaced(self):
        with open(self.path("agentconf.ini"), "w") as existing:
            existing.write("old")
        extract_parameters(parameters(), self.directory.name)
        with open(self.path("agentconf.ini")) as result:
            self.assertIn("medulla.example.test", result.read())

    def test_path_traversal_is_refused_and_nothing_is_written(self):
        archive = tar_of({"good.ini": b"x", "../evil.ini": b"x"})
        with self.assertRaisesRegex(ParametersRefused, "Unsafe archive member"):
            extract_parameters(archive, self.directory.name)
        self.assertEqual(os.listdir(self.directory.name), [])

    def test_symbolic_link_is_refused(self):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode="w") as tar:
            link = tarfile.TarInfo("agentconf.ini")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            tar.addfile(link)
        with self.assertRaisesRegex(ParametersRefused, "Unsafe archive member"):
            extract_parameters(output.getvalue(), self.directory.name)


if __name__ == "__main__":
    unittest.main()
