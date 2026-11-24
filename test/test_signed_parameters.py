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
import urllib.error
from datetime import datetime, timedelta, timezone
from unittest import mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

from pulse_xmpp_agent.lib.signed_parameters import (
    ParametersRefused,
    ParametersUnavailable,
    discover_bootstrap,
    download_parameters,
    extract_parameters,
    read_bootstrap,
    read_dns_bootstrap,
    read_registry_bootstrap,
    refresh_parameters,
    update_parameters,
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
    manifest = {
        "server": server,
        "organisation": organisation,
        "download_tag": organisation,
        "version": version,
    }
    return tar_of(
        {
            "manifest.json": json.dumps(manifest).encode(),
            "agentconf.ini": b"[connection]\nserver = medulla.example.test\n",
        }
    )


class ChainTestCase(unittest.TestCase):
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


class TestVerifyParameters(ChainTestCase):
    def verify(
        self, archive=None, signature=None, server=None, intermediate=None, revocations=None, **options
    ):
        archive = parameters() if archive is None else archive
        signature = sign(self.server_key, archive) if signature is None else signature
        revocation_list, revocation_signature = revocations or self.revocations()
        arguments = {"expected_server": SERVER, "expected_download_tag": ORGANISATION}
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


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *arguments):
        self.close()


class TestUpdateParameters(ChainTestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.etc = os.path.join(directory.name, "etc")
        os.mkdir(self.etc)
        self.state = os.path.join(directory.name, "state.json")
        self.requests = []
        self.archive = parameters()
        revocation_list, revocation_signature = self.revocations()
        self.published = {
            "parameters.tar": self.archive,
            "parameters.sig": sign(self.server_key, self.archive),
            "server.crt": pem(self.server) + pem(self.intermediate),
            "revocations.json": revocation_list,
            "revocations.sig": revocation_signature,
        }
        patcher = mock.patch("urllib.request.urlopen", side_effect=self.serve)
        patcher.start()
        self.addCleanup(patcher.stop)

    def serve(self, request, timeout=None, context=None):
        self.requests.append(request)
        name = request.full_url.rsplit("/", 1)[1]
        if name not in self.published:
            raise urllib.error.URLError("not found")
        return FakeResponse(self.published[name])

    def update(self):
        return update_parameters(pem(self.root), SERVER, ORGANISATION, self.etc, self.state)

    def test_parameters_are_downloaded_verified_and_written(self):
        self.assertEqual(self.update()["version"], 5)
        self.assertEqual(os.listdir(self.etc), ["agentconf.ini"])

    def test_requests_use_the_download_tag_and_the_referer(self):
        self.update()
        self.assertEqual(
            self.requests[0].full_url,
            f"https://{SERVER}/medulla_agent/{ORGANISATION}/parameters.tar",
        )
        self.assertEqual(self.requests[0].get_header("Referer"), f"https://{SERVER}/")

    def test_accepted_versions_are_remembered(self):
        self.update()
        with open(self.state) as content:
            self.assertEqual(
                json.load(content), {"parameters_version": 5, "revocation_version": 1}
            )

    def test_older_parameters_are_refused_after_an_update(self):
        self.update()
        older = parameters(version=4)
        self.published["parameters.tar"] = older
        self.published["parameters.sig"] = sign(self.server_key, older)
        with self.assertRaisesRegex(ParametersRefused, "older than 5"):
            self.update()

    def test_same_version_is_not_written_again(self):
        self.update()
        path = os.path.join(self.etc, "agentconf.ini")
        with open(path, "w") as output:
            output.write("rewritten by the agent")
        self.assertFalse(self.update()["applied"])
        with open(path) as content:
            self.assertEqual(content.read(), "rewritten by the agent")

    def test_same_version_is_written_again_after_a_reinstallation(self):
        self.update()
        os.remove(os.path.join(self.etc, "agentconf.ini"))
        self.assertTrue(self.update()["applied"])
        self.assertTrue(os.path.exists(os.path.join(self.etc, "agentconf.ini")))

    def test_older_version_stays_refused_after_a_reinstallation(self):
        self.update()
        os.remove(os.path.join(self.etc, "agentconf.ini"))
        older = parameters(version=4)
        self.published["parameters.tar"] = older
        self.published["parameters.sig"] = sign(self.server_key, older)
        with self.assertRaisesRegex(ParametersRefused, "older than 5"):
            self.update()
        self.assertFalse(os.path.exists(os.path.join(self.etc, "agentconf.ini")))

    def test_newer_version_is_written(self):
        self.update()
        newer = parameters(version=6)
        self.published["parameters.tar"] = newer
        self.published["parameters.sig"] = sign(self.server_key, newer)
        self.assertTrue(self.update()["applied"])

    def bootstrap(self):
        with open(os.path.join(self.etc, "bootstrap.ini"), "w") as output:
            output.write(f"[bootstrap]\nserver={SERVER}\ntag={ORGANISATION}\n")
        with open(os.path.join(self.etc, "parameters-root.crt"), "wb") as output:
            output.write(pem(self.root))

    def test_refresh_without_bootstrap_does_nothing(self):
        self.assertFalse(refresh_parameters(self.etc))
        self.assertEqual(self.requests, [])

    def test_refresh_writes_the_parameters(self):
        self.bootstrap()
        self.assertTrue(refresh_parameters(self.etc))
        self.assertTrue(os.path.exists(os.path.join(self.etc, "agentconf.ini")))
        self.assertTrue(os.path.exists(os.path.join(self.etc, "parameters-state.json")))

    def test_refresh_does_not_raise_when_the_server_is_down(self):
        self.bootstrap()
        self.published.clear()
        with self.assertLogs(level="ERROR"):
            self.assertFalse(refresh_parameters(self.etc))

    def test_refresh_does_not_raise_on_refused_parameters(self):
        self.bootstrap()
        self.published["parameters.tar"] += b"x"
        with self.assertLogs(level="ERROR"):
            self.assertFalse(refresh_parameters(self.etc))
        self.assertFalse(os.path.exists(os.path.join(self.etc, "agentconf.ini")))

    def test_refresh_does_not_raise_without_root_certificate(self):
        self.bootstrap()
        os.remove(os.path.join(self.etc, "parameters-root.crt"))
        with self.assertLogs(level="ERROR"):
            self.assertFalse(refresh_parameters(self.etc))

    def empty_bootstrap(self):
        # What the base installer writes without /server and /tag
        self.bootstrap()
        with open(os.path.join(self.etc, "bootstrap.ini"), "w") as output:
            output.write("[bootstrap]\nserver=\ntag=\n")

    def test_refresh_finds_the_server_in_the_registry(self):
        self.empty_bootstrap()
        with fake_registry({"server": SERVER, "tag": ORGANISATION}), mock.patch("subprocess.run"):
            self.assertTrue(refresh_parameters(self.etc))
        self.assertEqual(
            read_bootstrap(os.path.join(self.etc, "bootstrap.ini")), (SERVER, ORGANISATION)
        )

    def test_refresh_keeps_the_server_found_first(self):
        self.empty_bootstrap()
        with fake_registry({"server": SERVER, "tag": ORGANISATION}), mock.patch("subprocess.run"):
            refresh_parameters(self.etc)
        with fake_registry({"server": "other.example.test", "tag": "other"}):
            refresh_parameters(self.etc)
        self.assertTrue(all(SERVER in request.full_url for request in self.requests))

    def test_refresh_waits_when_no_source_gives_a_server(self):
        self.empty_bootstrap()
        with fake_registry({}), mock.patch(
            "pulse_xmpp_agent.lib.signed_parameters.read_dns_bootstrap", return_value=None
        ):
            self.assertFalse(refresh_parameters(self.etc))
        self.assertEqual(self.requests, [])
        self.assertIsNone(read_bootstrap(os.path.join(self.etc, "bootstrap.ini")))

    def test_windows_settings_are_applied_with_new_parameters(self):
        self.bootstrap()
        archive = tar_of(
            {
                "manifest.json": json.dumps(
                    {
                        "server": SERVER,
                        "organisation": ORGANISATION,
                        "download_tag": ORGANISATION,
                        "version": 5,
                    }
                ).encode(),
                "agentconf.ini": b"[connection]\n",
                "medulla-rootca.cert.pem": b"root",
                "medulla-ca-chain.cert.pem": b"chain",
            }
        )
        self.published["parameters.tar"] = archive
        self.published["parameters.sig"] = sign(self.server_key, archive)
        with mock.patch("sys.platform", "win32"), mock.patch("subprocess.run") as run:
            self.assertTrue(refresh_parameters(self.etc))
        commands = [call.args[0] for call in run.call_args_list]
        self.assertEqual([command[0] for command in commands], ["icacls", "certutil", "certutil"])
        self.assertEqual(commands[1][:3], ["certutil", "-addstore", "root"])
        self.assertEqual(commands[2][:3], ["certutil", "-addstore", "ca"])

    def test_windows_settings_are_not_applied_without_new_parameters(self):
        self.bootstrap()
        refresh_parameters(self.etc)
        with mock.patch("sys.platform", "win32"), mock.patch("subprocess.run") as run:
            self.assertFalse(refresh_parameters(self.etc))
        run.assert_not_called()

    def test_failing_windows_command_does_not_raise(self):
        self.bootstrap()
        with mock.patch("sys.platform", "win32"), mock.patch(
            "subprocess.run", side_effect=OSError("not found")
        ), self.assertLogs(level="ERROR"):
            self.assertTrue(refresh_parameters(self.etc))

    def test_refused_parameters_write_nothing(self):
        self.published["parameters.tar"] += b"x"
        with self.assertRaises(ParametersRefused):
            self.update()
        self.assertEqual(os.listdir(self.etc), [])
        self.assertFalse(os.path.exists(self.state))

    def test_missing_file_changes_nothing(self):
        del self.published["revocations.sig"]
        with self.assertRaisesRegex(ParametersUnavailable, "revocations.sig"):
            self.update()
        self.assertEqual(os.listdir(self.etc), [])

    def test_unreadable_state_is_refused(self):
        with open(self.state, "w") as output:
            output.write("garbage")
        with self.assertRaisesRegex(ParametersRefused, "not readable"):
            self.update()

    def test_invalid_server_or_tag_is_refused_without_a_request(self):
        for server, tag in (("evil.test/../x", "tag"), (SERVER, "../evil")):
            with self.assertRaisesRegex(ParametersUnavailable, "Invalid"):
                download_parameters(server, tag)
        self.assertEqual(self.requests, [])

    def test_too_large_file_is_refused(self):
        with mock.patch("pulse_xmpp_agent.lib.signed_parameters.MAX_DOWNLOAD_SIZE", 4):
            with self.assertRaisesRegex(ParametersUnavailable, "too large"):
                self.update()


class TestReadBootstrap(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = os.path.join(directory.name, "bootstrap.ini")

    def test_server_and_tag_are_read(self):
        with open(self.path, "w") as output:
            output.write("[bootstrap]\nserver=medulla.example.test\ntag=7f3c\n")
        self.assertEqual(read_bootstrap(self.path), ("medulla.example.test", "7f3c"))

    def test_missing_file_gives_nothing(self):
        self.assertIsNone(read_bootstrap(self.path))

    def test_incomplete_file_gives_nothing(self):
        with open(self.path, "w") as output:
            output.write("[bootstrap]\nserver=medulla.example.test\n")
        self.assertIsNone(read_bootstrap(self.path))


class FakeWinreg:
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 1
    KEY_WOW64_64KEY = 2

    def __init__(self, values):
        self.values = values
        self.opened = []

    def OpenKey(self, root, path, reserved, access):
        if self.values is None:
            raise FileNotFoundError(path)
        self.opened.append((root, path, access))
        return mock.MagicMock()

    def QueryValueEx(self, key, name):
        if name not in self.values:
            raise FileNotFoundError(name)
        return self.values[name], 1


def fake_registry(values):
    """Windows registry holding values under the bootstrap key (None: no key)."""
    winreg = FakeWinreg(values)
    patcher = mock.patch.dict("sys.modules", {"winreg": winreg})
    platform = mock.patch("sys.platform", "win32")

    class Both:
        def __enter__(self):
            patcher.start()
            platform.start()
            return winreg

        def __exit__(self, *arguments):
            platform.stop()
            patcher.stop()

    return Both()


class TestDiscoverBootstrap(unittest.TestCase):
    def test_registry_values_are_read_in_the_64_bit_view(self):
        with fake_registry({"server": f" {SERVER} ", "tag": ORGANISATION}) as winreg:
            self.assertEqual(read_registry_bootstrap(), (SERVER, ORGANISATION))
        self.assertEqual(winreg.opened, [("HKLM", r"SOFTWARE\Medulla\Bootstrap", 3)])

    def test_missing_registry_key_gives_nothing(self):
        with fake_registry(None):
            self.assertIsNone(read_registry_bootstrap())

    def test_incomplete_registry_key_gives_nothing(self):
        with fake_registry({"server": SERVER}):
            self.assertIsNone(read_registry_bootstrap())

    def test_registry_is_only_read_on_windows(self):
        with mock.patch("sys.platform", "linux"):
            self.assertIsNone(read_registry_bootstrap())

    def test_invalid_registry_values_are_refused(self):
        with fake_registry({"server": "evil.test/../x", "tag": ORGANISATION}):
            with self.assertLogs(level="ERROR"):
                self.assertIsNone(discover_bootstrap())


def srv(host, port=443, priority=0, weight=0):
    return mock.Mock(host=host, port=port, priority=priority, weight=weight)


def txt(text):
    return mock.Mock(text=text)


class TestDnsBootstrap(unittest.TestCase):
    def setUp(self):
        self.records = {}
        self.queries = []
        for target, value in (
            ("socket.getfqdn", "pc42.client.example"),
            ("pulse_xmpp_agent.lib.signed_parameters._dns_query", self.query),
        ):
            patcher = (
                mock.patch(target, return_value=value)
                if isinstance(value, str)
                else mock.patch(target, side_effect=value)
            )
            patcher.start()
            self.addCleanup(patcher.stop)

    def query(self, name, record_type):
        self.queries.append((name, record_type))
        return self.records.get((name, record_type), [])

    def publish(self, services, texts):
        self.records[("_medulla._tcp.client.example", "SRV")] = services
        self.records[("_medulla.client.example", "TXT")] = texts

    def test_server_and_tag_are_read_in_the_machine_domain(self):
        self.publish([srv("medulla.client.example.")], [txt("tag=7f3c")])
        self.assertEqual(read_dns_bootstrap(), ("medulla.client.example", "7f3c"))
        self.assertEqual(
            self.queries,
            [("_medulla._tcp.client.example", "SRV"), ("_medulla.client.example", "TXT")],
        )

    def test_other_port_than_https_is_kept(self):
        self.publish([srv("medulla.client.example", port=8443)], [txt("tag=7f3c")])
        self.assertEqual(read_dns_bootstrap(), ("medulla.client.example:8443", "7f3c"))

    def test_preferred_service_is_used(self):
        self.publish(
            [srv("backup.client.example", priority=10), srv("main.client.example", priority=0)],
            [txt("tag=7f3c")],
        )
        self.assertEqual(read_dns_bootstrap()[0], "main.client.example")

    def test_tag_is_found_among_other_texts(self):
        self.publish([srv("medulla.client.example")], [txt("v=spf1 -all"), txt(b" tag = 7f3c ")])
        self.assertEqual(read_dns_bootstrap()[1], "7f3c")

    def test_no_tag_gives_nothing(self):
        self.publish([srv("medulla.client.example")], [txt("v=spf1 -all")])
        self.assertIsNone(read_dns_bootstrap())

    def test_no_service_gives_nothing_without_asking_for_the_tag(self):
        self.assertIsNone(read_dns_bootstrap())
        self.assertEqual(self.queries, [("_medulla._tcp.client.example", "SRV")])

    def test_machine_without_domain_asks_nothing(self):
        with mock.patch("socket.getfqdn", return_value="pc42"):
            self.assertIsNone(read_dns_bootstrap())
        self.assertEqual(self.queries, [])

    def test_missing_dns_library_gives_nothing(self):
        with mock.patch(
            "pulse_xmpp_agent.lib.signed_parameters._dns_query", side_effect=ImportError("pycares")
        ), self.assertLogs(level="ERROR"):
            self.assertIsNone(read_dns_bootstrap())

    def test_registry_comes_before_the_dns(self):
        self.publish([srv("dns.client.example")], [txt("tag=from-dns")])
        with fake_registry({"server": SERVER, "tag": ORGANISATION}):
            self.assertEqual(discover_bootstrap(), (SERVER, ORGANISATION))

    def test_dns_is_used_without_registry(self):
        self.publish([srv("dns.client.example")], [txt("tag=from-dns")])
        with fake_registry(None):
            self.assertEqual(discover_bootstrap(), ("dns.client.example", "from-dns"))

    def test_invalid_dns_values_are_refused(self):
        self.publish([srv("evil.example/../x")], [txt("tag=7f3c")])
        with mock.patch("sys.platform", "linux"), self.assertLogs(level="ERROR"):
            self.assertIsNone(discover_bootstrap())


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
