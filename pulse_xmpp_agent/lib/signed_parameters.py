# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Verify the signed client parameters downloaded by the base agent.

The chain of trust follows the UEFI Secure Boot principle:

    root key (embedded in the agent)
      -> signs the certificate of each Medulla server
      -> signs the revocation list
    server key
      -> signs the parameters archive of each organisation

Nothing read from the archive is trusted before its signature is checked.
"""
import io
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MANIFEST_NAME = "manifest.json"
ACCEPTED_CERTIFICATE_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512)


class ParametersRefused(Exception):
    """The parameters must not be applied. The message gives the reason."""


def _load_certificate(pem, label):
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError:
        raise ParametersRefused(f"The {label} certificate is not readable")


def _rsa_public_key(certificate, label):
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise ParametersRefused(f"The {label} certificate does not hold an RSA key")
    return public_key


def _is_signed_by(certificate, signature, data, label):
    try:
        _rsa_public_key(certificate, label).verify(
            signature, data, padding.PKCS1v15(), hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


def _validity_dates(certificate):
    # The *_utc attributes replace the naive ones from cryptography 42
    if hasattr(certificate, "not_valid_before_utc"):
        return certificate.not_valid_before_utc, certificate.not_valid_after_utc
    return (
        certificate.not_valid_before.replace(tzinfo=timezone.utc),
        certificate.not_valid_after.replace(tzinfo=timezone.utc),
    )


def _check_server_certificate(root, server):
    if server.issuer != root.subject:
        raise ParametersRefused("The server certificate was not issued by the root")
    if not isinstance(server.signature_hash_algorithm, ACCEPTED_CERTIFICATE_HASHES):
        raise ParametersRefused("The server certificate uses a weak hash algorithm")
    try:
        _rsa_public_key(root, "root").verify(
            server.signature,
            server.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ParametersRefused("The server certificate is not signed by the root")

    not_before, not_after = _validity_dates(server)
    if not not_before <= datetime.now(timezone.utc) <= not_after:
        raise ParametersRefused("The server certificate is not valid at this date")

    try:
        constraints = server.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return
    if constraints.value.ca:
        raise ParametersRefused("The server certificate must not be an authority")


def _check_not_revoked(root, server, revocation_list, signature, minimum_version):
    if not _is_signed_by(root, signature, revocation_list, "root"):
        raise ParametersRefused("The revocation list is not signed by the root")
    try:
        content = json.loads(revocation_list)
        version = content["version"]
        revoked = content["revoked"]
    except (ValueError, KeyError, TypeError):
        raise ParametersRefused("The revocation list is not readable")
    if type(version) is not int or not isinstance(revoked, list):
        raise ParametersRefused("The revocation list is not readable")
    if version < minimum_version:
        raise ParametersRefused(
            f"Revocation list version {version} is older than {minimum_version}"
        )
    if format(server.serial_number, "x") in revoked:
        raise ParametersRefused("This server is revoked")
    return version


def _read_manifest(archive):
    try:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            manifest = json.load(tar.extractfile(MANIFEST_NAME))
    except (tarfile.TarError, KeyError, ValueError, TypeError, AttributeError):
        raise ParametersRefused("The parameters manifest is not readable")
    if not isinstance(manifest, dict):
        raise ParametersRefused("The parameters manifest is not readable")
    return manifest


def _common_name(certificate):
    names = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return names[0].value if names else None


def verify_parameters(
    root_pem,
    server_pem,
    archive,
    signature,
    revocation_list,
    revocation_signature,
    expected_server,
    expected_organisation,
    installed_version=0,
    installed_revocation_version=0,
):
    """
    Check the whole chain of trust of a parameters archive.

    Args:
        root_pem (bytes): Root certificate embedded in the agent.
        server_pem (bytes): Certificate published by the server.
        archive (bytes): Parameters archive (tar).
        signature (bytes): Signature of the archive by the server key.
        revocation_list (bytes): Revocation list (JSON).
        revocation_signature (bytes): Signature of the list by the root key.
        expected_server (str): Name of the server the agent was given.
        expected_organisation (str): Tag of the organisation of the agent.
        installed_version (int): Last parameters version accepted.
        installed_revocation_version (int): Last revocation list version accepted.

    Returns:
        dict: The manifest, plus "revocation_version" to remember for next time.

    Raises:
        ParametersRefused: If any check fails.
    """
    root = _load_certificate(root_pem, "root")
    server = _load_certificate(server_pem, "server")

    _check_server_certificate(root, server)
    revocation_version = _check_not_revoked(
        root, server, revocation_list, revocation_signature, installed_revocation_version
    )
    if not _is_signed_by(server, signature, archive, "server"):
        raise ParametersRefused("The parameters signature is invalid")

    manifest = _read_manifest(archive)
    if _common_name(server) != expected_server or manifest.get("server") != expected_server:
        raise ParametersRefused(f"These parameters are not for server {expected_server}")
    if manifest.get("organisation") != expected_organisation:
        raise ParametersRefused(
            f"These parameters are not for organisation {expected_organisation}"
        )
    version = manifest.get("version")
    if type(version) is not int:
        raise ParametersRefused("The parameters version is not readable")
    if version < installed_version:
        raise ParametersRefused(
            f"Parameters version {version} is older than {installed_version}"
        )
    return dict(manifest, revocation_version=revocation_version)


def extract_parameters(archive, destination):
    """
    Write the files of a verified archive into destination.

    Every member is checked before the first write, so a refused archive
    leaves the destination untouched.

    Args:
        archive (bytes): Archive already accepted by verify_parameters.
        destination (str): Directory of the agent configuration files.

    Returns:
        list: Names of the files written.

    Raises:
        ParametersRefused: If a member could write outside destination.
    """
    files = {}
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            if not member.isfile() or os.path.basename(member.name) != member.name:
                raise ParametersRefused(f"Unsafe archive member: {member.name}")
            if member.name in ("", ".", ".."):
                raise ParametersRefused(f"Unsafe archive member: {member.name}")
            if member.name != MANIFEST_NAME:
                files[member.name] = tar.extractfile(member).read()

    for name, content in files.items():
        descriptor, temporary = tempfile.mkstemp(dir=destination)
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
        os.replace(temporary, os.path.join(destination, name))
    return sorted(files)
