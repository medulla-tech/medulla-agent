# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Verify the signed client parameters downloaded by the base agent.

The chain of trust follows the UEFI Secure Boot principle:

    root key (its certificate is embedded in the agent)
      -> signs the intermediate authority
      -> signs the revocation list
    intermediate key
      -> signs the certificate of each Medulla server
    server key
      -> signs the parameters archive of each organisation

Nothing read from the archive is trusted before its signature is checked.
"""
import configparser
import io
import json
import os
import re
import tarfile
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MANIFEST_NAME = "manifest.json"
PUBLISHED_FILES = (
    "parameters.tar",
    "parameters.sig",
    "server.crt",
    "revocations.json",
    "revocations.sig",
)
MAX_DOWNLOAD_SIZE = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT = 30
NAME_REGEX = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(:[0-9]+)?")
ACCEPTED_CERTIFICATE_HASHES = (hashes.SHA256, hashes.SHA384, hashes.SHA512)
PEM_CERTIFICATE = re.compile(
    b"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", re.DOTALL
)


class ParametersRefused(Exception):
    """The parameters must not be applied. The message gives the reason."""


class ParametersUnavailable(Exception):
    """The parameters could not be downloaded. Nothing was changed."""


def _load_certificate(pem, label):
    try:
        return x509.load_pem_x509_certificate(pem)
    except ValueError:
        raise ParametersRefused(f"The {label} certificate is not readable")


def _load_chain(pem):
    # The server publishes its certificate followed by the intermediate
    certificates = PEM_CERTIFICATE.findall(pem)
    if len(certificates) != 2:
        raise ParametersRefused("The server chain must hold the server and the intermediate")
    return (
        _load_certificate(certificates[0], "server"),
        _load_certificate(certificates[1], "intermediate"),
    )


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


def _check_issued_by(issuer, certificate, label, issuer_label):
    if certificate.issuer != issuer.subject:
        raise ParametersRefused(f"The {label} certificate was not issued by the {issuer_label}")
    if not isinstance(certificate.signature_hash_algorithm, ACCEPTED_CERTIFICATE_HASHES):
        raise ParametersRefused(f"The {label} certificate uses a weak hash algorithm")
    try:
        _rsa_public_key(issuer, issuer_label).verify(
            certificate.signature,
            certificate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            certificate.signature_hash_algorithm,
        )
    except InvalidSignature:
        raise ParametersRefused(f"The {label} certificate is not signed by the {issuer_label}")

    not_before, not_after = _validity_dates(certificate)
    if not not_before <= datetime.now(timezone.utc) <= not_after:
        raise ParametersRefused(f"The {label} certificate is not valid at this date")


def _is_authority(certificate):
    try:
        constraints = certificate.extensions.get_extension_for_class(x509.BasicConstraints)
    except x509.ExtensionNotFound:
        return False
    return constraints.value.ca


def _check_chain(root, intermediate, server):
    _check_issued_by(root, intermediate, "intermediate", "root")
    if not _is_authority(intermediate):
        raise ParametersRefused("The intermediate certificate must be an authority")
    _check_issued_by(intermediate, server, "server", "intermediate")
    if _is_authority(server):
        raise ParametersRefused("The server certificate must not be an authority")


def _check_not_revoked(root, certificates, revocation_list, signature, minimum_version):
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
    for label, certificate in certificates.items():
        if format(certificate.serial_number, "x") in revoked:
            raise ParametersRefused(f"This {label} is revoked")
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
    expected_download_tag,
    installed_version=0,
    installed_revocation_version=0,
):
    """
    Check the whole chain of trust of a parameters archive.

    Args:
        root_pem (bytes): Root certificate embedded in the agent.
        server_pem (bytes): Certificate of the server, then the intermediate.
        archive (bytes): Parameters archive (tar).
        signature (bytes): Signature of the archive by the server key.
        revocation_list (bytes): Revocation list (JSON).
        revocation_signature (bytes): Signature of the list by the root key.
        expected_server (str): Name of the server the agent was given.
        expected_download_tag (str): Download tag of the organisation of the agent.
        installed_version (int): Last parameters version accepted.
        installed_revocation_version (int): Last revocation list version accepted.

    Returns:
        dict: The manifest, plus "revocation_version" to remember for next time.

    Raises:
        ParametersRefused: If any check fails.
    """
    root = _load_certificate(root_pem, "root")
    server, intermediate = _load_chain(server_pem)

    _check_chain(root, intermediate, server)
    revocation_version = _check_not_revoked(
        root,
        {"server": server, "intermediate": intermediate},
        revocation_list,
        revocation_signature,
        installed_revocation_version,
    )
    if not _is_signed_by(server, signature, archive, "server"):
        raise ParametersRefused("The parameters signature is invalid")

    manifest = _read_manifest(archive)
    if _common_name(server) != expected_server or manifest.get("server") != expected_server:
        raise ParametersRefused(f"These parameters are not for server {expected_server}")
    if manifest.get("download_tag") != expected_download_tag:
        raise ParametersRefused(
            f"These parameters are not for organisation {expected_download_tag}"
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


def read_bootstrap(path):
    """
    Read the server and the download tag given to the installer.

    Args:
        path (str): The bootstrap.ini file written by the installer.

    Returns:
        tuple: (server, download_tag), or None without a usable file.
    """
    config = configparser.ConfigParser()
    if not config.read(path):
        return None
    server = config.get("bootstrap", "server", fallback="").strip()
    download_tag = config.get("bootstrap", "tag", fallback="").strip()
    if not server or not download_tag:
        return None
    return server, download_tag


def download_parameters(server, download_tag, tls_context=None):
    """
    Download the files published for an organisation.

    Nothing downloaded here is trusted before verify_parameters.

    Args:
        server (str): Address of the Medulla server.
        download_tag (str): Download tag of the organisation.
        tls_context (ssl.SSLContext): Overrides the default TLS checks.

    Returns:
        dict: The content of each file of PUBLISHED_FILES.

    Raises:
        ParametersUnavailable: If a file cannot be downloaded.
    """
    if not NAME_REGEX.fullmatch(server) or not NAME_REGEX.fullmatch(download_tag):
        raise ParametersUnavailable("Invalid server or download tag")

    base_url = f"https://{server}/medulla_agent/{download_tag}"
    files = {}
    for name in PUBLISHED_FILES:
        # The web server filters this directory on the Referer
        request = urllib.request.Request(
            f"{base_url}/{name}", headers={"Referer": f"https://{server}/"}
        )
        try:
            with urllib.request.urlopen(
                request, timeout=DOWNLOAD_TIMEOUT, context=tls_context
            ) as response:
                content = response.read(MAX_DOWNLOAD_SIZE + 1)
        except (urllib.error.URLError, OSError) as error:
            raise ParametersUnavailable(f"Cannot download {name}: {error}")
        if len(content) > MAX_DOWNLOAD_SIZE:
            raise ParametersUnavailable(f"{name} is too large")
        files[name] = content
    return files


def _read_state(path):
    if not os.path.exists(path):
        return {"parameters_version": 0, "revocation_version": 0}
    try:
        with open(path) as content:
            state = json.load(content)
        versions = (state["parameters_version"], state["revocation_version"])
    except (OSError, ValueError, KeyError, TypeError):
        # Going back to zero would accept an older version
        raise ParametersRefused(f"The state file {path} is not readable")
    if any(type(version) is not int for version in versions):
        raise ParametersRefused(f"The state file {path} is not readable")
    return state


def _write_state(path, state):
    descriptor, temporary = tempfile.mkstemp(dir=os.path.dirname(path) or ".")
    with os.fdopen(descriptor, "w") as output:
        json.dump(state, output)
    os.replace(temporary, path)


def update_parameters(
    root_pem, server, download_tag, destination, state_path, tls_context=None
):
    """
    Download, verify and write the parameters of an organisation.

    Args:
        root_pem (bytes): Root certificate embedded in the agent.
        server (str): Address of the Medulla server.
        download_tag (str): Download tag of the organisation.
        destination (str): Directory of the agent configuration files.
        state_path (str): File remembering the last accepted versions.
        tls_context (ssl.SSLContext): Overrides the default TLS checks.

    Returns:
        dict: The manifest of the applied parameters.

    Raises:
        ParametersUnavailable: If the files cannot be downloaded.
        ParametersRefused: If any check fails. Nothing is written.
    """
    state = _read_state(state_path)
    files = download_parameters(server, download_tag, tls_context)
    manifest = verify_parameters(
        root_pem,
        files["server.crt"],
        files["parameters.tar"],
        files["parameters.sig"],
        files["revocations.json"],
        files["revocations.sig"],
        server,
        download_tag,
        state["parameters_version"],
        state["revocation_version"],
    )
    extract_parameters(files["parameters.tar"], destination)
    _write_state(
        state_path,
        {
            "parameters_version": manifest["version"],
            "revocation_version": manifest["revocation_version"],
        },
    )
    return manifest
