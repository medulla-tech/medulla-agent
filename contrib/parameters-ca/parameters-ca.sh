#!/bin/bash
#
# (c) 2026 Siveo, http://www.siveo.net
#
# $Id$
#
# This file is part of Medulla.
#
# Medulla is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Medulla is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Medulla; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# Manages the chain of trust of the client parameters:
#   root -> intermediate -> server certificates
# "init", "intermediate" and "revoke" need the root key, which stays offline.
# "sign" only needs the intermediate key. "request" runs on the Medulla server.
# None of the keys of the root or the intermediate belong on a client server.

set -eu
set -o pipefail
umask 077

NAME_REGEX='^[A-Za-z0-9][A-Za-z0-9._-]*$'
ROOT_DAYS=3650
INTERMEDIATE_DAYS=1825
SERVER_DAYS=365

display_usage() {
    echo "Usage:"
    echo "  $0 init --dir=<root dir> [--test]"
    echo "  $0 intermediate --dir=<root dir> --ca-dir=<intermediate dir> [--test]"
    echo "  $0 request --server=<name> [--key-dir=<dir>]"
    echo "  $0 sign --ca-dir=<intermediate dir> --csr=<file> --out=<file> [--days=<days>]"
    echo "  $0 revoke --dir=<root dir> --certificate=<file>"
    echo
    echo "  --test: creates a key without passphrase, for tests only"
}

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

sign_revocations() {
    openssl dgst -sha256 -sign "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/revocations.sig.new" \
        "${ROOT_DIR}/revocations.json.new"
    mv -f "${ROOT_DIR}/revocations.json.new" "${ROOT_DIR}/revocations.json"
    mv -f "${ROOT_DIR}/revocations.sig.new" "${ROOT_DIR}/revocations.sig"
    chmod 644 "${ROOT_DIR}/revocations.json" "${ROOT_DIR}/revocations.sig"
}

command_init() {
    [ ! -e "${ROOT_DIR}/root.key" ] || fail "A root already exists in ${ROOT_DIR}"
    mkdir -p "${ROOT_DIR}"
    local subject="/O=Siveo/CN=Medulla Parameters Root"
    local encryption=()
    if [ "${TEST_ROOT}" == "1" ]; then
        subject="/O=Siveo/CN=Medulla Parameters Root TEST"
        encryption=(-nodes)
    fi
    openssl req -x509 -newkey rsa:4096 "${encryption[@]}" -days "${ROOT_DAYS}" -sha256 \
        -subj "${subject}" -keyout "${ROOT_DIR}/root.key" -out "${ROOT_DIR}/root.crt" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign"
    chmod 600 "${ROOT_DIR}/root.key"
    chmod 644 "${ROOT_DIR}/root.crt"
    printf '{"version": 1, "revoked": []}\n' > "${ROOT_DIR}/revocations.json.new"
    sign_revocations
    echo "Root created in ${ROOT_DIR}"
}

command_intermediate() {
    [ -r "${ROOT_DIR}/root.key" ] || fail "No root in ${ROOT_DIR}"
    [ ! -e "${CA_DIR}/ca.key" ] || fail "An intermediate already exists in ${CA_DIR}"
    mkdir -p "${CA_DIR}"
    local subject="/O=Siveo/CN=Medulla Parameters Intermediate"
    local encryption=()
    if [ "${TEST_ROOT}" == "1" ]; then
        subject="/O=Siveo/CN=Medulla Parameters Intermediate TEST"
        encryption=(-nodes)
    fi
    openssl req -newkey rsa:4096 "${encryption[@]}" -sha256 -subj "${subject}" \
        -keyout "${CA_DIR}/ca.key" -out "${CA_DIR}/ca.csr"
    local extensions="${CA_DIR}/.ca.ext"
    printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n' > "${extensions}"
    openssl x509 -req -in "${CA_DIR}/ca.csr" -CA "${ROOT_DIR}/root.crt" -CAkey "${ROOT_DIR}/root.key" \
        -CAserial "${ROOT_DIR}/serial" -CAcreateserial -days "${INTERMEDIATE_DAYS}" -sha256 \
        -extfile "${extensions}" -out "${CA_DIR}/ca.crt" 2>/dev/null \
        || { rm -f "${extensions}"; fail "Cannot sign the intermediate"; }
    rm -f "${extensions}" "${CA_DIR}/ca.csr"
    chmod 600 "${CA_DIR}/ca.key"
    chmod 644 "${CA_DIR}/ca.crt"
    echo "Intermediate created in ${CA_DIR}"
}

command_request() {
    [[ ${SERVER_NAME} =~ ${NAME_REGEX} ]] || fail "Invalid server name: ${SERVER_NAME}"
    [ ! -e "${KEY_DIR}/server.key" ] || fail "A key already exists in ${KEY_DIR}"
    mkdir -p "${KEY_DIR}"
    openssl req -newkey rsa:3072 -nodes -sha256 -subj "/CN=${SERVER_NAME}" \
        -keyout "${KEY_DIR}/server.key" -out "${KEY_DIR}/server.csr"
    chmod 600 "${KEY_DIR}/server.key"
    chmod 644 "${KEY_DIR}/server.csr"
    echo "Send ${KEY_DIR}/server.csr to Siveo. The key stays on this server."
}

command_sign() {
    [ -r "${CA_DIR}/ca.key" ] || fail "No intermediate in ${CA_DIR}"
    [ -r "${CSR}" ] || fail "Cannot read the request ${CSR}"
    [[ ${DAYS} =~ ^[1-9][0-9]*$ ]] || fail "Invalid number of days: ${DAYS}"
    [ ! -e "${OUTPUT}" ] || fail "${OUTPUT} already exists"
    openssl req -in "${CSR}" -noout -verify 2>/dev/null || fail "Invalid request ${CSR}"
    local name
    name=$(openssl req -in "${CSR}" -noout -subject -nameopt multiline \
        | sed -n 's/^ *commonName *= *//p')
    [[ ${name} =~ ${NAME_REGEX} ]] || fail "Invalid server name: ${name}"

    local extensions="${CA_DIR}/.server.ext"
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n' > "${extensions}"
    openssl x509 -req -in "${CSR}" -CA "${CA_DIR}/ca.crt" -CAkey "${CA_DIR}/ca.key" \
        -CAserial "${CA_DIR}/serial" -CAcreateserial -days "${DAYS}" -sha256 \
        -extfile "${extensions}" -out "${OUTPUT}" 2>/dev/null \
        || { rm -f "${extensions}" "${OUTPUT}"; fail "Cannot sign ${CSR}"; }
    rm -f "${extensions}"
    # The agent receives the whole chain up to the root it already holds
    cat "${CA_DIR}/ca.crt" >> "${OUTPUT}"
    chmod 644 "${OUTPUT}"
    echo "Certificate of ${name} written to ${OUTPUT}"
}

command_revoke() {
    [ -r "${ROOT_DIR}/root.key" ] || fail "No root in ${ROOT_DIR}"
    [ -r "${CERTIFICATE}" ] || fail "Cannot read the certificate ${CERTIFICATE}"
    openssl verify -CAfile "${ROOT_DIR}/root.crt" -untrusted "${CERTIFICATE}" "${CERTIFICATE}" >/dev/null 2>&1 \
        || fail "${CERTIFICATE} was not issued by this root"
    local serial
    serial=$(openssl x509 -in "${CERTIFICATE}" -noout -serial | cut -d= -f2)
    python3 - "${ROOT_DIR}/revocations.json" "${serial}" <<'PYTHON'
import json
import sys

source, serial = sys.argv[1:3]
with open(source) as content:
    revocations = json.load(content)
# The agent compares the serial in lower case, without leading zeros
serial = format(int(serial, 16), "x")
if serial not in revocations["revoked"]:
    revocations["revoked"].append(serial)
revocations["version"] += 1
with open(source + ".new", "w") as content:
    json.dump(revocations, content)
    content.write("\n")
PYTHON
    sign_revocations
    echo "Certificate revoked. Publish revocations.json and revocations.sig."
}

ROOT_DIR=""
CA_DIR=""
KEY_DIR="/etc/medulla/parameters"
SERVER_NAME=""
CSR=""
OUTPUT=""
CERTIFICATE=""
DAYS=${SERVER_DAYS}
TEST_ROOT=0

COMMAND=${1:-}
[ $# -eq 0 ] || shift
for i in "$@"; do
    case $i in
        --dir=*) ROOT_DIR="${i#*=}" ;;
        --ca-dir=*) CA_DIR="${i#*=}" ;;
        --key-dir=*) KEY_DIR="${i#*=}" ;;
        --server=*) SERVER_NAME="${i#*=}" ;;
        --csr=*) CSR="${i#*=}" ;;
        --out=*) OUTPUT="${i#*=}" ;;
        --certificate=*) CERTIFICATE="${i#*=}" ;;
        --days=*) DAYS="${i#*=}" ;;
        --test) TEST_ROOT=1 ;;
        *)
            display_usage
            exit 1
            ;;
    esac
done

case ${COMMAND} in
    init)
        [ -n "${ROOT_DIR}" ] || fail "--dir is required"
        command_init
        ;;
    intermediate)
        [ -n "${ROOT_DIR}" ] && [ -n "${CA_DIR}" ] || fail "--dir and --ca-dir are required"
        command_intermediate
        ;;
    request)
        command_request
        ;;
    sign)
        [ -n "${CA_DIR}" ] && [ -n "${OUTPUT}" ] || fail "--ca-dir and --out are required"
        command_sign
        ;;
    revoke)
        [ -n "${ROOT_DIR}" ] || fail "--dir is required"
        command_revoke
        ;;
    *)
        display_usage
        exit 1
        ;;
esac
