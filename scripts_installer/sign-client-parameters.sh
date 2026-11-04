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
# Builds and signs the parameters archive of an organisation, then publishes
# parameters.tar, parameters.sig, server.crt and the revocation list in
# <output>/<download tag>/,
# next to the agents of the organisation.
# The base agent verifies them with lib/signed_parameters.py.

set -eu
set -o pipefail

ORGANISATION="default"
DOWNLOAD_TAG=""
CONFIG_DIR="/var/lib/pulse2/clients/config"
CERTIFICATES_DIR="/var/lib/pulse2/clients"
SIGNING_KEY="/etc/medulla/parameters/server.key"
SERVER_CERTIFICATE="/etc/medulla/parameters/server.crt"
REVOCATIONS_DIR="/etc/medulla/parameters"
OUTPUT_DIR="/var/lib/pulse2/medulla_agent"

CONFIG_FILES="agentconf.ini agentconf.ini.tpl manage_scheduler_machine.ini inventory.ini
start_machine.ini startupdate.ini updateopenssh.ini updatetightvnc.ini
updatebackupclient.ini am___server_tcpip.ini"
CERTIFICATE_FILES="medulla-rootca.cert.pem medulla-ca-chain.cert.pem"
NAME_REGEX='^[A-Za-z0-9][A-Za-z0-9._-]*$'

display_usage() {
    echo "Usage: $0 [--organisation=<tag>] [--download-tag=<dl_tag>] [--config-dir=<dir>] [--certificates-dir=<dir>]"
    echo "          [--key=<file>] [--certificate=<file>] [--revocations-dir=<dir>] [--output=<dir>]"
}

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

check_arguments() {
    for i in "$@"; do
        case $i in
            --organisation=*)
                ORGANISATION="${i#*=}"
                ;;
            --download-tag=*)
                DOWNLOAD_TAG="${i#*=}"
                ;;
            --config-dir=*)
                CONFIG_DIR="${i#*=}"
                ;;
            --certificates-dir=*)
                CERTIFICATES_DIR="${i#*=}"
                ;;
            --key=*)
                SIGNING_KEY="${i#*=}"
                ;;
            --certificate=*)
                SERVER_CERTIFICATE="${i#*=}"
                ;;
            --revocations-dir=*)
                REVOCATIONS_DIR="${i#*=}"
                ;;
            --output=*)
                OUTPUT_DIR="${i#*=}"
                ;;
            *)
                display_usage
                exit 1
                ;;
        esac
    done
    [[ ${ORGANISATION} =~ ${NAME_REGEX} ]] || fail "Invalid organisation: ${ORGANISATION}"
    # The download tag is used to build a path
    DOWNLOAD_TAG="${DOWNLOAD_TAG:-${ORGANISATION}}"
    [[ ${DOWNLOAD_TAG} =~ ${NAME_REGEX} ]] || fail "Invalid download tag: ${DOWNLOAD_TAG}"
}

check_signing_material() {
    [ -r "${SIGNING_KEY}" ] || fail "Cannot read the signing key ${SIGNING_KEY}"
    [ -r "${SERVER_CERTIFICATE}" ] || fail "Cannot read the certificate ${SERVER_CERTIFICATE}"
    [ -r "${REVOCATIONS_DIR}/revocations.json" ] && [ -r "${REVOCATIONS_DIR}/revocations.sig" ] \
        || fail "Cannot read the revocation list in ${REVOCATIONS_DIR}"
    local key_public certificate_public
    key_public=$(openssl pkey -in "${SIGNING_KEY}" -pubout)
    certificate_public=$(openssl x509 -in "${SERVER_CERTIFICATE}" -noout -pubkey)
    [ "${key_public}" == "${certificate_public}" ] || fail "The key does not match the certificate"
    openssl x509 -in "${SERVER_CERTIFICATE}" -noout -checkend 0 >/dev/null \
        || fail "The certificate ${SERVER_CERTIFICATE} has expired"
    SERVER_NAME=$(openssl x509 -in "${SERVER_CERTIFICATE}" -noout -subject -nameopt multiline \
        | sed -n 's/^ *commonName *= *//p')
    [[ ${SERVER_NAME} =~ ${NAME_REGEX} ]] || fail "Invalid certificate name: ${SERVER_NAME}"
}

next_version() {
    # A version must never go down: the agents would refuse the parameters
    local published="${OUTPUT_DIR}/${DOWNLOAD_TAG}/parameters.tar"
    if [ ! -e "${published}" ]; then
        echo 1
        return
    fi
    local version
    version=$(tar -xOf "${published}" manifest.json \
        | python3 -c 'import json, sys; print(json.load(sys.stdin)["version"])') \
        || fail "Cannot read the version of ${published}"
    [[ ${version} =~ ^[0-9]+$ ]] || fail "Invalid version in ${published}"
    echo $((version + 1))
}

build_and_sign() {
    local work=$1 version=$2
    local file
    mkdir "${work}/content"
    for file in ${CONFIG_FILES}; do
        cp -L "${CONFIG_DIR}/${file}" "${work}/content/" || fail "Missing file ${file}"
    done
    for file in ${CERTIFICATE_FILES}; do
        cp -L "${CERTIFICATES_DIR}/${file}" "${work}/content/" || fail "Missing file ${file}"
    done
    printf '{"server": "%s", "organisation": "%s", "download_tag": "%s", "version": %s}\n' \
        "${SERVER_NAME}" "${ORGANISATION}" "${DOWNLOAD_TAG}" "${version}" > "${work}/content/manifest.json"
    # Flat names only: the agent refuses any member with a path
    tar --owner=0 --group=0 -cf "${work}/parameters.tar" -C "${work}/content" \
        manifest.json ${CONFIG_FILES} ${CERTIFICATE_FILES}
    openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${work}/parameters.sig" "${work}/parameters.tar"
    openssl x509 -in "${SERVER_CERTIFICATE}" -noout -pubkey > "${work}/public.pem"
    openssl dgst -sha256 -verify "${work}/public.pem" -signature "${work}/parameters.sig" \
        "${work}/parameters.tar" >/dev/null || fail "The signature cannot be verified"
}

publish() {
    local work=$1
    local destination="${OUTPUT_DIR}/${DOWNLOAD_TAG}"
    mkdir -p "${destination}"
    chmod 755 "${destination}"
    cp "${SERVER_CERTIFICATE}" "${work}/server.crt"
    cp "${REVOCATIONS_DIR}/revocations.json" "${REVOCATIONS_DIR}/revocations.sig" "${work}/"
    chmod 644 "${work}/parameters.tar" "${work}/parameters.sig" "${work}/server.crt" \
        "${work}/revocations.json" "${work}/revocations.sig"
    mv -f "${work}/server.crt" "${work}/revocations.json" "${work}/revocations.sig" \
        "${work}/parameters.sig" "${work}/parameters.tar" "${destination}/"
}

check_arguments "$@"
check_signing_material
mkdir -p "${OUTPUT_DIR}"
VERSION=$(next_version)
WORK=$(mktemp -d "${OUTPUT_DIR}/.signing.XXXXXX")
trap 'rm -rf -- "${WORK}"' EXIT
build_and_sign "${WORK}" "${VERSION}"
publish "${WORK}"
echo "Parameters version ${VERSION} of ${ORGANISATION} signed for ${SERVER_NAME}"
