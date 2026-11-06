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
# Installs a new revocation list on the server and publishes it next to the
# parameters of every organisation. The list must be signed by the root and
# must not be older than the installed one.

set -eu
set -o pipefail

SOURCE_DIR=""
ROOT_CERTIFICATE="/var/lib/pulse2/clients/parameters-root.crt"
REVOCATIONS_DIR="/etc/medulla/parameters"
OUTPUT_DIR="/var/lib/pulse2/medulla_agent"

display_usage() {
    echo "Usage: $0 --source=<dir> [--root=<file>] [--revocations-dir=<dir>] [--output=<dir>]"
    echo "  --source: folder holding revocations.json and revocations.sig"
}

fail() {
    echo "ERROR: $1" >&2
    exit 1
}

list_version() {
    python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["version"])' "$1"
}

check_arguments() {
    for i in "$@"; do
        case $i in
            --source=*)
                SOURCE_DIR="${i#*=}"
                ;;
            --root=*)
                ROOT_CERTIFICATE="${i#*=}"
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
    [ -n "${SOURCE_DIR}" ] || { display_usage; exit 1; }
}

check_list() {
    [ -r "${SOURCE_DIR}/revocations.json" ] && [ -r "${SOURCE_DIR}/revocations.sig" ] \
        || fail "Cannot read the revocation list in ${SOURCE_DIR}"
    [ -r "${ROOT_CERTIFICATE}" ] || fail "Cannot read the root certificate ${ROOT_CERTIFICATE}"

    local public_key
    public_key=$(mktemp)
    openssl x509 -in "${ROOT_CERTIFICATE}" -noout -pubkey > "${public_key}"
    if ! openssl dgst -sha256 -verify "${public_key}" -signature "${SOURCE_DIR}/revocations.sig" \
        "${SOURCE_DIR}/revocations.json" >/dev/null 2>&1; then
        rm -f "${public_key}"
        fail "The revocation list is not signed by the root"
    fi
    rm -f "${public_key}"

    NEW_VERSION=$(list_version "${SOURCE_DIR}/revocations.json") \
        || fail "The revocation list is not readable"
    [[ ${NEW_VERSION} =~ ^[0-9]+$ ]] || fail "Invalid revocation list version"
    if [ -e "${REVOCATIONS_DIR}/revocations.json" ]; then
        local current
        current=$(list_version "${REVOCATIONS_DIR}/revocations.json") \
            || fail "The installed revocation list is not readable"
        [ "${NEW_VERSION}" -ge "${current}" ] \
            || fail "Revocation list version ${NEW_VERSION} is older than ${current}"
    fi
}

install_list() {
    local destination=$1 file
    for file in revocations.sig revocations.json; do
        cp "${SOURCE_DIR}/${file}" "${destination}/.${file}.new"
        chmod 644 "${destination}/.${file}.new"
        mv -f "${destination}/.${file}.new" "${destination}/${file}"
    done
}

check_arguments "$@"
check_list
mkdir -p "${REVOCATIONS_DIR}"
install_list "${REVOCATIONS_DIR}"

PUBLISHED=0
for archive in "${OUTPUT_DIR}"/*/parameters.tar; do
    [ -e "${archive}" ] || continue
    install_list "$(dirname "${archive}")"
    PUBLISHED=$((PUBLISHED + 1))
done
echo "Revocation list version ${NEW_VERSION} published for ${PUBLISHED} organisation(s)"
