#!/bin/bash
# -*- coding: utf-8 -*-
#
#
# (c) 2016-2023 Siveo, http://www.siveo.net
# (c) 2024-2025 Medulla, http://www.medulla-tech.io
#
# $Id$
#
# This file is part of MMC, http://www.medulla-tech.io
#
# MMC is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# any later version.
#
# MMC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MMC; If not, see <http://www.gnu.org/licenses/>.

# """
# This script is designed to generate Medulla XMPP agent for Linux
# """

. /etc/os-release

# To be defined
AGENT_VERSION="5.4.4"
BASE_URL="https://agents.siveo.net" # Overridden if --base-url is defined

# Go to own folder
cd "$(dirname $0)"

# Display usage
display_usage() {
	echo -e "\nUsage:\n$0 [--inventory-tag=<Tag added to the inventory>]\n"
    echo -e "\t [--minimal [--base-url=<URL for downloading agent and dependencies from>]]\n"
    echo -e "\t [--vnc-port=<Default port 5900>]\n"
    echo -e "\t [--vnc-password=<DES-encrypted VNC password>]"
    echo -e "\t [--ssh-port=<Default port 22>]\n"
}

check_arguments() {
	for i in "$@"; do
        case $i in
            --inventory-tag=*)
		        INVENTORY_TAG="${i#*=}"
		        shift
		        ;;
            --minimal*)
                MINIMAL=1
                shift
                ;;
            --base-url*)
                TEST_URL="${i#*=}"
                shift
                ;;
            --disable-vnc*)
                DISABLE_VNC=1
                shift
                ;;
            --vnc-port*)
                VNC_PORT="${i#*=}"
                shift
                ;;
            --vnc-password*)
                VNC_PASSWORD="${i#*=}"
                shift
                ;;
            --ssh-port*)
                SSH_PORT="${i#*=}"
                shift
                ;;
            --disable-rdp*)
                DISABLE_RDP=1
                shift
                ;;
            --disable-inventory*)
                DISABLE_INVENTORY=1
                shift
                ;;
            --disable-geoloc*)
                DISABLE_GEOLOC=1
                shift
                ;;
            --linux-distros*)
                DISTROS="${i#*=}"
                shift
                ;;
            --conf-xmppserver*)
                shift
                ;;
            --conf-xmppport*)
                shift
                ;;
            --conf-xmpppasswd*)
                shift
                ;;
            --aes-key*)
                shift
                ;;
            --xmpp-passwd*)
                shift
                ;;
            --chat-domain*)
                shift
                ;;
            --updateserver*)
                shift
                ;;
	        *)
		        # unknown option
		        display_usage
		        exit 1
		        ;;
	    esac
	done
	if [[ ${MINIMAL} ]] && [[ ${TEST_URL} ]]; then
		URL_REGEX='^https?://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'
		if [[ ${TEST_URL} =~ ${URL_REGEX} ]]; then
			BASE_URL=${TEST_URL}
		else
			colored_echo red "The base-url parameter is not valid"
			colored_echo red "We will use ${BASE_URL}"
		fi
	fi
	if [[ ! ${MINIMAL} ]]; then
        echo "we only support minimal installer"
		exit 0 # Remove when we support full version as well
	fi
}

colored_echo() {
    local color=$1;
    if ! [[ $color =~ '^[0-9]$' ]] ; then
		case $(echo $color | tr '[:upper:]' '[:lower:]') in
			black) color=0 ;;
			red) color=1 ;;
			green) color=2 ;;
			yellow) color=3 ;;
			blue) color=4 ;;
			magenta) color=5 ;;
			cyan) color=6 ;;
			white|*) color=7 ;; # white or invalid color
		esac
    fi
    tput setaf $color;
    echo "${@:2}";
    tput sgr0;
}

exit_code() {
    return=$?
    if [ $return -ne 0 ];then coloredEcho red "### DEBUG Exit code" $return; fi
}

sed_escape() {
	echo "$@" |sed -e 's/[\/&\$"]/\\&/g'
}

update_installer_scripts() {
	colored_echo blue "### INFO Updating installer scripts..."
    if [[ ${MINIMAL} -eq 1 ]]; then
        GENERATED_FILE="Medulla-Agent-linux-MINIMAL-${AGENT_VERSION}"
	else
        GENERATED_FILE="Medulla-Agent-linux-FULL-${AGENT_VERSION}"
	fi
    if [[ "${INVENTORY_TAG}" == "" ]]; then
        GENERATED_FILE="${GENERATED_FILE}.sh"
    else
        GENERATED_FILE="${GENERATED_FILE}-${INVENTORY_TAG}.sh"
    fi
    sed -e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@BASE_URL@@/$(sed_escape ${BASE_URL})/" \
		-e "s/@@AGENT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@VNC_PASSWORD@@/${VNC_PASSWORD}/" \
		-e "s/@@SSH_PORT@@/${SSH_PORT}/" \
		install-pulse-agent-linux.sh.in \
		> ${GENERATED_FILE}

    # Create symlinks to latest version
    if [[ ${INVENTORY_TAG} == '' ]]; then
        if [[ ${MINIMAL} -eq 1 ]]; then
            ln -s -f Medulla-Agent-linux-MINIMAL-${AGENT_VERSION}.sh Medulla-Agent-linux-MINIMAL-latest.sh
        else
            ln -s -f Medulla-Agent-linux-FULL-${AGENT_VERSION}.sh Medulla-Agent-linux-FULL-latest.sh
        fi
    fi
	colored_echo green "### INFO Updating installer scripts... Done"
}

# Run the script
check_arguments "$@"
update_installer_scripts
