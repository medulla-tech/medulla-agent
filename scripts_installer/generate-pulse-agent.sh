#!/bin/bash
# -*- coding: utf-8 -*-
#
# (c) 2015 siveo, http://www.siveo.net
# $Id$
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2. If not, see <http://www.gnu.org/licenses/>.
#

# """
# This script is designed to generate Pulse XMPP agent for Windows
# It downloads the necessary dependencies, modifies the nsi file and finally
# runs makensis to generate the agent
# """

# To be defined for minimal install
# If server in not accessibe, BASE_URL="https://agents.siveo.net" can be used
# Find out the FQDN of the server - Overridden if --base-url is defined
dig `hostname -f` +nosearch +short | tail -n1 | grep -q -E '([0-9]{1,3}\.){3}[0-9]{1,3}'
if [ $? -eq 0 ]; then
	BASE_URL=http://`hostname -f`/downloads
else
	BASE_URL=http://`hostname`/downloads
fi

# Go to own folder
cd "$(dirname $0)"

# Display usage
display_usage() {
    echo -e "\nUsage:\n$0 [--conf-xmppserver=<XMPP configuration server>]"
    echo -e "\t [--conf-xmppport=<XMPP configuration server port>]"
    echo -e "\t [--conf-xmpppasswd=<XMPP configuration server password>]"
    echo -e "\t [--aes-key=<32-character AES PSK>]"
    echo -e "\t [--xmpp-passwd=<XMPP server password>]"
    echo -e "\t [--chat-domain=<XMPP domain>]"
    echo -e "\t [--inventory-tag=<Tag added to the inventory>]"
    echo -e "\t [--minimal [--base-url=<URL for downloading agent and dependencies from>]]"
    echo -e "\t [--disable-vnc (Disable VNC Server)]"
    echo -e "\t [--vnc-port=<Default port 5900>]"
    echo -e "\t [--vnc-password=<DES-encrypted VNC password>]"
    echo -e "\t [--ssh-port=<Default port 22>]"
    echo -e "\t [--disable-rdp (Disable RDP setup)]"
    echo -e "\t [--disable-inventory (Disable Fusion Inventory)]"
    echo -e "\t [--disable-geoloc (Disable geolocalisation for example on machines which do not access internet)]"
    echo -e "\t [--linux-distros (Used linux distros)]"
}

check_arguments() {
    colored_echo blue "Checking arguments $@"
	for i in "$@"; do
		case $i in
			--conf-xmppserver=*)
				PUBLIC_XMPP_SERVER_ADDRESS="${i#*=}"
				shift
				;;
			--conf-xmppport=*)
				PUBLIC_XMPP_SERVER_PORT="${i#*=}"
				shift
				;;
            --conf-xmpppasswd=*)
                PUBLIC_XMPP_SERVER_PASSWORD="${i#*=}"
                shift
                ;;
            --aes-key=*)
                AES_KEY="${i#*=}"
                shift
                ;;
            --xmpp-passwd=*)
                XMPP_SERVER_PASSWORD="${i#*=}"
                shift
                ;;
            --chat-domain=*)
                CHAT_DOMAIN="${i#*=}"
                shift
                ;;
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
                URL_OPTION="--base-url=${TEST_URL}"
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
                LINUX_DISTROS="--linux-distros=${i#*=}"
                shift
                ;;
            *)
                # unknown option
                display_usage
                exit 0
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

compute_settings() {
    # Compute settings for generating agent
    colored_echo green "Generating with the following settings:"

    colored_echo green " - XMPP configuration server: '${PUBLIC_XMPP_SERVER_ADDRESS}'"

    if [ -z "${PUBLIC_XMPP_SERVER_PORT}" ]; then
        PUBLIC_XMPP_SERVER_PORT="5222"
    fi
    colored_echo green " - XMPP configuration server port: '${PUBLIC_XMPP_SERVER_PORT}'"

    colored_echo green " - XMPP configuration server password: '${PUBLIC_XMPP_SERVER_PASSWORD}'"

    colored_echo green " - AES pre-shared key: '${AES_KEY}'"

    colored_echo green " - XMPP server password: '${XMPP_SERVER_PASSWORD}'"

    colored_echo green " - XMPP chat domain: '${CHAT_DOMAIN}'"

    if [ -z "${INVENTORY_TAG}" ]; then
        colored_echo green " - Inventory TAG: None"
        INVENTORY_TAG_OPTIONS=""
    else
        colored_echo green " - Inventory TAG: ${INVENTORY_TAG}"
        INVENTORY_TAG_OPTIONS="--inventory-tag=${INVENTORY_TAG}"
    fi

    if [[ ${MINIMAL} -eq 1 ]]; then
        colored_echo green " - Agent generated: minimal"
        colored_echo green " - Base URL: '${BASE_URL}'"
        OPTIONS_MINIMAL="--minimal --base-url=${BASE_URL}"
    else
        colored_echo green " - Agent generated: full"
    fi

    if [ -z ${DISABLE_VNC} ]; then
        colored_echo green " - VNC server is enabled"
        colored_echo green " - VNC server password: '${VNC_PASSWORD}'"
        VNC_PASSWORD_OPTIONS="--vnc-password=${VNC_PASSWORD}"
    else
        colored_echo green " - VNC server is disabled"
        DISABLE_VNC="--disable-vnc"
    fi

    if [ -z ${VNC_PORT} ]; then
        colored_echo green " - VNC server listening port: 5900"
        VNC_PORT_OPTIONS=""
    else
        colored_echo green " - VNC server listening port: ${VNC_PORT}"
        VNC_PORT_OPTIONS="--vnc-port=${VNC_PORT}"
    fi

    if [ -z ${SSH_PORT} ]; then
        colored_echo green " - SSH server listening port: 22"
        SSH_PORT_OPTIONS=""
    else
        colored_echo green " - SSH server listening port: ${SSH_PORT}"
        SSH_PORT_OPTIONS="--ssh-port=${SSH_PORT}"
    fi

    if [ -z ${DISABLE_RDP} ]; then
        colored_echo green " - RDP configuration is enabled"
    else
        colored_echo green " - RDP configuration is disabled"
        DISABLE_RDP="--disable-rdp"
    fi

    if [ -z ${DISABLE_INVENTORY} ]; then
        colored_echo green " - Fusion Inventory is enabled"
    else
        colored_echo green " - Fusion Inventory is disabled"
        DISABLE_INVENTORY="--disable-inventory"
    fi

    if [ -z ${DISABLE_GEOLOC} ]; then
        colored_echo green " - Geolocalisation is enabled"
    else
        colored_echo green " - Geolocalisation is disabled"
        DISABLE_GEOLOC="--disable-geoloc"
    fi

}

update_config_file() {
    CONFIG_FILE='config/agentconf.ini'
    # Backup the config file if no backup present
    if [ ! -e ${CONFIG_FILE}.bak ]; then
        cp ${CONFIG_FILE} ${CONFIG_FILE}.bak
    fi
    # Update the config file for the agent
    crudini --set ${CONFIG_FILE} configuration_server confserver ${PUBLIC_XMPP_SERVER_ADDRESS}
    crudini --set ${CONFIG_FILE} configuration_server confport ${PUBLIC_XMPP_SERVER_PORT}
    crudini --set ${CONFIG_FILE} configuration_server confpassword ${PUBLIC_XMPP_SERVER_PASSWORD}
    crudini --set ${CONFIG_FILE} configuration_server keyAES32 ${AES_KEY}
    crudini --set ${CONFIG_FILE} connection password ${XMPP_SERVER_PASSWORD}
    crudini --set ${CONFIG_FILE} chat domain ${CHAT_DOMAIN}
    if [ ! -z ${DISABLE_GEOLOC} ]; then
        crudini --set ${CONFIG_FILE} type geolocalisation False
    fi
	unix2dos ${CONFIG_FILE}
}

update_generation_options_file() {
    # Save arguments to file for future use
    echo "--conf-xmppserver=${PUBLIC_XMPP_SERVER_ADDRESS} --conf-xmppport=${PUBLIC_XMPP_SERVER_PORT} --conf-xmpppasswd=${PUBLIC_XMPP_SERVER_PASSWORD} --aes-key=${AES_KEY} --xmpp-passwd=${XMPP_SERVER_PASSWORD} --chat-domain=${CHAT_DOMAIN} ${INVENTORY_TAG_OPTIONS} ${URL_OPTION} ${DISABLE_VNC} ${VNC_PORT_OPTIONS} ${VNC_PASSWORD_OPTIONS} ${SSH_PORT_OPTIONS} ${DISABLE_RDP} ${DISABLE_INVENTORY} ${DISABLE_GEOLOC} ${LINUX_DISTROS} " > .generation_options
    # Update generation_options var
    if [ -e .generation_options ]; then
       colored_echo blue "Extracting parameters from previous options file (.generation_options)."
       GENERATION_OPTIONS=$(cat .generation_options)
    fi
}

extract_parameters() {
    CONFIG_FILE='config/agentconf.ini'
    # Convert to unix to be able to use crudini
    dos2unix ${CONFIG_FILE}
    # Extract current parameters from agentconf.ini and .generation_options
	# Check that agentconf.ini is present
	if [ -e ${CONFIG_FILE} ]; then
		colored_echo blue "Extracting parameters from previous config file (${CONFIG_FILE})."
        CONFIG_OPTIONS="--conf-xmppserver=$(crudini --get ${CONFIG_FILE} configuration_server confserver)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmppport=$(crudini --get ${CONFIG_FILE} configuration_server confport)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmpppasswd=$(crudini --get ${CONFIG_FILE} configuration_server confpassword)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --aes-key=$(crudini --get ${CONFIG_FILE} configuration_server keyAES32)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --xmpp-passwd=$(crudini --get ${CONFIG_FILE} connection password)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --chat-domain=$(crudini --get ${CONFIG_FILE} chat domain)"
	else
		colored_echo blue "No previous config file found. Parameters needed at runtime"
	fi

    if [ -e .generation_options ]; then
        colored_echo blue "Extracting parameters from previous options file (.generation_options)."
        GENERATION_OPTIONS=$(cat .generation_options)
    fi
}

generate_agent_win() {
	# Generate Medulla Agent for Windows
	colored_echo blue "Generating Medulla Agent for Windows..."
	COMMAND="./win/generate-pulse-agent-win.sh ${GENERATION_OPTIONS} ${OPTIONS_MINIMAL}"
	echo "Running "${COMMAND}
	${COMMAND}
}

generate_agent_lin() {
    # Generate Medulla Agent for Linux
	colored_echo blue "Generating Medulla Agent for Linux..."
	COMMAND="./lin/generate-pulse-agent-linux.sh ${GENERATION_OPTIONS} ${OPTIONS_MINIMAL}"
	echo "Running "${COMMAND}
	${COMMAND}
}

generate_agent_mac() {
    # Generate Medulla Agent for MacOS
    colored_echo blue "Generating Medulla Agent for MacOS..."
    COMMAND="./mac/generate-pulse-agent-mac.sh ${GENERATION_OPTIONS} ${OPTIONS_MINIMAL}"
    echo "Running "${COMMAND}
    ${COMMAND}
}

# And finally we run the functions
extract_parameters # Read current parameters
check_arguments ${CONFIG_OPTIONS} ${GENERATION_OPTIONS} $@ # First load previous parameters then overwrite with new ones
compute_settings
update_config_file
update_generation_options_file

generate_agent_win
generate_agent_lin
generate_agent_mac
