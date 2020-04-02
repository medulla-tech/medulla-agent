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
    echo -e "\t [--conf-xmppmuchost=<XMPP configuration server MUC host>]"
    echo -e "\t [--conf-xmppmucpasswd=<XMPP configuration server MUC password>]"
    echo -e "\t [--xmpp-passwd=<XMPP server password>]"
    echo -e "\t [--xmpp-mucserver=<XMPP MUC server>]"
    echo -e "\t [--xmpp-mucpasswd=<XMPP server MUC password>]"
    echo -e "\t [--chat-domain=<XMPP domain>]"
    echo -e "\t [--aes-key=<32-character AES PSK>]"
    echo -e "\t [--inventory-tag=<Tag added to the inventory>]"
    echo -e "\t [--minimal [--base-url=<URL for downloading agent and dependencies from>]]"
    echo -e "\t [--disable-vnc (Disable VNC Server)]"
    echo -e "\t [--vnc-port=<Default port 5900>]"
    echo -e "\t [--ssh-port=<Default port 22>]"
    echo -e "\t [--disable-rdp (Disable RDP setup)]"
    echo -e "\t [--disable-inventory (Disable Fusion Inventory)]"
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
            --conf-xmppmuchost=*)
                PUBLIC_XMPP_SERVER_MUCHOST="${i#*=}"
                shift
                ;;
            --conf-xmppmucpasswd=*)
                PUBLIC_XMPP_SERVER_MUCPASSWORD="${i#*=}"
                shift
                ;;
            --xmpp-passwd=*)
                XMPP_SERVER_PASSWORD="${i#*=}"
                shift
                ;;
            --xmpp-mucserver=*)
                XMPP_MUC_SERVER="${i#*=}"
                shift
                ;;
            --xmpp-mucpasswd=*)
                XMPP_SERVER_MUCPASSWORD="${i#*=}"
                shift
                ;;
            --chat-domain=*)
                CHAT_DOMAIN="${i#*=}"
                shift
                ;;
            --aes-key=*)
                AES_KEY="${i#*=}"
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

    if [ -z "${PUBLIC_XMPP_SERVER_MUCHOST}" ]; then
        PUBLIC_XMPP_SERVER_MUCHOST="conference.pulse"
    fi
    colored_echo green " - XMPP configuration server MUC host: '${PUBLIC_XMPP_SERVER_MUCHOST}'"

    colored_echo green " - XMPP configuration server MUC password: '${PUBLIC_XMPP_SERVER_MUCPASSWORD}'"

    colored_echo green " - XMPP server password: '${XMPP_SERVER_PASSWORD}'"

    colored_echo green " - XMPP MUC server: '${XMPP_MUC_SERVER}'"

    colored_echo green " - XMPP server MUC password: '${XMPP_SERVER_MUCPASSWORD}'"

    colored_echo green " - XMPP chat domain: '${CHAT_DOMAIN}'"

    colored_echo green " - AES pre-shared key: '${AES_KEY}'"

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
}

update_config_file() {
    # Backup the config file if no backup present
    if [ ! -e config/agentconf.ini.bak ]; then
        cp config/agentconf.ini config/agentconf.ini.bak
    fi
    # Update the config file for the agent
    cp config/agentconf.ini.in config/agentconf.ini
    sed -i "s/@@AGENT_CONF_XMPP_SERVER@@/${PUBLIC_XMPP_SERVER_ADDRESS}/" config/agentconf.ini
    sed -i "s/@@AGENT_CONF_XMPP_PORT@@/${PUBLIC_XMPP_SERVER_PORT}/" config/agentconf.ini
    sed -i "s/@@AGENT_CONF_XMPP_PASSWORD@@/${PUBLIC_XMPP_SERVER_PASSWORD}/" config/agentconf.ini
    sed -i "s/@@AGENT_CONF_XMPP_MUC_DOMAIN@@/${PUBLIC_XMPP_SERVER_MUCHOST}/" config/agentconf.ini
    sed -i "s/@@AGENT_CONF_XMPP_MUC_PASSWORD@@/${PUBLIC_XMPP_SERVER_MUCPASSWORD}/" config/agentconf.ini
    sed -i "s/@@XMPP_PASSWORD@@/${XMPP_SERVER_PASSWORD}/" config/agentconf.ini
    sed -i "s/@@CHATROOM_SERVER@@/${XMPP_MUC_SERVER}/" config/agentconf.ini
    sed -i "s/@@CHATROOM_PASSWORD@@/${XMPP_SERVER_MUCPASSWORD}/" config/agentconf.ini
	sed -i "s/@@CHAT_DOMAIN@@/${CHAT_DOMAIN}/" config/agentconf.ini
	sed -i "s/@@AGENT_AES_KEY_32_CHARS@@/${AES_KEY}/" config/agentconf.ini
	unix2dos config/agentconf.ini
}

update_generation_options_file() {
    # Save arguments to file for future use
    echo "${INVENTORY_TAG_OPTIONS} ${URL_OPTION} ${DISABLE_VNC} ${VNC_PORT_OPTIONS} ${SSH_PORT_OPTIONS} ${DISABLE_RDP} ${DISABLE_INVENTORY} " > .generation_options
}

extract_parameters() {
    # Extract current parameters from agentconf.ini and .generation_options
	# Check that agentconf.ini is present
	if [ -e config/agentconf.ini ]; then
		colored_echo blue "Extracting parameters from previous config file (config/agentconf.ini)."
        CONFIG_OPTIONS="--conf-xmppserver=$(crudini --get config/agentconf.ini configuration_server confserver)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmppport=$(crudini --get config/agentconf.ini configuration_server confport)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmpppasswd=$(crudini --get config/agentconf.ini configuration_server confpassword)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmppmuchost=$(crudini --get config/agentconf.ini configuration_server confmuc_domain)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --conf-xmppmucpasswd=$(crudini --get config/agentconf.ini configuration_server confmuc_password)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --xmpp-passwd=$(crudini --get config/agentconf.ini connection password)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --xmpp-mucserver=$(crudini --get config/agentconf.ini chatroom server)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --xmpp-mucpasswd=$(crudini --get config/agentconf.ini chatroom password)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --chat-domain=$(crudini --get config/agentconf.ini chat domain)"
        CONFIG_OPTIONS="${CONFIG_OPTIONS} --aes-key=$(crudini --get config/agentconf.ini configuration_server keyAES32)"
	else
		colored_echo blue "No previous config file found. Parameters needed at runtime"
	fi

    if [ -e .generation_options ]; then
        colored_echo blue "Extracting parameters from previous options file (.generation_options)."
        GENERATION_OPTIONS=$(cat .generation_options)
    fi
}

generate_agent_win() {
	# Generate Pulse Agent for Windows
	colored_echo blue "Generating Pulse Agent for Windows..."
	COMMAND="./win/generate-pulse-agent-win.sh ${GENERATION_OPTIONS} ${OPTIONS_MINIMAL}"
	echo "Running "${COMMAND}
	${COMMAND}
}

generate_agent_lin() {
    # Generate Pulse Agent for Linux
	colored_echo blue "Generating Pulse Agent for Linux..."
	COMMAND="./lin/generate-pulse-agent-linux.sh ${GENERATION_OPTIONS} ${OPTIONS_MINIMAL}"
	echo "Running "${COMMAND}
	${COMMAND}
}

generate_agent_mac() {
    # Generate Pulse Agent for MacOS
    colored_echo blue "Generating Pulse Agent for MacOS..."
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
