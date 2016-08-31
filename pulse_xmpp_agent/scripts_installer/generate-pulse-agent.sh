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

# Go to own folder
cd "`dirname $0`"

# Display usage
display_usage() {
	echo -e "\nUsage:\n$0 [--conf-xmppserver=<XMPP configuration server>] \n"
  echo -e "\t [--conf-xmppport=<XMPP configuration server port>] \n"
	echo -e "\t --conf-xmpppasswd=<XMPP configuration server password> \n"
  echo -e "\t [--conf-xmppmuchost=<XMPP configuration server MUC host>] \n"
  echo -e "\t --conf-xmppmucpasswd=<XMPP configuration server MUC password> \n"
  echo -e "\t --xmpp-passwd=<XMPP server password> \n"
  echo -e "\t --xmpp-mucpasswd=<XMPP server MUC password>\n"
}

check_arguments() {
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
      --xmpp-mucpasswd=*)
        XMPP_SERVER_MUCPASSWORD="${i#*=}"
        shift
        ;;
			*)
        # unknown option
        display_usage
        exit 0
    		;;
		esac
	done
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
  colored_echo blue "Generating with the following settings:"
  if [ -z "${PUBLIC_XMPP_SERVER_ADDRESS}" ]; then
    PUBLIC_XMPP_SERVER_ADDRESS=`grep public_ip /etc/mmc/pulse2/package-server/package-server.ini.local | awk '{print $3}'`
  fi
  colored_echo blue " - XMPP configuration server: '${PUBLIC_XMPP_SERVER_ADDRESS}'"
  if [ -z "${PUBLIC_XMPP_SERVER_PORT}" ]; then
    PUBLIC_XMPP_SERVER_PORT="5222"
  fi
  colored_echo blue " - XMPP configuration server port: '${PUBLIC_XMPP_SERVER_PORT}'"
  colored_echo blue " - XMPP configuration server password: '${PUBLIC_XMPP_SERVER_PASSWORD}'"
  if [ -z "${PUBLIC_XMPP_SERVER_MUCHOST}" ]; then
    PUBLIC_XMPP_SERVER_MUCHOST="conference.localhost"
  fi
  colored_echo blue " - XMPP configuration server MUC host: '${PUBLIC_XMPP_SERVER_MUCHOST}'"
  colored_echo blue " - XMPP configuration server MUC password: '${PUBLIC_XMPP_SERVER_MUCPASSWORD}'"
  colored_echo blue " - XMPP server password: '${XMPP_SERVER_PASSWORD}'"
  colored_echo blue " - XMPP server MUC password: '${XMPP_SERVER_MUCPASSWORD}'"
}

update_config_file() {
  # Update the config file for the agent
  cp config/agentconf.ini.in config/agentconf.ini
  sed -i "s/@@AGENT_CONF_XMPP_SERVER@@/${PUBLIC_XMPP_SERVER_ADDRESS}/" config/agentconf.ini
  sed -i "s/@@AGENT_CONF_XMPP_PORT@@/${PUBLIC_XMPP_SERVER_PORT}/" config/agentconf.ini
  sed -i "s/@@AGENT_CONF_XMPP_PASSWORD@@/${PUBLIC_XMPP_SERVER_PASSWORD}/" config/agentconf.ini
  sed -i "s/@@AGENT_CONF_XMPP_MUC_DOMAIN@@/${PUBLIC_XMPP_SERVER_MUCHOST}/" config/agentconf.ini
  sed -i "s/@@AGENT_CONF_XMPP_MUC_PASSWORD@@/${PUBLIC_XMPP_SERVER_MUCPASSWORD}/" config/agentconf.ini
  sed -i "s/@@XMPP_PASSWORD@@/${XMPP_SERVER_PASSWORD}/" config/agentconf.ini
  sed -i "s/@@CHATROOM_PASSWORD@@/${XMPP_SERVER_MUCPASSWORD}/" config/agentconf.ini
}

generate_agent() {
  # Generate Pulse Agent for Windows
  colored_echo blue "Generating Pulse Agent for Windows..."
  ./win32/generate-pulse-agent-win.sh
}

# And finally we run the functions
if [ $# -lt 4 ]; then
	display_usage
	exit 0
else
	check_arguments "$@"
fi
compute_settings
update_config_file
generate_agent
