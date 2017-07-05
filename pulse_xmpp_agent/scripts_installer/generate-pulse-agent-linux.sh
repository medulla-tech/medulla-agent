#!/bin/bash
# -*- coding: utf-8 -*-
#
# (c) 2017 siveo, http://www.siveo.net
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
# This script is designed to generate Pulse XMPP agent for Linux
# """

# TODO: Create rpm and deb repositories
#				Manage inventory tags

# Go to own folder
cd "$(dirname $0)"

# Display usage
display_usage() {
	echo -e "\nUsage:\n$0 [--inventory-tag=<Tag added to the inventory>]\n"
	echo -e "\t [--minimal]\n"
}

check_arguments() {
	for i in "$@"; do
		case $i in
      --inventory-tag=*)
        INVENTORY_TAG="${i#*=}"
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

compute_parameters() {
	PULSE_AGENT_FILENAME="${PULSE_AGENT_NAME}-${AGENT_VERSION}.tar.gz"
	PULSE_AGENT_CONFFILE_FILENAME="agentconf.ini"
	PULSE_AGENT_PLUGINS="${PULSE_AGENT_PLUGINS_NAME}-${PULSE_AGENT_PLUGINS_VERSION}.tar.gz"
	FUSION_INVENTORY_AGENT_FILENAME="${FUSION_INVENTORY_AGENT_NAME}_windows-x86_${FUSION_INVENTORY_AGENT_VERSION}.exe"
	FUSION_INVENTORY_AGENT_URL="https://github.com/tabad/fusioninventory-agent-windows-installer/releases/download/${FUSION_INVENTORY_AGENT_VERSION}/${FUSION_INVENTORY_AGENT_FILENAME}"
}

display_usage() {
	echo -e "\nUsage:\n$0 \n"
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

prepare_system() {
	colored_echo blue "### INFO Installing tools needed..."
	# Install needed tools
	apt-get -y install createrepo
	colored_echo green "### INFO Installing tools needed... Done"
}

create_repos() {
	colored_echo blue "### INFO Creating package repositories..."
	# Create RPM repository

	# Create DEB repository

	colored_echo green "### INFO Creating package repositories... Done"
}


generate_agent_installer() {
	colored_echo blue "### INFO Generating installer..."

	PULSE_SERVER=`grep public_ip /etc/mmc/pulse2/package-server/package-server.ini.local | awk '{print $3}'`
	sed -e "s/@@PULSE_SERVER@@/${PULSE_SERVER}/" install-pulse-agent-linux.sh.in > install-pulse-agent-linux.sh
	if [ ! $? -eq 0 ]; then
		colored_echo red "### ER... Generation of agent failed. Please restart"
		exit 1
	fi
	chmod +x install-pulse-agent-linux.sh

	colored_echo green "### INFO  Generating installer... Done"
}

create_pulse_user() {
	useradd pulse -d /var/lib/pulse2 -s /bin/rbash
	mkdir -p /var/lib/pulse2/packages
	chmod -R 770 /var/lib/pulse2/packages
}

# Run the script
check_arguments "$@"
compute_parameters
prepare_system
create_repos
generate_agent_installer
create_pulse_user
