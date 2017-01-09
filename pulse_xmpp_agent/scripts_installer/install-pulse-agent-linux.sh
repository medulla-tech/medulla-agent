#!/bin/bash
#
# (c) 2015-2016 siveo, http://www.siveo.net
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

# TODO: Install freerdp

PACKAGELIST="wget shorewall pulse-xmpp-agent pulse-xmppmaster-agentplugins pulseagent-plugins-machine freerdp openssh-server"

check_root() {
    if [ "$(id -u)" != "0" ]; then
        echo "This script must be run as root" 1>&2
	exit 1
    fi
}

check_distro() {
    if [ ! -e /etc/os-release ]; then
        echo "We are not able to find your linux distibution"
    else
        DISTRO=`cat /etc/os-release | grep ^ID= | cut -f2 -d'='`
    fi
}

install_agent() {
    case "$DISTRO" in
      mageia)
        # Use repository

        # Install packages
  	    urpmi $PACKAGELIST
        ;;
      debian)
        # Use repository

        # Install packages
  	    apt-get install $PACKAGELIST
        ;;
      *)
  	    echo "We do not support your distribution yet"
        ;;
    esac
}

configure_pulse() {
    if [[ ! -d /etc/pulse-xmpp-agent ]]; then
      mkdir /etc/pulse-xmpp-agent
    fi
    pushd /etc/pulse-xmpp-agent
        wget http://@@PULSE_SERVER@@/downloads/config/agentconf.ini
    popd
}

configure_iptables() {
	echo "ACCEPT net fw tcp 22" >> /etc/shorewall/rules
	service shorewall restart
}

check_root
check_distro
install_agent
configure_pulse
configure_iptables
