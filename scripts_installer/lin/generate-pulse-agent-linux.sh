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

. /etc/os-release

# To be defined
AGENT_VERSION="2.1.0"
SIVEO_BASE_URL="https://agents.siveo.net"
SSH_PUB_KEY="/root/.ssh/id_rsa.pub"
PULSE_AGENT_CONFFILE_FILENAME="agentconf.ini"
PULSE_SCHEDULER_CONFFILE_FILENAME="manage_scheduler.ini"
PULSE_INVENTORY_CONFFILE_FILENAME="inventory.ini"


# Go to own folder
cd "$(dirname $0)"

# Display usage
display_usage() {
	echo -e "\nUsage:\n$0 [--inventory-tag=<Tag added to the inventory>]\n"
    echo -e "\t [--minimal [--base-url=<URL for downloading agent and dependencies from>]]\n"
    echo -e "\t [--vnc-port=<Default port 5900>]\n"
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
            --vnc-port*)
                VNC_PORT="${i#*=}"
                shift
                ;;
            --ssh-port*)
                SSH_PORT="${i#*=}"
                shift
                ;;
            --linux-distros*)
                DISTROS="${i#*=}"
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
            BASE_URL=""
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
        GENERATED_FILE="Pulse-Agent-linux-MINIMAL-${AGENT_VERSION}"
	else
        GENERATED_FILE="Pulse-Agent-linux-FULL-${AGENT_VERSION}"
	fi
    if [[ "${INVENTORY_TAG}" == "" ]]; then
        GENERATED_FILE="${GENERATED_FILE}.sh"
    else
        GENERATED_FILE="${GENERATED_FILE}-${INVENTORY_TAG}.sh"
    fi
	sed -e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@PULSE_AGENT_CONFFILE_FILENAME@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_SCHEDULER_CONFFILE_FILENAME@@/${PULSE_SCHEDULER_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_INVENTORY_CONFFILE_FILENAME@@/${PULSE_INVENTORY_CONFFILE_FILENAME}/" \
        -e "s/@@VNC_PORT@@/${VNC_PORT}/" \
        -e "s/@@SSH_PORT@@/${SSH_PORT}/" \
		deb/pulse-agent-linux/debian/pulse-agent-linux.postinst.in \
		> deb/pulse-agent-linux/debian/pulse-agent-linux.postinst
    sed -e "s/@@AGENT_VERSION@@/${AGENT_VERSION}/" \
        deb/pulse-agent-linux/debian/control.in \
		> deb/pulse-agent-linux/debian/control
    sed -e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@SIVEO_BASE_URL@@/$(sed_escape ${SIVEO_BASE_URL})/" \
		-e "s/@@BASE_URL@@/$(sed_escape ${BASE_URL})/" \
		-e "s/@@AGENT_VERSION@@/${AGENT_VERSION}/" \
		install-pulse-agent-linux.sh.in \
		> ${GENERATED_FILE}

    # Create symlinks to latest version
    if [[ ${INVENTORY_TAG} == '' ]]; then
        if [[ ${MINIMAL} -eq 1 ]]; then
            ln -s -f Pulse-Agent-linux-MINIMAL-${AGENT_VERSION}.sh Pulse-Agent-linux-MINIMAL-latest.sh
        else
            ln -s -f Pulse-Agent-linux-FULL-${AGENT_VERSION}.sh Pulse-Agent-linux-FULL-latest.sh
        fi
    fi
	colored_echo green "### INFO Updating installer scripts... Done"
}

generate_agent_package() {
	colored_echo blue "### INFO Generating agent package..."

	# We copy the config files to deb bundle
	mkdir -p deb/pulse-agent-linux/etc/pulse-xmpp-agent
	for config_files in $PULSE_AGENT_CONFFILE_FILENAME $PULSE_SCHEDULER_CONFFILE_FILENAME $PULSE_INVENTORY_CONFFILE_FILENAME; do
		cp /var/lib/pulse2/clients/config/$config_files deb/pulse-agent-linux/etc/pulse-xmpp-agent/
	done
	mkdir -p deb/pulse-agent-linux/var/lib/pulse2/.ssh
	cp -fv $SSH_PUB_KEY deb/pulse-agent-linux/var/lib/pulse2/.ssh/authorized_keys

	colored_echo green "### INFO  Generating agent package... Done"
}

check_linux_distribution() {
    if [[ $ID == "centos" ]]; then
        LINUX_DISTRO="rhel"
    else
        LINUX_DISTRO=$ID
    fi

    DISTRO_VERSION=$VERSION_ID

    case ${LINUX_DISTRO} in
        "debian"|"mageia"|"rhel")
            ;;

        *)
            echo "We only support Debian, Mageia, and rhel"
            exit 1
            ;;
    esac
}

install_package() {
    case ${LINUX_DISTRO} in
        "debian")
            apt -y install "$@"
            ;;
        "mageia")
            urpmi --auto "$@"
            ;;
        "rhel")
            yum -y install "$@"
            ;;
        *)
            ;;
    esac
}

remove_package() {
    case ${LINUX_DISTRO} in
        "debian")
            apt -y remove "$@"
            ;;
        "mageia")
            urpme --auto "$@"
            ;;
        "rhel")
            yum -y remove "$@"
            ;;
        *)
            ;;
    esac
}

install_repos() {
    if [[ $LINUX_DISTRO == "debian" ]]; then
        INSTALLED_REPOS=`dpkg -l |grep pulse-agent-linux-repo|awk '{print $2}'`
    else
        INSTALLED_REPOS=`rpm -qa --queryformat "%-30{NAME} \n" |grep pulse-agent-linux-repo`
    fi
    echo $INSTALLED_REPOS

    for distro in $(echo ${DISTROS} | sed "s/,/ /g")
    do
        echo "$distro"
        case $distro in
            debian-buster)
                install_package pulse-agent-linux-repo-buster
                INSTALLED_REPOS=( "${INSTALLED_REPOS[@]/pulse-agent-linux-repo-buster}" )
                ;;
            debian-stretch)
                install_package pulse-agent-linux-repo-stretch
                INSTALLED_REPOS=( "${INSTALLED_REPOS[@]/pulse-agent-linux-repo-stretch}" )
                ;;
            ubuntu-bionic)
                install_package pulse-agent-linux-repo-bionic
                INSTALLED_REPOS=( "${INSTALLED_REPOS[@]/pulse-agent-linux-repo-bionic}" )
                ;;
            ubuntu-eoan)
                install_package pulse-agent-linux-repo-eoan
                INSTALLED_REPOS=( "${INSTALLED_REPOS[@]/pulse-agent-linux-repo-eoan}" )
                ;;
            ubuntu-xenial)
                install_package pulse-agent-linux-repo-xenial
                INSTALLED_REPOS=( "${INSTALLED_REPOS[@]/pulse-agent-linux-repo-xenial}" )
                ;;
            *)
                echo "the distribution $distro is not yet supported"
                ;;
        esac
    done
    if [ $LINUX_DISTRO == "debian" ]; then
        remove_package $INSTALLED_REPOS -y
    fi

}

build_deb() {
	pushd /var/lib/pulse2/clients/lin/deb/pulse-agent-linux/
		dpkg-buildpackage
        cd ..

        if [ -d "debian/9" ]; then
            cp -fv *.deb debian/9
            pushd debian/9
                dpkg-scanpackages -m . /dev/null | gzip -9c > Packages.gz
            popd
        fi
        if [ -d "debian/10" ]; then
            cp -fv *.deb debian/10
            pushd debian/10
                dpkg-scanpackages -m . /dev/null | gzip -9c > Packages.gz
            popd
        fi

        if [ -d "ubuntu/16.04" ]; then
            cp -fv *.deb ubuntu/16.04
            pushd ubuntu/16.04
                dpkg-scanpackages -m . /dev/null | gzip -9c > Packages.gz
            popd
        fi

        if [ -d "ubuntu/18.04" ]; then
            cp -fv *.deb ubuntu/18.04
            pushd ubuntu/18.04
                dpkg-scanpackages -m . /dev/null | gzip -9c > Packages.gz
            popd
        fi


        if [ -d "ubuntu/19.10" ]; then
            cp -fv *.deb ubuntu/19.10
            pushd ubuntu/19.10
                dpkg-scanpackages -m . /dev/null | gzip -9c > Packages.gz
            popd
        fi

	popd
}

# Run the script
check_arguments "$@"
check_linux_distribution
update_installer_scripts
generate_agent_package
install_repos
build_deb
