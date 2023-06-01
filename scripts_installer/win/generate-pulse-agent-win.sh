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

#	Files needed for the full version of the installer:
#	In /var/lib/pulse2/clients/win32/downloads/:
#	https://www.python.org/ftp/python/2.7.9/python-2.7.9.amd64.msi
#	https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi
#	http://mirrors.kernel.org/sources.redhat.com/cygwin/x86/release/curl/libcurl4/libcurl4-7.52.1-1.tar.xz
#	https://www.itefix.net/dl/cwRsync_5.5.0_x86_Free.zip

# To be defined for minimal install
BASE_URL="https://agents.siveo.net" # Overridden if --base-url is defined

# Go to own folder
cd "`dirname $0`"

# To be defined
AGENT_VERSION="2.1.9"
PULSE_AGENT_FILENAME="pulse-xmpp-agent-${AGENT_VERSION}.tar.gz"
AGENT_PLUGINS_FILENAME="pulse-machine-plugins-${AGENT_VERSION}.tar.gz"
PYTHON64_FILENAME="python-2.7.9.amd64.msi"
PY_VCPYTHON27_FILENAME="VCForPython27.msi"
LIBCURL_DL_FILENAME="libcurl4-7.52.1-1.tar.xz"
LIBCURL_FILENAME="cygcurl-4.dll"
PY_MODULES_64_FILENAMES="pypiwin32-219-cp27-none-win_amd64.whl \
pycurl-7.43.0-cp27-none-win_amd64.whl \
lxml-3.6.0-cp27-none-win_amd64.whl \
psutil-5.4.3-cp27-none-win_amd64.whl \
simplejson-3.16.0-cp27-cp27m-win_amd64.whl \
"
PY_MODULES_COMMON_FILENAMES="netifaces-0.10.5.tar.gz \
comtypes-1.1.3-2.zip \
configparser-3.5.0.tar.gz \
sleekxmpp-1.3.1.tar.gz \
WMI-1.4.9.zip \
zipfile2-0.0.12-py2.py3-none-any.whl \
pycrypto-2.6.1.tar.gz \
python_dateutil-2.6.1-py2.py3-none-any.whl \
six-1.10.0-py2.py3-none-any.whl \
croniter-0.3.16.tar.gz \
pysftp-0.2.9.tar.gz \
paramiko-1.18.5-py2.py3-none-any.whl \
ecdsa-0.13-py2.py3-none-any.whl \
requests-2.18.4-py2.py3-none-any.whl \
idna-2.6-py2.py3-none-any.whl \
urllib3-1.22-py2.py3-none-any.whl \
certifi-2019.3.9-py2.py3-none-any.whl \
chardet-3.0.4-py2.py3-none-any.whl \
pathlib-1.0.1.tar.gz \
CherryPy-8.9.1-py2.py3-none-any.whl \
Routes-2.4.1-py2.py3-none-any.whl \
repoze.lru-0.7-py3-none-any.whl \
WebOb-1.8.5-py2.py3-none-any.whl \
"
PULSE_AGENT_MODULE="pulse_xmpp_agent"
RSYNC_DL_FILENAME="cwRsync_5.5.0_x86_Free.zip"
RSYNC_FILENAME="rsync.zip"
OPENSSH_NAME="Pulse SSH"
OPENSSH_VERSION="7.7"
LAUNCHER_SSH_KEY="/root/.ssh/id_rsa.pub"
DOWNLOADS_DIR="downloads"
SSH_PORT="22"
VNC_PORT="5900"
CREATE_PROFILE_FILENAME="create-profile.ps1"
REMOVE_PROFILE_FILENAME="remove-profile.ps1"
PULSE_SERVICE_FILENAME="pulse-service.py"
PULSE_AGENT_CONFFILE_FILENAME="agentconf.ini"
PULSE_SCHEDULER_CONFFILE_FILENAME="manage_scheduler_machine.ini"
PULSE_INVENTORY_CONFFILE_FILENAME="inventory.ini"
PULSE_START_CONFFILE_FILENAME="start_machine.ini"
PULSE_STARTUPDATE_CONFFILE_FILENAME="startupdate.ini"
PULSE_AGENTUPDATEOPENSSH_CONFFILE="updateopenssh.ini"
PULSE_AGENTUPDATETIGHTVNC_CONFFILE="updatetightvnc.ini"
PULSE_AGENTUPDATEBACKUPCLIENT_CONFFILE="updatebackupclient.ini"
PULSE_AGENT_TASK_XML_FILENAME="pulse-agent-task.xml"
DISABLE_VNC=0
DISABLE_RDP=0
DISABLE_INVENTORY=0
CHERRYPY_NAME="Pulse CherryPy"
CHERRYPY_VERSION="8.9.1"
NETWORK_NAME="Medulla network notify"
RDP_NAME="Pulse RDP"
SYNCTHING_NAME="Pulse Syncthing"
FILETREE_NAME="Pulse Filetree Generator"
PAEXEC_NAME="PAExec"

# Display usage
display_usage() {
    echo -e "\nUsage:\n$0 [--inventory-tag=<Tag added to the inventory>]\n"
    echo -e "\t [--minimal [--base-url=<URL for downloading agent and dependencies from>]]\n"
    echo -e "\t [--disable-vnc [Disable VNC Server]\n"
    echo -e "\t [--vnc-port=<Default port 5900>]\n"
    echo -e "\t [--ssh-port=<Default port 22>]\n"
    echo -e "\t [--disable-rdp [Disable RDP setup]\n"
    echo -e "\t [--disable-inventory [Disable Fusion Inventory]\n"
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
                [ ! -z ${i} ] && VNC_PORT="${i#*=}"
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
            --linux-distros*)
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

compute_parameters_full() {
    PY_MODULES_64=''
    PY_MODULES_COMMON=''
    DELETE_PY_MODULES=''

    FULL_OR_DL_PYTHON64=$(sed_escape 'File "'${DOWNLOADS_DIR}'/'${PYTHON64_FILENAME}'"')
    FULL_OR_DL_PY_VCPYTHON27=$(sed_escape 'File "'${DOWNLOADS_DIR}'/'${PY_VCPYTHON27_FILENAME}'"')
    FULL_OR_DL_LIBCURL=$(sed_escape 'File "'${DOWNLOADS_DIR}'/bin/'${LIBCURL_FILENAME}'"')
    for FILENAME in ${PY_MODULES_64_FILENAMES}; do
        PY_MODULES_64='File "'${DOWNLOADS_DIR}'/python_modules/'${FILENAME}'"XOXOXOX'${PY_MODULES_64}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_64_FILENAMES=$(sed_escape ${PY_MODULES_64})
    for FILENAME in ${PY_MODULES_COMMON_FILENAMES}; do
        PY_MODULES_COMMON='File "'${DOWNLOADS_DIR}'/python_modules/'${FILENAME}'"XOXOXOX'${PY_MODULES_COMMON}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_COMMON_FILENAMES=$(sed_escape ${PY_MODULES_COMMON})
    DELETE_PY_MODULES_FILENAMES=$(sed_escape ${DELETE_PY_MODULES})
    FULL_OR_DL_RSYNC=$(sed_escape 'File "'${DOWNLOADS_DIR}'/'${RSYNC_FILENAME}'"')
    GENERATED_SIZE='FULL'
}

compute_parameters_dl() {
    DL_URL="${BASE_URL}/win/downloads"
    DL_MODULES_URL="${DL_URL}/python_modules"
    PY_MODULES_64=''
    PY_MODULES_COMMON=''
    DELETE_PY_MODULES=''

    FULL_OR_DL_PYTHON64=$(sed_escape '${DownloadFile} '${DL_URL}'/'${PYTHON64_FILENAME}' '${PYTHON64_FILENAME})
    FULL_OR_DL_PY_VCPYTHON27=$(sed_escape '${DownloadFile} '${DL_URL}'/'${PY_VCPYTHON27_FILENAME}' '${PY_VCPYTHON27_FILENAME})
    FULL_OR_DL_LIBCURL=$(sed_escape '${DownloadFile} '${DL_URL}'/bin/'${LIBCURL_FILENAME}' '${LIBCURL_FILENAME})
    for FILENAME in ${PY_MODULES_64_FILENAMES}; do
        PY_MODULES_64='${DownloadFile} '${DL_MODULES_URL}'/'${FILENAME}' '${FILENAME}'XOXOXOX'${PY_MODULES_64}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_64_FILENAMES=$(sed_escape ${PY_MODULES_64})
    for FILENAME in ${PY_MODULES_COMMON_FILENAMES}; do
        PY_MODULES_COMMON='${DownloadFile} '${DL_MODULES_URL}'/'${FILENAME}' '${FILENAME}'XOXOXOX'${PY_MODULES_COMMON}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_COMMON_FILENAMES=$(sed_escape ${PY_MODULES_COMMON})
    DELETE_PY_MODULES_FILENAMES=$(sed_escape ${DELETE_PY_MODULES})
    FULL_OR_DL_RSYNC=$(sed_escape '${DownloadFile} '${DL_URL}'/'${RSYNC_FILENAME}' '${RSYNC_FILENAME})
    GENERATED_SIZE='MINIMAL'
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
    if [ $return -ne 0 ];then colored_echo red "### DEBUG Exit code" $return; fi
}

sed_escape() {
	echo "$@" |sed -e 's/[\/&\$"]/\\&/g'
}

prepare_mandatory_includes() {
	colored_echo blue "### INFO Preparing mandatory includes..."
    mkdir -p ${DOWNLOADS_DIR}/bin
	# rsync
	if [ -e ${DOWNLOADS_DIR}/${RSYNC_DL_FILENAME} ]; then
		pushd ${DOWNLOADS_DIR}
		unzip -o -q ${RSYNC_DL_FILENAME}
		mkdir rsync
		rm -f rsync.zip
		FOLDERNAME="${RSYNC_DL_FILENAME%.*}"
		cp ${FOLDERNAME}/bin/* rsync
		rm rsync/cygcrypto-1.0.0.dll
		rm rsync/cygssp-0.dll
		rm rsync/ssh-keygen.exe
		rm rsync/ssh.exe
		zip -r rsync.zip rsync
		rm -rf rsync
		rm -rf ${FOLDERNAME}
		popd
	else
		colored_echo red "${RSYNC_DL_FILENAME} is not present in ${DOWNLOADS_DIR}. Please restart."
		exit 1
	fi
	# libcurl
	if [ -e ${DOWNLOADS_DIR}/${LIBCURL_DL_FILENAME} ]; then
		pushd ${DOWNLOADS_DIR}
		tar xJf ${LIBCURL_DL_FILENAME}
        mv usr/bin/cygcurl-4.dll bin
        rm -rf usr
		popd
	else
		colored_echo red "${LIBCURL_DL_FILENAME} is not present in ${DOWNLOADS_DIR}. Please restart."
		exit 1
	fi
	colored_echo green "### INFO Preparing mandatory includes... Done"
}

enable_and_configure_vnc_plugin() {

    if [ $DISABLE_VNC = "1" ]; then
        crudini --del --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updatetightvnc
    else
        crudini --set --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updatetightvnc
        crudini --set ../config/${PULSE_AGENTUPDATETIGHTVNC_CONFFILE} parameters rfbport ${VNC_PORT}
    fi
}

configure_ssh_plugin() {
    crudini --set ../config/${PULSE_AGENTUPDATEOPENSSH_CONFFILE} parameters sshport ${SSH_PORT}
}

enable_and_configure_inventory_plugin() {

    if [ $DISABLE_INVENTORY = "1" ]; then
        crudini --del --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updatefusion
    else
        crudini --set --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updatefusion
    fi
}

configure_rdp_plugin() {
    if [ $DISABLE_RDP = "1" ]; then
        crudini --del --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updaterdp
    else
        crudini --set --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins liststartplugin updaterdp
    fi
}


update_nsi_script() {
	colored_echo blue "### INFO Updating NSIS script..."
    LAUNCHER_SSH_KEY=$(sed_escape ${LAUNCHER_SSH_KEY})

	sed -e "s/@@AGENT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOADS_DIR}/" \
		-e "s/@@PYTHON64_FILENAME@@/${PYTHON64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PYTHON64@@/${FULL_OR_DL_PYTHON64}/" \
		-e "s/@@PY_VCPYTHON27_FILENAME@@/${PY_VCPYTHON27_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_VCPYTHON27@@/${FULL_OR_DL_PY_VCPYTHON27}/" \
		-e "s/@@LIBCURL_FILENAME@@/${LIBCURL_FILENAME}/" \
        -e "s/@@FULL_OR_DL_LIBCURL@@/${FULL_OR_DL_LIBCURL}/" \
        -e "s/@@FULL_OR_DL_PY_MODULES_64_FILENAMES@@/${FULL_OR_DL_PY_MODULES_64_FILENAMES}/" \
        -e "s/@@FULL_OR_DL_PY_MODULES_COMMON_FILENAMES@@/${FULL_OR_DL_PY_MODULES_COMMON_FILENAMES}/" \
        -e "s/@@DELETE_PY_MODULES_FILENAMES@@/${DELETE_PY_MODULES_FILENAMES}/" \
		-e "s/@@PULSE_AGENT_FILENAME@@/${PULSE_AGENT_FILENAME}/" \
		-e "s/@@AGENT_PLUGINS_FILENAME@@/${AGENT_PLUGINS_FILENAME}/" \
		-e "s/@@PULSE_AGENT_CONFFILE@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_SCHEDULER_CONFFILE@@/${PULSE_SCHEDULER_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_INVENTORY_CONFFILE@@/${PULSE_INVENTORY_CONFFILE_FILENAME}/" \
        -e "s/@@PULSE_START_CONFFILE@@/${PULSE_START_CONFFILE_FILENAME}/" \
        -e "s/@@PULSE_STARTUPDATE_CONFFILE@@/${PULSE_STARTUPDATE_CONFFILE_FILENAME}/" \
        -e "s/@@PULSE_AGENTUPDATEOPENSSH_CONFFILE@@/${PULSE_AGENTUPDATEOPENSSH_CONFFILE}/" \
        -e "s/@@PULSE_AGENTUPDATETIGHTVNC_CONFFILE@@/${PULSE_AGENTUPDATETIGHTVNC_CONFFILE}/" \
        -e "s/@@PULSE_UPDATEBACKUPCLIENT_CONFFILE@@/${PULSE_AGENTUPDATEBACKUPCLIENT_CONFFILE}/" \
        -e "s/@@PULSE_AGENT_MODULE@@/${PULSE_AGENT_MODULE}/" \
        -e "s/@@PULSE_AGENT_TASK_XML_FILENAME@@/${PULSE_AGENT_TASK_XML_FILENAME}/" \
        -e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
        -e "s/@@OPENSSH_VERSION@@/${OPENSSH_VERSION}/" \
        -e "s/@@LAUNCHER_SSH_KEY@@/${LAUNCHER_SSH_KEY}/" \
        -e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
        -e "s/@@GENERATED_SIZE@@/${GENERATED_SIZE}/" \
        -e "s/@@CREATE_PROFILE_FILENAME@@/${CREATE_PROFILE_FILENAME}/" \
        -e "s/@@REMOVE_PROFILE_FILENAME@@/${REMOVE_PROFILE_FILENAME}/" \
        -e "s/@@PULSE_SERVICE_FILENAME@@/${PULSE_SERVICE_FILENAME}/" \
        -e "s/@@CHERRYPY_NAME@@/${CHERRYPY_NAME}/" \
        -e "s/@@CHERRYPY_VERSION@@/${CHERRYPY_VERSION}/" \
        -e "s/@@NETWORK_NAME@@/${NETWORK_NAME}/" \
        -e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
        -e "s/@@RDP_NAME@@/${RDP_NAME}/" \
        -e "s/@@SYNCTHING_NAME@@/${SYNCTHING_NAME}/" \
        -e "s/@@FILETREE_NAME@@/${FILETREE_NAME}/" \
        -e "s/@@PAEXEC_NAME@@/${PAEXEC_NAME}/" \
		agent-installer.nsi.in \
		> agent-installer.nsi

    # Replace XOXOXOX with new line
    sed -i 's/XOXOXOX/\
/g' agent-installer.nsi

	colored_echo green "### INFO Updating NSIS script.. Done"
}

generate_agent_installer() {
	colored_echo blue "### INFO Generating installer..."
	makensis -V2 agent-installer.nsi
	if [ ! $? -eq 0 ]; then
		colored_echo red "### ER... Generation of agent failed. Please restart"
		exit 1
	fi

    # Create symlinks to latest version
    if [[ ${INVENTORY_TAG} == '' ]]; then
        if [[ ${MINIMAL} -eq 1 ]]; then
	    ln -s -f Medulla-Agent-windows-MINIMAL-${AGENT_VERSION}.exe Medulla-Agent-windows-MINIMAL-latest.exe
        else
	    ln -s -f Medulla-Agent-windows-FULL-${AGENT_VERSION}.exe Medulla-Agent-windows-FULL-latest.exe
        fi
    fi

    for package in Medulla-Agent-windows-MINIMAL-latest Medulla-Agent-windows-FULL-latest;
    do
        cp -fv /var/lib/pulse2/clients/win/${package}.exe /var/lib/pulse2/imaging/postinst/winutils/
    done

    colored_echo green "### INFO  Generating installer... Done"

}

# Run the script
check_arguments "$@"
prepare_mandatory_includes
if [[ ${MINIMAL} -eq 1 ]]; then
	compute_parameters_dl
else
	compute_parameters_full
fi
update_nsi_script
configure_ssh_plugin
enable_and_configure_vnc_plugin
enable_and_configure_inventory_plugin
configure_rdp_plugin
generate_agent_installer
