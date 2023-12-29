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
AGENT_VERSION="3.1.0"
PULSE_AGENT_FILENAME="pulse-xmpp-agent-${AGENT_VERSION}.tar.gz"
AGENT_PLUGINS_FILENAME="pulse-machine-plugins-${AGENT_VERSION}.tar.gz"
PYTHON64_FILENAME="python-3.11.3-amd64.exe"
LIBCURL_DL_FILENAME="libcurl4-8.0.1-1.tar.xz"
LIBCURL_FILENAME="cygcurl-4.dll"
PY_MODULES_64_FILENAMES="CherryPy-18.8.0-py2.py3-none-any.whl \
cheroot-9.0.0-py2.py3-none-any.whl \
packaging-23.1-py3-none-any.whl \
python_dateutil-2.8.2-py2.py3-none-any.whl \
PyNaCl-1.5.0-cp36-abi3-win_amd64.whl \
comtypes-1.1.14-py2.py3-none-any.whl \
paramiko-3.1.0-py3-none-any.whl \
pytz-2023.3-py2.py3-none-any.whl \
PyQt6-6.6.1-cp38-abi3-win_amd64.whl  \
croniter-1.3.14-py2.py3-none-any.whl \
pathlib-1.0.1-py3-none-any.whl \
pywin32-306-cp311-cp311-win_amd64.whl \
PyQt6_Qt6-6.6.1-py3-none-win_amd64.whl \
cryptography-41.0.2-cp37-abi3-win_amd64.whl \
ply-3.11-py2.py3-none-any.whl \
repoze.lru-0.7-py3-none-any.whl \
PyQt6_sip-13.6.0-cp311-cp311-win_amd64.whl \
ecdsa-0.18.0-py2.py3-none-any.whl \
portend-3.1.0-py3-none-any.whl \
requests-2.28.2-py3-none-any.whl \
Routes-2.5.1-py2.py3-none-any.whl \
idna-3.4-py3-none-any.whl \
psutil-5.9.5-cp36-abi3-win_amd64.whl \
simplejson-3.19.1-py3-none-any.whl \
WMI-1.5.1-py2.py3-none-any.whl \
inflect-6.0.4-py3-none-any.whl \
pyasn1-0.5.0-py2.py3-none-any.whl \
sip-6.8.1-py3-none-any.whl \
WebOb-1.8.7-py2.py3-none-any.whl \
jaraco.classes-3.2.3-py3-none-any.whl \
pyasn1_modules-0.3.0-py2.py3-none-any.whl \
six-1.16.0-py2.py3-none-any.whl \
aiodns-3.0.0-py3-none-any.whl \
jaraco.collections-4.1.0-py3-none-any.whl \
pycares-4.3.0-cp311-cp311-win_amd64.whl \
slixmpp-1.8.4.tar.gz \
autocommand-2.2.2-py3-none-any.whl \
jaraco.context-4.3.0-py3-none-any.whl \
pycparser-2.21-py2.py3-none-any.whl \
syncthing2-2.4.4-py3-none-any.whl \
bcrypt-4.0.1-cp36-abi3-win_amd64.whl \
jaraco.functools-3.6.0-py3-none-any.whl \
pycryptodome-3.18.0-cp35-abi3-win_amd64.whl \
tempora-5.2.2-py3-none-any.whl \
certifi-2022.12.7-py3-none-any.whl \
jaraco.text-3.11.1-py3-none-any.whl \
pycurl-7.45.1-cp311-cp311-win_amd64.whl \
toml-0.10.2-py2.py3-none-any.whl \
cffi-1.15.1-cp311-cp311-win_amd64.whl \
lxml-4.9.2-cp311-cp311-win_amd64.whl \
pydantic-1.10.7-cp311-cp311-win_amd64.whl \
typing_extensions-4.5.0-py3-none-any.whl \
chardet-5.1.0-py3-none-any.whl \
more_itertools-9.1.0-py3-none-any.whl \
pyparsing-3.0.9-py3-none-any.whl \
urllib3-1.26.15-py2.py3-none-any.whl \
charset_normalizer-3.1.0-cp311-cp311-win_amd64.whl \
netifaces2-0.0.18-cp37-abi3-win_amd64.whl \
zc.lockfile-3.0.post1-py3-none-any.whl \
pypiwin32-223-py3-none-any.whl \
PyYAML-6.0.1-cp311-cp311-win_amd64.whl \
lmdb-1.4.1-cp311-cp311-win_amd64.whl \
netaddr-0.8.0-py2.py3-none-any.whl \
"
PULSE_AGENT_MODULE="pulse_xmpp_agent"
RSYNC_DL_FILENAME="cwrsync_6.2.8_x64_free.zip"
RSYNC_FILENAME="rsync.zip"
OPENSSH_NAME="Pulse SSH"
OPENSSH_VERSION="8.9"
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
CHERRYPY_VERSION="18.8.0"
NETWORK_NAME="Medulla network notify"
RDP_NAME="Pulse RDP"
SYNCTHING_NAME="Pulse Syncthing"
FILETREE_NAME="Pulse Filetree Generator"
PAEXEC_NAME="PAExec"
ROOTCERTIFICATE_FILENAME="medulla-rootca.cert.pem"
CACERTIFICATE_FILENAME="medulla-ca-chain.cert.pem"
CACERT_NAME="Medulla CA Cert"
CACERT_VERSION="1.1"

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
    DELETE_PY_MODULES=''

    FULL_OR_DL_PYTHON64=$(sed_escape 'File "'${DOWNLOADS_DIR}'/'${PYTHON64_FILENAME}'"')
    FULL_OR_DL_LIBCURL=$(sed_escape 'File "'${DOWNLOADS_DIR}'/bin/'${LIBCURL_FILENAME}'"')
    for FILENAME in ${PY_MODULES_64_FILENAMES}; do
        PY_MODULES_64='File "'${DOWNLOADS_DIR}'/python_modules/'${FILENAME}'"XOXOXOX'${PY_MODULES_64}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_64_FILENAMES=$(sed_escape ${PY_MODULES_64})
    DELETE_PY_MODULES_FILENAMES=$(sed_escape ${DELETE_PY_MODULES})
    FULL_OR_DL_RSYNC=$(sed_escape 'File "'${DOWNLOADS_DIR}'/'${RSYNC_FILENAME}'"')
    GENERATED_SIZE='FULL'
}

compute_parameters_dl() {
    DL_URL="${BASE_URL}/win/downloads"
    DL_MODULES_URL="${DL_URL}/python_modules"
    PY_MODULES_64=''
    DELETE_PY_MODULES=''

    FULL_OR_DL_PYTHON64=$(sed_escape '${DownloadFile} '${DL_URL}'/'${PYTHON64_FILENAME}' '${PYTHON64_FILENAME})
    FULL_OR_DL_LIBCURL=$(sed_escape '${DownloadFile} '${DL_URL}'/bin/'${LIBCURL_FILENAME}' '${LIBCURL_FILENAME})
    for FILENAME in ${PY_MODULES_64_FILENAMES}; do
        PY_MODULES_64='${DownloadFile} '${DL_MODULES_URL}'/'${FILENAME}' '${FILENAME}'XOXOXOX'${PY_MODULES_64}
        DELETE_PY_MODULES='Delete $INSTDIR\tmp\'${FILENAME}'XOXOXOX'${DELETE_PY_MODULES}
    done
    FULL_OR_DL_PY_MODULES_64_FILENAMES=$(sed_escape ${PY_MODULES_64})
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
        FOLDERNAME="${RSYNC_DL_FILENAME%.*}"
		unzip -o -q ${RSYNC_DL_FILENAME} -d ${FOLDERNAME}
		mkdir rsync
		rm -f rsync.zip
		cp ${FOLDERNAME}/bin/* rsync
		rm rsync/ssh-keygen.exe
		rm rsync/ssh.exe
        rm rsync/ssh-agent.exe
        rm rsync/ssh-add.exe     
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
        crudini --set --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins listexcludedplugins updatetightvnc
    else
        crudini --set ../config/${PULSE_AGENTUPDATETIGHTVNC_CONFFILE} parameters rfbport ${VNC_PORT}
    fi
}

configure_ssh_plugin() {
    crudini --set ../config/${PULSE_AGENTUPDATEOPENSSH_CONFFILE} parameters sshport ${SSH_PORT}
}

configure_rdp_plugin() {
    if [ $DISABLE_RDP = "1" ]; then
        crudini --set --list ../config/${PULSE_STARTUPDATE_CONFFILE_FILENAME} plugins listexcludedplugins updaterdp
    fi
}


update_nsi_script() {
	colored_echo blue "### INFO Updating NSIS script..."
    LAUNCHER_SSH_KEY=$(sed_escape ${LAUNCHER_SSH_KEY})

	sed -e "s/@@AGENT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOADS_DIR}/" \
		-e "s/@@PYTHON64_FILENAME@@/${PYTHON64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PYTHON64@@/${FULL_OR_DL_PYTHON64}/" \
		-e "s/@@LIBCURL_FILENAME@@/${LIBCURL_FILENAME}/" \
        -e "s/@@FULL_OR_DL_LIBCURL@@/${FULL_OR_DL_LIBCURL}/" \
        -e "s/@@FULL_OR_DL_PY_MODULES_64_FILENAMES@@/${FULL_OR_DL_PY_MODULES_64_FILENAMES}/" \
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
        -e "s/@@CACERT_NAME@@/${CACERT_NAME}/" \
        -e "s/@@CACERT_VERSION@@/${CACERT_VERSION}/" \
        -e "s/@@NETWORK_NAME@@/${NETWORK_NAME}/" \
        -e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
        -e "s/@@RDP_NAME@@/${RDP_NAME}/" \
        -e "s/@@SYNCTHING_NAME@@/${SYNCTHING_NAME}/" \
        -e "s/@@FILETREE_NAME@@/${FILETREE_NAME}/" \
        -e "s/@@PAEXEC_NAME@@/${PAEXEC_NAME}/" \
        -e "s/@@CACERTIFICATE@@/${CACERTIFICATE_FILENAME}/" \
        -e "s/@@ROOTCERTIFICATE@@/${ROOTCERTIFICATE_FILENAME}/" \
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
configure_rdp_plugin
generate_agent_installer
