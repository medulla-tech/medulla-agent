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

# To be defined
AGENT_VERSION="0.1"
PYTHON_VERSION="2.7.9"
PY_WIN32_VERSION="219"
PY_PIP_MODULE="pip"
PY_PIP_VERSION="8.1.2"
PY_NETIFACES_MODULE="netifaces"
PY_NETIFACES_VERSION="0.10.5"
PY_COMTYPES_MODULE="comtypes"
PY_COMTYPES_VERSION="1.1.3-2"
PY_CONFIGPARSER_MODULE="configparser"
PY_CONFIGPARSER_VERSION="3.5.0"
PY_UTILS_MODULE="utils"
PY_UTILS_VERSION="0.9.0"
PY_SLEEKXMPP_MODULE="sleekxmpp"
PY_SLEEKXMPP_VERSION="1.3.1"
PY_WMI_MODULE="wmi"
PY_WMI_VERSION="1.4.9"
PULSE_AGENT_NAME="pulse-xmpp-agent"
PULSE_AGENT_MODULE="pulse_xmpp_agent"
OPENSSH_NAME="OpenSSH-Win32"
OPENSSH_VERSION="v0.0.0.9"
LAUNCHER_SSH_KEY="\/root\/\.ssh\/id_rsa.pub"
FUSION_INVENTORY_AGENT_NAME="fusioninventory-agent"
FUSION_INVENTORY_AGENT_VERSION="2.3.18"
DOWNLOAD_FOLDER="py_downloads"
PULSE_AGENT_PLUGINS_NAME="pulse-agent-plugins"
PULSE_AGENT_PLUGINS_VERSION="0.1"
RSYNC_FILENAME="rsync.zip"


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
      --minimal*)
        MINIMAL=1
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
	PYTHON_FILENAME="python-${PYTHON_VERSION}.msi"
	# PYTHON_URL="http://pulse_agents.siveo.net/${PYTHON_FILENAME}"
	PYTHON_URL="https://www.python.org/ftp/python/${PYTHON_VERSION}/${PYTHON_FILENAME}"
	PY_VCPYTHON27_FILENAME="VCForPython27.msi"
	PY_VCPYTHON27_URL="https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/${PY_VCPYTHON27_FILENAME}"
	#PY_WIN32_FILENAME="pywin32-${PY_WIN32_VERSION}.zip"
	#PY_WIN32_URL="http://downloads.sourceforge.net/project/pywin32/pywin32/Build%20${PY_WIN32_VERSION}/${PY_WIN32_FILENAME}"
	PY_WIN32_FILENAME="pypiwin32-${PY_WIN32_VERSION}-cp27-none-win32.whl"
	PY_WIN32_URL="https://pypi.python.org/packages/cd/59/7cc2407b15bcd13d43933a5ae163de89b6f366dda8b2b7403453e61c3a05/${PY_WIN32_FILENAME}"
	PY_PIP_FILENAME="${PY_PIP_MODULE}-${PY_PIP_VERSION}.tar.gz"
	PY_NETIFACES_FILENAME="${PY_NETIFACES_MODULE}-${PY_NETIFACES_VERSION}.tar.gz"
	PY_COMTYPES_FILENAME="${PY_COMTYPES_MODULE}-${PY_COMTYPES_VERSION}.zip"
	PY_CONFIGPARSER_FILENAME="${PY_CONFIGPARSER_MODULE}-${PY_CONFIGPARSER_VERSION}.tar.gz"
	PY_UTILS_FILENAME="${PY_UTILS_MODULE}-${PY_UTILS_VERSION}.tar.gz"
	PY_SLEEKXMPP_FILENAME="${PY_SLEEKXMPP_MODULE}-${PY_SLEEKXMPP_VERSION}.tar.gz"
	PY_WMI_FILENAME="WMI-${PY_WMI_VERSION}.zip"
	PULSE_AGENT_FILENAME="${PULSE_AGENT_NAME}-${AGENT_VERSION}.tar.gz"
	PULSE_AGENT_CONFFILE_FILENAME="agentconf.ini"
	PULSE_AGENT_TASK_XML="pulse-agent-task.xml"
	PULSE_AGENT_PLUGINS="${PULSE_AGENT_PLUGINS_NAME}-${PULSE_AGENT_PLUGINS_VERSION}.tar.gz"
	OPENSSH_FILENAME="${OPENSSH_NAME}.zip"
	OPENSSH_URL="https://github.com/PowerShell/Win32-OpenSSH/releases/download/${OPENSSH_VERSION}/${OPENSSH_FILENAME}"
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
	apt-get -y install nsis python-pip
	colored_echo green "### INFO Installing tools needed... Done"
}

download_wget() {
	local URL=$1
	local FILENAME=$2
	if [ ! -d ${DOWNLOAD_FOLDER} ]; then
		mkdir ${DOWNLOAD_FOLDER}
	fi
	if [ -e ${DOWNLOAD_FOLDER}/${FILENAME} ]; then
		colored_echo green "${FILENAME} already available. Skipping download."
	else
		colored_echo blue "Downloading ${FILENAME}..."
		wget --directory-prefix=${DOWNLOAD_FOLDER} ${URL}
		if [ ! -e ${DOWNLOAD_FOLDER}/${FILENAME} ]; then
			colored_echo red "${FILENAME} download failed. Please restart."
			exit 1
		fi
	fi
}

download_pip() {
	local PY_MODULE=$1
	local PY_MODULE_FILENAME=$2
	if [ ! -d ${DOWNLOAD_FOLDER} ]; then
		mkdir ${DOWNLOAD_FOLDER}
	fi
	if [ -e ${DOWNLOAD_FOLDER}/${PY_MODULE_FILENAME} ]; then
		colored_echo green "${PY_MODULE_FILENAME} already available. Skipping download."
	else
		colored_echo blue "Downloading ${PY_MODULE_FILENAME}..."
		pip install ${PY_MODULE} --download="${DOWNLOAD_FOLDER}"
		if [ ! -e ${DOWNLOAD_FOLDER}/${PY_MODULE_FILENAME} ]; then
			colored_echo red "${PY_MODULE_FILENAME} download failed. Please restart."
			exit 1
		fi
	fi
}

download_agent_dependencies() {
	colored_echo blue "### INFO Downloading python and dependencies..."
	download_wget ${PYTHON_URL} ${PYTHON_FILENAME}
	download_wget ${PY_VCPYTHON27_URL} ${PY_VCPYTHON27_FILENAME}
	download_pip ${PY_PIP_MODULE} ${PY_PIP_FILENAME}
	download_pip ${PY_NETIFACES_MODULE} ${PY_NETIFACES_FILENAME}
	download_pip ${PY_COMTYPES_MODULE} ${PY_COMTYPES_FILENAME}
	download_pip ${PY_CONFIGPARSER_MODULE} ${PY_CONFIGPARSER_FILENAME}
	download_pip ${PY_UTILS_MODULE} ${PY_UTILS_FILENAME}
	download_pip ${PY_SLEEKXMPP_MODULE} ${PY_SLEEKXMPP_FILENAME}
	download_pip ${PY_WMI_MODULE} ${PY_WMI_FILENAME}
	download_wget ${PY_WIN32_URL} ${PY_WIN32_FILENAME}
	download_wget ${OPENSSH_URL} ${OPENSSH_FILENAME}
	download_wget ${FUSION_INVENTORY_AGENT_URL} ${FUSION_INVENTORY_AGENT_FILENAME}
	colored_echo green "### INFO Downloading python and dependencies.. Done"
}

update_nsi_script_full() {
	colored_echo blue "### INFO Updating NSIS script..."
	FULL_PYTHON_FILENAME='File "${DOWNLOADS_DIR}/${PYTHON_FILENAME}"'
	FULL_PY_VCPYTHON27='File "${DOWNLOADS_DIR}/${PY_VCPYTHON27}"'
	FULL_PY_WIN32='File "${DOWNLOADS_DIR}/${PY_WIN32}"'
	FULL_PY_PIP='File "${DOWNLOADS_DIR}/${PY_PIP}"'
	FULL_PY_NETIFACES='File "${DOWNLOADS_DIR}/${PY_NETIFACES}"'
	FULL_PY_COMTYPES='File "${DOWNLOADS_DIR}/${PY_COMTYPES}"'
	FULL_PY_CONFIGPARSER='File "${DOWNLOADS_DIR}/${PY_CONFIGPARSER}"'
	FULL_PY_UTILS='File "${DOWNLOADS_DIR}/${PY_UTILS}"'
	FULL_PY_SLEEKXMPP='File "${DOWNLOADS_DIR}/${PY_SLEEKXMPP}"'
	FULL_PY_WMI='File "${DOWNLOADS_DIR}/${PY_WMI}"'
	FULL_OPENSSH='File "${DOWNLOADS_DIR}/${OPENSSH_FILENAME}"'
	FULL_FUSION_INVENTORY_AGENT='File "${DOWNLOADS_DIR}/${FUSION_INVENTORY_AGENT_FILENAME}"'
	INSTALL_FULL_PY_WIN32='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN32}`'
	INSTALL_FULL_PY_PIP='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PIP}`'
	INSTALL_FULL_PY_NETIFACES='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_NETIFACES}`'
	INSTALL_FULL_PY_COMTYPES='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_COMTYPES}`'
	INSTALL_FULL_PY_CONFIGPARSER='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --pre --no-index --find-links="$INSTDIR\tmp" ${PY_CONFIGPARSER}`'
	INSTALL_FULL_PY_UTILS='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_UTILS}`'
	INSTALL_FULL_PY_SLEEKXMPP='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SLEEKXMPP}`'
	INSTALL_FULL_PY_WMI='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WMI}`'

	sed -e "s/@@PRODUCT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOAD_FOLDER}/" \
		-e "s/@@PYTHON_FILENAME@@/${PYTHON_FILENAME}/" \
		-e "s/@@PYTHON_URL@@/$(sed_escape ${PYTHON_URL})/" \
		-e "s/@@FULL_OR_DL_PYTHON_FILENAME@@/$(sed_escape ${FULL_PYTHON_FILENAME})/" \
		-e "s/@@PY_VCPYTHON27@@/${PY_VCPYTHON27_FILENAME}/" \
		-e "s/@@PY_VCPYTHON27_URL@@/$(sed_escape ${PY_VCPYTHON27_URL})/" \
		-e "s/@@FULL_OR_DL_PY_VCPYTHON27@@/$(sed_escape ${FULL_PY_VCPYTHON27})/" \
		-e "s/@@PY_WIN32@@/${PY_WIN32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN32@@/$(sed_escape ${FULL_PY_WIN32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN32@@/$(sed_escape ${INSTALL_FULL_PY_WIN32})/" \
		-e "s/@@PY_PIP@@/${PY_PIP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PIP@@/$(sed_escape ${FULL_PY_PIP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PIP@@/$(sed_escape ${INSTALL_FULL_PY_PIP})/" \
		-e "s/@@PY_NETIFACES@@/${PY_NETIFACES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${FULL_PY_NETIFACES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${INSTALL_FULL_PY_NETIFACES})/" \
		-e "s/@@PY_COMTYPES@@/${PY_COMTYPES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${FULL_PY_COMTYPES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${INSTALL_FULL_PY_COMTYPES})/" \
		-e "s/@@PY_CONFIGPARSER@@/${PY_CONFIGPARSER_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${FULL_PY_CONFIGPARSER})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${INSTALL_FULL_PY_CONFIGPARSER})/" \
		-e "s/@@PY_UTILS@@/${PY_UTILS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_UTILS@@/$(sed_escape ${FULL_PY_UTILS})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_UTILS@@/$(sed_escape ${INSTALL_FULL_PY_UTILS})/" \
		-e "s/@@PY_SLEEKXMPP@@/${PY_SLEEKXMPP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${FULL_PY_SLEEKXMPP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${INSTALL_FULL_PY_SLEEKXMPP})/" \
		-e "s/@@PY_WMI@@/${PY_WMI_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WMI@@/$(sed_escape ${FULL_PY_WMI})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WMI@@/$(sed_escape ${INSTALL_FULL_PY_WMI})/" \
		-e "s/@@PULSE_AGENT@@/${PULSE_AGENT_FILENAME}/" \
		-e "s/@@PULSE_AGENT_CONFFILE@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_AGENT_NAME@@/${PULSE_AGENT_NAME}/" \
		-e "s/@@PULSE_AGENT_MODULE@@/${PULSE_AGENT_MODULE}/" \
		-e "s/@@PULSE_AGENT_TASK_XML@@/${PULSE_AGENT_TASK_XML}/" \
		-e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
		-e "s/@@OPENSSH_FILENAME@@/${OPENSSH_FILENAME}/" \
		-e "s/@@FULL_OR_DL_OPENSSH@@/$(sed_escape ${FULL_OPENSSH})/" \
		-e "s/@@LAUNCHER_SSH_KEY@@/${LAUNCHER_SSH_KEY}/" \
		-e "s/@@FUSION_INVENTORY_AGENT_FILENAME@@/${FUSION_INVENTORY_AGENT_FILENAME}/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT@@/$(sed_escape ${FULL_FUSION_INVENTORY_AGENT})/" \
		-e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@PULSE_AGENT_PLUGINS@@/${PULSE_AGENT_PLUGINS}/" \
		-e "s/@@RSYNC_FILENAME@@/${RSYNC_FILENAME}/" \
		-e "s/@@GENERATED_SIZE@@/FULL/" \
		agent-installer.nsi.in \
		> agent-installer.nsi
	colored_echo green "### INFO Updating NSIS script.. Done"
}

update_nsi_script_dl() {
	colored_echo blue "### INFO Updating NSIS script..."
	DL_PYTHON_FILENAME='${DownloadFile} '"${PYTHON_URL}"' ${PYTHON_FILENAME}'
	DL_PY_VCPYTHON27='${DownloadFile} '"${PY_VCPYTHON27_URL}"' ${PY_VCPYTHON27}'
	DL_PY_WIN32='${DownloadFile} '"${PY_WIN32_URL}"' ${PY_WIN32_FILENAME}'
	DL_OPENSSH='${DownloadFile} '"${OPENSSH_URL}"' ${OPENSSH_FILENAME}'
	DL_FUSION_INVENTORY_AGENT='${DownloadFile} '"${FUSION_INVENTORY_AGENT_URL}"' ${FUSION_INVENTORY_AGENT_FILENAME}'
	INSTALL_DL_PY_WIN32='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN32}`'
	INSTALL_DL_PY_PIP='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_PIP}`'
	INSTALL_DL_PY_NETIFACES='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_NETIFACES}`'
	INSTALL_DL_PY_COMTYPES='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_COMTYPES}`'
	INSTALL_DL_PY_CONFIGPARSER='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade --pre ${PY_CONFIGPARSER}`'
	INSTALL_DL_PY_UTILS='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_UTILS}`'
	INSTALL_DL_PY_SLEEKXMPP='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_SLEEKXMPP}`'
	INSTALL_DL_PY_WMI='StrCpy $0 `C:\Python27\Scripts\pip install --upgrade ${PY_WMI}`'

	sed -e "s/@@PRODUCT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOAD_FOLDER}/" \
		-e "s/@@PYTHON_FILENAME@@/${PYTHON_FILENAME}/" \
		-e "s/@@PYTHON_URL@@/$(sed_escape ${PYTHON_URL})/" \
		-e "s/@@FULL_OR_DL_PYTHON_FILENAME@@/$(sed_escape ${DL_PYTHON_FILENAME})/" \
		-e "s/@@PY_VCPYTHON27@@/${PY_VCPYTHON27_FILENAME}/" \
		-e "s/@@PY_VCPYTHON27_URL@@/$(sed_escape ${PY_VCPYTHON27_URL})/" \
		-e "s/@@FULL_OR_DL_PY_VCPYTHON27@@/$(sed_escape ${DL_PY_VCPYTHON27})/" \
		-e "s/@@PY_WIN32@@/${PY_WIN32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN32@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN32@@/$(sed_escape ${INSTALL_DL_PY_WIN32})/" \
		-e "s/@@PY_PIP@@/${PY_PIP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PIP@@/$(sed_escape ${INSTALL_DL_PY_PIP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PIP@@/$(sed_escape ${INSTALL_DL_PY_PIP})/" \
		-e "s/@@PY_NETIFACES@@/${PY_NETIFACES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_NETIFACES@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${INSTALL_DL_PY_NETIFACES})/" \
		-e "s/@@PY_COMTYPES@@/${PY_COMTYPES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_COMTYPES@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${INSTALL_DL_PY_COMTYPES})/" \
		-e "s/@@PY_CONFIGPARSER@@/${PY_CONFIGPARSER_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CONFIGPARSER@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${INSTALL_DL_PY_CONFIGPARSER})/" \
		-e "s/@@PY_UTILS@@/${PY_UTILS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_UTILS@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_UTILS@@/$(sed_escape ${INSTALL_DL_PY_UTILS})/" \
		-e "s/@@PY_SLEEKXMPP@@/${PY_SLEEKXMPP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SLEEKXMPP@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${INSTALL_DL_PY_SLEEKXMPP})/" \
		-e "s/@@PY_WMI@@/${PY_WMI_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WMI@@//" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WMI@@/$(sed_escape ${INSTALL_DL_PY_WMI})/" \
		-e "s/@@PULSE_AGENT@@/${PULSE_AGENT_FILENAME}/" \
		-e "s/@@PULSE_AGENT_CONFFILE@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_AGENT_NAME@@/${PULSE_AGENT_NAME}/" \
		-e "s/@@PULSE_AGENT_MODULE@@/${PULSE_AGENT_MODULE}/" \
		-e "s/@@PULSE_AGENT_TASK_XML@@/${PULSE_AGENT_TASK_XML}/" \
		-e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
		-e "s/@@OPENSSH_FILENAME@@/${OPENSSH_FILENAME}/" \
		-e "s/@@FULL_OR_DL_OPENSSH@@/$(sed_escape ${DL_OPENSSH})/" \
		-e "s/@@LAUNCHER_SSH_KEY@@/${LAUNCHER_SSH_KEY}/" \
		-e "s/@@FUSION_INVENTORY_AGENT_FILENAME@@/${FUSION_INVENTORY_AGENT_FILENAME}/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT@@/$(sed_escape ${DL_FUSION_INVENTORY_AGENT})/" \
		-e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@PULSE_AGENT_PLUGINS@@/${PULSE_AGENT_PLUGINS}/" \
		-e "s/@@RSYNC_FILENAME@@/${RSYNC_FILENAME}/" \
		-e "s/@@GENERATED_SIZE@@/MINIMAL/" \
		agent-installer.nsi.in \
		> agent-installer.nsi
	colored_echo green "### INFO Updating NSIS script.. Done"
}

generate_agent_installer() {
	colored_echo blue "### INFO Generating installer..."
	makensis agent-installer.nsi
	if [ ! $? -eq 0 ]; then
		colored_echo red "### ER... Generation of agent failed. Please restart"
		exit 1
	fi
	colored_echo green "### INFO  Generating installer... Done"
}

# Run the script
check_arguments "$@"
compute_parameters
prepare_system
if [[ ${MINIMAL} -eq 1 ]]; then
	update_nsi_script_dl
else
	download_agent_dependencies
	update_nsi_script_full
fi
generate_agent_installer
