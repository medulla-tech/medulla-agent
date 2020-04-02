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
#	https://www.python.org/ftp/python/2.7.9/python-2.7.9.msi
#	https://www.python.org/ftp/python/2.7.9/python-2.7.9.amd64.msi
#	https://download.microsoft.com/download/7/9/6/796EF2E4-801B-4FC4-AB28-B59FBF6D907B/VCForPython27.msi
#	http://mirrors.kernel.org/sources.redhat.com/cygwin/x86/release/curl/libcurl4/libcurl4-7.52.1-1.tar.xz
#	https://www.itefix.net/dl/cwRsync_5.5.0_x86_Free.zip
#   https://github.com/PowerShell/Win32-OpenSSH/releases/download/v0.0.21.0/OpenSSH-Win32.zip
#   https://github.com/PowerShell/Win32-OpenSSH/releases/download/v0.0.21.0/OpenSSH-Win64.zip
#   https://github.com/fusioninventory/fusioninventory-agent/releases/download/2.4/fusioninventory-agent_windows-x86_2.4.exe
#   https://github.com/fusioninventory/fusioninventory-agent/releases/download/2.4/fusioninventory-agent_windows-x64_2.4.exe
#   https://www.tightvnc.com/download/2.8.8/tightvnc-2.8.8-gpl-setup-32bit.msi
#   https://www.tightvnc.com/download/2.8.8/tightvnc-2.8.8-gpl-setup-64bit.msi
#	In /var/lib/pulse2/clients/win32/downloads/python_modules/:
#	https://pypi.python.org/packages/cd/59/7cc2407b15bcd13d43933a5ae163de89b6f366dda8b2b7403453e61c3a05/pypiwin32-219-cp27-none-win32.whl
#	https://files.pythonhosted.org/packages/a5/8d/739f12d811d19cd6686f97bb96b65b0e4c8ca428fb02581d872b912b14cf/pypiwin32-219-cp27-none-win_amd64.whl
#	https://pypi.python.org/packages/a7/4c/8e0771a59fd6e55aac993a7cc1b6a0db993f299514c464ae6a1ecf83b31d/netifaces-0.10.5.tar.gz
#	https://pypi.python.org/packages/85/11/722b9ce6725bf8160bd8aca68b1e61bd9db422ab12dae28daa7defab2cdc/comtypes-1.1.3-2.zip
#	https://pypi.python.org/packages/7c/69/c2ce7e91c89dc073eb1aa74c0621c3eefbffe8216b3f9af9d3885265c01c/configparser-3.5.0.tar.gz
#	https://pypi.python.org/packages/07/49/42c86388fed58455e7e18d3821d7687f4921e47a40cb312e69b82f75c660/utils-0.9.0.tar.gz
#	https://pypi.python.org/packages/2e/33/7adcc8d6b35cb72f9cc56785a3d9c63d540200c476b0cb3a0926f5b51102/sleekxmpp-1.3.1.tar.gz
#	https://pypi.python.org/packages/03/2d/cbf13257c0115bef37b6b743758411cec70c565405cbd08d0f7059bc715f/WMI-1.4.9.zip
#	https://pypi.python.org/packages/60/ad/d6bc08f235b66c11bbb76df41b973ce93544a907cc0e23c726ea374eee79/zipfile2-0.0.12-py2.py3-none-any.whl
#   https://files.pythonhosted.org/packages/69/f1/387306c495d8f9b6518ea35348668bc1e8bf56b9c7f1425b5f12df79c356/pycurl-7.43.0-cp27-none-win32.whl
#   https://files.pythonhosted.org/packages/a6/5f/09e4740d4ec0c273e2a6ebbceb3d90f4be52f46d94ccac2639c9328e397b/pycurl-7.43.0-cp27-none-win_amd64.whl
#	https://pypi.python.org/packages/f1/c7/e19d317cc948095abc872a6e6ae78ac80260f2b45771dfa7a7ce86865f5b/lxml-3.6.0-cp27-none-win32.whl
#	https://files.pythonhosted.org/packages/35/a7/6a1a44d3a37358f8fda5d1b992c837cb2db8940293c2d84faa145f29e88a/lxml-3.6.0-cp27-none-win_amd64.whl
#	https://pypi.python.org/packages/60/db/645aa9af249f059cc3a368b118de33889219e0362141e75d4eaf6f80f163/pycrypto-2.6.1.tar.gz
#	https://files.pythonhosted.org/packages/4b/0d/7ed381ab4fe80b8ebf34411d14f253e1cf3e56e2820ffa1d8844b23859a2/python_dateutil-2.6.1-py2.py3-none-any.whl
#   https://pypi.python.org/packages/c8/0a/b6723e1bc4c516cb687841499455a8505b44607ab535be01091c0f24f079/six-1.10.0-py2.py3-none-any.whl
#   https://pypi.python.org/packages/58/2a/17d003f2a9a0188cf9365d63b3351c6522b7d83996b70270c65c789e35b9/croniter-0.3.16.tar.gz
#   https://pypi.python.org/packages/e5/cc/6dd427e738a8db6d0b66525856da43d2ef12c4c19269863927f7cf0e2aaf/psutil-5.4.3-cp27-none-win32.whl
#   https://files.pythonhosted.org/packages/b9/e4/6867765edcab8d12a52c84c9b0af492ecb99f8cc565ad552341bcf73ebd9/psutil-5.4.3-cp27-none-win_amd64.whl
#   https://github.com/syncthing/syncthing/releases/download/v1.1.0/syncthing-windows-386-v1.1.0.zip
#   https://github.com/syncthing/syncthing/releases/download/v1.1.0/syncthing-windows-amd64-v1.1.0.zip
#   https://files.pythonhosted.org/packages/36/60/45f30390a38b1f92e0a8cf4de178cd7c2bc3f874c85430e40ccf99df8fe7/pysftp-0.2.9.tar.gz
#	https://files.pythonhosted.org/packages/95/a8/72f860ff71bc260a4c815f50c65e04d69b9c5a3e51ff82afe3cd6757faa9/paramiko-1.18.5-py2.py3-none-any.whl
#	https://files.pythonhosted.org/packages/63/f4/73669d51825516ce8c43b816c0a6b64cd6eb71d08b99820c00792cb42222/ecdsa-0.13-py2.py3-none-any.whl
#   https://files.pythonhosted.org/packages/ef/4e/9f04fc58040cbf05984d7ca9393ff2dbc8b6909b163a768fc28786eacf06/syncthing-2.3.1.tar.gz
#	https://files.pythonhosted.org/packages/49/df/50aa1999ab9bde74656c2919d9c0c085fd2b3775fd3eca826012bef76d8c/requests-2.18.4-py2.py3-none-any.whl
#	https://files.pythonhosted.org/packages/27/cc/6dd9a3869f15c2edfab863b992838277279ce92663d334df9ecf5106f5c6/idna-2.6-py2.py3-none-any.whl
#	https://files.pythonhosted.org/packages/63/cb/6965947c13a94236f6d4b8223e21beb4d576dc72e8130bd7880f600839b8/urllib3-1.22-py2.py3-none-any.whl
#   https://files.pythonhosted.org/packages/60/75/f692a584e85b7eaba0e03827b3d51f45f571c2e793dd731e598828d380aa/certifi-2019.3.9-py2.py3-none-any.whl
#   https://files.pythonhosted.org/packages/bc/a9/01ffebfb562e4274b6487b4bb1ddec7ca55ec7510b22e4c51f14098443b8/chardet-3.0.4-py2.py3-none-any.whl
#   https://files.pythonhosted.org/packages/ac/aa/9b065a76b9af472437a0059f77e8f962fe350438b927cb80184c32f075eb/pathlib-1.0.1.tar.gz

# To be defined for minimal install
BASE_URL="https://agents.siveo.net" # Overridden if --base-url is defined

# Go to own folder
cd "`dirname $0`"

# To be defined
AGENT_VERSION="2.0.6"
PYTHON_VERSION="2.7.9"
PY_WIN32_MODULE="pypiwin32"
PY_WIN32_VERSION="219"
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
PY_ZIPFILE_MODULE="zipfile2"
PY_ZIPFILE_VERSION="0.0.12"
LIBCURL_NAME="libcurl4"
LIBCURL_VERSION="7.52.1-1"
LIBCURL_FILENAME="cygcurl-4.dll"
PY_CURL_MODULE="pycurl"
PY_CURL_VERSION="7.43.0"
PY_LXML_MODULE="lxml"
PY_LXML_VERSION="3.6.0"
PY_CRYPTO_MODULE="pycrypto"
PY_CRYPTO_VERSION="2.6.1"
PY_CRON_MODULE="croniter"
PY_CRON_VERSION="0.3.16"
PY_CRON_DEPS_1_MODULE="python_dateutil"
PY_CRON_DEPS_1_VERSION="2.6.1"
PY_CRON_DEPS_2_MODULE="six"
PY_CRON_DEPS_2_VERSION="1.10.0"
PY_PSUTIL_MODULE="psutil"
PY_PSUTIL_VERSION="5.4.3"
PY_SFTP_MODULE="pysftp"
PY_SFTP_VERSION="0.2.9"
PY_SFTP_DEPS_1_MODULE="paramiko"
PY_SFTP_DEPS_1_VERSION="1.18.5"
PY_SFTP_DEPS_2_MODULE="ecdsa"
PY_SFTP_DEPS_2_VERSION="0.13"
PY_SYNCTHING_MODULE="syncthing"
PY_SYNCTHING_VERSION="2.3.1"
PY_REQUESTS_MODULE="requests"
PY_REQUESTS_VERSION="2.18.4"
PY_REQUESTS_DEPS_1_MODULE="idna"
PY_REQUESTS_DEPS_1_VERSION="2.6"
PY_REQUESTS_DEPS_2_MODULE="urllib3"
PY_REQUESTS_DEPS_2_VERSION="1.22"
PY_REQUESTS_DEPS_3_MODULE="certifi"
PY_REQUESTS_DEPS_3_VERSION="2019.3.9"
PY_REQUESTS_DEPS_4_MODULE="chardet"
PY_REQUESTS_DEPS_4_VERSION="3.0.4"
PY_PATHLIB_MODULE="pathlib"
PY_PATHLIB_VERSION="1.0.1"
PULSE_AGENT_NAME="pulse-xmpp-agent"
PULSE_AGENT_MODULE="pulse_xmpp_agent"
RSYNC_NAME="cwRsync"
RSYNC_VERSION="5.5.0"
OPENSSH_NAME="OpenSSH"
LAUNCHER_SSH_KEY="\/root\/\.ssh\/id_rsa.pub"
FUSION_INVENTORY_AGENT_NAME="fusioninventory-agent"
FUSION_INVENTORY_AGENT_VERSION="2.4.2"
VNC_AGENT_NAME="tightvnc"
VNC_AGENT_VERSION="2.8.8"
DOWNLOAD_FOLDER="downloads"
VNC_PORT="5900"
SSH_PORT="22"
SYNCTHING_NAME="syncthing"
SYNCTHING_VERSION="1.1.0"
CREATE_PROFILE_NAME="create-profile.ps1"
PULSE_SERVICE_NAME="pulse-service.py"
NETCHECK_SERVICE_NAME="netcheck-service.py"
NETCHECK_PROGRAM_NAME="networkevents.py"
NETCHECK_SERVICE_DISPLAYNAME="Pulse network notify"
DISABLE_VNC=0
DISABLE_RDP=0
DISABLE_INVENTORY=0

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

compute_parameters() {
	PYTHON32_FILENAME="python-${PYTHON_VERSION}.msi"
    PYTHON64_FILENAME="python-${PYTHON_VERSION}.amd64.msi"
	PYTHON32_URL="${BASE_URL}/win/downloads/${PYTHON32_FILENAME}"
	PYTHON64_URL="${BASE_URL}/win/downloads/${PYTHON64_FILENAME}"
	PY_VCPYTHON27_FILENAME="VCForPython27.msi"
	PY_VCPYTHON27_URL="${BASE_URL}/win/downloads/${PY_VCPYTHON27_FILENAME}"
	PY_WIN3232_FILENAME="${PY_WIN32_MODULE}-${PY_WIN32_VERSION}-cp27-none-win32.whl"
	PY_WIN3264_FILENAME="${PY_WIN32_MODULE}-${PY_WIN32_VERSION}-cp27-none-win_amd64.whl"
	PY_WIN3232_URL="${BASE_URL}/win/downloads/python_modules/${PY_WIN3232_FILENAME}"
	PY_WIN3264_URL="${BASE_URL}/win/downloads/python_modules/${PY_WIN3264_FILENAME}"
	PY_NETIFACES_FILENAME="${PY_NETIFACES_MODULE}-${PY_NETIFACES_VERSION}.tar.gz"
	PY_NETIFACES_URL="${BASE_URL}/win/downloads/python_modules/${PY_NETIFACES_FILENAME}"
	PY_COMTYPES_FILENAME="${PY_COMTYPES_MODULE}-${PY_COMTYPES_VERSION}.zip"
	PY_COMTYPES_URL="${BASE_URL}/win/downloads/python_modules/${PY_COMTYPES_FILENAME}"
	PY_CONFIGPARSER_FILENAME="${PY_CONFIGPARSER_MODULE}-${PY_CONFIGPARSER_VERSION}.tar.gz"
	PY_CONFIGPARSER_URL="${BASE_URL}/win/downloads/python_modules/${PY_CONFIGPARSER_FILENAME}"
	PY_UTILS_FILENAME="${PY_UTILS_MODULE}-${PY_UTILS_VERSION}.tar.gz"
	PY_UTILS_URL="${BASE_URL}/win/downloads/python_modules/${PY_UTILS_FILENAME}"
	PY_SLEEKXMPP_FILENAME="${PY_SLEEKXMPP_MODULE}-${PY_SLEEKXMPP_VERSION}.tar.gz"
	PY_SLEEKXMPP_URL="${BASE_URL}/win/downloads/python_modules/${PY_SLEEKXMPP_FILENAME}"
	PY_WMI_FILENAME="WMI-${PY_WMI_VERSION}.zip"
	PY_WMI_URL="${BASE_URL}/win/downloads/python_modules/${PY_WMI_FILENAME}"
	PY_ZIPFILE_FILENAME="${PY_ZIPFILE_MODULE}-${PY_ZIPFILE_VERSION}-py2.py3-none-any.whl"
	PY_ZIPFILE_URL="${BASE_URL}/win/downloads/python_modules/${PY_ZIPFILE_FILENAME}"
	LIBCURL_DL_FILENAME="${LIBCURL_NAME}-${LIBCURL_VERSION}.tar.xz"
	LIBCURL_URL="${BASE_URL}/win/downloads/${LIBCURL_DL_FILENAME}"
	PY_CURL32_FILENAME="${PY_CURL_MODULE}-${PY_CURL_VERSION}-cp27-none-win32.whl"
	PY_CURL64_FILENAME="${PY_CURL_MODULE}-${PY_CURL_VERSION}-cp27-none-win_amd64.whl"
	PY_CURL32_URL="${BASE_URL}/win/downloads/python_modules/${PY_CURL32_FILENAME}"
	PY_CURL64_URL="${BASE_URL}/win/downloads/python_modules/${PY_CURL64_FILENAME}"
	PY_LXML32_FILENAME="${PY_LXML_MODULE}-${PY_LXML_VERSION}-cp27-none-win32.whl"
	PY_LXML64_FILENAME="${PY_LXML_MODULE}-${PY_LXML_VERSION}-cp27-none-win_amd64.whl"
	PY_LXML32_URL="${BASE_URL}/win/downloads/python_modules/${PY_LXML32_FILENAME}"
	PY_LXML64_URL="${BASE_URL}/win/downloads/python_modules/${PY_LXML64_FILENAME}"
	PY_CRYPTO_FILENAME="${PY_CRYPTO_MODULE}-${PY_CRYPTO_VERSION}.tar.gz"
	PY_CRYPTO_URL="${BASE_URL}/win/downloads/python_modules/${PY_CRYPTO_FILENAME}"
	PY_CRON_FILENAME="${PY_CRON_MODULE}-${PY_CRON_VERSION}.tar.gz"
	PY_CRON_URL="${BASE_URL}/win/downloads/python_modules/${PY_CRON_FILENAME}"
	PY_CRON_DEPS_1_FILENAME="${PY_CRON_DEPS_1_MODULE}-${PY_CRON_DEPS_1_VERSION}-py2.py3-none-any.whl"
	PY_CRON_DEPS_1_URL="${BASE_URL}/win/downloads/python_modules/${PY_CRON_DEPS_1_FILENAME}"
	PY_CRON_DEPS_2_FILENAME="${PY_CRON_DEPS_2_MODULE}-${PY_CRON_DEPS_2_VERSION}-py2.py3-none-any.whl"
	PY_CRON_DEPS_2_URL="${BASE_URL}/win/downloads/python_modules/${PY_CRON_DEPS_2_FILENAME}"
	PY_PSUTIL32_FILENAME="${PY_PSUTIL_MODULE}-${PY_PSUTIL_VERSION}-cp27-none-win32.whl"
	PY_PSUTIL64_FILENAME="${PY_PSUTIL_MODULE}-${PY_PSUTIL_VERSION}-cp27-none-win_amd64.whl"
	PY_PSUTIL32_URL="${BASE_URL}/win/downloads/python_modules/${PY_PSUTIL32_FILENAME}"
	PY_PSUTIL64_URL="${BASE_URL}/win/downloads/python_modules/${PY_PSUTIL64_FILENAME}"
	PY_SFTP_FILENAME="${PY_SFTP_MODULE}-${PY_SFTP_VERSION}.tar.gz"
	PY_SFTP_URL="${BASE_URL}/win/downloads/python_modules/${PY_SFTP_FILENAME}"
	PY_SFTP_DEPS_1_FILENAME="${PY_SFTP_DEPS_1_MODULE}-${PY_SFTP_DEPS_1_VERSION}-py2.py3-none-any.whl"
	PY_SFTP_DEPS_1_URL="${BASE_URL}/win/downloads/python_modules/${PY_SFTP_DEPS_1_FILENAME}"
	PY_SFTP_DEPS_2_FILENAME="${PY_SFTP_DEPS_2_MODULE}-${PY_SFTP_DEPS_2_VERSION}-py2.py3-none-any.whl"
	PY_SFTP_DEPS_2_URL="${BASE_URL}/win/downloads/python_modules/${PY_SFTP_DEPS_2_FILENAME}"
	PY_SYNCTHING_FILENAME="${PY_SYNCTHING_MODULE}-${PY_SYNCTHING_VERSION}.tar.gz"
	PY_SYNCTHING_URL="${BASE_URL}/win/downloads/python_modules/${PY_SYNCTHING_FILENAME}"
	PY_REQUESTS_FILENAME="${PY_REQUESTS_MODULE}-${PY_REQUESTS_VERSION}-py2.py3-none-any.whl"
	PY_REQUESTS_URL="${BASE_URL}/win/downloads/python_modules/${PY_REQUESTS_FILENAME}"
	PY_REQUESTS_DEPS_1_FILENAME="${PY_REQUESTS_DEPS_1_MODULE}-${PY_REQUESTS_DEPS_1_VERSION}-py2.py3-none-any.whl"
	PY_REQUESTS_DEPS_1_URL="${BASE_URL}/win/downloads/python_modules/${PY_REQUESTS_DEPS_1_FILENAME}"
	PY_REQUESTS_DEPS_2_FILENAME="${PY_REQUESTS_DEPS_2_MODULE}-${PY_REQUESTS_DEPS_2_VERSION}-py2.py3-none-any.whl"
	PY_REQUESTS_DEPS_2_URL="${BASE_URL}/win/downloads/python_modules/${PY_REQUESTS_DEPS_2_FILENAME}"
	PY_REQUESTS_DEPS_3_FILENAME="${PY_REQUESTS_DEPS_3_MODULE}-${PY_REQUESTS_DEPS_3_VERSION}-py2.py3-none-any.whl"
	PY_REQUESTS_DEPS_3_URL="${BASE_URL}/win/downloads/python_modules/${PY_REQUESTS_DEPS_3_FILENAME}"
	PY_REQUESTS_DEPS_4_FILENAME="${PY_REQUESTS_DEPS_4_MODULE}-${PY_REQUESTS_DEPS_4_VERSION}-py2.py3-none-any.whl"
	PY_REQUESTS_DEPS_4_URL="${BASE_URL}/win/downloads/python_modules/${PY_REQUESTS_DEPS_4_FILENAME}"
	PY_PATHLIB_FILENAME="${PY_PATHLIB_MODULE}-${PY_PATHLIB_VERSION}.tar.gz"
	PY_PATHLIB_URL="${BASE_URL}/win/downloads/python_modules/${PY_PATHLIB_FILENAME}"
	PULSE_AGENT_FILENAME="${PULSE_AGENT_NAME}-${AGENT_VERSION}.tar.gz"
	PULSE_AGENT_CONFFILE_FILENAME="agentconf.ini"
	PULSE_SCHEDULER_CONFFILE_FILENAME="manage_scheduler.ini"
	PULSE_INVENTORY_CONFFILE_FILENAME="inventory.ini"
	PULSE_AGENT_TASK_XML="pulse-agent-task.xml"
	RSYNC_FILENAME="${RSYNC_NAME}_${RSYNC_VERSION}_x86_Free.zip"
	RSYNC_URL="${BASE_URL}/win/downloads/${RSYNC_FILENAME}"
	OPENSSH32_FILENAME="${OPENSSH_NAME}-Win32.zip"
	OPENSSH32_URL="${BASE_URL}/win/downloads/${OPENSSH32_FILENAME}"
	OPENSSH64_FILENAME="${OPENSSH_NAME}-Win64.zip"
	OPENSSH64_URL="${BASE_URL}/win/downloads/${OPENSSH64_FILENAME}"
	FUSION_INVENTORY_AGENT32_FILENAME="${FUSION_INVENTORY_AGENT_NAME}_windows-x86_${FUSION_INVENTORY_AGENT_VERSION}.exe"
	FUSION_INVENTORY_AGENT64_FILENAME="${FUSION_INVENTORY_AGENT_NAME}_windows-x64_${FUSION_INVENTORY_AGENT_VERSION}.exe"
	FUSION_INVENTORY_AGENT32_URL="${BASE_URL}/win/downloads/${FUSION_INVENTORY_AGENT32_FILENAME}"
	FUSION_INVENTORY_AGENT64_URL="${BASE_URL}/win/downloads/${FUSION_INVENTORY_AGENT64_FILENAME}"
	VNC_AGENT32_FILENAME="${VNC_AGENT_NAME}-${VNC_AGENT_VERSION}-gpl-setup-32bit.msi"
	VNC_AGENT64_FILENAME="${VNC_AGENT_NAME}-${VNC_AGENT_VERSION}-gpl-setup-64bit.msi"
	VNC_AGENT32_URL="${BASE_URL}/win/downloads/${VNC_AGENT32_FILENAME}"
	VNC_AGENT64_URL="${BASE_URL}/win/downloads/${VNC_AGENT64_FILENAME}"
    SYNCTHING32_FILENAME="${SYNCTHING_NAME}-windows-386-v${SYNCTHING_VERSION}.zip"
    SYNCTHING32_URL="${BASE_URL}/win/downloads/${SYNCTHING32_FILENAME}"
    SYNCTHING64_FILENAME="${SYNCTHING_NAME}-windows-amd64-v${SYNCTHING_VERSION}.zip"
    SYNCTHING64_URL="${BASE_URL}/win/downloads/${SYNCTHING64_FILENAME}"
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
	colored_echo blue "### INFO Preparing mandatory includes..."
	# rsync
	if [ -e ${DOWNLOAD_FOLDER}/${RSYNC_FILENAME} ]; then
		pushd ${DOWNLOAD_FOLDER}
		unzip ${RSYNC_FILENAME}
		mkdir rsync
		rm -f rsync.zip
		FOLDERNAME="${RSYNC_FILENAME%.*}"
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
		colored_echo red "${RSYNC_FILENAME} is not present in ${DOWNLOAD_FOLDER}. Please restart."
		exit 1
	fi
	# libcurl
	if [ -e ${DOWNLOAD_FOLDER}/${LIBCURL_DL_FILENAME} ]; then
		pushd ${DOWNLOAD_FOLDER}
		tar xJf ${LIBCURL_DL_FILENAME}
		popd
	else
		colored_echo red "${LIBCURL_DL_FILENAME} is not present in ${DOWNLOAD_FOLDER}. Please restart."
		exit 1
	fi
	colored_echo green "### INFO Preparing mandatory includes... Done"
}

update_nsi_script_full() {
	colored_echo blue "### INFO Updating NSIS script..."
	FULL_PYTHON32_FILENAME='File "${DOWNLOADS_DIR}/${PYTHON32_FILENAME}"'
	FULL_PYTHON64_FILENAME='File "${DOWNLOADS_DIR}/${PYTHON64_FILENAME}"'
	FULL_PY_VCPYTHON27='File "${DOWNLOADS_DIR}/${PY_VCPYTHON27}"'
	FULL_PY_WIN3232='File "${DOWNLOADS_DIR}/python_modules/${PY_WIN3232_FILENAME}"'
	FULL_PY_WIN3264='File "${DOWNLOADS_DIR}/python_modules/${PY_WIN3264_FILENAME}"'
	FULL_PY_NETIFACES='File "${DOWNLOADS_DIR}/python_modules/${PY_NETIFACES_FILENAME}"'
	FULL_PY_COMTYPES='File "${DOWNLOADS_DIR}/python_modules/${PY_COMTYPES_FILENAME}"'
	FULL_PY_CONFIGPARSER='File "${DOWNLOADS_DIR}/python_modules/${PY_CONFIGPARSER_FILENAME}"'
	FULL_PY_UTILS='File "${DOWNLOADS_DIR}/python_modules/${PY_UTILS_FILENAME}"'
	FULL_PY_SLEEKXMPP='File "${DOWNLOADS_DIR}/python_modules/${PY_SLEEKXMPP_FILENAME}"'
	FULL_PY_WMI='File "${DOWNLOADS_DIR}/python_modules/${PY_WMI_FILENAME}"'
	FULL_PY_ZIPFILE='File "${DOWNLOADS_DIR}/python_modules/${PY_ZIPFILE_FILENAME}"'
	FULL_PY_CURL32='File "${DOWNLOADS_DIR}/python_modules/${PY_CURL32_FILENAME}"'
	FULL_PY_CURL64='File "${DOWNLOADS_DIR}/python_modules/${PY_CURL64_FILENAME}"'
	FULL_PY_LXML32='File "${DOWNLOADS_DIR}/python_modules/${PY_LXML32_FILENAME}"'
	FULL_PY_LXML64='File "${DOWNLOADS_DIR}/python_modules/${PY_LXML64_FILENAME}"'
	FULL_PY_CRYPTO='File "${DOWNLOADS_DIR}/python_modules/${PY_CRYPTO_FILENAME}"'
	FULL_PY_CRON='File "${DOWNLOADS_DIR}/python_modules/${PY_CRON_FILENAME}"'
	FULL_PY_CRON_DEPS_1='File "${DOWNLOADS_DIR}/python_modules/${PY_CRON_DEPS_1_FILENAME}"'
	FULL_PY_CRON_DEPS_2='File "${DOWNLOADS_DIR}/python_modules/${PY_CRON_DEPS_2_FILENAME}"'
	FULL_PY_PSUTIL32='File "${DOWNLOADS_DIR}/python_modules/${PY_PSUTIL32_FILENAME}"'
	FULL_PY_PSUTIL64='File "${DOWNLOADS_DIR}/python_modules/${PY_PSUTIL64_FILENAME}"'
	FULL_PY_SFTP='File "${DOWNLOADS_DIR}/python_modules/${PY_SFTP_FILENAME}"'
	FULL_PY_SFTP_DEPS_1='File "${DOWNLOADS_DIR}/python_modules/${PY_SFTP_DEPS_1_FILENAME}"'
	FULL_PY_SFTP_DEPS_2='File "${DOWNLOADS_DIR}/python_modules/${PY_SFTP_DEPS_2_FILENAME}"'
	FULL_PY_SYNCTHING='File "${DOWNLOADS_DIR}/python_modules/${PY_SYNCTHING_FILENAME}"'
	FULL_PY_REQUESTS='File "${DOWNLOADS_DIR}/python_modules/${PY_REQUESTS_FILENAME}"'
	FULL_PY_REQUESTS_DEPS_1='File "${DOWNLOADS_DIR}/python_modules/${PY_REQUESTS_DEPS_1_FILENAME}"'
	FULL_PY_REQUESTS_DEPS_2='File "${DOWNLOADS_DIR}/python_modules/${PY_REQUESTS_DEPS_2_FILENAME}"'
	FULL_PY_REQUESTS_DEPS_3='File "${DOWNLOADS_DIR}/python_modules/${PY_REQUESTS_DEPS_3_FILENAME}"'
	FULL_PY_REQUESTS_DEPS_4='File "${DOWNLOADS_DIR}/python_modules/${PY_REQUESTS_DEPS_4_FILENAME}"'
	FULL_PY_PATHLIB='File "${DOWNLOADS_DIR}/python_modules/${PY_PATHLIB_FILENAME}"'
	FULL_OPENSSH32='File "${DOWNLOADS_DIR}/${OPENSSH32_FILENAME}"'
	FULL_OPENSSH64='File "${DOWNLOADS_DIR}/${OPENSSH64_FILENAME}"'
	FULL_FUSION_INVENTORY_AGENT32='File "${DOWNLOADS_DIR}/${FUSION_INVENTORY_AGENT32_FILENAME}"'
	FULL_FUSION_INVENTORY_AGENT64='File "${DOWNLOADS_DIR}/${FUSION_INVENTORY_AGENT64_FILENAME}"'
	FULL_VNC_AGENT32='File "${DOWNLOADS_DIR}/${VNC_AGENT32_FILENAME}"'
	FULL_VNC_AGENT64='File "${DOWNLOADS_DIR}/${VNC_AGENT64_FILENAME}"'
	FULL_SYNCTHING32='File "${DOWNLOADS_DIR}/${SYNCTHING32_FILENAME}"'
	FULL_SYNCTHING64='File "${DOWNLOADS_DIR}/${SYNCTHING64_FILENAME}"'
	INSTALL_FULL_PY_WIN3232='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN3232_FILENAME}`'
	INSTALL_FULL_PY_WIN3264='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN3264_FILENAME}`'
	INSTALL_FULL_PY_NETIFACES='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_NETIFACES_FILENAME}`'
	INSTALL_FULL_PY_COMTYPES='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_COMTYPES_FILENAME}`'
	INSTALL_FULL_PY_CONFIGPARSER='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --pre --no-index --find-links="$INSTDIR\tmp" ${PY_CONFIGPARSER_FILENAME}`'
	INSTALL_FULL_PY_UTILS='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_UTILS_FILENAME}`'
	INSTALL_FULL_PY_SLEEKXMPP='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SLEEKXMPP_FILENAME}`'
	INSTALL_FULL_PY_WMI='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WMI_FILENAME}`'
	INSTALL_FULL_PY_ZIPFILE='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_ZIPFILE_FILENAME}`'
	INSTALL_FULL_PY_CURL32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CURL32_FILENAME}`'
	INSTALL_FULL_PY_CURL64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CURL64_FILENAME}`'
	INSTALL_FULL_PY_LXML32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_LXML32_FILENAME}`'
	INSTALL_FULL_PY_LXML64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_LXML64_FILENAME}`'
	INSTALL_FULL_PY_CRYPTO='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CRYPTO_FILENAME}`'
	INSTALL_FULL_PY_CRON='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CRON_FILENAME}`'
	INSTALL_FULL_PY_PSUTIL32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PSUTIL32_FILENAME}`'
	INSTALL_FULL_PY_PSUTIL64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PSUTIL64_FILENAME}`'
	INSTALL_FULL_PY_SFTP='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SFTP_FILENAME}`'
	INSTALL_FULL_PY_SYNCTHING='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SYNCTHING_FILENAME}`'
	INSTALL_FULL_PY_REQUESTS='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_REQUESTS_FILENAME}`'
	INSTALL_FULL_PY_PATHLIB='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PATHLIB_FILENAME}`'

	[ ${DISABLE_VNC} -eq 1 ] && sed -i "/^\s*Section\s\"VNC.*;$/ s|^|;|; /^\s*Section\s\"VNC/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

	[ ${DISABLE_RDP} -eq 1 ] && sed -i "/^\s*Section\s\"RDP.*;$/ s|^|;|; /^\s*Section\s\"RDP/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

	[ ${DISABLE_INVENTORY} -eq 1 ] && sed -i "/^\s*Section\s\"Fusion.*;$/ s|^|;|; /^\s*Section\s\"Fusion/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

	sed -e "s/@@PRODUCT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOAD_FOLDER}/" \
		-e "s/@@PYTHON32_FILENAME@@/${PYTHON32_FILENAME}/" \
		-e "s/@@PYTHON64_FILENAME@@/${PYTHON64_FILENAME}/" \
		-e "s/@@PYTHON32_URL@@/$(sed_escape ${PYTHON32_URL})/" \
		-e "s/@@PYTHON64_URL@@/$(sed_escape ${PYTHON64_URL})/" \
		-e "s/@@FULL_OR_DL_PYTHON32_FILENAME@@/$(sed_escape ${FULL_PYTHON32_FILENAME})/" \
		-e "s/@@FULL_OR_DL_PYTHON64_FILENAME@@/$(sed_escape ${FULL_PYTHON64_FILENAME})/" \
		-e "s/@@PY_VCPYTHON27@@/${PY_VCPYTHON27_FILENAME}/" \
		-e "s/@@PY_VCPYTHON27_URL@@/$(sed_escape ${PY_VCPYTHON27_URL})/" \
		-e "s/@@FULL_OR_DL_PY_VCPYTHON27@@/$(sed_escape ${FULL_PY_VCPYTHON27})/" \
		-e "s/@@PY_WIN3232_FILENAME@@/${PY_WIN3232_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN3232@@/$(sed_escape ${FULL_PY_WIN3232})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN3232@@/$(sed_escape ${INSTALL_FULL_PY_WIN3232})/" \
		-e "s/@@PY_WIN3264_FILENAME@@/${PY_WIN3264_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN3264@@/$(sed_escape ${FULL_PY_WIN3264})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN3264@@/$(sed_escape ${INSTALL_FULL_PY_WIN3264})/" \
		-e "s/@@PY_NETIFACES_FILENAME@@/${PY_NETIFACES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${FULL_PY_NETIFACES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${INSTALL_FULL_PY_NETIFACES})/" \
		-e "s/@@PY_COMTYPES_FILENAME@@/${PY_COMTYPES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${FULL_PY_COMTYPES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${INSTALL_FULL_PY_COMTYPES})/" \
		-e "s/@@PY_CONFIGPARSER_FILENAME@@/${PY_CONFIGPARSER_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${FULL_PY_CONFIGPARSER})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${INSTALL_FULL_PY_CONFIGPARSER})/" \
		-e "s/@@PY_UTILS_FILENAME@@/${PY_UTILS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_UTILS@@/$(sed_escape ${FULL_PY_UTILS})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_UTILS@@/$(sed_escape ${INSTALL_FULL_PY_UTILS})/" \
		-e "s/@@PY_SLEEKXMPP_FILENAME@@/${PY_SLEEKXMPP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${FULL_PY_SLEEKXMPP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${INSTALL_FULL_PY_SLEEKXMPP})/" \
		-e "s/@@PY_WMI_FILENAME@@/${PY_WMI_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WMI@@/$(sed_escape ${FULL_PY_WMI})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WMI@@/$(sed_escape ${INSTALL_FULL_PY_WMI})/" \
		-e "s/@@PY_ZIPFILE_FILENAME@@/${PY_ZIPFILE_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_ZIPFILE@@/$(sed_escape ${FULL_PY_ZIPFILE})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_ZIPFILE@@/$(sed_escape ${INSTALL_FULL_PY_ZIPFILE})/" \
		-e "s/@@LIBCURL_FILENAME@@/${LIBCURL_FILENAME}/" \
		-e "s/@@PY_CURL32_FILENAME@@/${PY_CURL32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CURL32@@/$(sed_escape ${FULL_PY_CURL32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CURL32@@/$(sed_escape ${INSTALL_FULL_PY_CURL32})/" \
		-e "s/@@PY_CURL64_FILENAME@@/${PY_CURL64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CURL64@@/$(sed_escape ${FULL_PY_CURL64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CURL64@@/$(sed_escape ${INSTALL_FULL_PY_CURL64})/" \
		-e "s/@@PY_LXML32_FILENAME@@/${PY_LXML32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_LXML32@@/$(sed_escape ${FULL_PY_LXML32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_LXML32@@/$(sed_escape ${INSTALL_FULL_PY_LXML32})/" \
		-e "s/@@PY_LXML64_FILENAME@@/${PY_LXML64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_LXML64@@/$(sed_escape ${FULL_PY_LXML64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_LXML64@@/$(sed_escape ${INSTALL_FULL_PY_LXML64})/" \
		-e "s/@@PY_CRYPTO_FILENAME@@/${PY_CRYPTO_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRYPTO@@/$(sed_escape ${FULL_PY_CRYPTO})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CRYPTO@@/$(sed_escape ${INSTALL_FULL_PY_CRYPTO})/" \
		-e "s/@@PY_CRON_FILENAME@@/${PY_CRON_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON@@/$(sed_escape ${FULL_PY_CRON})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CRON@@/$(sed_escape ${INSTALL_FULL_PY_CRON})/" \
		-e "s/@@PY_CRON_DEPS_1_FILENAME@@/${PY_CRON_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON_DEPS_1@@/$(sed_escape ${FULL_PY_CRON_DEPS_1})/" \
		-e "s/@@PY_CRON_DEPS_2_FILENAME@@/${PY_CRON_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON_DEPS_2@@/$(sed_escape ${FULL_PY_CRON_DEPS_2})/" \
		-e "s/@@PY_PSUTIL32_FILENAME@@/${PY_PSUTIL32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PSUTIL32@@/$(sed_escape ${FULL_PY_PSUTIL32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PSUTIL32@@/$(sed_escape ${INSTALL_FULL_PY_PSUTIL32})/" \
		-e "s/@@PY_PSUTIL64_FILENAME@@/${PY_PSUTIL64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PSUTIL64@@/$(sed_escape ${FULL_PY_PSUTIL64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PSUTIL64@@/$(sed_escape ${INSTALL_FULL_PY_PSUTIL64})/" \
		-e "s/@@PY_SFTP_FILENAME@@/${PY_SFTP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP@@/$(sed_escape ${FULL_PY_SFTP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SFTP@@/$(sed_escape ${INSTALL_FULL_PY_SFTP})/" \
		-e "s/@@PY_SFTP_DEPS_1_FILENAME@@/${PY_SFTP_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP_DEPS_1@@/$(sed_escape ${FULL_PY_SFTP_DEPS_1})/" \
		-e "s/@@PY_SFTP_DEPS_2_FILENAME@@/${PY_SFTP_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP_DEPS_2@@/$(sed_escape ${FULL_PY_SFTP_DEPS_2})/" \
		-e "s/@@PY_SYNCTHING_FILENAME@@/${PY_SYNCTHING_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SYNCTHING@@/$(sed_escape ${FULL_PY_SYNCTHING})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SYNCTHING@@/$(sed_escape ${INSTALL_FULL_PY_SYNCTHING})/" \
		-e "s/@@PY_REQUESTS_FILENAME@@/${PY_REQUESTS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS@@/$(sed_escape ${FULL_PY_REQUESTS})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_REQUESTS@@/$(sed_escape ${INSTALL_FULL_PY_REQUESTS})/" \
		-e "s/@@PY_REQUESTS_DEPS_1_FILENAME@@/${PY_REQUESTS_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_1@@/$(sed_escape ${FULL_PY_REQUESTS_DEPS_1})/" \
		-e "s/@@PY_REQUESTS_DEPS_2_FILENAME@@/${PY_REQUESTS_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_2@@/$(sed_escape ${FULL_PY_REQUESTS_DEPS_2})/" \
		-e "s/@@PY_REQUESTS_DEPS_3_FILENAME@@/${PY_REQUESTS_DEPS_3_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_3@@/$(sed_escape ${FULL_PY_REQUESTS_DEPS_3})/" \
		-e "s/@@PY_REQUESTS_DEPS_4_FILENAME@@/${PY_REQUESTS_DEPS_4_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_4@@/$(sed_escape ${FULL_PY_REQUESTS_DEPS_4})/" \
		-e "s/@@PY_PATHLIB_FILENAME@@/${PY_PATHLIB_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PATHLIB@@/$(sed_escape ${FULL_PY_PATHLIB})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PATHLIB@@/$(sed_escape ${INSTALL_FULL_PY_PATHLIB})/" \
		-e "s/@@PULSE_AGENT@@/${PULSE_AGENT_FILENAME}/" \
		-e "s/@@PULSE_AGENT_CONFFILE@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_SCHEDULER_CONFFILE@@/${PULSE_SCHEDULER_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_INVENTORY_CONFFILE@@/${PULSE_INVENTORY_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_AGENT_NAME@@/${PULSE_AGENT_NAME}/" \
		-e "s/@@PULSE_AGENT_MODULE@@/${PULSE_AGENT_MODULE}/" \
		-e "s/@@PULSE_AGENT_TASK_XML@@/${PULSE_AGENT_TASK_XML}/" \
		-e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
		-e "s/@@OPENSSH32_FILENAME@@/${OPENSSH32_FILENAME}/" \
		-e "s/@@OPENSSH64_FILENAME@@/${OPENSSH64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_OPENSSH32@@/$(sed_escape ${FULL_OPENSSH32})/" \
		-e "s/@@FULL_OR_DL_OPENSSH64@@/$(sed_escape ${FULL_OPENSSH64})/" \
		-e "s/@@LAUNCHER_SSH_KEY@@/${LAUNCHER_SSH_KEY}/" \
		-e "s/@@FUSION_INVENTORY_AGENT32_FILENAME@@/${FUSION_INVENTORY_AGENT32_FILENAME}/" \
		-e "s/@@FUSION_INVENTORY_AGENT64_FILENAME@@/${FUSION_INVENTORY_AGENT64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT32@@/$(sed_escape ${FULL_FUSION_INVENTORY_AGENT32})/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT64@@/$(sed_escape ${FULL_FUSION_INVENTORY_AGENT64})/" \
		-e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@VNC_AGENT32_FILENAME@@/${VNC_AGENT32_FILENAME}/" \
		-e "s/@@VNC_AGENT64_FILENAME@@/${VNC_AGENT64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_VNC_AGENT32@@/$(sed_escape ${FULL_VNC_AGENT32})/" \
		-e "s/@@FULL_OR_DL_VNC_AGENT64@@/$(sed_escape ${FULL_VNC_AGENT64})/" \
		-e "s/@@SYNCTHING32_FILENAME@@/${SYNCTHING32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_SYNCTHING32@@/$(sed_escape ${FULL_SYNCTHING32})/" \
		-e "s/@@SYNCTHING64_FILENAME@@/${SYNCTHING64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_SYNCTHING64@@/$(sed_escape ${FULL_SYNCTHING64})/" \
		-e "s/@@RSYNC_FILENAME@@/rsync.zip/" \
		-e "s/@@GENERATED_SIZE@@/FULL/" \
        -e "s/@@RFB_PORT@@/${VNC_PORT}/" \
        -e "s/@@SSH_PORT@@/${SSH_PORT}/" \
        -e "s/@@CREATE_PROFILE_NAME@@/${CREATE_PROFILE_NAME}/" \
        -e "s/@@PULSE_SERVICE_NAME@@/${PULSE_SERVICE_NAME}/" \
        -e "s/@@NETCHECK_SERVICE_NAME@@/${NETCHECK_SERVICE_NAME}/" \
        -e "s/@@NETCHECK_PROGRAM_NAME@@/${NETCHECK_PROGRAM_NAME}/" \
        -e "s/@@NETCHECK_SERVICE_DISPLAYNAME@@/${NETCHECK_SERVICE_DISPLAYNAME}/" \
		agent-installer.nsi.in \
		> agent-installer.nsi
	colored_echo green "### INFO Updating NSIS script.. Done"
}

update_nsi_script_dl() {
	colored_echo blue "### INFO Updating NSIS script..."
	DL_PYTHON32_FILENAME='${DownloadFile} '"${PYTHON32_URL}"' ${PYTHON32_FILENAME}'
	DL_PYTHON64_FILENAME='${DownloadFile} '"${PYTHON64_URL}"' ${PYTHON64_FILENAME}'
	DL_PY_VCPYTHON27='${DownloadFile} '"${PY_VCPYTHON27_URL}"' ${PY_VCPYTHON27}'
	DL_PY_WIN3232='${DownloadFile} '"${PY_WIN3232_URL}"' ${PY_WIN3232_FILENAME}'
	DL_PY_WIN3264='${DownloadFile} '"${PY_WIN3264_URL}"' ${PY_WIN3264_FILENAME}'
	DL_PY_NETIFACES='${DownloadFile} '"${PY_NETIFACES_URL}"' ${PY_NETIFACES_FILENAME}'
	DL_PY_COMTYPES='${DownloadFile} '"${PY_COMTYPES_URL}"' ${PY_COMTYPES_FILENAME}'
	DL_PY_CONFIGPARSER='${DownloadFile} '"${PY_CONFIGPARSER_URL}"' ${PY_CONFIGPARSER_FILENAME}'
	DL_PY_UTILS='${DownloadFile} '"${PY_UTILS_URL}"' ${PY_UTILS_FILENAME}'
	DL_PY_SLEEKXMPP='${DownloadFile} '"${PY_SLEEKXMPP_URL}"' ${PY_SLEEKXMPP_FILENAME}'
	DL_PY_WMI='${DownloadFile} '"${PY_WMI_URL}"' ${PY_WMI_FILENAME}'
	DL_PY_ZIPFILE='${DownloadFile} '"${PY_ZIPFILE_URL}"' ${PY_ZIPFILE_FILENAME}'
	DL_PY_CURL32='${DownloadFile} '"${PY_CURL32_URL}"' ${PY_CURL32_FILENAME}'
	DL_PY_CURL64='${DownloadFile} '"${PY_CURL64_URL}"' ${PY_CURL64_FILENAME}'
	DL_PY_LXML32='${DownloadFile} '"${PY_LXML32_URL}"' ${PY_LXML32_FILENAME}'
	DL_PY_LXML64='${DownloadFile} '"${PY_LXML64_URL}"' ${PY_LXML64_FILENAME}'
	DL_PY_CRYPTO='${DownloadFile} '"${PY_CRYPTO_URL}"' ${PY_CRYPTO_FILENAME}'
	DL_PY_CRON='${DownloadFile} '"${PY_CRON_URL}"' ${PY_CRON_FILENAME}'
	DL_PY_CRON_DEPS_1='${DownloadFile} '"${PY_CRON_DEPS_1_URL}"' ${PY_CRON_DEPS_1_FILENAME}'
	DL_PY_CRON_DEPS_2='${DownloadFile} '"${PY_CRON_DEPS_2_URL}"' ${PY_CRON_DEPS_2_FILENAME}'
	DL_PY_PSUTIL32='${DownloadFile} '"${PY_PSUTIL32_URL}"' ${PY_PSUTIL32_FILENAME}'
	DL_PY_PSUTIL64='${DownloadFile} '"${PY_PSUTIL64_URL}"' ${PY_PSUTIL64_FILENAME}'
	DL_PY_SFTP='${DownloadFile} '"${PY_SFTP_URL}"' ${PY_SFTP_FILENAME}'
	DL_PY_SFTP_DEPS_1='${DownloadFile} '"${PY_SFTP_DEPS_1_URL}"' ${PY_SFTP_DEPS_1_FILENAME}'
	DL_PY_SFTP_DEPS_2='${DownloadFile} '"${PY_SFTP_DEPS_2_URL}"' ${PY_SFTP_DEPS_2_FILENAME}'
	DL_PY_SYNCTHING='${DownloadFile} '"${PY_SYNCTHING_URL}"' ${PY_SYNCTHING_FILENAME}'
	DL_PY_REQUESTS='${DownloadFile} '"${PY_REQUESTS_URL}"' ${PY_REQUESTS_FILENAME}'
	DL_PY_REQUESTS_DEPS_1='${DownloadFile} '"${PY_REQUESTS_DEPS_1_URL}"' ${PY_REQUESTS_DEPS_1_FILENAME}'
	DL_PY_REQUESTS_DEPS_2='${DownloadFile} '"${PY_REQUESTS_DEPS_2_URL}"' ${PY_REQUESTS_DEPS_2_FILENAME}'
	DL_PY_REQUESTS_DEPS_3='${DownloadFile} '"${PY_REQUESTS_DEPS_3_URL}"' ${PY_REQUESTS_DEPS_3_FILENAME}'
	DL_PY_REQUESTS_DEPS_4='${DownloadFile} '"${PY_REQUESTS_DEPS_4_URL}"' ${PY_REQUESTS_DEPS_4_FILENAME}'
	DL_PY_PATHLIB='${DownloadFile} '"${PY_PATHLIB_URL}"' ${PY_PATHLIB_FILENAME}'
	DL_OPENSSH32='${DownloadFile} '"${OPENSSH32_URL}"' ${OPENSSH32_FILENAME}'
	DL_OPENSSH64='${DownloadFile} '"${OPENSSH64_URL}"' ${OPENSSH64_FILENAME}'
	DL_FUSION_INVENTORY_AGENT32='${DownloadFile} '"${FUSION_INVENTORY_AGENT32_URL}"' ${FUSION_INVENTORY_AGENT32_FILENAME}'
	DL_FUSION_INVENTORY_AGENT64='${DownloadFile} '"${FUSION_INVENTORY_AGENT64_URL}"' ${FUSION_INVENTORY_AGENT64_FILENAME}'
	DL_VNC_AGENT32='${DownloadFile} '"$VNC_AGENT32_URL"' ${VNC_AGENT32_FILENAME}'
	DL_VNC_AGENT64='${DownloadFile} '"$VNC_AGENT64_URL"' ${VNC_AGENT64_FILENAME}'
	DL_SYNCTHING32='${DownloadFile} '"$SYNCTHING32_URL"' ${SYNCTHING32_FILENAME}'
	DL_SYNCTHING64='${DownloadFile} '"$SYNCTHING64_URL"' ${SYNCTHING64_FILENAME}'
	INSTALL_DL_PY_WIN3232='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN3232_FILENAME}`'
	INSTALL_DL_PY_WIN3264='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WIN3264_FILENAME}`'
	INSTALL_DL_PY_NETIFACES='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_NETIFACES_FILENAME}`'
	INSTALL_DL_PY_COMTYPES='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_COMTYPES_FILENAME}`'
	INSTALL_DL_PY_CONFIGPARSER='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --pre --no-index --find-links="$INSTDIR\tmp" ${PY_CONFIGPARSER_FILENAME}`'
	INSTALL_DL_PY_UTILS='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_UTILS_FILENAME}`'
	INSTALL_DL_PY_SLEEKXMPP='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SLEEKXMPP_FILENAME}`'
	INSTALL_DL_PY_WMI='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_WMI_FILENAME}`'
	INSTALL_DL_PY_ZIPFILE='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_ZIPFILE_FILENAME}`'
	INSTALL_DL_PY_CURL32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CURL32_FILENAME}`'
	INSTALL_DL_PY_CURL64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CURL64_FILENAME}`'
	INSTALL_DL_PY_LXML32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_LXML32_FILENAME}`'
	INSTALL_DL_PY_LXML64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_LXML64_FILENAME}`'
	INSTALL_DL_PY_CRYPTO='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CRYPTO_FILENAME}`'
	INSTALL_DL_PY_CRON='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_CRON_FILENAME}`'
	INSTALL_DL_PY_PSUTIL32='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PSUTIL32_FILENAME}`'
	INSTALL_DL_PY_PSUTIL64='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PSUTIL64_FILENAME}`'
	INSTALL_DL_PY_SFTP='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SFTP_FILENAME}`'
	INSTALL_DL_PY_SYNCTHING='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_SYNCTHING_FILENAME}`'
	INSTALL_DL_PY_REQUESTS='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_REQUESTS_FILENAME}`'
	INSTALL_DL_PY_PATHLIB='StrCpy $0 `C:\Python27\Scripts\pip install --quiet --upgrade --no-index --find-links="$INSTDIR\tmp" ${PY_PATHLIB_FILENAME}`'

        [ ${DISABLE_VNC} -eq 1 ] && sed -i "/^\s*Section\s\"VNC.*;$/ s|^|;|; /^\s*Section\s\"VNC/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

        [ ${DISABLE_RDP} -eq 1 ] && sed -i "/^\s*Section\s\"RDP.*;$/ s|^|;|; /^\s*Section\s\"RDP/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

        [ ${DISABLE_INVENTORY} -eq 1 ] && sed -i "/^\s*Section\s\"Fusion.*;$/ s|^|;|; /^\s*Section\s\"Fusion/, /SectionEnd$/ s|^|;|" agent-installer.nsi.in

	sed -e "s/@@PRODUCT_VERSION@@/${AGENT_VERSION}/" \
		-e "s/@@DOWNLOADS_DIR@@/${DOWNLOAD_FOLDER}/" \
		-e "s/@@PYTHON32_FILENAME@@/${PYTHON32_FILENAME}/" \
		-e "s/@@PYTHON64_FILENAME@@/${PYTHON64_FILENAME}/" \
		-e "s/@@PYTHON32_URL@@/$(sed_escape ${PYTHON32_URL})/" \
		-e "s/@@PYTHON64_URL@@/$(sed_escape ${PYTHON64_URL})/" \
		-e "s/@@FULL_OR_DL_PYTHON32_FILENAME@@/$(sed_escape ${DL_PYTHON32_FILENAME})/" \
		-e "s/@@FULL_OR_DL_PYTHON64_FILENAME@@/$(sed_escape ${DL_PYTHON64_FILENAME})/" \
		-e "s/@@PY_VCPYTHON27@@/${PY_VCPYTHON27_FILENAME}/" \
		-e "s/@@PY_VCPYTHON27_URL@@/$(sed_escape ${PY_VCPYTHON27_URL})/" \
		-e "s/@@FULL_OR_DL_PY_VCPYTHON27@@/$(sed_escape ${DL_PY_VCPYTHON27})/" \
		-e "s/@@PY_WIN3232_FILENAME@@/${PY_WIN3232_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN3232@@/$(sed_escape ${DL_PY_WIN3232})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN3232@@/$(sed_escape ${INSTALL_DL_PY_WIN3232})/" \
		-e "s/@@PY_WIN3264_FILENAME@@/${PY_WIN3264_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WIN3264@@/$(sed_escape ${DL_PY_WIN3264})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WIN3264@@/$(sed_escape ${INSTALL_DL_PY_WIN3264})/" \
		-e "s/@@PY_NETIFACES_FILENAME@@/${PY_NETIFACES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${DL_PY_NETIFACES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_NETIFACES@@/$(sed_escape ${INSTALL_DL_PY_NETIFACES})/" \
		-e "s/@@PY_COMTYPES_FILENAME@@/${PY_COMTYPES_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${DL_PY_COMTYPES})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_COMTYPES@@/$(sed_escape ${INSTALL_DL_PY_COMTYPES})/" \
		-e "s/@@PY_CONFIGPARSER_FILENAME@@/${PY_CONFIGPARSER_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${DL_PY_CONFIGPARSER})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CONFIGPARSER@@/$(sed_escape ${INSTALL_DL_PY_CONFIGPARSER})/" \
		-e "s/@@PY_UTILS_FILENAME@@/${PY_UTILS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_UTILS@@/$(sed_escape ${DL_PY_UTILS})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_UTILS@@/$(sed_escape ${INSTALL_DL_PY_UTILS})/" \
		-e "s/@@PY_SLEEKXMPP_FILENAME@@/${PY_SLEEKXMPP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${DL_PY_SLEEKXMPP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SLEEKXMPP@@/$(sed_escape ${INSTALL_DL_PY_SLEEKXMPP})/" \
		-e "s/@@PY_WMI_FILENAME@@/${PY_WMI_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_WMI@@/$(sed_escape ${DL_PY_WMI})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_WMI@@/$(sed_escape ${INSTALL_DL_PY_WMI})/" \
		-e "s/@@PY_ZIPFILE_FILENAME@@/${PY_ZIPFILE_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_ZIPFILE@@/$(sed_escape ${DL_PY_ZIPFILE})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_ZIPFILE@@/$(sed_escape ${INSTALL_DL_PY_ZIPFILE})/" \
		-e "s/@@LIBCURL_FILENAME@@/${LIBCURL_FILENAME}/" \
		-e "s/@@PY_CURL32_FILENAME@@/${PY_CURL32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CURL32@@/$(sed_escape ${DL_PY_CURL32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CURL32@@/$(sed_escape ${INSTALL_DL_PY_CURL32})/" \
		-e "s/@@PY_CURL64_FILENAME@@/${PY_CURL64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CURL64@@/$(sed_escape ${DL_PY_CURL64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CURL64@@/$(sed_escape ${INSTALL_DL_PY_CURL64})/" \
		-e "s/@@PY_LXML32_FILENAME@@/${PY_LXML32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_LXML32@@/$(sed_escape ${DL_PY_LXML32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_LXML32@@/$(sed_escape ${INSTALL_DL_PY_LXML32})/" \
		-e "s/@@PY_LXML64_FILENAME@@/${PY_LXML64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_LXML64@@/$(sed_escape ${DL_PY_LXML64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_LXML64@@/$(sed_escape ${INSTALL_DL_PY_LXML64})/" \
		-e "s/@@PY_CRYPTO_FILENAME@@/${PY_CRYPTO_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRYPTO@@/$(sed_escape ${DL_PY_CRYPTO})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CRYPTO@@/$(sed_escape ${INSTALL_DL_PY_CRYPTO})/" \
		-e "s/@@PY_CRON_FILENAME@@/${PY_CRON_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON@@/$(sed_escape ${DL_PY_CRON})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_CRON@@/$(sed_escape ${INSTALL_DL_PY_CRON})/" \
		-e "s/@@PY_CRON_DEPS_1_FILENAME@@/${PY_CRON_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON_DEPS_1@@/$(sed_escape ${DL_PY_CRON_DEPS_1})/" \
		-e "s/@@PY_CRON_DEPS_2_FILENAME@@/${PY_CRON_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_CRON_DEPS_2@@/$(sed_escape ${DL_PY_CRON_DEPS_2})/" \
		-e "s/@@PY_PSUTIL32_FILENAME@@/${PY_PSUTIL32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PSUTIL32@@/$(sed_escape ${DL_PY_PSUTIL32})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PSUTIL32@@/$(sed_escape ${INSTALL_DL_PY_PSUTIL32})/" \
		-e "s/@@PY_PSUTIL64_FILENAME@@/${PY_PSUTIL64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PSUTIL64@@/$(sed_escape ${DL_PY_PSUTIL64})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PSUTIL64@@/$(sed_escape ${INSTALL_DL_PY_PSUTIL64})/" \
		-e "s/@@PY_SFTP_FILENAME@@/${PY_SFTP_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP@@/$(sed_escape ${DL_PY_SFTP})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SFTP@@/$(sed_escape ${INSTALL_DL_PY_SFTP})/" \
		-e "s/@@PY_SFTP_DEPS_1_FILENAME@@/${PY_SFTP_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP_DEPS_1@@/$(sed_escape ${DL_PY_SFTP_DEPS_1})/" \
		-e "s/@@PY_SFTP_DEPS_2_FILENAME@@/${PY_SFTP_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SFTP_DEPS_2@@/$(sed_escape ${DL_PY_SFTP_DEPS_2})/" \
		-e "s/@@PY_SYNCTHING_FILENAME@@/${PY_SYNCTHING_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_SYNCTHING@@/$(sed_escape ${DL_PY_SYNCTHING})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_SYNCTHING@@/$(sed_escape ${INSTALL_DL_PY_SYNCTHING})/" \
		-e "s/@@PY_REQUESTS_FILENAME@@/${PY_REQUESTS_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS@@/$(sed_escape ${DL_PY_REQUESTS})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_REQUESTS@@/$(sed_escape ${INSTALL_DL_PY_REQUESTS})/" \
		-e "s/@@PY_REQUESTS_DEPS_1_FILENAME@@/${PY_REQUESTS_DEPS_1_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_1@@/$(sed_escape ${DL_PY_REQUESTS_DEPS_1})/" \
		-e "s/@@PY_REQUESTS_DEPS_2_FILENAME@@/${PY_REQUESTS_DEPS_2_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_2@@/$(sed_escape ${DL_PY_REQUESTS_DEPS_2})/" \
		-e "s/@@PY_REQUESTS_DEPS_3_FILENAME@@/${PY_REQUESTS_DEPS_3_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_3@@/$(sed_escape ${DL_PY_REQUESTS_DEPS_3})/" \
		-e "s/@@PY_REQUESTS_DEPS_4_FILENAME@@/${PY_REQUESTS_DEPS_4_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_REQUESTS_DEPS_4@@/$(sed_escape ${DL_PY_REQUESTS_DEPS_4})/" \
		-e "s/@@PY_PATHLIB_FILENAME@@/${PY_PATHLIB_FILENAME}/" \
		-e "s/@@FULL_OR_DL_PY_PATHLIB@@/$(sed_escape ${DL_PY_PATHLIB})/" \
		-e "s/@@INSTALL_FULL_OR_DL_PY_PATHLIB@@/$(sed_escape ${INSTALL_DL_PY_PATHLIB})/" \
		-e "s/@@PULSE_AGENT@@/${PULSE_AGENT_FILENAME}/" \
		-e "s/@@PULSE_AGENT_CONFFILE@@/${PULSE_AGENT_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_SCHEDULER_CONFFILE@@/${PULSE_SCHEDULER_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_INVENTORY_CONFFILE@@/${PULSE_INVENTORY_CONFFILE_FILENAME}/" \
		-e "s/@@PULSE_AGENT_NAME@@/${PULSE_AGENT_NAME}/" \
		-e "s/@@PULSE_AGENT_MODULE@@/${PULSE_AGENT_MODULE}/" \
		-e "s/@@PULSE_AGENT_TASK_XML@@/${PULSE_AGENT_TASK_XML}/" \
		-e "s/@@OPENSSH_NAME@@/${OPENSSH_NAME}/" \
		-e "s/@@OPENSSH32_FILENAME@@/${OPENSSH32_FILENAME}/" \
		-e "s/@@OPENSSH64_FILENAME@@/${OPENSSH64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_OPENSSH32@@/$(sed_escape ${DL_OPENSSH32})/" \
		-e "s/@@FULL_OR_DL_OPENSSH64@@/$(sed_escape ${DL_OPENSSH64})/" \
		-e "s/@@LAUNCHER_SSH_KEY@@/${LAUNCHER_SSH_KEY}/" \
		-e "s/@@FUSION_INVENTORY_AGENT32_FILENAME@@/${FUSION_INVENTORY_AGENT32_FILENAME}/" \
		-e "s/@@FUSION_INVENTORY_AGENT64_FILENAME@@/${FUSION_INVENTORY_AGENT64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT32@@/$(sed_escape ${DL_FUSION_INVENTORY_AGENT32})/" \
		-e "s/@@FULL_OR_DL_FUSION_INVENTORY_AGENT64@@/$(sed_escape ${DL_FUSION_INVENTORY_AGENT64})/" \
		-e "s/@@INVENTORY_TAG@@/${INVENTORY_TAG}/" \
		-e "s/@@VNC_AGENT32_FILENAME@@/${VNC_AGENT32_FILENAME}/" \
		-e "s/@@VNC_AGENT64_FILENAME@@/${VNC_AGENT64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_VNC_AGENT32@@/$(sed_escape ${DL_VNC_AGENT32})/" \
		-e "s/@@FULL_OR_DL_VNC_AGENT64@@/$(sed_escape ${DL_VNC_AGENT64})/" \
		-e "s/@@SYNCTHING32_FILENAME@@/${SYNCTHING32_FILENAME}/" \
		-e "s/@@FULL_OR_DL_SYNCTHING32@@/$(sed_escape ${DL_SYNCTHING32})/" \
		-e "s/@@SYNCTHING64_FILENAME@@/${SYNCTHING64_FILENAME}/" \
		-e "s/@@FULL_OR_DL_SYNCTHING64@@/$(sed_escape ${DL_SYNCTHING64})/" \
		-e "s/@@RSYNC_FILENAME@@/rsync.zip/" \
		-e "s/@@GENERATED_SIZE@@/MINIMAL/" \
        -e "s/@@RFB_PORT@@/${VNC_PORT}/" \
        -e "s/@@SSH_PORT@@/${SSH_PORT}/" \
        -e "s/@@CREATE_PROFILE_NAME@@/${CREATE_PROFILE_NAME}/" \
        -e "s/@@PULSE_SERVICE_NAME@@/${PULSE_SERVICE_NAME}/" \
        -e "s/@@NETCHECK_SERVICE_NAME@@/${NETCHECK_SERVICE_NAME}/" \
        -e "s/@@NETCHECK_PROGRAM_NAME@@/${NETCHECK_PROGRAM_NAME}/" \
        -e "s/@@NETCHECK_SERVICE_DISPLAYNAME@@/${NETCHECK_SERVICE_DISPLAYNAME}/" \
		agent-installer.nsi.in \
		> agent-installer.nsi
	colored_echo green "### INFO Updating NSIS script.. Done"
}

generate_agent_installer() {
	colored_echo blue "### INFO Generating installer..."
	makensis -V1 agent-installer.nsi
	if [ ! $? -eq 0 ]; then
		colored_echo red "### ER... Generation of agent failed. Please restart"
		exit 1
	fi

    # Create symlinks to latest version
    if [[ ${INVENTORY_TAG} == '' ]]; then
        if [[ ${MINIMAL} -eq 1 ]]; then
	    ln -s -f Pulse-Agent-windows-MINIMAL-${AGENT_VERSION}.exe Pulse-Agent-windows-MINIMAL-latest.exe
        else
	    ln -s -f Pulse-Agent-windows-FULL-${AGENT_VERSION}.exe Pulse-Agent-windows-FULL-latest.exe
        fi
    fi

    for package in Pulse-Agent-windows-MINIMAL-latest Pulse-Agent-windows-FULL-latest;
    do
        cp -fv /var/lib/pulse2/clients/win/${package}.exe /var/lib/pulse2/imaging/postinst/winutils/
    done

        [ ${DISABLE_VNC} -eq 1 ] && sed -i "/\s;*Section\s\"VNC.*;$/ s|^|;|; /\s*Section\s\"VNC/, /SectionEnd$/ s|^;||" agent-installer.nsi.in

        [ ${DISABLE_RDP} -eq 1 ] && sed -i "/\s;*Section\s\"RDP.*;$/ s|^|;|; /\s*Section\s\"RDP/, /SectionEnd$/ s|^;||" agent-installer.nsi.in

        [ ${DISABLE_INVENTORY} -eq 1 ] && sed -i "/\s;*Section\s\"Fusion.*;$/ s|^|;|; /\s*Section\s\"Fusion/, /SectionEnd$/ s|^;||" agent-installer.nsi.in


        colored_echo green "### INFO  Generating installer... Done"

}

# Run the script
check_arguments "$@"
compute_parameters
prepare_mandatory_includes
if [[ ${MINIMAL} -eq 1 ]]; then
	update_nsi_script_dl
else
	update_nsi_script_full
fi
generate_agent_installer
