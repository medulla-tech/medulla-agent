# -*- coding: utf-8 -*-
#
# (c) 2020 siveo, http://www.siveo.net
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
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
# file : plugin_updatefusion.py

import sys
from lib import utils
from distutils.version import StrictVersion
import pycurl
import logging
import platform
import tempfile
import os

TIGHTVNC = '2.8.8'

logger = logging.getLogger()

plugin = {"VERSION": "1.02", "NAME": "updatetightvnc", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checktightvncversion()
        if StrictVersion(installed_version) < StrictVersion(TIGHTVNC):
            updatetightvnc(xmppobject)
    except Exception:
        pass


def checktightvncversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\{DEE0B752-52D8-4615-9BEE-1EDA46628960} /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            tightvncversion = result['result'][0].strip().split()[-1]
        else:
            # TIGHTVNC is not installed. We will force installation by returning
            # version 0.1
            tightvncversion = '0.1'
    return tightvncversion


def updatetightvnc(xmppobject):
    logger.info("Updating TightVNC Agent to version %s" % TIGHTVNC)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    Used_rfb_port = 5900
    if hasattr(xmppobject.config, 'rfbport'):
        Used_rfb_port = xmppobject.config.rfbport

    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            architecture = '64bit'
        else:
            architecture = '32bit'
        filename = 'tightvnc-%s-gpl-setup-%s.msi' % (
            TIGHTVNC, architecture)
        dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            install_options = "/quiet /qn /norestart"
            install_options = install_options + " ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1"
            # Disable embedded Java WebSrv on port 5800
            install_options = install_options + " SET_ACCEPTHTTPCONNECTIONS=1 VALUE_OF_ACCEPTHTTPCONNECTIONS=0"
            # Enable RFB on port 5900
            install_options = install_options + " SET_ACCEPTRFBCONNECTIONS=1 VALUE_OF_ACCEPTRFBCONNECTIONS=1"
            # Enable loopback connection
            install_options = install_options + " SET_ALLOWLOOPBACK=1 VALUE_OF_ALLOWLOOPBACK=1"
            # Allow on all interfaces
            install_options = install_options + " SET_LOOPBACKONLY=1 VALUE_OF_LOOPBACKONLY=0"
            # Only allow from 127.0.0.1 and query user
            install_options = install_options + " SET_IPACCESSCONTROL=1 VALUE_OF_IPACCESSCONTROL=0.0.0.0-255.255.255.255:2"
            # Default answser on timeout is reject
            install_options = install_options + " SET_QUERYACCEPTONTIMEOUT=1 VALUE_OF_QUERYACCEPTONTIMEOUT=0"
            # Timeout is 20s
            install_options = install_options + " SET_QUERYTIMEOUT=1 VALUE_OF_QUERYTIMEOUT=20"
            # Show service icon
            install_options = install_options + " SET_RUNCONTROLINTERFACE=1 VALUE_OF_RUNCONTROLINTERFACE=1"
            # Hide wallpaper
            install_options = install_options + " SET_REMOVEWALLPAPER=1 VALUE_OF_REMOVEWALLPAPER=1"
            # Share between multiple connection
            install_options = install_options + " SET_ALWASHARED=1 SET_NEVERSHARED=1 VALUE_OF_ALWASHARED=1 VALUE_OF_NEVERSHARED=0"
            # Disable authentication
            install_options = install_options + " SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=0"
            # Ensure remote inputs are enabled
            install_options = install_options + " SET_BLOCKREMOTEINPUT=1 VALUE_OF_BLOCKREMOTEINPUT=0"
            # Don't do anything when terminating VNC session
            install_options = install_options + " SET_DISCONNECTACTION=1 VALUE_OF_DISCONNECTACTION=0"
            # Set the server listening port
            install_options = install_options + " SET_RFBPORT=1 VALUE_OF_RFBPORT=%s" % Used_rfb_port

            # Run installer
            cmd = 'msiexec /i %s %s REBOOT=R' % (filename, install_options)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result['code'] == 0:
                logger.info("%s installed successfully to version %s" % (filename, TIGHTVNC))
                
            else:
                logger.error("Error installing %s: %s"
                             % (filename, cmd_result['result']))

            utils.simplecommand("netsh advfirewall firewall add rule name=\"Remote Desktop for Pulse VNC\" dir=in action=allow protocol=TCP localport=%s" % Used_rfb_port)
        else:
            # Download error
            logger.error("%s" % txtmsg)

