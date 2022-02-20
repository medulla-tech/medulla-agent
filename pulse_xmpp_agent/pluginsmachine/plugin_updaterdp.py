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

import sys
import os
from distutils.version import StrictVersion
import logging
import zipfile
import platform
from lib import utils

RDPVERSION = "0.2"

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updaterdp", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkrdpversion()
        if StrictVersion(installed_version) < StrictVersion(RDPVERSION):
            updaterdp(xmppobject, installed_version)
    except Exception:
        pass


def checkrdpversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RDP" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            rdpversion = result["result"][0].strip().split()[-1]
        else:
            # The rdp configuration is not installed. We will force installation by returning
            # version 0.0
            rdpversion = "0.0"
    return rdpversion


def updaterdpversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RDP" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % RDPVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info("we successfully updated Pulse RDP to version " % RDPVERSION)

        if version == "0.0":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RDP" '
                '/v "DisplayName" /t REG_SZ  /d "Pulse RDP" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RDP" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)
            logger.info("RDP Configuration updated.")


def updaterdp(xmppobject, installed_version):
    logger.info("Updating RDP Configuration.")
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            '/v "fDenyTSConnections" /t REG_DWORD  /d "0x00000000" /f'
        )

        utils.simplecommand(cmd)

        cmd = (
            'REG ADD "hklm\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
            '/v "fSingleSessionPerUser" /t REG_DWORD  /d "0x00000000" /f'
        )
        utils.simplecommand(cmd)

        cmd = (
            'REG ADD "hklm\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
            '/v "UserAuthentication" /t REG_DWORD  /d "0x00000000" /f'
        )
        utils.simplecommand(cmd)

        cmd = (
            'REG ADD "hklm\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
            '/v "SecurityLayer" /t REG_DWORD  /d "0x00000000" /f'
        )
        utils.simplecommand(cmd)

        utils.simplecommand(
            'netsh advfirewall firewall add rule name="Remote Desktop for Pulse RDP" dir=in action=allow protocol=TCP localport=3389'
        )

        updaterdpversion(RDPVERSION)
