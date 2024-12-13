# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils
from lib.agentconffile import (
    medullaPath,
)

RDPVERSION = "0.3"

logger = logging.getLogger()
plugin = {"VERSION": "1.4", "NAME": "updaterdp", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug(" PL-RDP ###################################################")
    logger.debug(" PL-RDP call %s from %s" % (plugin, message["from"]))
    logger.debug(" PL-RDP ###################################################")
    try:
        # Update if version is lower
        installed_version = checkrdpversion()
        if StrictVersion(installed_version) < StrictVersion(RDPVERSION):
            updaterdp(xmppobject, installed_version)
    except Exception:
        pass


def checkrdpversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            rdpversion = result["result"][0].strip().split()[-1]
        else:
            # The rdp configuration is not installed. We will force installation by returning
            # version 0.0
            rdpversion = "0.0"

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" /v "DisplayIcon"'
        result = utils.simplecommand(cmd)

        if result["code"] != 0:
            cmd = (
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f'
            )
            utils.simplecommand(cmd)
    return rdpversion


def updaterdpversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % RDPVERSION
        )
        result = utils.simplecommand(cmd)

        cmdDisplay = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" '
            '/v "DisplayName" /t REG_SZ  /d "Medulla RDP" /f'
        )
        utils.simplecommand(cmdDisplay)

        cmdEditor = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla RDP" '
            '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
        )
        utils.simplecommand(cmdiEditor)
        if result["code"] == 0:
            logger.info(
                " PL-RDP We successfully updated Medulla RDP to version " % RDPVERSION
            )


def updaterdp(xmppobject, installed_version):
    logger.info(" PL-RDP Updating RDP Configuration.")
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
            'netsh advfirewall firewall add rule name="Remote Desktop for Medulla RDP" dir=in action=allow protocol=TCP localport=3389'
        )

        updaterdpversion(RDPVERSION)
