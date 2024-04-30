# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils

KIOSKLAUNCHERVERSION = "1.0.0"

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updatekiosklauncher", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        check_if_binary_ok()
        # Update if version is lower
        installed_version = kiosklauncherversion()
        if StrictVersion(installed_version) < StrictVersion(KIOSKLAUNCHERVERSION):
            updatekiosklauncher(xmppobject)
            updatekiosklauncherversion(installed_version)
    except Exception:
        pass


def check_if_binary_ok():
    if sys.platform.startswith("win"):
        regedit = False
        binary = False
        reinstall = False

        # We check if we have the Regedit entry
        cmd_reg = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" /s | Find "DisplayVersion"'
        result_reg = utils.simplecommand(cmd_reg)
        if result_reg["code"] == 0:
            regedit = True

        # We check if the binary is available
        pulsedir_path = os.path.join("c:\\", "progra~1", "Medulla", "bin")
        filename = "RunMedullaKiosk.bat"

        if os.path.isfile(os.path.join(pulsedir_path, filename)):
            binary = True

        if regedit is False or binary is False:
            reinstall = True

        if reinstall:
            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" '
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug("The Medulla kiosk launcher is ready to be reinstalled.")
            else:
                logger.debug("We failed to reinitialize the registry entry.")


def kiosklauncherversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            KIOSKLAUNCHERVERSION = result["result"][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.1
            KIOSKLAUNCHERVERSION = "0.1"
    return KIOSKLAUNCHERVERSION


def updatekiosklauncherversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % KIOSKLAUNCHERVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated Medulla kiosk launcher to version %s"
                % KIOSKLAUNCHERVERSION
            )

        if version == "0.1":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla kiosk launcher" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk launcher" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatekiosklauncher(xmppobject):
    logger.info("Updating Medulla kiosk launcher to version %s" % KIOSKLAUNCHERVERSION)
    if sys.platform.startswith("win"):
        pulsedir_path = os.path.join("c:\\", "progra~1", "Medulla", "bin")

        filename = "RunMedullaKiosk.bat"
        dl_url = "http://%s/downloads/win/%s" % (xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(pulsedir_path, filename)
        ).downloadurl()
        if result:
            logger.debug("%s" % txtmsg)
        else:
            # Download error
            logger.error("%s" % txtmsg)

        if os.path.isfile(os.path.join(pulsedir_path, filename)):
            # Copy file to C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp
            src = os.path.join(pulsedir_path, filename)
            dest = os.path.join(
                "c:\\",
                "ProgramData",
                "Microsoft",
                "Windows",
                "Start Menu",
                "Programs",
                "StartUp",
            )
            try:
                shutil.copy(src, dest)
            except shutil.Error as e:
                logger.error("Error copying file %s: %s" % (src, e))
            except IOError as e:
                logger.error("Error copying file %s: %s" % (src, e.strerror))
