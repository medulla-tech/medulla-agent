# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)

NOTIFICATIONVERSION = "3.2.1"

logger = logging.getLogger()

plugin = {"VERSION": "1.7", "NAME": "updatenotification", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        check_if_binary_ok()
        # Update if version is lower
        installed_version = notificationversion()
        if StrictVersion(installed_version) < StrictVersion(NOTIFICATIONVERSION):
            updatenotification(xmppobject)
            updatenotificationversion(installed_version)
    except Exception as error_loading:
        logger.error("An error occured while loading the plugin")
        logger.error(f"We have the error \n {error_loading}")
        pass


def check_if_binary_ok():
    if sys.platform.startswith("win"):
        regedit = False
        binary = False
        reinstall = False
        logo = False

        # We check if we have the Regedit entry
        cmd_reg = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" /s | Find "DisplayVersion"'
        result_reg = utils.simplecommand(cmd_reg)
        if result_reg["code"] == 0:
            regedit = True

        # We check if the binary is available
        pulsedir_path = os.path.join(medullaPath(), "bin")
        filename = "pulse2_update_notification.py"
        image = "medulla_logo.png"

        if os.path.isfile(os.path.join(pulsedir_path, filename)):
            binary = True

        if os.path.isfile(os.path.join(pulsedir_path, image)):
            logo = True

        reinstall = not (regedit and binary and logo)

        if reinstall:
            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug(
                    "The Pulse Notification module is ready to be reinstalled."
                )
            else:
                logger.debug("We failed to reinitialize the registry entry.")


def notificationversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            notificationversion = result["result"][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.1
            notificationversion = "0.1"

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" /v "DisplayIcon"'
        result = utils.simplecommand(cmd)

        if result["code"] != 0:
            cmd = (
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f'
            )
            utils.simplecommand(cmd)
    return notificationversion


def updatenotificationversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % NOTIFICATIONVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated Pulse notification to version %s"
                % NOTIFICATIONVERSION
            )

        if version == "0.1":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '
                '/v "DisplayName" /t REG_SZ  /d "Pulse notification" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatenotification(xmppobject):
    logger.info("Updating Pulse Notification to version %s" % NOTIFICATIONVERSION)
    if sys.platform.startswith("win"):
        pulsedir_path = os.path.join(medullaPath(), "bin")

        filenames = ["pulse2_update_notification.py", "medulla_logo.png"]
        for filename in filenames:
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
