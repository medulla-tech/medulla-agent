# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


"""
Update FusionInventory Plugin

This module defines a plugin for updating the FusionInventory Agent on a machine.
The plugin checks the installed version of FusionInventory and updates it if the version is lower than the specified version.

Variables:
    - FUSIONVERSION (str): The target version of FusionInventory.
    - logger (Logger): Logger object for logging messages.
    - plugin (dict): Plugin information dictionary containing version, name, and type.
    - utils: Utility functions from the lib module.

Functions:
    - action(xmppobject, action, sessionid, data, message, dataerreur): Main function for the plugin.
    - checkfusionversion(): Checks the currently installed version of FusionInventory.
    - check_if_binary_ok(): Checks if the FusionInventory binary is correctly installed.
    - updatefusion(xmppobject): Updates FusionInventory to the specified version.

Note: This plugin assumes the availability of certain commands and paths on Windows systems.

"""

import sys
from lib import utils
from distutils.version import StrictVersion
import logging
import platform
import tempfile
import os

# ma_variable est utilisée pour stocker ...
FUSIONVERSION = "2.6"

logger = logging.getLogger()

plugin = {"VERSION": "1.7", "NAME": "updatefusion", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    """
    Main function for the update FusionInventory plugin.

    @arg xmppobject: XMPP object.
    :param action: Action to be performed.
    :param sessionid: Session ID.
    :param data: Data related to the action.
    :param message: Incoming XMPP message.
    :param dataerreur: Data related to errors.

    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        if not hasattr(xmppobject.config, "agent") or (
            hasattr(xmppobject.config, "agent")
            and xmppobject.config.agent != "glpiagent"
        ):
            # Update if version is lower
            check_if_binary_ok()
            installed_version = checkfusionversion()
            if StrictVersion(installed_version) < StrictVersion(FUSIONVERSION):
                updatefusion(xmppobject)
    except Exception as error_plugin:
        logger.error("An error occured. The error code is %s" % str(error_plugin))
        pass


def checkfusionversion():
    """
    Check the currently installed version of FusionInventory.

    :return: The installed version of FusionInventory (str).

    """
    if sys.platform.startswith("win"):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\FusionInventory-Agent /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            fusionversion = result["result"][0].strip().split()[-1]
        else:
            # Fusion is not installed. We will force installation by returning
            # version 0.1
            fusionversion = "0.1"
        return fusionversion


def check_if_binary_ok():
    """
    Check if the FusionInventory binary is correctly installed.

    """
    if sys.platform.startswith("win"):
        # We check if the fusion inventory binary is correctly installed.
        fusiondir_path = os.path.join("c:\\", "progra~1", "FusionInventory-Agent")
        fusion_bin_path = os.path.join(fusiondir_path, "fusioninventory-agent.bat")

        if os.path.isfile(fusion_bin_path):
            logger.debug("FusionInventory is correctly installed. Nothing to do")
        else:
            logger.info(
                "FusionInventory is not present, we need to install the component."
            )

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\FusionInventory-Agent" '
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug("The FusionInventory module is ready to be reinstalled.")
            else:
                logger.debug(
                    "We failed to reinitialize the registry entry for FusionInventory."
                )


def updatefusion(xmppobject):
    """
    Update FusionInventory to the specified version.

    :param xmppobject: XMPP object.

    """
    logger.info("Updating FusionInventory Agent to version %s" % FUSIONVERSION)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith("win"):
        if platform.architecture()[0] == "64bit":
            architecture = "x64"
        else:
            architecture = "x86"
        filename = "fusioninventory-agent_windows-%s_%s.exe" % (
            architecture,
            FUSIONVERSION,
        )
        dl_url = "http://%s/downloads/win/downloads/%s" % (
            xmppobject.config.Server,
            filename,
        )
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            # Run installer
            cmd = "%s /S /acceptlicense /no-start-menu /execmode=Manual" % filename
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info("%s installed successfully" % filename)
            else:
                logger.error(
                    "Error installing %s: %s" % (filename, cmd_result["result"])
                )
        else:
            # Download error
            logger.error("%s" % txtmsg)
