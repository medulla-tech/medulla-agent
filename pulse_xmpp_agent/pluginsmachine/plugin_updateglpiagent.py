# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from lib import utils
from distutils.version import StrictVersion
import logging
import platform
import tempfile
import os

FUSIONVERSION = "2.5.2"
GLPIAGENTVERSION = "1.4"
logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updateglpiagent", "TYPE": "machine"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        if (
            hasattr(xmppobject.config, "agent")
            and xmppobject.config.agent == "glpiagent"
        ):
            # Update if version is lower
            check_if_binary_ok()
            installed_version = checkGlpiAgentVersion()
            if StrictVersion(installed_version) < StrictVersion(GLPIAGENTVERSION):
                updateGlpiAgent(xmppobject)
    except Exception as error:
        logger.debug(str(error))
        pass


def checkGlpiAgentVersion():
    if sys.platform.startswith("win"):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\{E1BE6C18-6BF4-1014-844A-F1F114E3EA24} /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            glpiagentversion = result["result"][0].strip().split()[-1]
    return glpiagentversion


def check_if_binary_ok():
    if sys.platform.startswith("win"):
        # We check if the GLPI-Agent inventory binary is correctly installed.
        glpiAgentdir_path = os.path.join("c:\\", "progra~1", "GLPI-Agent")
        glpiAgent_bin_path = os.path.join(glpiAgentdir_path, "glpi-agent.bat")

        if os.path.isfile(glpiAgent_bin_path):
            logger.debug("Glpi-Agent is correctly installed. Nothing to do")
        else:
            logger.info("Glpi-Agent is not present, we need to install the component.")

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\{E1BE6C18-6BF4-1014-844A-F1F114E3EA24}" '
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug("The Glpi-Agent module is ready to be reinstalled.")
            else:
                logger.debug(
                    "We failed to reinitialize the registry entry for Glpi-Agent."
                )


def updateGlpiAgent(xmppobject):
    logger.info("Updating Glpi-Agent to version %s" % FUSIONVERSION)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith("win"):
        if platform.architecture()[0] == "64bit":
            architecture = "x64"
        else:
            architecture = "x86"
        filename = "GLPI-Agent-%s-%s.msi" % (GLPIAGENTVERSION, architecture)
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
            cmd = "msiexec /i %s /quiet" % filename
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
