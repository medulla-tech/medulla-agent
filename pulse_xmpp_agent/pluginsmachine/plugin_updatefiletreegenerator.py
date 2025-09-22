# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)

FILETREEVERSION = "0.1"

logger = logging.getLogger()
plugin = {"VERSION": "0.5", "NAME": "updatefiletreegenerator", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkfiletreegeneratorversion()
        if StrictVersion(installed_version) < StrictVersion(FILETREEVERSION):
            updatefiletreegenerator(xmppobject, installed_version)
    except Exception:
        pass


def checkfiletreegeneratorversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Filetree Generator" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            filetreegeneratorversion = result["result"][0].strip().split()[-1]
        else:
            # The filetree generator is not installed. We will force installation by returning
            # version 0.0
            filetreegeneratorversion = "0.0"

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Filetree Generator" /v "DisplayIcon"'
        result = utils.simplecommand(cmd)

        if result["code"] != 0:
            cmd = (
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Filetree Generator" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f'
            )
            utils.simplecommand(cmd)
    return filetreegeneratorversion


def updatefiletreegeneratorversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Filetree Generator" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % FILETREEVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated Pulse Filetree Generator to version %s"
                % FILETREEVERSION
            )

        if version == "0.0":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\\Pulse Filetree Generator" '
                '/v "DisplayName" /t REG_SZ  /d "Pulse Filetree Generator" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\\Pulse Filetree Generator" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatefiletreegenerator(xmppobject, installed_version):
    logger.info(
        "Updating Filetree Generator from version %s to version %s"
        % (installed_version, FILETREEVERSION)
    )
    if sys.platform.startswith("win"):
        pulsedir_path = os.path.join(medullaPath(), "bin")

        filename = "pulse-filetree-generator.exe"
        dl_url = "%s/downloads/win/%s" % (xmppobject.config.update_server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(pulsedir_path, filename)
        ).downloadurl()
        if result:
            # Download success
            try:
                updatefiletreegeneratorversion(installed_version)
            except IOError as errorcopy:
                logger.error(
                    "Error while copying the file with the error: %s" % errorcopy
                )
        else:
            # Download error
            logger.error("%s" % txtmsg)
