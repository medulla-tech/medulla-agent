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
# file : plugin_updatefiletreegenerator.py

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils

FILETREEVERSION = "0.1"

logger = logging.getLogger()

plugin = {"VERSION": "0.2", "NAME": "updatefiletreegenerator", "TYPE": "machine"}


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
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = "pulse-filetree-generator.exe"
        dl_url = "http://%s/downloads/win/%s" % (xmppobject.config.Server, filename)
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
