# -*- coding: utf-8 -*-
#
# (c) 2022 siveo, http://www.siveo.net
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
# file : plugin_updatevim.py

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
import hashlib

APPVERSION = "9.0"
SHA1SUM = "C22CEAF166D10BDF094D78FD997FC30F02DFC238"
APPNAME = "Medulla Vim"
REGKEY = "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\%s" % APPNAME

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatevim", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")

    try:
        check_if_binary_ok()
        # Update if version is lower
        installed_version = checkversion()
        if StrictVersion(installed_version) < StrictVersion(APPVERSION):
            updateapp(xmppobject, installed_version)
    except Exception:
        pass


def check_if_binary_ok():
    if sys.platform.startswith("win"):
        regedit = False
        binary = False
        reinstall = False

        # We check if we have the Regedit entry
        cmd_reg = 'reg query "%s" /s | Find "DisplayVersion"' % REGKEY
        result_reg = utils.simplecommand(cmd_reg)
        if result_reg["code"] == 0:
            regedit = True

        # We check if the binary is available
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")
        filename = "vim.exe"

        if os.path.isfile(os.path.join(pulsedir_path, filename)):
            sha1_hash = hashlib.sha1()
            with open(os.path.join(pulsedir_path, filename), "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha1_hash.update(byte_block)
            if sha1_hash.hexdigest().upper() == SHA1SUM:
                binary = True

        if regedit is False or binary is False:
            reinstall = True

        if reinstall:
            cmd = 'REG ADD "%s" /v "DisplayVersion" /t REG_SZ  /d "0.0" /f' % REGKEY
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug("%s is ready to be reinstalled." % APPNAME)
            else:
                logger.debug("We failed to reinitialize the registry entry.")


def checkversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "%s" /s | Find "DisplayVersion"' % REGKEY
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            version = result["result"][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.0
            version = "0.0"
    return version


def updateversion(version):
    if sys.platform.startswith("win"):
        cmd = 'REG ADD "%s" /v "DisplayVersion" /t REG_SZ  /d "%s" /f' % (
            REGKEY,
            APPVERSION,
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated %s to version %s" % (APPNAME, APPVERSION)
            )

        if version == "0.0":
            cmdDisplay = 'REG ADD "%s" /v "DisplayName" /t REG_SZ  /d "%s" /f' % (
                REGKEY,
                APPNAME,
            )
            utils.simplecommand(cmdDisplay)
            cmd = 'REG ADD "%s" /v "Publisher" /t REG_SZ  /d "SIVEO" /f' % REGKEY
            utils.simplecommand(cmd)


def updateapp(xmppobject, installed_version):
    logger.info(
        "Updating %s from version %s to version %s"
        % (APPNAME, installed_version, APPVERSION)
    )
    if sys.platform.startswith("win"):
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = "vim.exe"
        dl_url = "http://%s/downloads/win/downloads/%s" % (
            xmppobject.config.Server,
            filename,
        )
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(pulsedir_path, "vim.exe")
        ).downloadurl()
        if result:
            # Download success
            try:
                updateversion(installed_version)
            except IOError as errorcopy:
                logger.error(
                    "Error while copying the file with the error: %s" % errorcopy
                )
        else:
            # Download error
            logger.error("%s" % txtmsg)
