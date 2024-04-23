# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
import hashlib

APPVERSION = "1.29"
SHA1SUM = "0FC135B131D0BB47C9A0AAF02490701303B76D3B"
APPNAME = "PAExec"
REGKEY = "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\%s" % APPNAME

logger = logging.getLogger()

plugin = {"VERSION": "1.51", "NAME": "updatepaexec", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
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
        medulladir_path = os.path.join("c:\\", "progra~1", "Medulla", "bin")
        filename = "paexec.exe"

        if os.path.isfile(os.path.join(medulladir_path, filename)):
            sha1_hash = hashlib.sha1()
            with open(os.path.join(medulladir_path, filename), "rb") as f:
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
        medulladir_path = os.path.join("c:\\", "progra~1", "Medulla", "bin")

        filename = "paexec_1_29.exe"
        dl_url = "http://%s/downloads/win/downloads/%s" % (
            xmppobject.config.Server,
            filename,
        )
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(medulladir_path, "paexec.exe")
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
