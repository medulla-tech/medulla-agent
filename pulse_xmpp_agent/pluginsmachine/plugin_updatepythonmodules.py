# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from distutils.version import StrictVersion
import logging
import tempfile
import os
import pkg_resources

from lib import utils

NETIFACESVERSION = "0.0.22"
logger = logging.getLogger()

plugin = {"VERSION": "0.1", "NAME": "updatepythonmodules", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
            if sys.platform.startswith("win"):
                # Update if version is lower
                netifaces_installed_version = checkNetifacesVersion()
                if StrictVersion(netifaces_installed_version) < StrictVersion(GLPIAGENTVERSION):
                    updateNetifaces(xmppobject)
    except Exception as error:
        logger.error(str(error))
        pass


def checkNetifacesVersion():
    if sys.platform.startswith("win"):
        netifacesVersion = pkg_resources.get_distribution("netifaces2").version
        return netifacesVersion


def updateNetifaces(xmppobject):
    logger.info("Updating Netifaces python module to version %s" % NETIFACESVERSION)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith("win"):
        filename = f"netifaces2-{NETIFACESVERSION}-cp37-abi3-win_amd64.whl"
        dl_url = f"http://{xmppobject.config.Server}/downloads/win/downloads/python_modules/{filename}"
        logger.debug(f"Downloading {dl_url}")

        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()

        if result:
            # Download success
            logger.info("%s" % txtmsg)
            os.chdir(install_tempdir)
            # Run installer
            cmd = f"msiexec /i {filename} /quiet"
            cmd = f'"c:\Program Files\Python3\Scripts\pip3.exe" install --upgrade {filename}'
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
