# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
import hashlib

APPVERSION = "1.2.3"
SHA1SUM = "a95d7098080fc3994ab434c2a5c4ec8f85817b11"
APPNAME = "RustDesk"
REGKEY = "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\%s" % APPNAME

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updaterustdesk", "TYPE": "machine"}


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
        rustdeskdir_path = os.path.join(os.environ["ProgramFiles"], "RustDesk")
        filename = "rustdesk.exe"

        if os.path.isfile(os.path.join(rustdeskdir_path, filename)):
            sha1_hash = hashlib.sha1()
            with open(os.path.join(rustdeskdir_path, filename), "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha1_hash.update(byte_block)
            if sha1_hash.hexdigest().upper() == SHA1SUM.upper():
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


def updateapp(xmppobject, installed_version):
    logger.info(
        "Updating %s from version %s to version %s"
        % (APPNAME, installed_version, APPVERSION)
    )

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith("win"):
        filename = "rustdesk-%s-x86_64.exe" % APPVERSION
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

            try:
                cmd = ".\%s --silent-install" % filename
            except Exception as error_install:
                logger.error(
                    "Error while installing RustDesk with the error: %s" % error_install
                )

        else:
            # Download error
            logger.error("%s" % txtmsg)
