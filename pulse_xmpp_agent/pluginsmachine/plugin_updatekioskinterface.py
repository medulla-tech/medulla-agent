# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
from lib import utils
import tempfile
from lib.agentconffile import (
    medullaPath,
)

KIOSKINTERFACEVERSION = "1.0.0"

logger = logging.getLogger()

plugin = {"VERSION": "1.5", "NAME": "updatekioskinterface", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("PL-KIOSK ###################################################")
    logger.debug("PL-KIOSK call %s from %s" % (plugin, message["from"]))
    logger.debug("PL-KIOSK ###################################################")
    try:
        # Update if version is lower
        installed_version = kioskinterfaceversion()
        if StrictVersion(installed_version) < StrictVersion(KIOSKINTERFACEVERSION):
            updatekioskinterface(xmppobject, installed_version)
    except Exception:
        pass


def kioskinterfaceversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            KIOSKINTERFACEVERSION = result["result"][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.1
            KIOSKINTERFACEVERSION = "0.1"

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" /v "DisplayIcon"'
        result = utils.simplecommand(cmd)

        if result["code"] != 0:
            cmd = (
                f'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                f'/v "DisplayIcon" /t REG_SZ /d "{os.path.join(medullaPath(), "bin", "install.ico")}" /f'
            )
            utils.simplecommand(cmd)
    return KIOSKINTERFACEVERSION


def updatekioskinterfaceversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % KIOSKINTERFACEVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "PL-KIOSK we successfully updated Medulla kiosk interface to version %s"
                % KIOSKINTERFACEVERSION
            )

        if version == "0.1":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla kiosk interface" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla kiosk interface" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatekioskinterface(xmppobject, installed_version):
    logger.info(
        "PL-KIOSK Updating Medulla kiosk interface to version %s"
        % KIOSKINTERFACEVERSION
    )
    version_info = utils.PythonVersionInfo()
    if sys.platform.startswith("win"):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = "kiosk-interface-%s.tar.gz" % KIOSKINTERFACEVERSION
        dl_url = "http://%s/downloads/%s" % (xmppobject.config.Server, filename)
        logger.debug("PL-KIOSK Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            logger.debug("PL-KIOSK %s" % txtmsg)
            cmd = (
                'C:\\Progra~1\\Python%s\\Scripts\\pip%s install --quiet --upgrade --no-index --find-links="%s" %s'
                % (
                    version_info.version_major,
                    version_info.version_major,
                    install_tempdir,
                    filename,
                )
            )
            os.chdir(install_tempdir)
            logger.debug("PL-KIOSK Running %s" % cmd)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info(
                    "PL-KIOSK %s installed successfully to version %s"
                    % (filename, KIOSKINTERFACEVERSION)
                )
                updatekioskinterfaceversion(installed_version)
            else:
                logger.error(
                    "PL-KIOSK Error installing %s: %s"
                    % (filename, cmd_result["result"])
                )

        else:
            # Download error
            logger.error("PL-KIOSK %s" % txtmsg)
