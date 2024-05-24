# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import tempfile
from lib import utils

CHERRYPYVERSION = "18.8.0"

logger = logging.getLogger()
plugin = {"VERSION": "2.2", "NAME": "updatecherrypy", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug(" PL-CHERRYP ###################################################")
    logger.debug(" PL-CHERRYP call %s from %s" % (plugin, message["from"]))
    logger.debug(" PL-CHERRYP ###################################################")
    try:
        # Update if version is lower
        installed_version = checkcherrypyversion()
        if StrictVersion(installed_version) < StrictVersion(CHERRYPYVERSION):
            updatecherrypy(xmppobject, installed_version)
    except Exception:
        pass


def checkcherrypyversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CherryPy" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            cherrypyversion = result["result"][0].strip().split()[-1]
        else:
            # The filetree generator is not installed. We will force installation by returning
            # version 0.0
            cherrypyversion = "0.0"
    return cherrypyversion


def updatecherrypyversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla CherryPy" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % CHERRYPYVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                " PL-CHERRYP We successfully updated Medulla CherryPy to version %s" % CHERRYPYVERSION
            )

        if version == "0.0":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\\Medulla CherryPy" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla CherryPy" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\\Medulla CherryPy" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatecherrypy(xmppobject, installed_version):
    logger.info(" PL-CHERRYP Updating CherryPy to version %s" % CHERRYPYVERSION)
    version_info = utils.PythonVersionInfo()
    if sys.platform.startswith("win"):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
        cherrypy_filename = "CherryPy-%s-py2.py3-none-any.whl" % CHERRYPYVERSION
        python_modules = [
            "Routes-2.4.1-py2.py3-none-any.whl",
            "repoze.lru-0.7-py3-none-any.whl",
            "WebOb-1.8.5-py2.py3-none-any.whl",
            "pypiwin32-219-cp27-none-win_amd64.whl",
            "six-1.10.0-py2.py3-none-any.whl",
        ]

        for module_to_dl in python_modules:
            dl_url = "http://%s/downloads/win/downloads/python_modules/%s" % (
                xmppobject.config.Server,
                module_to_dl,
            )
            logger.debug(" PL-CHERRYP Downloading %s" % dl_url)
            result, txtmsg = utils.downloadfile(
                dl_url, os.path.join(install_tempdir, module_to_dl)
            ).downloadurl()

        dl_url = "http://%s/downloads/win/downloads/python_modules/%s" % (
            xmppobject.config.Server,
            cherrypy_filename,
        )
        logger.debug(" PL-CHERRYP Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, cherrypy_filename)
        ).downloadurl()

        if result:
            cmd = (
                'C:\\Program\ Files\\Python%s\\Scripts\\pip%s install --quiet --upgrade --no-index --find-links="%s" CherryPy-%s-py2.py3-none-any.whl'
                % (
                    version_info.version,
                    version_info.version_major,
                    install_tempdir,
                    CHERRYPYVERSION,
                )
            )
            os.chdir(install_tempdir)
            utils.simplecommand(cmd)

            updatecherrypyversion(installed_version)
        else:
            # Download error
            logger.error(" PL-CHERRYP %s" % txtmsg)
