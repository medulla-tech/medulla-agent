# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import tempfile
from lib import utils

BEFOREAGENTVERSION = "5.6.2"
# BEFOREAGENTVERSION variable is used to set the version from which the python modules will not be updated. 
# All agent versions before that version will have the python modules updated.

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "updatepythonmodules", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):

    if not sys.platform.startswith("win"):
        return
    logger.debug(" PL-PYMODULES ###################################################")
    logger.debug(" PL-PYMODULES call %s from %s" % (plugin, message["from"]))
    logger.debug(" PL-PYMODULES ###################################################")
    try:
        # Update if version is lower
        installed_version = checkagentversion()
        if StrictVersion(BEFOREAGENTVERSION) < StrictVersion(installed_version) :
            updatepythonmodules(xmppobject, installed_version)
    except Exception:
        pass


def checkagentversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Medulla Agent" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        agentversion = result["result"][0].strip().split()[-1]
    return agentversion


def updatepythonmodules(xmppobject, installed_version):
    logger.info(" PL-PYMODULES Updating Python modules to version %s" % BEFOREAGENTVERSION)
    version_info = utils.PythonVersionInfo()

    if sys.platform.startswith("win"):
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
        python_modules = [
        ]

        for module_to_dl in python_modules:
            dl_url = "%s/downloads/win/downloads/python_modules/%s" % (
                xmppobject.config.update_server,
                module_to_dl,
            )
            logger.debug(" PL-PYMODULES Downloading %s" % dl_url)
            result, txtmsg = utils.downloadfile(
                dl_url, os.path.join(install_tempdir, module_to_dl)
            ).downloadurl()
            if result:
                cmd = (
                    'C:\\Program\ Files\\Python%s\\Scripts\\pip%s install --quiet --upgrade --no-index --find-links="%s" %s'
                    % (
                        version_info.version,
                        version_info.version_major,
                        install_tempdir,
                        module_to_dl,
                    )
                )
                os.chdir(install_tempdir)
                cmd_result = utils.simplecommand(cmd)
                if cmd_result["code"] != 0:
                    logger.error(" PL-PYMODULES %s: %s" % (module_to_dl, cmd_result["result"]))
            else:
                # Download error
                logger.error(" PL-PYMODULES %s: %s" % (module_to_dl, txtmsg))
    
    if sys.platform.startswith("linux"):
        python_modules = [
            "distro",
        ]
        for module_to_install in python_modules:
            cmd = (
                '/opt/medulla/bin/python%s.%s -m pip install --quiet --upgrade --no-index %s'
                % (
                    version_info.version_major,
                    version_info.version_minor,
                    module_to_install,
                )
            )
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] != 0:
                logger.error(" PL-PYMODULES %s: %s" % (module_to_install, cmd_result["result"]))
