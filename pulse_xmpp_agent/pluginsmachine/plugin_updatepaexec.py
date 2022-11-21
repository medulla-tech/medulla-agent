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
# file : plugin_updatepaexec.py

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
PAEXECVERSION = '1.29'

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updatepaexec", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkpaexecversion()
        if StrictVersion(installed_version) < StrictVersion(PAEXECVERSION):
            updatepaexec(xmppobject, installed_version)
    except Exception:
        pass


def checkpaexecversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\PAExec" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            paexecversion = result['result'][0].strip().split()[-1]
        else:
            # PaExec is not installed. We will force installation by returning
            # version 0.0
            paexecversion = '0.0'
    return paexecversion

def updatepaexecversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\PAExec" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % PAEXECVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.info("we successfully updated PAExec to version %s" % PAEXECVERSION)

        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\PAExec" '\
                    '/v "DisplayName" /t REG_SZ  /d "PAExec" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\PAExec" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updatepaexec(xmppobject, installed_version):
    logger.info("Updating PAExec from version %s to version %s" % (installed_version, PAEXECVERSION))
    if sys.platform.startswith('win'):
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = 'paexec_1_29.exe'
        dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(pulsedir_path, 'paexec.exe')).downloadurl()
        if result:
            # Download success
            try:
                updatepaexecversion(installed_version)
            except IOError as errorcopy:
                logger.error("Error while copying the file with the error: %s" % errorcopy)
        else:
            # Download error
            logger.error("%s" % txtmsg)

