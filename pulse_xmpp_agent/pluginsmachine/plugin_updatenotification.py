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
# file : plugin_updatenotification.py

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
NOTIFICATIONVERSION = '2.1.9'

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatenotification", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        check_if_binary_ok()
        # Update if version is lower
        installed_version = notificationversion()
        if StrictVersion(installed_version) < StrictVersion(NOTIFICATIONVERSION):
            updatenotification(xmppobject)
            updatenotificationversion(installed_version)
    except Exception:
        pass

def check_if_binary_ok():
    if sys.platform.startswith('win'):
        regedit = False
        binary = False
        reinstall = False

        # We check if we have the Regedit entry
        cmd_reg = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" /s | Find "DisplayVersion"'
        result_reg = utils.simplecommand(cmd_reg)
        if result_reg['code'] == 0:
            regedit = True

        # We check if the binary is available
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")
        filename = 'pulse2_update_notification.py'

        if os.path.isfile(os.path.join(pulsedir_path, filename)): 
            binary = True

        if regedit is False or binary is False: 
            reinstall = True

        if reinstall:
            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '\
                    '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            result = utils.simplecommand(cmd)
            if result['code'] == 0:
                logger.debug("The Pulse Notification module is ready to be reinstalled.")
            else:
                logger.debug("We failed to reinitialize the registry entry.")

def notificationversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            notificationversion = result['result'][0].strip().split()[-1]
        else:
            # Not installed. We will force installation by returning
            # version 0.1
            notificationversion = '0.1'
    return notificationversion

def updatenotificationversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % NOTIFICATIONVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.info("we successfully updated Pulse notification to version %s" % NOTIFICATIONVERSION)

        if version == "0.1":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '\
                    '/v "DisplayName" /t REG_SZ  /d "Pulse notification" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse notification" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updatenotification(xmppobject):
    logger.info("Updating Pulse Notification to version %s" % NOTIFICATIONVERSION)
    if sys.platform.startswith('win'):
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = 'pulse2_update_notification.py'
        dl_url = 'http://%s/downloads/win/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(pulsedir_path, filename)).downloadurl()
        if result:
            logger.debug("%s" % txtmsg)
        else:
            # Download error
            logger.error("%s" % txtmsg)
