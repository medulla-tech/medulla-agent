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
# file : plugin_updatenetworkcheck.py

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
NETWORKVERSION = '2.1.3'

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updatenetworkcheck", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checknetworkcheckversion()
        if StrictVersion(installed_version) < StrictVersion(NETWORKVERSION):
            updatenetworkcheck(xmppobject)
            updatenetworkcheckversion(installed_version)
    except Exception:
        pass


def checknetworkcheckversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            networkcheckversion = result['result'][0].strip().split()[-1]
        else:
            # Fusion is not installed. We will force installation by returning
            # version 0.1
            networkcheckversion = '0.1'
    return networkcheckversion

def updatenetworkcheckversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % NETWORKVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.info("we successfully updated Pulse network notify to version %s" % NETWORKVERSION)

        if version == "0.1":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" '\
                    '/v "DisplayName" /t REG_SZ  /d "Pulse network notify" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updatenetworkcheck(xmppobject):
    logger.info("Updating Network Check to version %s" % NETWORKVERSION)
    if sys.platform.startswith('win'):
        pywintypes27_file = os.path.join("c:\\", "Python27", "Lib", "site-packages", "pywin32_system32", "pywintypes27.dll")
        win32_path = os.path.join("c:\\", "Python27", "Lib", "site-packages", "win32")
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = 'networkevents.py'
        dl_url = 'http://%s/downloads/win/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(pulsedir_path, filename)).downloadurl()
        if result:
            logger.debug("%s" % txtmsg)
        else:
            # Download error
            logger.error("%s" % txtmsg)

        # We stop the service
        stop_command = "sc stop pulsenetworknotify"
        stop_service = utils.simplecommand(stop_command)
        # Activation of network notify windows service
        if not os.path.isfile(os.path.join(win32_path, "pywintypes27.dll")):
            shutil.copyfile(pywintypes27_file, os.path.join(win32_path, "pywintypes27.dll"))

        servicefilename = 'netcheck-service.py'
        service_dl_url = 'http://%s/downloads/win/%s' % (
            xmppobject.config.Server, servicefilename)
        serviceresult, servicetxtmsg = utils.downloadfile(service_dl_url, os.path.join(pulsedir_path, servicefilename)).downloadurl()
        if serviceresult:
            # Download success
            logger.info("%s" % servicetxtmsg)
            # Run installer
            servicecmd = 'C:\Python27\python.exe "%s\%s" --startup=auto install' % (pulsedir_path, servicefilename)
            servicecmd_result = utils.simplecommand(servicecmd)
            if servicecmd_result['code'] == 0:
                logger.info("%s installed successfully" % servicefilename)
            else:
                logger.error("Error installing %s: %s"
                             % (servicefilename, servicecmd_result['result']))

            update_command = 'C:\Python27\python.exe "%s\%s" update' % (pulsedir_path, servicefilename)
            utils.simplecommand(update_command)

            restart_command = 'C:\Python27\python.exe "%s\%s" restart' % (pulsedir_path, servicefilename)
            utils.simplecommand(restart_command)
        else:
            # Download error
            logger.error("%s" % servicetxtmsg)
