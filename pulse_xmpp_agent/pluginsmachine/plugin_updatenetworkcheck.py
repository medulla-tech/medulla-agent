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
from lib import utils
from distutils.version import StrictVersion
import pycurl
import logging
import platform
import shutil

NETWORKVERSION = '2.1.2'

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatenetworkcheck", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checknetworkcheckversion()
        if StrictVersion(installed_version) < StrictVersion(NETWORKVERSION):
            updatenetworkcheck(xmppobject)
            updatenetworkcheckversion(NETWORKVERSION)
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

        if version == "0.1":
            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" '\
                    '/v "DisplayName" /t REG_SZ  /d "Pulse network notify" /f'
            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

        result = utils.simplecommand(cmd)

def updatenetworkcheck(xmppobject):
    logger.info("Updating Network Check to version %s" % NETWORKVERSION)
    if sys.platform.startswith('win'):
        filename = 'networkevents.py'
        dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            # Copy file
            shutil.copyfile(pywintypes27_file, win32_path)
            if cmd_result['code'] == 0:
                logger.info("%s installed successfully" % filename)
            else:
                logger.error("Error installing %s: %s"
                             % (filename, cmd_result['result']))
        else:
            # Download error
            logger.error("%s" % txtmsg)

        pulsedir_path = os.path.join(os.environ["ProgramFiles"],"Pulse","bin")
        shutil.copyfile(filename, pulsedir_path)
        # Activation of network notify windows service
        pywintypes27_file = os.path.join("c:\\", "Python27", "Lib", "site-packages", "pywin32_system32", "pywintypes27.dll")
        win32_path = os.path.join("c:\\", "Python27", "Lib", "site-packages"," win32")

        if not os.path.isfile(pywintypes27_file):
            shutil.copyfile(pywintypes27_file, win32_path)

        servicefilename = 'netcheck-service.py'
        service_dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, servicefilename)
        logger.debug("Downloading %s" % service_dl_url)
        serviceresult, servicetxtmsg = utils.downloadfile(service_dl_url).downloadurl()
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
        else:
            # Download error
            logger.error("%s" % servicetxtmsg)
