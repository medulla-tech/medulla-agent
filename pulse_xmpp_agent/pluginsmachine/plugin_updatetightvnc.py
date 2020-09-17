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
# file : plugin_updatefusion.py

import sys
from lib import utils
from distutils.version import StrictVersion
import pycurl
import logging
import platform

TIGHTVNC = '2.8.27'

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatetightvnc", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checktightvncversion()
        if StrictVersion(installed_version) < StrictVersion(TIGHTVNC):
            updatetightvnc(xmppobject)
    except Exception:
        pass


def checktightvncversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\{DEE0B752-52D8-4615-9BEE-1EDA46628960} /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            tightvncversion = result['result'][0].strip().split()[-1]
        else:
            # TIGHTVNC is not installed. We will force installation by returning
            # version 0.1
            tightvncversion = '0.1'
    return tightvncversion


def updatetightvnc(xmppobject):
    logger.info("Updating TightVNC Agent to version %s" % TIGHTVNC)
    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            architecture = '64bit'
        else:
            architecture = '32bit'
        filename = 'tightvnc-%s-gpl-setup-%s.msi' % (
            tightvncversion, architecture)
        dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            # Run installer
            cmd = 'msiexec /x %s /qn REBOOT=R' % filename
            cmd_result = utils.simplecommand(cmd)
            if cmd_result['code'] == 0:
                logger.info("%s installed successfully" % filename)
                
            else:
                logger.error("Error installing %s: %s"
                             % (filename, cmd_result['result']))
        else:
            # Download error
            logger.error("%s" % txtmsg)

