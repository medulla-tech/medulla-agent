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
# file : plugin_updatesyncthing.py

import sys
import os
from distutils.version import StrictVersion
import logging
import zipfile
import platform
from lib import utils
SYNCTHINGVERSION = '1.6.1'

logger = logging.getLogger()

plugin = {"VERSION": "1.04", "NAME": "updatesyncthing", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checksyncthingversion()
        if StrictVersion(installed_version) < StrictVersion(SYNCTHINGVERSION):
            updatesyncthing(xmppobject, installed_version)
    except Exception:
        pass


def checksyncthingversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Syncthing" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            syncthingversion = result['result'][0].strip().split()[-1]
        else:
            # The filetree generator is not installed. We will force installation by returning
            # version 0.0
            syncthingversion = '0.0'
    return syncthingversion

def updatesyncthingversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Syncthing" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % SYNCTHINGVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.debug("we successfully changed the version of Syncthing")

        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\Syncthing" '\
                    '/v "DisplayName" /t REG_SZ  /d "Syncthing" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\\Syncthing" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updatesyncthing(xmppobject, installed_version):
    logger.info("Updating Syncthing to version %s" % SYNCTHINGVERSION)
    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            architecture = 'amd64'
        else:
            architecture = '386'
        logger.error("archi %s" % architecture)
        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

        filename = 'syncthing-windows-%s-v%s.zip' % (architecture, SYNCTHINGVERSION)
        dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url).downloadurl()
        if result:
            # Download success
            try:
                #TODO: Kill syncthing process first
                zip_file = zipfile.ZipFile(filename, 'r')
                zip_file.extract("syncthing.exe", path=pulsedir_path)
                updatesyncthingversion(installed_version)
            except IOError as errorcopy:
                logger.error("Error while copying the file with the error: %s" % errorcopy)
        else:
            # Download error
            logger.error("%s" % txtmsg)

