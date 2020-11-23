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
import tempfile
import shutil
from lib import utils
SYNCTHINGVERSION = '1.6.1'

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updatesyncthing", "TYPE": "machine"}


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
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Syncthing" '\
                    '/v "DisplayName" /t REG_SZ  /d "Syncthing" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Syncthing" '\
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
        pulseconfig_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc")
        syncthingconfig_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc", "syncthing")
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")

        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = 'syncthing-windows-%s-v%s.zip' % (architecture, SYNCTHINGVERSION)
        extracted_path = 'syncthing-windows-%s-v%s' % (architecture, SYNCTHINGVERSION)
        dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()
        if result:
            # Download success
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            #TODO: Kill syncthing process first
            syncthing_zip_file = zipfile.ZipFile(filename, 'r')
            syncthing_zip_file.extractall()
            utils.simplecommand("taskkill.exe /F /IM syncthing.exe")
            shutil. copyfile(os.path.join(extracted_path, "syncthing.exe"), os.path.join(pulsedir_path, "syncthing.exe"))
            os.chdir(current_dir)

            utils.simplecommand("netsh advfirewall firewall add rule name=\"Syncthing for Pulse\" dir=in action=allow protocol=TCP localport=22000")

            os.symlink(os.path.join(pulseconfig_path, "syncthing.ini"), os.path.join(syncthingconfig_path, "config.xml"))
            updatesyncthingversion(installed_version)
        else:
            # Download error
            logger.error("%s" % txtmsg)

