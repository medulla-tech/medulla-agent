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

import sys
import os
from distutils.version import StrictVersion
import logging
import zipfile
import platform
import tempfile
import shutil
from lib import utils
import re

logger = logging.getLogger()

plugin = {"VERSION": "1.11", "NAME": "updatedoublerun", "TYPE": "machine"}

RSYNC_VERSION = "3.1.2.1"

# Comma separated list of orgs which do not need double run
# TODO: See how to handle this on a plain text file.
P4ONLYUCANSS = ''

def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")

    # Update if version is lower
    installed_version = checkdoublerunversion()
    if StrictVersion(installed_version) < StrictVersion(plugin['VERSION']):
        if nodoublerun():
            ret = disabledoublerun(xmppobject)
            if ret is not False:
                updatedoublerunversion(installed_version)
            else:
                logger.error("Plugin Doublerun - Quitting on error. Check previous logs")
                return
        else:
            ret = enabledoublerun(xmppobject)
            if ret is not False:
                updatedoublerunversion(installed_version)
            else:
                logger.error("Plugin Doublerun - Quitting on error. Check previous logs")
                return

def checkdoublerunversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Doublerun Plugin" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            doublerunversion = result['result'][0].strip().split()[-1]
        else:
            doublerunversion = '0.0'
    logger.debug("Plugin Doublerun - Currently installed version: %s" % doublerunversion)
    return doublerunversion

def checkrsyncversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" /s | Find "DisplayVersion"'

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            rsyncversion = result['result'][0].strip().split()[-1]
        else:
            rsyncversion = '0.0'
    logger.debug("Plugin Doublerun - RSync Currently installed version: %s" % rsyncversion)
    return rsyncversion

def updatedoublerunversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Doublerun Plugin" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % plugin['VERSION']

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.info("Plugin Doublerun - Updating to version %s in registry successful" % plugin['VERSION'])

        # Add more parameters to the key if we are creating it instead of updating it
        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Doublerun Plugin" '\
                    '/v "DisplayName" /t REG_SZ  /d "Pulse Doublerun Plugin" /f'
            utils.simplecommand(cmdDisplay)
            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Doublerun Plugin" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            utils.simplecommand(cmd)

def nodoublerun():
    if sys.platform.startswith('win'):
        hostname = platform.node().split('.', 1)[0]
        ucanss = re.findall(r'\d+', hostname)[0][0:6]
        if ucanss in list(P4ONLYUCANSS.replace(" ", "").split(",")):
            logger.debug("Plugin Doublerun - Rsync will be enable")
            return True
    logger.debug("Plugin Doublerun - Doublerun will be enabled")
    return False

def enabledoublerun(xmppobject):
    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            windows_system = 'SysWOW64'
            nytrio_sshdir_path = os.path.join(os.environ["ProgramFiles(x86)"], "Nytrio", "OpenSSH")
        else:
            windows_system = 'System32'
            nytrio_sshdir_path = os.path.join(os.environ["ProgramFiles"], "Nytrio", "OpenSSH")
        rsync_dest_folder = os.path.join("C:\\", "Windows", windows_system)

        # Stop Nytrio ssh daemon
        logger.debug("Plugin Doublerun - Stopping Nytrio sshd")
        utils.simplecommand("sc stop sshd")

        # Delete all Pulse rsync files
        rsync_files = ['cyggcc_s-1.dll',
                       'cygiconv-2.dll',
                       'cygintl-8.dll',
                       'cygpopt-0.dll',
                       'cygwin1.dll',
                       'cygz.dll',
                       'rsync.exe']
        for rsync_file in rsync_files:
            full_rsync_file_name = os.path.join(rsync_dest_folder, rsync_file)
            if os.path.isfile(full_rsync_file_name):
                try:
                    logger.debug("Plugin Doublerun - Deleting file %s" % full_rsync_file_name)
                    os.remove(full_rsync_file_name)
                except Exception as e:
                    logger.error("Plugin Doublerun - Failed deleting file %s: %s" % (full_rsync_file_name, e))
                    raise PluginError

        # Copy nytrio cygwin dll to Windows system folder
        try:
            logger.debug("Plugin Doublerun - Copying Nytrio cygwin1.dll file to %s" % rsync_dest_folder)
            shutil.copy(os.path.join(nytrio_sshdir_path, 'bin', 'cygwin1.dll'), os.path.join(rsync_dest_folder, 'cygwin1.dll'))
        except Exception as e:
            logger.error("Plugin Doublerun - Failed copying Nytrio cygwin1.dll file: %s" % e)
            raise PluginError

        # Enable autostart Nytrio ssh daemon
        logger.debug("Plugin Doublerun - Enable autostart Nytrio sshd")
        utils.simplecommand("sc config sshd start= auto")

        # Start Nytrio ssh daemon
        logger.debug("Plugin Doublerun - Restarting Nytrio sshd")
        utils.simplecommand("sc start sshd")

        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] != 0:
            logger.info("Plugin Doublerun - The Pulse Rsync is already removed")
        else:
            regclean = 'REG DELETE "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" /f"'
            utils.simplecommand(regclean)
            if result['code'] == 0:
                logger.info("Plugin Doublerun - Doublerun is now enabled - Siveo Rsync is removed.")

def disabledoublerun(xmppobject):
    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            windows_system = 'SysWOW64'
        else:
            windows_system = 'System32'

        installed_rsync = checkrsyncversion()

        if installed_rsync >= RSYNC_VERSION:
            logger.debug("Plugin Doublerun - The Pulse Rsync is already installed")
        else:
            windows_tempdir = os.path.join("C:\\", "Windows", "Temp")
            rsync_dest_folder = os.path.join("C:\\", "Windows", windows_system)

            rsync_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
            rsync_filename = 'rsync.zip'
            rsync_extracted_path = 'rsync'
            rsync_dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, rsync_filename)
            logger.debug("Plugin Doublerun - Download rsync from %s" % rsync_dl_url)
            rsync_result, rsync_txtmsg = utils.downloadfile(rsync_dl_url, os.path.join(rsync_tempdir, rsync_filename)).downloadurl()

            if rsync_result is not False:
                # Stop Nytrio ssh daemon
                logger.debug("Plugin Doublerun - Stopping Nytrio sshd")
                utils.simplecommand("sc stop sshd")

                current_dir = os.getcwd()
                os.chdir(rsync_tempdir)
                rsync_zip_file = zipfile.ZipFile(rsync_filename, 'r')
                rsync_zip_file.extractall()

                rsync_files = os.listdir(os.path.join(rsync_tempdir, "rsync"))
                for rsync_file in rsync_files:
                    full_rsync_file_name = os.path.join(rsync_tempdir, "rsync", rsync_file)

                    if os.path.isfile(full_rsync_file_name):
                        try:
                            logger.debug("Plugin Doublerun - Copying file %s to %s" % (full_rsync_file_name, rsync_dest_folder))
                            shutil.copy(full_rsync_file_name, os.path.join(rsync_dest_folder, rsync_file))
                        except Exception as e:
                            logger.error("Plugin Doublerun - Failed copying file %s: %s" % (full_rsync_file_name, e))
                            return False

                add_editor = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" '\
                        '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
                utils.simplecommand(add_editor)

                add_name = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" '\
                        '/v "DisplayName" /t REG_SZ  /d "Pulse RSync" /f'
                utils.simplecommand(add_name)

                add_version = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse RSync" '\
                        '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % RSYNC_VERSION
                utils.simplecommand(add_version)

                # Disable autostart Nytrio sshd
                logger.debug("Plugin Doublerun - Disable autostart Nytrio sshd")
                utils.simplecommand("sc config sshd start= disabled")

                logger.info("Plugin Doublerun - Siveo Rsync %s enabled" % RSYNC_VERSION)
            else:
                logger.error("Plugin Doublerun - Failed to download rsync - Check ARS web server or missing rsync file: %s" % rsync_dl_url)
                return False

class PluginError(Exception):
    """
    Class to define own exception
    """
    pass
