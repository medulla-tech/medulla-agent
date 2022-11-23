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
# file : plugin_updatebackupclient.py

import sys
from lib import utils
from distutils.version import StrictVersion
import logging
import tempfile
import os
import socket

URBACKUP_VERSION = '2.4.11'

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updatebackupclient", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Do not proceed if backup_enabled is not set to 1
        if hasattr(xmppobject.config, 'backup_enabled'):
            if bool(int(xmppobject.config.backup_enabled)):
                # Update if version is lower
                installed_version = checkurbackupversion()
                if StrictVersion(installed_version) < StrictVersion(URBACKUP_VERSION):
                    updatebackupclient(xmppobject)
                    backupclientsettings(xmppobject)
    except Exception:
        pass


def checkurbackupversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\UrBackup /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            urbackupversion = result['result'][0].strip().split()[-1]
        else:
            # urbackup is not installed. We will force installation by returning
            # version 0.1
            urbackupversion = '0.1'
    return urbackupversion


def updatebackupclient(xmppobject):
    logger.info("Updating UrBackup client to version %s" % URBACKUP_VERSION)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith('win'):
        filename = 'UrBackup Client %s.exe' % URBACKUP_VERSION
        dl_url = 'http://%s/downloads/win/downloads/%s' % (
            xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            install_options = "/S"


            # Run installer
            cmd = '%s %s' % (filename, install_options)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result['code'] == 0:
                logger.info("%s installed successfully to version %s" % (filename, URBACKUP_VERSION))
            else:
                logger.error("Error installing %s: %s"
                             % (filename, cmd_result['result']))
        else:
            # Download error
            logger.error("%s" % txtmsg)

def backupclientsettings(xmppobject):
    logger.info("Configuring UrBackup client settings")

    hostname = socket.gethostname()
    urbackup_dir = os.path.join("c:\\", "Program Files", "UrBackup")

    if sys.platform.startswith('win'):
        filename = os.path.join('%s' % urbackup_dir, 'UrBackupClient_cmd.exe')
        if os.path.exists(filename):
            os.chdir(urbackup_dir)
            cmd = '"%s" set-settings -k  internet_mode_enabled -v true -k internet_server -v %s -k internet_server_port -v %s -k internet_authkey -v %s -k computername -v %s -k internet_image_backups -v true -k internet_full_file_backups -v true' % (filename, xmppobject.config.backup_server, xmppobject.config.backup_port, xmppobject.config.authkey, hostname)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result['code'] == 0:
                logger.info("Settings successfully applied to client %s" % (hostname))
            else:
                logger.error("Error applying settings: %s" % (filename, cmd_result['result']))
