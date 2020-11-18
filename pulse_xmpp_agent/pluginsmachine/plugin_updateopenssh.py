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
OPENSSHVERSION = '7.7'

logger = logging.getLogger()

plugin = {"VERSION": "1.05", "NAME": "updateopenssh", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkopensshversion()
        if StrictVersion(installed_version) < StrictVersion(OPENSSHVERSION):
            updateopenssh(xmppobject, installed_version)
    except Exception:
        pass


def checkopensshversion():
    if sys.platform.startswith('win'):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            opensshversion = result['result'][0].strip().split()[-1]
        else:
            # The filetree generator is not installed. We will force installation by returning
            # version 0.0
            opensshversion = '0.0'
    return opensshversion

def updateopensshversion(version):
    if sys.platform.startswith('win'):
        cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % OPENSSHVERSION

        result = utils.simplecommand(cmd)
        if result['code'] == 0:
            logger.debug("we successfully changed the version of Syncthing")

        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                    '/v "DisplayName" /t REG_SZ  /d "OpenSSH" /f'
	    utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updateopenssh(xmppobject, installed_version):
    logger.info("Updating OpenSSH to version %s" % OPENSSHVERSION)

    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            architecture = 'Win64'
        else:
            architecture = 'Win32'

        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")
        opensshdir_path = os.path.join(os.environ["ProgramFiles"], "OpenSSH")
        mandriva_sshdir_path = os.path.join(os.environ["ProgramFiles"], "Mandriva", "OpenSSH")
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")

        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = 'OpenSSH-%s.zip' % architecture
        extracted_path = 'openssh-windows-%s' % architecture
        dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, filename)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()


        if result:
            # Download success
            if os.path.isfile(os.path.join(opensshdir_path, "uninstall-sshd.ps1")):
                openssh_uninstall = utils.simplecommand("sc.exe query ssh-agent")

                if openssh_uninstall['code'] == 0:
                    utils.simplecommand("sc.exe stop ssh-agent")
                    utils.simplecommand("sc.exe delete ssh-agent")

                daemon_uninstall = utils.simplecommand("sc.exe query sshdaemon")
                if daemon_uninstall['code'] == 0:
                    utils.simplecommand("sc.exe stop sshdaemon")
                    utils.simplecommand("sc.exe delete sshdaemon")
            else:
                logger.debug("No previous SSH found")

            if os.path.isdir(mandriva_sshdir_path):
                current_dir = os.getcwd()
                os.chdir(mandriva_sshdir_path)
                uninstall_mandriva_ssh = utils.simplecommand("uninst.exe /S")
                if uninstall_mandriva_ssh['code'] == 0:
                    logger.debug("Uninstallation successful")

                os.chdir(current_dir)
                os.rmdir(uninstall_mandriva_ssh)

            if os.path.isdir(opensshdir_path):
                os.rmdir(opensshdir_path)


            # Download success
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            openssh_zip_file = zipfile.ZipFile(filename, 'r')
            openssh_zip_file.extractall()
            try:
                os.rmdir(opensshdir_path)
            except OSError:
                logger.debug("Deletion of the directory %s failed" % opensshdir_path)

            try:
                os.mkdir(opensshdir_path)
            except OSError:
                logger.debug("Creation of the directory %s failed" % opensshdir_path)

            shutil.copytree(install_tempdir, opensshdir_path)
            os.chdir(current_dir)

#            updateopensshversion(installed_version)
        else:
            # Download error
            logger.error("%s" % txtmsg)

