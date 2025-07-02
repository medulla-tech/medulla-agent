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
OPENSSHVERSION = '9.8.1'

logger = logging.getLogger()

plugin = {"VERSION": "1.80", "NAME": "updateopenssh", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checkopensshversion()
        check_if_binary_ok()
        if StrictVersion(installed_version) < StrictVersion(OPENSSHVERSION):
            updateopenssh(xmppobject, installed_version)
        check_if_service_is_running()
    except Exception:
        pass

def check_if_binary_ok():
    if sys.platform.startswith('win'):
        # We check if we have the Regedit entry
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)

        if result['code'] == 0:
            regedit = True

        # We check if the openssh binary is correctly installed.
        opensshdir_path = os.path.join(os.environ["ProgramFiles"], "OpenSSH")
        sshdaemon_bin_path = os.path.join(opensshdir_path, "sshd.exe")

        if os.path.isfile(sshdaemon_bin_path):
            logger.debug("OpenSSH is correctly installed. Nothing to do")
        else:
            logger.error("Something went wrong, we need to reinstall the component.")

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            result = utils.simplecommand(cmd)
            if result['code'] == 0:
                logger.debug("The OpenSSH module is ready to be reinstalled.")
            else:
                logger.debug("We failed to reinitialize the registry entry.")

def check_if_service_is_running():
    if sys.platform.startswith('win'):
        is_ssh_started = utils.simplecommand("sc.exe query sshdaemon")
        if is_ssh_started['code'] == 0:
            state = [x.strip() for x in is_ssh_started['result'][3].split(' ') if x != ""][3]
            if state == "STOPPED":
                logger.debug("The OpenSSH does not seems started. We start it.")
                utils.simplecommand("sc.exe start sshdaemon")

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
            logger.info("we successfully changed the version of OpenSSH to version %s" % OPENSSHVERSION)

        if version == "0.0":
            cmdDisplay = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                    '/v "DisplayName" /t REG_SZ  /d "Pulse OpenSSH" /f'
            utils.simplecommand(cmdDisplay)

            cmd = 'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse SSH" '\
                    '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'

            utils.simplecommand(cmd)

def updateopenssh(xmppobject, installed_version):
    Used_ssh_port = "22"
    if hasattr(xmppobject.config, 'sshport'):
        Used_ssh_port = xmppobject.config.sshport

    logger.info("Updating OpenSSH to version %s" % OPENSSHVERSION)

    if sys.platform.startswith('win'):
        if platform.architecture()[0] == '64bit':
            architecture = 'Win64'
            windows_system = 'SysWOW64'
        else:
            architecture = 'Win32'
            windows_system = 'System32'

        pulsedir_path = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")
        opensshdir_path = os.path.join(os.environ["ProgramFiles"], "OpenSSH")
        sshdaemon_bin_path = os.path.join(opensshdir_path, "sshd.exe")
        mandriva_sshdir_path = os.path.join(os.environ["ProgramFiles(x86)"], "Mandriva", "OpenSSH")
        nytrio_sshdir_path = os.path.join(os.environ["ProgramFiles(x86)"], "Nytrio", "OpenSSH")
        windows_tempdir = os.path.join("C:\\", "Windows", "Temp")
        programdata_path = os.path.join("C:\\", "ProgramData", "ssh")
        rsync_dest_folder = os.path.join("C:\\", "Windows", windows_system)

        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = 'OpenSSH-%s.zip' % architecture
        extracted_path = 'OpenSSH-%s' % architecture
        dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, filename)
        result, txtmsg = utils.downloadfile(dl_url, os.path.join(install_tempdir, filename)).downloadurl()

        if result:
            # Download success
            agent_uninstall = utils.simplecommandstr("sc.exe qc ssh-agent")
            if agent_uninstall['code'] == 0:
                if opensshdir_path in agent_uninstall['result']:
                    utils.simplecommand("sc.exe stop ssh-agent")
                    utils.simplecommand("sc.exe delete ssh-agent")

            daemon_uninstall = utils.simplecommand("sc.exe query sshdaemon")
            if daemon_uninstall['code'] == 0:
                utils.simplecommand("sc.exe stop sshdaemon")
                utils.simplecommand("sc.exe delete sshdaemon")

            if os.path.isdir(mandriva_sshdir_path):
                current_dir = os.getcwd()
                os.chdir(mandriva_sshdir_path)
                uninstall_mandriva_ssh = utils.simplecommand("uninst.exe /S")
                if uninstall_mandriva_ssh['code'] == 0:
                    logger.debug("Uninstallation successful")

                os.chdir(current_dir)
                os.rmdir(uninstall_mandriva_ssh)


            if os.path.isdir(opensshdir_path):
                try:
                    shutil.rmtree(opensshdir_path)
                except OSError as e:
                    logger.debug("Deletion of the directory %s failed, with the error: %s" % (opensshdir_path, e))
                    return

            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            openssh_zip_file = zipfile.ZipFile(filename, 'r')
            openssh_zip_file.extractall()

            try:
                shutil.copytree(os.path.join(install_tempdir, extracted_path), opensshdir_path)
            except Exception as e:
                logger.debug("Failed to copy the files:  %s" % e)
                return

            os.chdir(current_dir)

            sshdaemonDesc = "SSH protocol based service to provide secure encrypted communications between two untrusted hosts over an insecure network."
            command_sshdaemon = "sc.exe create sshdaemon binPath= \"%s\" DisplayName= \"Pulse SSH Server\" start= auto" % sshdaemon_bin_path
            utils.simplecommand(command_sshdaemon)

            utils.simplecommand("sc.exe privs sshdaemon SeAssignPrimaryTokenPrivilege/SeTcbPrivilege/SeBackupPrivilege/SeRestorePrivilege/SeImpersonatePrivilege")

            utils.simplecommand("sc start sshdaemon")
            utils.simplecommand("sc stop sshdaemon")

            try:
                shutil.copyfile(os.path.join(opensshdir_path, "sshd_config_default"), os.path.join(programdata_path, "sshd_config"))
            except Exception as e:
                logger.debug("Failed to copy the files:  %s" % e)
                return

            # Now we customize the config file
            sshd_config_file = utils.file_get_contents(os.path.join(programdata_path, "sshd_config"))
            sshport = "Port %s" % Used_ssh_port
            sshd_config_file = sshd_config_file.replace("#Port 22", sshport)
            sshd_config_file = sshd_config_file.replace("#PubkeyAuthentication yes", "PubkeyAuthentication yes")
            sshd_config_file = sshd_config_file.replace("#PasswordAuthentication yes", "PasswordAuthentication no")
            sshd_config_file = sshd_config_file.replace("#PidFile /var/run/sshd.pid", "PidFile C:\Windows\Temp\sshd.pid")
            sshd_config_file = sshd_config_file.replace("AuthorizedKeysFile   .ssh/authorized_keys", "AuthorizedKeysFile       $\"${USERDIR}\pulseuser\.ssh\authorized_keys$\"")
            sshd_config_file = sshd_config_file.replace("#SyslogFacility AUTH", "SyslogFacility LOCAL0")
            sshd_config_file = sshd_config_file.replace("Match Group administrators", "#Match Group administrators")
            sshd_config_file = sshd_config_file.replace("       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys", "#       AuthorizedKeysFile __{PROGRAMDATA}__/ssh/administrators_authorized_keys")

            utils.file_put_contents(os.path.join(programdata_path, "sshd_config"), sshd_config_file)

            utils.simplecommand("sc start sshdaemon")

            utils.simplecommand("netsh advfirewall firewall add rule name=\"SSH for Pulse\" dir=in action=allow protocol=TCP localport=%s" % Used_ssh_port)
        else:
            # Download error
            logger.error("%s" % txtmsg)
            return

        if not os.path.isdir(nytrio_sshdir_path):
            rsync_tempdir = tempfile.mkdtemp(dir=windows_tempdir)
            rsync_filename = 'rsync.zip'
            rsync_extracted_path = 'rsync'
            rsync_dl_url = 'http://%s/downloads/win/downloads/%s' % (xmppobject.config.Server, rsync_filename)
            rsync_result, rsync_txtmsg = utils.downloadfile(rsync_dl_url, os.path.join(rsync_tempdir, rsync_filename)).downloadurl()

            if rsync_result:
                current_dir = os.getcwd()
                os.chdir(rsync_tempdir)
                rsync_zip_file = zipfile.ZipFile(rsync_filename, 'r')
                rsync_zip_file.extractall()

                rsync_files = os.listdir(os.path.join(rsync_tempdir, "rsync"))
                for rsync_file in rsync_files:
                    full_rsync_file_name = os.path.join(rsync_tempdir, "rsync",rsync_file)

                    if os.path.isfile(full_rsync_file_name):
                        try:
                            shutil.copy(full_rsync_file_name, os.path.join(rsync_dest_folder, rsync_file))
                        except Exception as e:
                            logger.debug("Failed to copy the files:  %s" % e)
                            return

            os.chdir(current_dir)
            os.chdir(opensshdir_path)
            utils.simplecommand("ssh-keygen -A")

        updateopensshversion(installed_version)
