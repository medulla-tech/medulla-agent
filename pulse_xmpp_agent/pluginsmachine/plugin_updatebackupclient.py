# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from lib import utils
from distutils.version import StrictVersion
import logging
import tempfile
import os
import socket

URBACKUP_VERSION = "2.5.25"

logger = logging.getLogger()

plugin = {"VERSION": "1.6", "NAME": "updatebackupclient", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Do not proceed if backup_enabled is not set to 1
        if hasattr(xmppobject.config, "backup_enabled"):
            if bool(int(xmppobject.config.backup_enabled)):
                # Update if version is lower
                installed_version = checkurbackupversion()
                if StrictVersion(installed_version) < StrictVersion(URBACKUP_VERSION):
                    updatebackupclient(xmppobject)
                    backupclientsettings(xmppobject)
    except Exception:
        pass


def checkurbackupversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\UrBackup /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            urbackupversion = result["result"][0].strip().split()[-1]
        else:
            # urbackup is not installed. We will force installation by returning
            # version 0.1
            urbackupversion = "0.1"
    return urbackupversion


def updatebackupclient(xmppobject):
    logger.info("Updating UrBackup client to version %s" % URBACKUP_VERSION)

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    if sys.platform.startswith("win"):
        filename = "UrBackup_Client_%s.exe" % URBACKUP_VERSION
        dl_url = "http://%s/downloads/win/downloads/%s" % (
            xmppobject.config.Server,
            filename,
        )
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            # Download success
            logger.info("%s" % txtmsg)
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            install_options = "/S"

            # Run installer
            cmd = "%s %s" % (filename, install_options)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info(
                    "%s installed successfully to version %s"
                    % (filename, URBACKUP_VERSION)
                )
            else:
                logger.error(
                    "Error installing %s: %s" % (filename, cmd_result["result"])
                )
        else:
            # Download error
            logger.error("%s" % txtmsg)


def backupclientsettings(xmppobject):
    logger.info("Configuring UrBackup client settings")

    hostname = socket.gethostname()
    urbackup_dir = os.path.join("c:\\", "progra~1", "UrBackup")
    logger.debug("Urbackup urbackup_dir: %s" % urbackup_dir)

    if sys.platform.startswith("win"):
        filename = os.path.join("%s" % urbackup_dir, "UrBackupClient_cmd.exe")
        if os.path.exists(filename):
            logger.debug("Urbackup filename: %s" % filename)
            os.chdir(urbackup_dir)
            cmd = (
                '"%s" set-settings -k  internet_mode_enabled -v true --server-url "%s" --name "%s" --authkey "%s" -k internet_image_backups -v false -k internet_full_file_backups -v true'
                % (
                    filename,
                    xmppobject.config.backup_server,
                    hostname,
                    xmppobject.config.authkey,
                )
            )
            logger.debug("Urbackup cmd: %s" % cmd)
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info("Settings successfully applied to client %s" % (hostname))
            else:
                logger.error(
                    "Error applying settings: %s in %s"
                    % (filename, cmd_result["result"])
                )
        else:
            logger.error("Urbackup filename %s does not exist" % filename)
