# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import zipfile
import platform
import tempfile
import shutil
import configparser
from lib import utils
from xml.etree import ElementTree

SYNCTHINGVERSION = "1.23.4"

logger = logging.getLogger()
plugin = {"VERSION": "1.25", "NAME": "updatesyncthing", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    if sys.platform.startswith("win"):
        try:
            # Update if version is lower
            installed_version = checksyncthingversion()
            if StrictVersion(installed_version) < StrictVersion(SYNCTHINGVERSION):
                updatesyncthing(xmppobject, installed_version)

            # Configure syncthing
            syncthingconfig_path = os.path.join(
                "c:\\", "progra~1", "Medulla", "etc", "syncthing"
            )
            syncthing_configfile = os.path.join(syncthingconfig_path, "config.xml")
            if os.path.isfile(syncthing_configfile):
                configuresyncthing(syncthing_configfile)

        except Exception:
            pass
    else:
        logger.debug("This plugin only support the Windows Platform")


def checksyncthingversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla Syncthing" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            syncthingversion = result["result"][0].strip().split()[-1]
        else:
            # The filetree generator is not installed. We will force installation by returning
            # version 0.0
            syncthingversion = "0.0"
    return syncthingversion


def updatesyncthingversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla Syncthing" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % SYNCTHINGVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated Syncthing to version " % SYNCTHINGVERSION
            )

        if version == "0.0":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla Syncthing" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla Syncthing" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla Syncthing" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)
            logger.info("Syncthing updated to version %s" % SYNCTHINGVERSION)


def configuresyncthing(config_file):
    tree = ElementTree.parse(config_file)
    config = tree.getroot()
    config.find("./options/urAccepted").text = -1
    config.find("./options/autoUpgradeIntervalH").text = 0
    config.find("./options/localAnnounceEnabled").text = "false"
    config.find("./options/globalAnnounceEnabled").text = "false"
    config.find("./options/relaysEnabled").text = "false"
    config.find("./options/stunKeepaliveSeconds").text = 0
    config.find("./options/crashReportingEnabled").text = "false"
    tree.write(config_file)


def updatesyncthing(xmppobject, installed_version):
    logger.info("Updating Syncthing to version %s" % SYNCTHINGVERSION)
    if sys.platform.startswith("win"):
        if platform.architecture()[0] == "64bit":
            architecture = "amd64"
        else:
            architecture = "386"
        medulladir_path = os.path.join("c:\\", "progra~1", "Medulla", "bin")
        medullaconfig_path = os.path.join("c:\\", "progra~1", "Medulla", "etc")
        syncthingconfig_path = os.path.join(
            "c:\\", "progra~1", "Medulla", "etc", "syncthing"
        )
        windows_tempdir = os.path.join("c:\\", "Windows", "Temp")

        install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

        filename = "syncthing-windows-%s-v%s.zip" % (architecture, SYNCTHINGVERSION)
        extracted_path = "syncthing-windows-%s-v%s" % (architecture, SYNCTHINGVERSION)
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
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            syncthing_zip_file = zipfile.ZipFile(filename, "r")
            syncthing_zip_file.extractall()
            utils.simplecommand("taskkill.exe /F /IM syncthing.exe")
            shutil.copyfile(
                os.path.join(extracted_path, "syncthing.exe"),
                os.path.join(medulladir_path, "syncthing.exe"),
            )
            os.chdir(current_dir)

            utils.simplecommand(
                'netsh advfirewall firewall add rule name="Syncthing for Medulla" dir=in action=allow protocol=TCP localport=22000'
            )

            mklink_command = 'mklink "%s" "%s"' % (
                os.path.join(medullaconfig_path, "syncthing.ini"),
                os.path.join(syncthingconfig_path, "config.xml"),
            )
            utils.simplecommand(mklink_command)

            # Enable syncthing now it is installed
            agentconf_file = os.path.join(medullaconfig_path, "agentconf.ini")
            Config = configparser.ConfigParser()
            Config.read(agentconf_file)
            if not Config.has_option("syncthing", "activation"):
                Config.add_section("syncthing")
            Config.set("syncthing", "activation", "1")
            with open(agentconf_file, "w") as configfile:
                Config.write(configfile)

            updatesyncthingversion(installed_version)
        else:
            # Download error
            logger.error("%s" % txtmsg)
