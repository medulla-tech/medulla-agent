# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils

NETWORKVERSION = "3.0.1"

logger = logging.getLogger()
plugin = {"VERSION": "2.2", "NAME": "updatenetworkcheck", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        check_if_binary_ok()
        # Update if version is lower
        installed_version = checknetworkcheckversion()
        if StrictVersion(installed_version) < StrictVersion(NETWORKVERSION):
            remove_old_service()
            updatenetworkcheck(xmppobject)
            updatenetworkcheckversion(installed_version)
    except Exception:
        pass


def remove_old_service():
    is_old_service_running = utils.simplecommand("sc.exe query pulsenetworknotify")
    if is_old_service_running["code"] == 0:
        utils.simplecommand("sc.exe stop pulsenetworknotify")
        utils.simplecommand("sc.exe delete pulsenetworknotify")
        regclean = 'REG DELETE "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse network notify" /f'
        utils.simplecommand(regclean)


def check_if_service_is_running():
    if sys.platform.startswith("win"):
        is_ssh_started = utils.simplecommand("sc.exe query medullanetnotify")
        if is_ssh_started["code"] == 0:
            state = [
                x.strip() for x in is_ssh_started["result"][3].split(" ") if x != ""
            ][3]
            if state == "STOPPED" or state == "RUNNING":
                logger.debug("The Pulse Network Notify plugin is installed.")
                return True
        return False


def stop_service():
    if sys.platform.startswith("win"):
        is_ssh_started = utils.simplecommand("sc.exe query medullanetnotify")
        if is_ssh_started["code"] == 0:
            state = [
                x.strip() for x in is_ssh_started["result"][3].split(" ") if x != ""
            ][3]
            if state == "RUNNING":
                utils.simplecommand("sc.exe stop sshdaemon")


def check_if_binary_ok():
    if sys.platform.startswith("win"):
        regedit = False
        binary = False
        is_service_installed = False
        reinstall = False

        # We check if we have the Regedit entry
        cmd_reg = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" /s | Find "DisplayVersion"'
        result_reg = utils.simplecommand(cmd_reg)
        if result_reg["code"] == 0:
            regedit = True

        # We check if the binary is available
        pulsedir_path = os.path.join("c:\\", "progra~1", "Pulse", "bin")
        servicefilename = "netcheck-service.py"

        if os.path.isfile(os.path.join(pulsedir_path, servicefilename)):
            binary = True

        is_service_installed = check_if_service_is_running()

        if (regedit is False and is_service_installed is True) or (
            binary is False and is_service_installed is True
        ):
            reinstall = True
            stop_service()

        if (binary is True and is_service_installed is False) or (
            regedit is True and is_service_installed is False
        ):
            reinstall = True

        if reinstall:
            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" '
                '/v "DisplayVersion" /t REG_SZ  /d "0.0" /f'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0:
                logger.debug(
                    "The Pulse Network Notify module is ready to be reinstalled."
                )
            else:
                logger.debug("We failed to reinitialize the registry entry.")


def checknetworkcheckversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            networkcheckversion = result["result"][0].strip().split()[-1]
        else:
            # Fusion is not installed. We will force installation by returning
            # version 0.1
            networkcheckversion = "0.1"
    return networkcheckversion


def updatenetworkcheckversion(version):
    if sys.platform.startswith("win"):
        cmd = (
            'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" '
            '/v "DisplayVersion" /t REG_SZ  /d "%s" /f' % NETWORKVERSION
        )

        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            logger.info(
                "we successfully updated Medulla network notify to version %s"
                % NETWORKVERSION
            )

        if version == "0.1":
            cmdDisplay = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" '
                '/v "DisplayName" /t REG_SZ  /d "Medulla network notify" /f'
            )
            utils.simplecommand(cmdDisplay)

            cmd = (
                'REG ADD "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Medulla network notify" '
                '/v "Publisher" /t REG_SZ  /d "SIVEO" /f'
            )

            utils.simplecommand(cmd)


def updatenetworkcheck(xmppobject):
    version_info = utils.PythonVersionInfo()
    logger.info("Updating Network Check to version %s" % NETWORKVERSION)
    if sys.platform.startswith("win"):
        pywintypesxxx_file = os.path.join(
            version_info.path_lib,
            "site-packages",
            "pywin32_system32",
            "pywintypes%s.dll" % version_info.version,
        )
        win32_path = os.path.join(version_info.get_path_packages_python(), "win32")
        pulsedir_path = os.path.join("c:\\", "progra~1", "Pulse", "bin")

        filename = "networkevents.py"
        dl_url = "http://%s/downloads/win/%s" % (xmppobject.config.Server, filename)
        logger.debug("Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(pulsedir_path, filename)
        ).downloadurl()
        if result:
            logger.debug("%s" % txtmsg)
        else:
            # Download error
            logger.error("%s" % txtmsg)

        # We stop the service
        stop_command = "sc stop medullanetnotify"
        stop_service = utils.simplecommand(stop_command)
        # Activation of network notify windows service
        if not os.path.isfile(
            os.path.join(win32_path, "pywintypes%s.dll" % version_info.version)
        ):
            shutil.copyfile(
                pywintypesxxx_file,
                os.path.join(win32_path, "pywintypes%s.dll" % version_info.version),
            )

        servicefilename = "netcheck-service.py"
        service_dl_url = "http://%s/downloads/win/%s" % (
            xmppobject.config.Server,
            servicefilename,
        )
        serviceresult, servicetxtmsg = utils.downloadfile(
            service_dl_url, os.path.join(pulsedir_path, servicefilename)
        ).downloadurl()
        if serviceresult:
            # Download success
            logger.info("%s" % servicetxtmsg)
            # Run installer
            querycmd = "sc query medullanetnotify"
            querycmd_result = utils.simplecommand(querycmd)
            # We need to have a copy of pythonservices named based on _exe_name_
            if not os.path.isfile(os.path.join(win32_path, "medullanetnotify.exe")):
                shutil.copyfile(
                    os.path.join(win32_path, "pythonservices.exe"),
                    os.path.join(win32_path, "medullanetnotify.exe"),
                )

            if querycmd_result["code"] != 0:
                servicecmd = '%s "%s\\%s" --startup=auto install' % (
                    utils.get_python_executable_console(),
                    pulsedir_path,
                    servicefilename,
                )
                servicecmd_result = utils.simplecommand(servicecmd)
                if servicecmd_result["code"] == 0:
                    logger.info("%s installed successfully" % servicefilename)
                else:
                    logger.error(
                        "Error installing %s: %s"
                        % (servicefilename, servicecmd_result["result"])
                    )

            update_command = '"%s %s\\%s" update' % (
                utils.get_python_executable_console(),
                pulsedir_path,
                servicefilename,
            )
            utils.simplecommand(update_command)

            restart_command = '%s "%s\\%s" restart' % (
                utils.get_python_executable_console(),
                pulsedir_path,
                servicefilename,
            )
            utils.simplecommand(restart_command)
        else:
            # Download error
            logger.error("%s" % servicetxtmsg)
