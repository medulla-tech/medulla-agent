# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from packaging.version import Version
import logging
import platform
import tempfile
import os
import traceback
from lib import utils
import time


TIGHTVNC = "2.8.81"
COMPLETETIGHTVNC = "2.8.81.0"
logger = logging.getLogger()

plugin = {"VERSION": "2.9", "NAME": "updatetightvnc", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(f"PL-TIGHT call {plugin} from {message['from']}")
    logger.debug("###################################################")
    if sys.platform.startswith("win"):
        try:
            identifyingnumber_cmd = (
                'wmic product get name,identifyingnumber | find "TightVNC"'
            )
            identifyingnumber_result = utils.simplecommand(identifyingnumber_cmd)
            if identifyingnumber_result["code"] == 0:
                identifyingnumber = (
                    identifyingnumber_result["result"][0].strip().split()[0]
                )
                installed_version = checktightvncversion(identifyingnumber)

                if Version(installed_version) < Version(COMPLETETIGHTVNC):
                    updatetightvnc(xmppobject)
                elif Version(installed_version) > Version("2.8.81"):
                    uninstall_cmd = f"msiexec /x {identifyingnumber} /quiet /qn"
                    uninstall_result = utils.simplecommand(uninstall_cmd)
                    if uninstall_result["code"] == 0:
                        logger.info(
                            f"PL-TIGHT Version {installed_version} uninstalled with success."
                        )
                    else:
                        logger.error(
                            f"PL-TIGHT Error when uninstalling the version {installed_version}: {uninstall_result['result']}"
                        )
                        return
                    updatetightvnc(xmppobject)
            else:
                updatetightvnc(xmppobject)
            check_tightvnc_configuration(xmppobject)
        except Exception as error_plugin:
            logger.debug(f"PL-TIGHT failed with the error {error_plugin}")
            logger.error(
                f"PL_TIGHT failed with the backtrace \n {traceback.format_exc()}"
            )
            pass


def check_tightvnc_configuration(xmppobject):
    """
    Check and modify TightVNC Server registry keys as necessary
    and restart the service if any changes are made.
    """
    if sys.platform.startswith("win"):
        configurations = [
            {
                "key": "AllowLoopback",
                "type": "REG_DWORD",
                "value": "0x1",
                "set_value": "1",
            },
            {
                "key": "LoopbackOnly",
                "type": "REG_DWORD",
                "value": "0x0",
                "set_value": "0",
            },
            {
                "key": "AcceptHttpConnections",
                "type": "REG_DWORD",
                "value": "0x0",
                "set_value": "0",
            },
            {
                "key": "UseVncAuthentication",
                "type": "REG_DWORD",
                "value": "0x1",
                "set_value": "1",
            },
            {
                "key": "Password",
                "type": "REG_BINARY",
                "value": xmppobject.config.password_rw,
                "set_value": xmppobject.config.password_rw,
            },
            {
                "key": "RepeatControlAuthentication",
                "type": "REG_DWORD",
                "value": "0x1",
                "set_value": "1",
            },
            {
                "key": "UseControlAuthentication",
                "type": "REG_DWORD",
                "value": "0x1",
                "set_value": "1",
            },
            {
                "key": "ControlPassword",
                "type": "REG_BINARY",
                "value": xmppobject.config.password_rw,
                "set_value": xmppobject.config.password_rw,
            },
        ]
        need_restart = False

        for config in configurations:
            cmd = f'reg query "hklm\\SOFTWARE\\TightVNC\\Server" /v {config["key"]} | Find "{config["key"]}"'
            result = utils.simplecommand(cmd)

            if result["code"] == 0:
                value = result["result"][0].strip().split()[-1]

                if config["key"] in ["Password", "ControlPassword"]:
                    # Compare the values in a case-insensitive manner
                    if value.lower() != config["value"].lower():
                        cmd = f'REG ADD "HKLM\\SOFTWARE\\TightVNC\\Server" /v {config["key"]} /t {config["type"]} /d "{config["set_value"]}" /f'
                        result = utils.simplecommand(cmd)

                        if result["code"] == 0:
                            logger.debug(
                                f"The registry entry for TightVNCServer {config['key']} is reconfigured."
                            )
                            need_restart = True
                        else:
                            logger.error(
                                f"We failed to reinitialize the registry entry for TightVNCServer {config['key']}"
                            )
                else:
                    if value != config["value"]:
                        cmd = f'REG ADD "HKLM\\SOFTWARE\\TightVNC\\Server" /v {config["key"]} /t {config["type"]} /d "{config["set_value"]}" /f'
                        result = utils.simplecommand(cmd)

                        if result["code"] == 0:
                            logger.debug(
                                f"The registry entry for TightVNCServer {config['key']} is reconfigured."
                            )
                            need_restart = True
                        else:
                            logger.error(
                                f"We failed to reinitialize the registry entry for TightVNCServer {config['key']}"
                            )

            elif result["code"] == 1:
                cmd = f'REG ADD "hklm\\SOFTWARE\\TightVNC\\Server" /v {config["key"]} /t {config["type"]} /d "{config["set_value"]}" /f'
                result = utils.simplecommand(cmd)

                if result["code"] == 0:
                    logger.debug(
                        f"PL-TIGHT TightVNCServer registry {config['key']} with value {config['set_value']} is reconfigured."
                    )
                    need_restart = True
                else:
                    logger.debug(
                        f"PL-TIGHT TightVNC Server registry key {config['key']} is correctly configured."
                    )

        if need_restart:
            cmd = "powershell Restart-Service -Name tvnserver"
            result = utils.simplecommand(cmd)

            if result["code"] == 0:
                logger.debug("PL-TIGHT TightVNCServer is reconfigured and restarted.")
            else:
                logger.debug(
                    "PL-TIGHT We failed to reinitialize the registry entry for TightVNCServer."
                )


def checktightvncversion(identifyingnumber):
    if sys.platform.startswith("win"):
        if identifyingnumber:
            cmd = (
                f"reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\"
                f'{identifyingnumber} /s | Find "DisplayVersion"'
            )
            result = utils.simplecommand(cmd)
            if result["code"] == 0 and result["result"]:
                tightvncversion = result["result"][0].strip().split()[-1]
        else:
            # TIGHTVNC is not installed. We will force installation by returning
            # version 0.1
            tightvncversion = "0.1"
    return tightvncversion


def updatetightvnc(xmppobject):
    logger.info(f"PL-TIGHT Updating TightVNC Agent to version {TIGHTVNC}")

    windows_tempdir = os.path.join("c:\\", "Windows", "Temp")
    install_tempdir = tempfile.mkdtemp(dir=windows_tempdir)

    Used_rfb_port = 5900
    if hasattr(xmppobject.config, "rfbport"):
        Used_rfb_port = xmppobject.config.rfbport

    if sys.platform.startswith("win"):
        if platform.architecture()[0] == "64bit":
            architecture = "64bit"
        else:
            architecture = "32bit"
        filename = "tightvnc-%s-gpl-setup-%s.msi" % (TIGHTVNC, architecture)
        dl_url = "http://%s/downloads/win/downloads/%s" % (
            xmppobject.config.Server,
            filename,
        )
        logger.debug(f"PL-TIGHT Downloading {dl_url}")
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            # Download success
            logger.info(f"PL-TIGHT {txtmsg}")
            current_dir = os.getcwd()
            os.chdir(install_tempdir)
            install_options = "/quiet /qn /norestart"
            install_options = (
                install_options
                + " ADDLOCAL=Server SERVER_REGISTER_AS_SERVICE=1 SERVER_ADD_FIREWALL_EXCEPTION=1 SERVER_ALLOW_SAS=1"
            )
            # Disable embedded Java WebSrv on port 5800
            install_options = (
                install_options
                + " SET_ACCEPTHTTPCONNECTIONS=1 VALUE_OF_ACCEPTHTTPCONNECTIONS=0"
            )
            # Enable RFB on port 5900
            install_options = (
                install_options
                + " SET_ACCEPTRFBCONNECTIONS=1 VALUE_OF_ACCEPTRFBCONNECTIONS=1"
            )
            # Enable loopback connection
            install_options = (
                install_options + " SET_ALLOWLOOPBACK=1 VALUE_OF_ALLOWLOOPBACK=0"
            )
            # Allow on all interfaces
            install_options = (
                install_options + " SET_LOOPBACKONLY=1 VALUE_OF_LOOPBACKONLY=0"
            )
            # Only allow from 127.0.0.1 and query user
            install_options = (
                install_options
                + " SET_IPACCESSCONTROL=1 VALUE_OF_IPACCESSCONTROL=0.0.0.0-255.255.255.255:2"
            )
            # Default answser on timeout is reject
            install_options = (
                install_options
                + " SET_QUERYACCEPTONTIMEOUT=1 VALUE_OF_QUERYACCEPTONTIMEOUT=0"
            )
            # Timeout is 20s
            install_options = (
                install_options + " SET_QUERYTIMEOUT=1 VALUE_OF_QUERYTIMEOUT=20"
            )
            # Show service icon
            install_options = (
                install_options
                + " SET_RUNCONTROLINTERFACE=1 VALUE_OF_RUNCONTROLINTERFACE=1"
            )
            # Hide wallpaper
            install_options = (
                install_options + " SET_REMOVEWALLPAPER=1 VALUE_OF_REMOVEWALLPAPER=1"
            )
            # Share between multiple connection
            install_options = (
                install_options
                + " SET_ALWASHARED=1 SET_NEVERSHARED=1 VALUE_OF_ALWASHARED=1 VALUE_OF_NEVERSHARED=0"
            )
            # Disable authentication
            install_options = (
                install_options
                + " SET_USEVNCAUTHENTICATION=1 VALUE_OF_USEVNCAUTHENTICATION=0"
            )
            # Ensure remote inputs are enabled
            install_options = (
                install_options + " SET_BLOCKREMOTEINPUT=1 VALUE_OF_BLOCKREMOTEINPUT=0"
            )
            # Don't do anything when terminating VNC session
            install_options = (
                install_options + " SET_DISCONNECTACTION=1 VALUE_OF_DISCONNECTACTION=0"
            )
            # Set the server listening port
            install_options = (
                install_options + " SET_RFBPORT=1 VALUE_OF_RFBPORT=%s" % Used_rfb_port
            )

            # Run installer
            cmd = "msiexec /i %s %s REBOOT=R" % (filename, install_options)

            count = 0
            while True:
                cmd_result = utils.simplecommand(cmd)
                if cmd_result["code"] == 0:
                    logger.info("PL-TIGHT %s installed successfully" % filename)
                    break
                else:
                    logger.error("PL-TIGHT Error installing %s: %s" % (filename, cmd_result["result"]))
                count += 1
                if count > 10:
                    logger.error("PL-TIGHT Failed to install %s after several attempts." % filename)
                    break
                time.sleep(60)

            utils.simplecommand(
                'netsh advfirewall firewall add rule name="Remote Desktop for Pulse VNC" dir=in action=allow protocol=TCP localport=%s'
                % Used_rfb_port
            )
        else:
            # Download error
            logger.error(f"PL-TIGHT {txtmsg}")
