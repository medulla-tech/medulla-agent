# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from lib import utils
from distutils.version import StrictVersion
import logging
import platform
import tempfile
import os
import winreg

TIGHTVNC = "2.8.84"

logger = logging.getLogger()

plugin = {"VERSION": "1.7", "NAME": "updatetightvnc", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("PL-TIGHT call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Update if version is lower
        installed_version = checktightvncversion(xmppobject)
        check_tightvnc_configuration(xmppobject)
        if StrictVersion(installed_version) < StrictVersion(TIGHTVNC):
            updatetightvnc(xmppobject)
    except Exception:
        pass


def check_tightvnc_configuration(xmppobject):
    """
    Check and modify TightVNC Server registry keys as necessary, and restart the service if any changes are made.
    """
    if sys.platform.startswith("win"):
        configurations = [
            {
                "key": "AllowLoopback",
                "type": "REG_DWORD",
                "value": "0x0",
                "set_value": "0",
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
                "set_value": "1"
            },
            {
                "key": "Password",
                "type": "REG_BINARY",
                "value": xmppobject.config.password_rw,
                "set_value": xmppobject.config.password_rw
            },
        ]
        need_restart = False
        try:
            # Open the TightVNC Server registry key
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\TightVNC\Server",
                0,
                winreg.KEY_ALL_ACCESS,
            )
        except FileNotFoundError:
            logger.debug("PL-TIGHT TightVNC Server registry key not found.")
            return

        for config in configurations:
            try:
                # Query the current value of the key
                value, _ = winreg.QueryValueEx(key, config["key"])
                if value != config["value"]:
                    # Modify the key
                    winreg.SetValueEx(
                        key, config["key"], 0, config["type"], config["set_value"]
                    )
                    logger.debug(
                        f"PL-TIGHT The registry entry for TightVNCServer {config['key']} is reconfigured."
                    )
                    need_restart = True
            except FileNotFoundError:
                logger.debug(
                    f"PL-TIGHT TightVNC Server registry key {config['key']} not found."
                )

        if need_restart:
            try:
                # Restart the TightVNC Server service
                import subprocess

                subprocess.check_call(
                    "powershell Restart-Service -Name tvnserver", shell=True
                )
                logger.debug("PL-TIGHT TightVNCServer is reconfigured and restarted.")
            except subprocess.CalledProcessError:
                logger.debug(
                    "PL-TIGHT We failed to reinitialize the registry entry for TightVNCServer."
                )


def checktightvncversion():
    if sys.platform.startswith("win"):
        cmd = 'reg query hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\{5AE9C1FB-F4F8-44A7-8550-F0592F56A1F2} /s | Find "DisplayVersion"'
        result = utils.simplecommand(cmd)
        if result["code"] == 0:
            tightvncversion = result["result"][0].strip().split()[-1]
        else:
            logger.debug(
                "PL-TIGHT TightVNCServer is not installed or not the corrresponding version."
            )
            # TIGHTVNC is not installed. We will force installation by returning
            # version 0.1
            tightvncversion = "0.1"
    return tightvncversion


def updatetightvnc(xmppobject):
    logger.info("PL-TIGHT Updating TightVNC Agent to version %s" % TIGHTVNC)

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
        logger.debug("PL-TIGHT Downloading %s" % dl_url)
        result, txtmsg = utils.downloadfile(
            dl_url, os.path.join(install_tempdir, filename)
        ).downloadurl()
        if result:
            # Download success
            logger.info("PL-TIGHT %s" % txtmsg)
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
            cmd_result = utils.simplecommand(cmd)
            if cmd_result["code"] == 0:
                logger.info(
                    "PL-TIGHT %s installed successfully to version %s"
                    % (filename, TIGHTVNC)
                )

            else:
                logger.error(
                    "PL-TIGHT Error installing %s: %s"
                    % (filename, cmd_result["result"])
                )

            utils.simplecommand(
                'netsh advfirewall firewall add rule name="Remote Desktop for Pulse VNC" dir=in action=allow protocol=TCP localport=%s'
                % Used_rfb_port
            )
        else:
            # Download error
            logger.error("PL-TIGHT %s" % txtmsg)
