# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin processes inventory from crontab descriptor time.
"""

import logging
import os
import psutil
import subprocess
from pulse_xmpp_agent.lib.utils import file_put_contents, simplecommand
from lib.agentconffile import directoryconffile
import configparser

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "scheduling_launch_kiosk", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/5 * * * *", "nb": -1}  # fmt: skip


def schedule_main(objectxmpp):
    logger.debug("###################################################")
    logger.debug("call %s ", plugin)
    logger.debug("###################################################")

    cleanup_old_kiosk()

    # Read the configuration on the first call
    num_compteur = getattr(objectxmpp, f'num_call_{plugin["NAME"]}')
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)

    # Check if enable_kiosk is set to True in the configuration
    if getattr(objectxmpp, "enable_kiosk", False):
        logger.debug("Kiosk is enabled in configuration.")
        pid_file = "C:\\Program Files\\Medulla\\bin\\kiosk.pid"

        # Verify if Kiosk is already running using the PID file
        if os.path.exists(pid_file):
            with open(pid_file, "r") as f:
                pid = int(f.read().strip())
            try:
                # Check if the process is still active
                p = psutil.Process(pid)
                if p.is_running() and p.status() != psutil.STATUS_ZOMBIE:
                    logger.debug("Kiosk is already running. PID: %d", pid)
                    return
            except psutil.NoSuchProcess:
                logger.warning(
                    f"Kiosk process with PID {pid} not found. Removing PID file."
                )
                os.remove(pid_file)

        session_id = get_session_id()
        if not session_id:
            logger.error("Cannot retrieve session ID. Kiosk will not be started.")
            return

        # Command to launch Kiosk if the process is not active
        command = f"""C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i {session_id} -d "C:\\Program Files\\Python3\\pythonw.exe" -m kiosk_interface"""

        logger.debug(f"Starting Kiosk. Command: {command}")
        process = subprocess.Popen(command, shell=True)

        # Create the PID file with the PID of the new process
        with open(pid_file, "w") as f:
            f.write(str(process.pid))
        logger.debug("Kiosk started successfully with PID: %d", process.pid)
    else:
        logger.debug("Kiosk is disabled in configuration.")


def read_config_plugin_agent(objectxmpp):
    configfilename = os.path.join(directoryconffile(), f'{plugin["NAME"]}.ini')
    logger.debug(f"Reading configuration file: {configfilename}")

    # Create the config file if it does not exist
    if not os.path.isfile(configfilename):
        logger.warning(f"No configuration file found: {configfilename}")
        logger.warning("Automatically creating the missing configuration file.")
        file_put_contents(
            configfilename,
            "[scheduling_launch_kiosk]\n"
            "# Enable execution of kiosk\n"
            "# enable_kiosk = True\n",
        )

    # Read the configuration file
    Config = configparser.ConfigParser()
    Config.read(configfilename)

    # Set enable_kiosk based on the configuration file
    try:
        objectxmpp.enable_kiosk = Config.getboolean(
            "scheduling_launch_kiosk", "enable_kiosk"
        )
    except (configparser.NoOptionError, ValueError):
        objectxmpp.enable_kiosk = (
            True  # Default to False if the setting is missing or invalid
        )
        logger.warning(
            "The 'enable_kiosk' option is missing or invalid. Defaulting to False."
        )


def get_session_id():
    try:
        re = simplecommand("query user")
        if len(re.get("result", [])) >= 2:
            userdata = [x.strip("> ") for x in re["result"][1].split(" ") if x != ""]
            user_id = userdata[2]
            logger.debug(f"Session ID: {user_id}")
            return user_id
        else:
            logger.warning("No active user session found.")
            return None
    except Exception as e:
        logger.error(f"Failed to retrieve session ID: {e}")
        return None


def cleanup_old_kiosk():
    """Terminate any old Kiosk process, remove old PID file, and delete old startup script."""
    old_pid_file = "C:\\Windows\\Temp\\kiosk.pid"
    startup_script = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\RunMedullaKiosk.bat"

    # Finish the Kiosk process if the PID file exists
    if os.path.exists(old_pid_file):
        try:
            with open(old_pid_file, "r") as f:
                pid = int(f.read().strip())
            psutil.Process(pid).terminate()
            logger.debug(f"Old Kiosk process with PID {pid} terminated.")
        except (psutil.NoSuchProcess, ValueError):
            logger.debug("No old Kiosk process found to terminate.")
        finally:
            os.remove(old_pid_file)
            logger.debug("old kiosk.pid file deleted.")

    # Remove the old starter script if there is
    if os.path.exists(startup_script):
        try:
            os.remove(startup_script)
            logger.debug(f"Old startup script '{startup_script}' successfully deleted.")
        except Exception as e:
            logger.error(f"Failed to delete old startup script '{startup_script}': {e}")
