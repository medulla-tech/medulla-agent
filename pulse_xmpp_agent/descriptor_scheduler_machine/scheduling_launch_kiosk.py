# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin processes kiosk launch based on crontab descriptor time.
"""

import logging
import sys
import os
from pulse_xmpp_agent.lib.utils import file_put_contents, shellcommandtimeout
from lib.agentconffile import directoryconffile
import configparser

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "scheduling_launch_kiosk", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/5 * * * *", "nb": -1}  # nb  -1 infinie


def schedule_main(objectxmpp):
    """
    Main function for the scheduling kiosk launch plugin.

    Args:
        objectxmpp: An object representing the XMPP connection.

    Notes:
        This function is called at specific intervals based on the crontab descriptor.
        It checks whether the kiosk should be enabled and launches it if necessary.

    """
    logger.debug("###################################################")
    logger.debug("call %s ", plugin)
    logger.debug("###################################################")
    num_compteur = getattr(objectxmpp, f'num_call_{plugin["NAME"]}')
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)
    if objectxmpp.enable_kiosk:
        # Check if kiosk is already running
        if os.path.exists(os.path.join("c:\\", "tmp", "kiosk.pid")):
            logger.debug("Kiosk is already running")
        else:
            # Run kiosk
            if sys.platform.startswith("win"):
                command = """C:\\progra~1\\pulse\\bin\\paexec.exe -accepteula -s -i 1 -d py.exe -3 -m kiosk_interface"""
                logger.debug(f"Starting Kiosk. Command: {command}")
            if command:
                shellcommandtimeout(command, 600).run()


def read_config_plugin_agent(objectxmpp):
    """
    Read the configuration file for the kiosk launch plugin.

    Args:
        objectxmpp: An object representing the XMPP connection.

    Notes:
        This function reads the configuration file for the kiosk launch plugin.
        If the configuration file does not exist, it creates one with default settings.

    """
    configfilename = os.path.join(directoryconffile(), f'{plugin["NAME"]}.ini')
    if not os.path.isfile(configfilename):
        logger.warning(f"there is no configuration file : {configfilename}")
        logger.warning("the missing configuration file is created automatically.")
        file_put_contents(
            configfilename,
            "[scheduling_launch_kiosk]\n"
            "# Enable execution of kiosk\n"
            "# enable_kiosk = True\n",
        )
    Config = configparser.ConfigParser()
    Config.read(configfilename)
    try:
        objectxmpp.enable_kiosk = Config.getbool(
            "scheduling_launch_kiosk", "enable_kiosk"
        )
    except BaseException:
        objectxmpp.enable_kiosk = True