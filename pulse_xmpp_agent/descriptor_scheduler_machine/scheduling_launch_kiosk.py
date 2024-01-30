# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
this plugin process inventory from crontab descriptor time
"""
import logging
import sys
import os
from lib import utils
from lib import agentconffile
import configparser

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "scheduling_launch_kiosk", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/5 * * * *", "nb": -1}  # nb  -1 infinie


def schedule_main(objectxmpp):
    logger.debug("###################################################")
    logger.debug("call %s ", plugin)
    logger.debug("###################################################")
    num_compteur = getattr(objectxmpp, "num_call_%s" % plugin['NAME'])
    if num_compteur == 0:
        read_config_plugin_agent(objectxmpp)
    if objectxmpp.enable_kiosk:
        # Check if kiosk is already running
        if sys.platform.startswith("win"):
            pidfile = os.path.join("c:\\", "windows", "temp", "kiosk.pid")
        else:
            pidfile = os.path.join("/", "tmp", "kiosk.pid")
        if os.path.exists(pidfile):
            logger.debug("Kiosk is already running")
        else:
            # Run kiosk
            if sys.platform.startswith("win"):
                command = (
                    """C:\\progra~1\\pulse\\bin\\paexec.exe -accepteula -s -i 1 -d py.exe -3 -m kiosk_interface"""
                )
                logger.debug("Starting Kiosk. Command: %s" % command)
            if command:
                utils.shellcommandtimeout(command, 600).run()

def read_config_plugin_agent(objectxmpp):
    configfilename = os.path.join(agentconffile.directoryconffile(), "%s.ini" % plugin['NAME'])
    if not os.path.isfile(configfilename):
        logger.warning("there is no configuration file : %s" % configfilename)
        logger.warning("the missing configuration file is created automatically.")
        utils.file_put_contents(
            configfilename,
            "[scheduling_launch_kiosk]\n"
            "# Enable execution of kiosk\n"
            "# enable_kiosk = True\n"
        )
    Config = configparser.ConfigParser()
    Config.read(configfilename)
    try:
        objectxmpp.enable_kiosk = Config.getbool("scheduling_launch_kiosk", "enable_kiosk")
    except BaseException:
        objectxmpp.enable_kiosk = True
