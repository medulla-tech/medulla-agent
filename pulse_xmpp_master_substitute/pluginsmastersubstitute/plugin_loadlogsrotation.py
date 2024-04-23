# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2019-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
import configparser
import shutil
import types
from lib.configuration import confParameter
from datetime import datetime, timedelta

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "loadlogsrotation", "TYPE": "substitute", "LOAD": "START"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

    if compteurcallplugin == 0:
        read_conf_logsrotation(objectxmpp)
        objectxmpp.Rotatelog = types.MethodType(Rotatelog, objectxmpp)
        objectxmpp.schedule("loadlogsrotation", 1800, objectxmpp.Rotatelog, repeat=True)

    objectxmpp.Rotatelog()


def read_conf_logsrotation(objectxmpp):
    """
    Read plugin configuration
    The folder holding the config file is in the variable objectxmpp.config.pathdirconffile
    """

    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    if not os.path.isfile(pathconffile):
        logger.error(
            "plugin %s\nConfiguration file missing\n  %s"
            "\neg conf:\n[parameters]\nrotation_cron = 23:00\nretention_days = 7"
            % (plugin["NAME"], pathconffile)
        )

        logger.warning(
            "default value for dirplugins is /var/lib/medulla/xmpp_baseplugin/"
        )
        objectxmpp.dirpluginlist = "/var/lib/medulla/xmpp_baseplugin/"
    else:
        Config = configparser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        objectxmpp.dirpluginlist = "/var/lib/medulla/xmpp_baseplugin/"
        if Config.has_option("parameters", "rotation_time"):
            objectxmpp.rotation_time = Config.get("parameters", "rotation_time")
        else:
            objectxmpp.rotation_time = "23:00"
        if Config.has_option("parameters", "retention_days"):
            objectxmpp.retention_days = Config.get("parameters", "retention_days")
        else:
            objectxmpp.retention_days = 7


def Rotatelog(self):
    """
    Runs the log rotation
    """
    logfile = confParameter().logfile
    logger.debug("Log file is %s" % logfile)
    if os.path.isfile(logfile):  # check if we even need to rotate
        now = datetime.now()
        nowminus30min = datetime.now() - timedelta(minutes=30)
        rottime = datetime.strptime(
            "%s %s" % (datetime.now().date(), self.rotation_time), "%Y-%m-%d %H:%M"
        )
        if rottime < now and rottime > nowminus30min:
            for i in range(int(self.retention_days), 0, -1):  # count backwards
                old_name = "%s.%s" % (logfile, i)
                new_name = "%s.%s" % (logfile, i + 1)
                try:
                    shutil.copyfile(old_name, new_name)
                except Exception:
                    pass
            try:
                shutil.copyfile(logfile, logfile + ".1")
            except Exception:
                pass
            open(logfile, "w").close()  # Truncate the log file
