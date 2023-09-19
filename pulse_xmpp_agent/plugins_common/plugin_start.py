# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
from lib import utils
from lib.agentconffile import directoryconffile
import configparser
import re

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "2.2", "NAME": "start", "TYPE": "all"}  # fmt: skip


def read_conf_plugin_start(objectxmpp):
    objectxmpp.liststartplugin = []
    if objectxmpp.config.agenttype in ["machine"]:
        configfilename = os.path.join(directoryconffile(), "start_machine.ini")
    elif objectxmpp.config.agenttype in ["relayserver"]:
        configfilename = os.path.join(directoryconffile(), "start_relay.ini")
    else:
        logger.error(
            "The %s agenttype is not supported in this function, it must be machine or relayserver."
            % objectxmpp.config.agenttype
        )
    objectxmpp.time_differed_start = 10
    if os.path.isfile(configfilename):
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        if os.path.isfile(configfilename + ".local"):
            Config.read(configfilename + ".local")
        if Config.has_option("plugins", "time_differed_start"):
            objectxmpp.time_differed_start = Config.getint(
                "plugins", "time_differed_start"
            )
        if Config.has_option("plugins", "liststartplugin"):
            liststartplugin = Config.get("plugins", "liststartplugin")
            objectxmpp.liststartplugin = [
                x
                for x in re.split(
                    r"[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\@\$\|\s]\s*",
                    liststartplugin,
                )
                if x.strip() != ""
            ]


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    logger.debug("compteurcallplugin = %s" % compteurcallplugin)
    if compteurcallplugin == 0:
        logger.debug("configure plugin %s" % action)
        read_conf_plugin_start(objectxmpp)
        objectxmpp.paramsdict = []

    startupdateskel = {
        "action": "",
        "sessionid": utils.getRandomName(6, "startplugin"),
        "ret": 0,
        "base64": False,
        "data": {},
    }
    msg = {
        "from": objectxmpp.boundjid.bare,
        "to": objectxmpp.boundjid.bare,
        "type": "chat",
    }

    for pluginstart in objectxmpp.liststartplugin:
        dataerreur = startupdateskel.copy()
        startupdate = startupdateskel.copy()
        startupdate["action"] = pluginstart
        dataerreur["action"] = "result" + startupdate["action"]
        dataerreur["data"] = {"msg": "error plugin: " + startupdate["action"]}
        dataerreur["ret"] = 255
        logger.debug(
            "Call of %s by plugin_start differed by %s s"
            % (pluginstart, objectxmpp.time_differed_start)
        )
        params = {"descriptor": startupdate, "errordescriptor": dataerreur, "msg": msg}
        objectxmpp.paramsdict.append(params)

    objectxmpp.call_plugin_differed(time_differed=objectxmpp.time_differed_start)
