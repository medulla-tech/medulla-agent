# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
# file  pulse_xmpp_agent/pluginsmachine/plugin_start.py

import sys
import os
import logging
from lib import utils
from lib.agentconffile import directoryconffile
import ConfigParser
import re

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "2.1", "NAME": "start", "TYPE": "all"}


def read_conf_plugin_start(objectxmpp):
    objectxmpp.liststartplugin = []
    if objectxmpp.config.agenttype in ["machine"]:
        configfilename = os.path.join(directoryconffile(), "start_machine.ini")
    elif objectxmpp.config.agenttype in ["relay"]:
        configfilename = os.path.join(directoryconffile(), "start_relay.ini")
    objectxmpp.time_differed_start = 10
    if os.path.isfile(configfilename):
        # lit la configuration
        Config = ConfigParser.ConfigParser()
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
        logger.info(
            "Call of %s by plugin_start differed by %s s"
            % (pluginstart, objectxmpp.time_differed_start)
        )
        params = {"descriptor": startupdate, "errordescriptor": dataerreur, "msg": msg}
        objectxmpp.paramsdict.append(params)

    objectxmpp.call_plugin_differed(time_differed=objectxmpp.time_differed_start)
