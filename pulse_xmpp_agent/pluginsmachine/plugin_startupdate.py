# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
 This plugin start all plugin list in init file startupdate.ini
 This plugin launch inventory is asked
"""

from lib import utils
import json
import logging
import os
from lib.agentconffile import directoryconffile
import configparser
import re

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.5", "NAME": "startupdate", "TYPE": "machine"}  # fmt: skip


def read_conf_plugin_startupdate(objectxmpp):
    objectxmpp.liststartpluginstartupdate = []
    objectxmpp.startupdateinventory = False
    objectxmpp.startupdateinventoryforced = False
    configfilename = os.path.join(directoryconffile(), "startupdate.ini")
    if os.path.isfile(configfilename):
        # lit la configuration
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        if Config.has_option("plugins", "liststartplugin"):
            liststartplugin = Config.get("plugins", "liststartplugin")
            objectxmpp.liststartpluginstartupdate = [
                x
                for x in re.split(
                    r"[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\@\$\|\s]\s*",
                    liststartplugin,
                )
                if x.strip() != ""
            ]
        else:
            createlistpluginupdate(objectxmpp)
        if Config.has_option("plugins", "inventory"):
            objectxmpp.startupdateinventory = Config.getboolean("plugins", "inventory")
        if Config.has_option("plugins", "inventoryforced"):
            objectxmpp.startupdateinventoryforced = Config.getboolean(
                "plugins", "inventoryforced"
            )

        if (
            len(objectxmpp.liststartpluginstartupdate) == 1
            and objectxmpp.liststartpluginstartupdate[0] == "all"
        ):
            createlistpluginupdate(objectxmpp)
        elif (
            "updatesettings" not in objectxmpp.liststartpluginstartupdate
            and os.path.isfile(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "plugin_updatesettings.py",
                )
            )
        ):
            # Run updatesettings if not explicitly defined in liststartplugin
            objectxmpp.liststartpluginstartupdate.append("updatesettings")
        # Remove excluded plugins
        if Config.has_option("plugins", "listexcludedplugins"):
            listexcludedplugins = Config.get("plugins", "listexcludedplugins")
            objectxmpp.listexcludedpluginsstartupdate = [
                x
                for x in re.split(
                    r"[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\@\$\|\s]\s*",
                    listexcludedplugins,
                )
                if x.strip() != ""
            ]
            for excludedpluginsstartupdate in objectxmpp.listexcludedpluginsstartupdate:
                objectxmpp.liststartpluginstartupdate.remove(excludedpluginsstartupdate)
    else:
        createlistpluginupdate(objectxmpp)


def createlistpluginupdate(objectxmpp):
    plugin_path = os.path.dirname(os.path.realpath(__file__))
    objectxmpp.liststartpluginstartupdate = [
        x[7:-3]
        for x in os.listdir(plugin_path)
        if x.startswith("plugin_update") and not x.endswith(".pyc")
    ]
    objectxmpp.liststartpluginstartupdate.remove("updateagent")


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    logger.debug("%s" % json.dumps(data, indent=4))
    objectxmpp.inventoryBool = False
    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        logger.debug("configure plugin %s" % action)
        read_conf_plugin_startupdate(objectxmpp)
    update = {
        "action": "",
        "sessionid": sessionid,
        "ret": 0,
        "base64": False,
        "data": {},
    }
    dataerreur = update.copy()
    msg = {
        "from": objectxmpp.boundjid.bare,
        "to": objectxmpp.boundjid.bare,
        "type": "chat",
    }
    for nameplugin in objectxmpp.liststartpluginstartupdate:
        logger.debug("from plugin %s call plugin %s" % (plugin["NAME"], nameplugin))
        update["action"] = nameplugin
        dataerreur["action"] = "result" + update["action"]
        dataerreur["data"] = {"msg": "error plugin: " + update["action"]}
        utils.call_plugin(
            update["action"],
            objectxmpp,
            update["action"],
            update["sessionid"],
            update["data"],
            msg,
            dataerreur,
        )
    # ## appelle
    if objectxmpp.startupdateinventory:
        # call inventory from machine.
        pam = {"forced": "noforced", "sessionid": sessionid}
        if objectxmpp.startupdateinventoryforced:
            pam["forced"] = "forced"
        logger.debug("call inventory %s" % pam)
        objectxmpp.handleinventory(**pam)
