# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import logging
import traceback
import types
import configparser

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "loadpluginschedulerlistversion", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        read_conf_load_plugin_scheduler_list_version(objectxmpp)
        objectxmpp.schedule(
            "updatelistpluginscheduler",
            objectxmpp.reload_schedulerplugins_interval,
            objectxmpp.loadPluginschedulerList,
            repeat=True,
        )
        logger.debug("%s" % hasattr(objectxmpp, "loadPluginschedulerList"))
        objectxmpp.loadPluginschedulerList()


def read_conf_load_plugin_scheduler_list_version(objectxmpp):
    """
    lit la configuration du plugin
    le repertoire ou doit se trouver le fichier de configuration est dans la variable objectxmpp.config.pathdirconffile
    """
    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)
    if not os.path.isfile(pathfileconf):
        logger.error(
            "plugin %s\nConfiguration file missing\n  %s\neg conf:"
            "\n[parameters]\ndirschedulerplugins = /var/lib/pulse2/xmpp_basepluginscheduler/"
            % (plugin["NAME"], pathfileconf)
        )
        logger.warning(
            "default value for dirplugins is /var/lib/pulse2/xmpp_basepluginscheduler"
        )
        objectxmpp.dirschedulerplugins = "/var/lib/pulse2/xmpp_basepluginscheduler"
        objectxmpp.reload_schedulerplugins_interval = 2000
    else:
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
        objectxmpp.dirschedulerplugins = "/var/lib/pulse2/xmpp_basepluginscheduler"
        if Config.has_option("parameters", "dirschedulerplugins"):
            objectxmpp.dirschedulerplugins = Config.get(
                "parameters", "dirschedulerplugins"
            )
        if Config.has_option("parameters", "reload_schedulerplugins_interval"):
            objectxmpp.reload_schedulerplugins_interval = Config.getint(
                "parameters", "reload_schedulerplugins_interval"
            )
        else:
            objectxmpp.reload_schedulerplugins_interval = 2000
    logger.debug(
        "directory base scheduler plugins is %s" % objectxmpp.dirschedulerplugins
    )
    logger.debug(
        "reload scheduler plugins interval%s"
        % objectxmpp.reload_schedulerplugins_interval
    )
    # function definie dynamiquement
    objectxmpp.plugin_loadpluginschedulerlistversion = types.MethodType(
        plugin_loadpluginschedulerlistversion, objectxmpp
    )
    objectxmpp.deployPluginscheduled = types.MethodType(
        deployPluginscheduled, objectxmpp
    )
    objectxmpp.loadPluginschedulerList = types.MethodType(
        loadPluginschedulerList, objectxmpp
    )


def plugin_loadpluginschedulerlistversion(self, msg, data):
    if "pluginscheduled" in data:
        for k, v in self.plugindatascheduler.items():
            if k in data["pluginscheduled"]:
                if v != data["pluginscheduled"][k]:
                    # deploy on version changes
                    logger.debug("update plugin %s on agent %s" % (k, msg["from"]))
                    self.deployPluginscheduled(msg, k)
                    self.restartmachineasynchrone(msg["from"])
                    break
                else:
                    logger.debug(
                        "No version change for %s on agent %s" % (k, msg["from"])
                    )
                    pass
            else:
                # The k plugin is not in the agent plugins list
                if k in self.plugintypescheduler:
                    if self.plugintypescheduler[k] == "all":
                        self.deployPluginscheduled(msg, k)
                        self.restartmachineasynchrone(msg["from"])
                        break
                    if (
                        self.plugintypescheduler[k] == "relayserver"
                        and data["agenttype"] == "relayserver"
                    ):
                        self.deployPluginscheduled(msg, k)
                        self.restartmachineasynchrone(msg["from"])
                        break
                    if (
                        self.plugintypescheduler[k] == "machine"
                        and data["agenttype"] == "machine"
                    ):
                        self.deployPluginscheduled(msg, k)
                        self.restartmachineasynchrone(msg["from"])
                        break


def deployPluginscheduled(self, msg, plugin):
    data = ""
    DataFile = {}
    namefile = os.path.join(self.dirschedulerplugins, "%s.py" % plugin)
    if os.path.isfile(namefile):
        logger.debug("File plugin scheduled found %s" % namefile)
    else:
        logger.error("File plugin scheduled not found %s" % namefile)
        return
    try:
        fileplugin = open(namefile, "rb")
        data = fileplugin.read().decode("utf8")
        fileplugin.close()
    except Exception:
        logger.error("An error occurend while trying to read the file %s" % namefile)
        logger.error("We hit the backtrace \n%s" % traceback.format_exc())
        return

    DataFile["action"] = "installpluginscheduled"
    DataFile["data"] = {}

    JsonData = {}
    JsonData["datafile"] = data
    JsonData["pluginname"] = "%s.py" % plugin
    DataFile["data"] = base64.b64encode(json.dumps(JsonData).encode("utf-8")).decode(
        "utf-8"
    )
    DataFile["sessionid"] = "sans"
    DataFile["base64"] = True

    try:
        self.send_message(mto=msg["from"], mbody=json.dumps(DataFile), mtype="chat")
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def loadPluginschedulerList(self):
    logger.debug("Verify base plugin scheduler")
    self.plugindatascheduler = {}
    self.plugintypescheduler = {}
    for element in os.listdir(self.dirschedulerplugins):
        if element.endswith(".py") and element.startswith("scheduling_"):
            f = open(os.path.join(self.dirschedulerplugins, element), "r")
            lignes = f.readlines()
            f.close()
            for ligne in lignes:
                if "VERSION" in ligne and "NAME" in ligne:
                    line = ligne.split("=")
                    plugin = eval(line[1])
                    self.plugindatascheduler[plugin["NAME"]] = plugin["VERSION"]
                    try:
                        self.plugintypescheduler[plugin["NAME"]] = plugin["TYPE"]
                    except Exception:
                        self.plugintypescheduler[plugin["NAME"]] = "machine"
                    break
