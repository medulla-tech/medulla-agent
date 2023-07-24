# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import logging
import traceback
import configparser
import types
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = { "VERSION": "1.1", "NAME": "loadpluginlistversion", "TYPE": "substitute", "LOAD": "START", }  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    # lit fichiers de configuration pour le plugin si pas charge.

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

    if compteurcallplugin == 0:
        read_conf_load_plugin_list_version(objectxmpp)
        objectxmpp.schedule(
            "updatelistplugin",
            objectxmpp.reload_plugins_interval,
            objectxmpp.loadPluginList,
            repeat=True,
        )
        logger.debug("status plugin : %s" % hasattr(objectxmpp, "loadPluginList"))
        objectxmpp.loadPluginList()


def read_conf_load_plugin_list_version(objectxmpp):
    """
    Read the plugin configuration

    The `objectxmpp.config.pathdirconffile` variable contains the path of the directory where
    the configuration file is stored
    """
    objectxmpp.config_loadpluginlistversion = True

    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)
    if not os.path.isfile(pathfileconf):
        logger.error(
            "The configuration file for the plugin %s is missing in %s \n"
            "it may contains [parameters]\ndirpluginlist = /var/lib/pulse2/xmpp_baseplugin/"
            % (plugin["NAME"], pathfileconf)
        )

        objectxmpp.dirpluginlist = "/var/lib/pulse2/xmpp_baseplugin/"
        objectxmpp.reload_plugins_interval = 1000
    else:
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
        objectxmpp.dirpluginlist = "/var/lib/pulse2/xmpp_baseplugin/"
        if Config.has_option("parameters", "dirpluginlist"):
            objectxmpp.dirpluginlist = Config.get("parameters", "dirpluginlist")

        if Config.has_option("parameters", "reload_plugins_interval"):
            objectxmpp.reload_plugins_interval = Config.getint(
                "parameters", "reload_plugins_interval"
            )
        else:
            objectxmpp.reload_plugins_interval = 1000
    logger.debug("directory base plugins is %s" % objectxmpp.dirpluginlist)
    logger.debug("reload plugins interval%s" % objectxmpp.reload_plugins_interval)
    # The loadPluginList function is dynamically defined.
    objectxmpp.file_deploy_plugin = []
    objectxmpp.loadPluginList = types.MethodType(loadPluginList, objectxmpp)
    objectxmpp.remoteinstallPlugin = types.MethodType(remoteinstallPlugin, objectxmpp)
    objectxmpp.deployPlugin = types.MethodType(deployPlugin, objectxmpp)
    objectxmpp.plugin_loadpluginlistversion = types.MethodType(
        plugin_loadpluginlistversion, objectxmpp
    )


def loadPluginList(self):
    """
    It searches the `name` and `version` informations of the plugins.
    It is used to compare it with the plugins installed on the machines.
    """
    logger.debug(
        "We search the plugin informations, to compare it with the one installed on the machines"
    )
    self.plugindata = {}
    self.plugintype = {}
    for element in [
        x
        for x in os.listdir(self.dirpluginlist)
        if x[-3:] == ".py" and x[:7] == "plugin_"
    ]:
        element_name = os.path.join(self.dirpluginlist, element)
        # Used to verify the syntax of the plugin
        # This way we do not deploy plugins with wrong syntax
        if os.system('python3 -m py_compile "%s"' % element_name) == 0:
            f = open(element_name, "r")
            lignes = f.readlines()
            f.close()
            for ligne in lignes:
                if "VERSION" in ligne and "NAME" in ligne:
                    l = ligne.split("=")
                    plugin = eval(l[1])
                    self.plugindata[plugin["NAME"]] = plugin["VERSION"]
                    try:
                        self.plugintype[plugin["NAME"]] = plugin["TYPE"]
                    except Exception:
                        self.plugintype[plugin["NAME"]] = "machine"
                    break
        else:
            logger.error(
                "As long as the ERROR SYNTAX is not fixed, the plugin [%s] is ignored."
                % os.path.join(self.dirpluginlist, element)
            )


def remoteinstallPlugin(self):
    """
    This function is used  to installed the plugins on the Machines and
    Relayservers.
    """
    restart_machine = set()
    for indexplugin in range(0, len(self.file_deploy_plugin)):
        plugmachine = self.file_deploy_plugin.pop(0)
        if XmppMasterDatabase().getPresencejid(plugmachine["dest"]):
            if plugmachine["type"] == "deployPlugin":
                logger.debug(
                    "install plugin normal %s to %s"
                    % (plugmachine["plugin"], plugmachine["dest"])
                )
                self.deployPlugin(plugmachine["dest"], plugmachine["plugin"])
                restart_machine.add(plugmachine["dest"])
            elif plugmachine["type"] == "deploySchedulingPlugin":
                # It is the updating code for the scheduling plugins.
                pass
    for jidmachine in restart_machine:  # Itération pour chaque élément
        # call one function by message to processing asynchronous tasks and can
        # add a tempo on restart action.
        self.event("restartmachineasynchrone", jidmachine)


def deployPlugin(self, jid, plugin):
    content = ""
    DataFile = {}
    FileName = os.path.join(self.dirpluginlist, "plugin_%s" % plugin)
    if not FileName.endswith(".py"):
        FileName += ".py"
    if os.path.isfile(FileName):
        logger.debug("File plugin found %s" % FileName)
    else:
        logger.error("The plugin file %s does not exists" % FileName)
        return
    try:
        PluginFile = open(FileName, "rb")
        content = PluginFile.read()
        PluginFile.close()
    except Exception:
        logger.error("File read error\n%s" % (traceback.format_exc()))
        return
    DataFile["action"] = "installplugin"
    DataFile["data"] = {}
    dd = {}
    dd["datafile"] = content
    dd["pluginname"] = "plugin_%s.py" % plugin
    DataFile["data"] = base64.b64encode(json.dumps(dd))
    DataFile["sessionid"] = "sans"
    DataFile["base64"] = True
    try:
        self.send_message(mto=jid, mbody=json.dumps(DataFile), mtype="chat")
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def plugin_loadpluginlistversion(self, msg, data):
    # function de rappel dans boucle de message.
    # cette function est definie dans l'instance mucbot, si on veut quel soit utiliser dans un autre plugin.
    # Show plugins information logs
    if "updatingplugin" in data and data["updatingplugin"] == False:
        logger.warning(
            'config remote agent [%s] is "not updating plugin"' % (msg["from"])
        )
        return
    restartAgent = False
    for k, v in self.plugindata.items():
        deploy = False
        try:
            # Check version
            if data["plugin"][k] != v:
                deploy = True
        except Exception:
            deploy = True
        if data["agenttype"] != "all":
            if data["agenttype"] == "relayserver" and self.plugintype[k] == "machine":
                deploy = False
            if data["agenttype"] == "machine" and self.plugintype[k] == "relayserver":
                deploy = False
        if deploy:
            try:
                logger.info(
                    "update %s version %s to version %s on Agent "
                    % (k, data["plugin"][k], v)
                )
            except KeyError:
                logger.info("install %s version %s to version on Agent " % (k, v))
            self.file_deploy_plugin.append(
                {"dest": msg["from"], "plugin": k, "type": "deployPlugin"}
            )
            # return True
    self.remoteinstallPlugin()
