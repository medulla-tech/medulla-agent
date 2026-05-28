# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import importlib.util
import json
import os
import logging
import time
import traceback
import configparser
import types
import py_compile
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import convert

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.2", "NAME": "loadpluginlistversion", "TYPE": "substitute", "LOAD": "START"}  # fmt: skip


def _validate_plugin_candidate(pathfile):
    """Validate a plugin locally before it is considered deployable.

    This avoids sending a plugin that is already known as invalid from the
    substitute side.
    """
    # 1) Syntax check: refuse a plugin with invalid Python syntax.
    py_compile.compile(pathfile, doraise=True)

    module_name = os.path.splitext(os.path.basename(pathfile))[0]
    spec = importlib.util.spec_from_file_location(module_name, pathfile)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to build import spec for {pathfile}")

    # 2) Real import: catches missing imports or import-time side effects.
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    # 3) Metadata check: the deployment logic needs at least NAME and VERSION
    # to compare local and remote plugin states.
    metadata = getattr(module, "plugin", None)
    if not isinstance(metadata, dict):
        raise ValueError("Missing plugin metadata dictionary 'plugin'")
    if "NAME" not in metadata or "VERSION" not in metadata:
        raise ValueError("Plugin metadata must define NAME and VERSION")

    return metadata


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

    This setup now also initializes the in-memory structures used to avoid
    redeploy loops after a failed plugin installation.
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
        if Config.has_option("parameters", "install_plugin_failure_cooldown"):
            objectxmpp.install_plugin_failure_cooldown = Config.getint(
                "parameters", "install_plugin_failure_cooldown"
            )
        else:
            objectxmpp.install_plugin_failure_cooldown = 1800
    logger.debug("directory base plugins is %s" % objectxmpp.dirpluginlist)
    logger.debug("reload plugins interval%s" % objectxmpp.reload_plugins_interval)
    logger.debug(
        "install plugin failure cooldown %s",
        objectxmpp.install_plugin_failure_cooldown,
    )
    # These runtime structures are shared with resultmsginfoerror to defer the
    # restart until the agent confirms which plugin installs actually succeeded.
    objectxmpp.file_deploy_plugin = []
    objectxmpp.plugin_install_failures = {}
    objectxmpp.pending_plugin_installs = {}
    objectxmpp.pending_plugin_install_success = {}
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
        # Only plugins that pass local validation are exposed as deployable.
        # This blocks bad plugins before they enter the deployment pipeline.
        try:
            plugin_metadata = _validate_plugin_candidate(element_name)
            self.plugindata[plugin_metadata["NAME"]] = plugin_metadata["VERSION"]
            try:
                self.plugintype[plugin_metadata["NAME"]] = plugin_metadata["TYPE"]
            except Exception:
                self.plugintype[plugin_metadata["NAME"]] = "machine"
        except Exception:
            logger.error(
                "Local plugin validation failed path=%s dirpluginlist=%s reason=scan-time validation; plugin ignored.\n%s",
                os.path.join(self.dirpluginlist, element),
                self.dirpluginlist,
                traceback.format_exc(),
            )


def remoteinstallPlugin(self):
    """
    This function is used  to installed the plugins on the Machines and
    Relayservers.

    The restart is no longer triggered here. We first wait for the agent to
    validate and acknowledge the installation result.
    """
    numberToUpdate = len(self.file_deploy_plugin)
    if numberToUpdate > 0:
        for indexplugin in range(0, numberToUpdate):
            plugmachine = self.file_deploy_plugin.pop(0)
            if XmppMasterDatabase().getPresencejid(plugmachine["dest"]):
                if plugmachine["type"] == "deployPlugin":
                    logger.debug(
                        "Queue deploy plugin=%s version=%s dest=%s",
                        plugmachine["plugin"],
                        plugmachine.get("version", ""),
                        plugmachine["dest"],
                    )
                    dest = str(plugmachine["dest"])
                    version = str(plugmachine.get("version", ""))
                    # Memorise the target version so the result handler can
                    # decide whether a restart is still justified.
                    self.pending_plugin_installs.setdefault(dest, set()).add(
                        (plugmachine["plugin"], version)
                    )
                    # The actual restart is postponed. We first wait for the
                    # agent to confirm success or failure for this exact plugin
                    # version in plugin_resultmsginfoerror.
                    self.deployPlugin(plugmachine["dest"], plugmachine["plugin"], version)
                elif plugmachine["type"] == "deploySchedulingPlugin":
                    # It is the updating code for the scheduling plugins.
                    pass


def deployPlugin(self, jid, plugin, version=None):
    """Envoie le plugin et la version cible attendue à l'agent distant."""
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
        # Revalidate right before send to avoid deploying a file that became
        # invalid after the last periodic plugin scan.
        _validate_plugin_candidate(FileName)
        PluginFile = open(FileName, "rb")
        content = PluginFile.read()
        PluginFile.close()
    except Exception:
        logger.error(
            "Pre-deploy validation failed plugin=%s version=%s dest=%s path=%s; plugin not sent.\n%s",
            plugin,
            version if version is not None else self.plugindata.get(plugin),
            jid,
            FileName,
            traceback.format_exc(),
        )
        return
    DataFile["action"] = "installplugin"
    DataFile["data"] = {}
    dd = {}
    dd["datafile"] = content
    dd["pluginname"] = "plugin_%s.py" % plugin
    dd["version"] = version if version is not None else self.plugindata.get(plugin)

    DataFile["data"] = convert.encode_to_string_base64(convert.convert_dict_to_json(dd))
    DataFile["sessionid"] = "sans"
    DataFile["base64"] = True
    try:
        self.send_message(mto=jid, mbody=json.dumps(DataFile), mtype="chat")
    except Exception:
        logger.error(
            "Failed to send plugin to agent plugin=%s version=%s dest=%s path=%s\n%s",
            plugin,
            version if version is not None else self.plugindata.get(plugin),
            jid,
            FileName,
            traceback.format_exc(),
        )


def plugin_loadpluginlistversion(self, msg, data):
    """Compare les versions plugin agent/master et prépare les déploiements.

    Cette fonction ajoute maintenant un garde-fou anti-boucle:
    si un couple agent + plugin + version a échoué récemment, le redéploiement
    est temporairement ignoré pendant le cooldown.
    """
    # function de rappel dans boucle de message.
    # cette function est definie dans l'instance mucbot, si on veut quel soit utiliser dans un autre plugin.
    # Show plugins information logs
    if "updatingplugin" in data and data["updatingplugin"] == False:
        logger.warning(
            'config remote agent [%s] is "not updating plugin"' % (msg["from"])
        )
        return
    # The cooldown blocks immediate redeploy of the same plugin version after a
    # failed install acknowledgement from the agent.
    now = time.time()
    jid_from = str(msg["from"])
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
            failure_key = (jid_from, k, str(v))
            cooldown_until = self.plugin_install_failures.get(failure_key, 0)
            if cooldown_until > now:
                # The same plugin version already failed recently on this agent.
                # Skipping here prevents install -> restart -> reinstall loops.
                logger.warning(
                    "Skip redeploy agent=%s plugin=%s version=%s cooldown_remaining=%.0fs known_remote_version=%s",
                    jid_from,
                    k,
                    v,
                    cooldown_until - now,
                    data.get("plugin", {}).get(k),
                )
                continue
            if cooldown_until:
                # Cooldown expired: allow a fresh deployment attempt.
                del self.plugin_install_failures[failure_key]
            try:
                logger.info(
                    "update plugin=%s agent=%s from_version=%s to_version=%s",
                    k,
                    jid_from,
                    data["plugin"][k],
                    v,
                )
            except KeyError:
                logger.info(
                    "install missing plugin=%s agent=%s target_version=%s",
                    k,
                    jid_from,
                    v,
                )
            # Queue the deployment instead of restarting immediately. The final
            # decision is taken after the agent validates the received plugin.
            self.file_deploy_plugin.append(
                {
                    "dest": msg["from"],
                    "plugin": k,
                    "version": str(v),
                    "type": "deployPlugin",
                }
            )
            # return True
    self.remoteinstallPlugin()
