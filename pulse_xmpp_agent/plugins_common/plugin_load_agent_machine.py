# -*- coding: utf-8 -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
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
#
# plugin register machine dans presence table xmpp.
#
# file pluginsmachine/plugin_load_agent_machine.py
#
"""
    Ce plugin install les plugins de codes necessaire au fonctionnement de l'agent machine dans des boucles événement différente. (Ce plugin doit etre appeler par le plugin start.
    (voir parametre pluginlist section [plugin] configuration agent)
    1) install serveur tcp/ip dans boucle événement asynio
           pugin TCP_IP command in/out
"""
import base64
import traceback
import os
import json
import logging
from slixmpp import jid
from lib import utils

# from lib.utils import getRandomName, call_plugin, call_plugin_separate
# , call_pluginseparatedthred
import re
from distutils.version import LooseVersion
import configparser

# this import will be used later
import types

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "load_agent_machine", "VERSIONAGENT": "2.0.0", "TYPE": "all"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        for _ in range(10):
            logger.error("JFKJFK load_agent_machine")

        logger.debug("###################################################")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("###################################################")
        strjidagent = str(xmppobject.boundjid.bare)

        logger.debug("========================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            logger.debug("===================== master_agent =====================")
            logger.debug("========================================================")
            read_conf_load_agent_machine(xmppobject)
            logger.debug("========================================================")
    except Exception as e:
        logger.error("Plugin load_TCIIP, we encountered the error %s" % str(e))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def read_conf_load_agent_machine(xmppobject):
    for _ in range(10):
        logger.debug("JFKJFK load_agent_machine")
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    namefichierconf = plugin["NAME"] + ".ini"

    ########## INSTALL ICI FUNCTION SPECIALISER ##########
    logger.debug("Install fonction code specialiser agent machine")
    xmppobject.list_function_agent_name = []
    # ---------- install "get_list_function_dyn_agent_machine" --------
    xmppobject.list_function_agent_name.append("get_list_function_dyn_agent_machine")
    xmppobject.get_list_function_dyn_agent_machine = types.MethodType(
        get_list_function_dyn_agent_machine, xmppobject
    )
    ########## END INSTALL ICI FUNCTION SPECIALISER ##########

    ### CREATE SERVER TCP/IP
    module = "%s/plugin_%s.py" % (xmppobject.modulepath, "__server_tcpip")
    logger.debug("===== INSTALL pluginsmachine/plugin___server_tcpip.py =====")

    logger.debug("module :% s " % module)
    try:
        utils.call_plugin(module, xmppobject, "__server_tcpip")

        for _ in range(10):
            logger.debug("JFKJFK END load_agent_machine")

    except:
        logger.error("install plufin__server_tcpip \n: %s" % (traceback.format_exc()))

    logger.debug("===== END pluginsmachine/plugin___server_tcpip.py =====")
    try:
        pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)
        if not os.path.isfile(pathfileconf):
            logger.warning(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing" % (plugin["NAME"], pathfileconf)
            )
    except Exception as e:
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def get_list_function_dyn_agent_machine(self):
    logger.debug(
        "return list function install from this plugin : %s"
        % xmppobject.list_function_agent_name
    )
    return xmppobject.list_function_agent_name
