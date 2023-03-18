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

# file  /pluginsmastersubstitute/plugin_updatemachinesystem.py

import base64
import json
import os
import logging
from lib.utils import ipfromdns, AESCipher, subnetnetwork
try:
    from lib.localisation import Point
    errorlocalisation = False
except ModuleNotFoundError:
    errorlocalisation = True
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.admin import AdminMasterDatabase
from random import randint
import operator
import traceback
import configparser
import netaddr

try:
    from lib.stat import statcallplugin
    statfuncton = True
except BaseException:
    statfuncton = False

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to update system agent (application, security)
# kb for window
# connectionconf et le nom du plugin appeler.

plugin = {"VERSION": "1.0","NAME": "updatemachinesystem","TYPE": "substitute","FEATURE":"update_remote_machine",}# fmt: skip


def action(objectxmpp, action, sessionid, data, msg, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    try:
        compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
        if compteurcallplugin == 0:
            if statfuncton:
                objectxmpp.stat_updatemachinesystem = statcallplugin(
                    objectxmpp, plugin["NAME"]
                )
            read_conf_updatemachinesystem(objectxmpp)
        else:
            if statfuncton:
                objectxmpp.stat_updatemachinesystem.statutility()

    except Exception as e:
        logger.error("\n%s" % (traceback.format_exc()))



def msg_log(msg_header, hostname, user, result, objectxmpp, data):
    if data["machine"].split(".")[0] in objectxmpp.updatemachinesystem_agent_showinfomachine:
        logger.info(
            "%s Rule selects "
            "the relay server for machine "
            "%s user %s \n %s" % (msg_header, hostname, user, result)
        )
        pass


def read_conf_updatemachinesystem(objectxmpp):
    """
    lit la configuration du plugin
    le repertoire ou doit se trouver le fichier de configuration est dans la variable objectxmpp.config.pathdirconffile
    """
    namefichierconf = plugin["NAME"] + ".ini"
    objectxmpp.pathfileconf = os.path.join(
        objectxmpp.config.pathdirconffile, namefichierconf
    )
    if not os.path.isfile(objectxmpp.pathfileconf):
        logger.error(
            "plugin %s\nConfiguration file  missing\n  %s"
            % (plugin["NAME"], objectxmpp.pathfileconf)
        )
        # creation fichier de configuration empty
        open(objectxmpp.pathfileconf, 'a').close()
        message_config(plugin["NAME"], objectxmpp.pathfileconf)
        if statfuncton:
            objectxmpp.stat_updatemachinesystem.display_param_config(msg="DEFAULT")
        return False
    else:
        Config = configparser.ConfigParser()
        Config.read(objectxmpp.pathfileconf)
        if os.path.exists(objectxmpp.pathfileconf + ".local"):
            Config.read(objectxmpp.pathfileconf + ".local")
            # lecture parametre ici ne pas oublier de mettre a jour les message sur la config "message_config"

            if statfuncton:
                objectxmpp.stat_updatemachinesystem.display_param_config("DEFAULT")
    return True


def message_config(nameplugin, pathfileconf):
    msg = (
        """=========configuration updatemachinesystem plugin master==========="
        check MASTER updatemachinesystem plugin config file
        The following parameters must be defined:
       """
    )
    logger.error("%s" % msg)
