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
# file pulse_xmpp_agent/pluginsmachine/plugin_startupdate.py

from lib import utils
import json
import traceback
import sys
import logging
import os
import time

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "1.0", "NAME": "startupdate", "TYPE": "machine"}

def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    logger.debug("%s" % json.dumps(data, indent=4))
    objectxmpp.inventoryBool = False
    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        logger.error("configuration")

    plugin_path = os.path.dirname(os.path.realpath(__file__))
    plugintocalling = [x[7:-3] for x in os.listdir(plugin_path)
                       if x.startswith("plugin_update") and
                       not x.endswith(".pyc")]
    plugintocalling.remove("updateagent")

    update = {"action": "",
              "sessionid": sessionid,
              "ret": 0,
              "base64": False,
              "data": {}}

    dataerreur = {"action": "result" + update["action"],
                  "data": {"msg": "error plugin : " + update["action"]},
                  'sessionid': sessionid,
                  'ret': 255,
                  'base64': False}

    msg = {'from': objectxmpp.boundjid.bare,
           "to": objectxmpp.boundjid.bare,
           'type': 'chat'}

    if 'data' not in update:
        update['data'] = {}

    for nameplugin in plugintocalling:
        logger.debug("from plugin %s call plugin %s" % (plugin['NAME'],
                                                        nameplugin))
        update["action"] = nameplugin
        utils.call_plugin(update["action"],
                          objectxmpp,
                          update["action"],
                          update['sessionid'],
                          update['data'],
                          msg,
                          dataerreur)
    time.sleep(5)

    # ## appelle
    if objectxmpp.inventoryBool:
        # call inventory from machine.
        pass
