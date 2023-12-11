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

# this plugin start all plugin list in init file startupdate.ini
# this plugin launch inventory is asked


from lib import utils
import json
import traceback
import sys
import logging
import os
import time
from lib.agentconffile import directoryconffile
import ConfigParser
import re

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "1.3", "NAME": "startupdate", "TYPE": "machine"}

def read_conf_plugin_startupdate(objectxmpp):
    objectxmpp.liststartpluginstartupdate = []
    objectxmpp.startupdateinventory = False
    objectxmpp.startupdateinventoryforced = False
    configfilename = os.path.join(directoryconffile(),"startupdate.ini")
    if os.path.isfile(configfilename):
        # lit la configuration
        Config = ConfigParser.ConfigParser()
        Config.read(configfilename)
        if Config.has_option('plugins', 'liststartplugin'):
            liststartplugin = Config.get('plugins', 'liststartplugin')
            objectxmpp.liststartpluginstartupdate = [x for x in
                                            re.split(r'[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\@\$\|\s]\s*',
                                                     liststartplugin)
                                            if x.strip()!=""]
        if Config.has_option('plugins', 'inventory'):
            objectxmpp.startupdateinventory = Config.getboolean('plugins', 'inventory')
        if Config.has_option('plugins', 'inventoryforced'):
            objectxmpp.startupdateinventoryforced = Config.getboolean('plugins', 'inventoryforced')

        if len(objectxmpp.liststartpluginstartupdate) == 1 and \
            objectxmpp.liststartpluginstartupdate[0] == "all":
            createlistpluginupdate(objectxmpp)
        elif 'updatesettings' not in objectxmpp.liststartpluginstartupdate and \
            os.path.isfile(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'plugin_updatesettings.py')):
            # Run updatesettings if not explicitly defined in liststartplugin
            objectxmpp.liststartpluginstartupdate.append("updatesettings")
    else:
        createlistpluginupdate(objectxmpp)

def createlistpluginupdate(objectxmpp):
    plugin_path = os.path.dirname(os.path.realpath(__file__))
    objectxmpp.liststartpluginstartupdate = [x[7:-3] for x in os.listdir(plugin_path)
                                            if x.startswith("plugin_update") and
                                             x.endswith(".py")]
    objectxmpp.liststartpluginstartupdate.remove("updateagent")

def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    logger.debug("%s" % json.dumps(data, indent=4))
    objectxmpp.inventoryBool = False
    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        logger.debug("configure plugin %s" % action)
        read_conf_plugin_startupdate(objectxmpp)
    update = {"action": "",
              "sessionid": sessionid,
              "ret": 0,
              "base64": False,
              "data": {}}
    dataerreur =  update.copy()
    msg = {'from': objectxmpp.boundjid.bare,
           "to": objectxmpp.boundjid.bare,
           'type': 'chat'}
    for nameplugin in objectxmpp.liststartpluginstartupdate:
        logger.debug("from plugin %s call plugin %s" % (plugin['NAME'],
                                                        nameplugin))
        update["action"] = nameplugin
        dataerreur["action"] = "result" + update["action"]
        dataerreur["data"] = {"msg": "error plugin: " + update["action"]}
        utils.call_plugin(update["action"],
                          objectxmpp,
                          update["action"],
                          update['sessionid'],
                          update['data'],
                          msg,
                          dataerreur)
    # ## appelle
    if objectxmpp.startupdateinventory:
        # call inventory from machine.
        pam={"forced": "noforced", "sessionid": sessionid}
        if objectxmpp.startupdateinventoryforced:
            pam['forced'] = "forced"
        logger.debug("call inventory %s" % pam)
        objectxmpp.handleinventory(**pam)
