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

import sys, os
import logging
from lib import utils
from lib.agentconffile import directoryconffile
import ConfigParser
import re

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = {"VERSION" : "2.0", "NAME" : "start", "TYPE" : "all"}

def read_conf_plugin_start(objectxmpp):
    objectxmpp.liststartplugin = []
    configfilename = os.path.join(directoryconffile(), "start.ini")
    if os.path.isfile(configfilename):
        # lit la configuration
        Config = ConfigParser.ConfigParser()
        Config.read(configfilename)
        if Config.has_option('plugins', 'liststartplugin'):
            liststartplugin = Config.get('plugins', 'liststartplugin')
            objectxmpp.liststartplugin = [x for x in  
                                            re.split(r'[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\@\$\|\s]\s*',
                                                     liststartplugin)
                                            if x.strip()!=""]

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")

    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)
    if compteurcallplugin == 0:
        logger.debug("configure plugin %s" % action)
        read_conf_plugin_start(objectxmpp)

    startupdate={"action": "",
                 "sessionid": utils.getRandomName(6, "startplugin"),
                 "ret": 0,
                 "base64": False,
                 "data": {}}
    msg = {'from': objectxmpp.boundjid.bare,
        "to" : objectxmpp.boundjid.bare,
        'type': 'chat' }
    dataerreur =  startupdate.copy()
    for pluginstart in objectxmpp.liststartplugin:
        startupdate["action"] = pluginstart
        dataerreur["action"] = "result" + startupdate["action"]
        dataerreur["action"] = {"msg": "error plugin: "+ startupdate["action"]}

        utils.call_plugin(startupdate["action"],
                            objectxmpp,
                            startupdate["action"],
                            startupdate['sessionid'],
                            startupdate['data'],
                            msg,
                            dataerreur)
