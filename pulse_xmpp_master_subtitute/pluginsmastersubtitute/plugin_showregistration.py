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
# file pluginsmastersubtitute/plugin_showregistration.py

import base64
import json
import sys, os
import logging
import platform
from lib.utils import file_get_contents, getRandomName, data_struct_message
import traceback
from sleekxmpp import jid
import types
import ConfigParser
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION" : "1.0", "NAME" : "showregistration", "TYPE" : "subtitute"}



def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")
    if logger.level == logging.DEBUG:
        try:
            compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

            if compteurcallplugin == 0:
                read_conf_showregistration(objectxmpp)
        except:
            logger.error("plugin %s\n%s"%(plugin['NAME'], traceback.format_exc()))
    else:
        logger.warning("debug level only for plugin %s"%(plugin['NAME']))

def read_conf_showregistration(objectxmpp):
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        logger.error("plugin %s\nConfiguration file :\n" \
                     "\t%s missing\n" \
                     "eg conf:\n[global]\n" \
                     "showinfo = False\n" \
                     "showplugins = False\n" \
                     "showinventoryxmpp = False\n"%(plugin['NAME'],
                                                    pathfileconf))
        logger.warning("\ndefault value for showinfo is False\n"\
                       "default value for showplugins is False\n"\
                       "default value for showinventoryxmpp is False")
        objectxmpp.showinfo = True
        objectxmpp.showplugins = True
        objectxmpp.showinventoryxmpp = True
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
        if Config.has_option("global", "showinfo"):
            objectxmpp.showinfo = Config.getboolean('global', 'showinfo')
        else:
            objectxmpp.showinfo = False

        if Config.has_option("global", "showplugins"):
            objectxmpp.showplugins = Config.getboolean('global', 'showplugins')
        else:
            objectxmpp.showplugins = False

        if Config.has_option("global", "showinventoryxmpp"):
            objectxmpp.showinventoryxmpp = Config.getboolean('global', 'showinventoryxmpp')
        else:
            objectxmpp.showinventoryxmpp = False

    objectxmpp.plugin_showregistration = types.MethodType(plugin_showregistration, objectxmpp)

def plugin_showregistration(self, msg, data):
    if logger.level == logging.DEBUG:
        

        if self.showinfo:
            self.presencedeployment = {}
            listrs = XmppMasterDatabase().listjidRSdeploy()
            if len(listrs) != 0:
                strchaine = ""
                for i in listrs:
                    li = XmppMasterDatabase().listmachinesfromdeploy(i[0])
                    strchaine += "\nRS [%s] for deploy on %s Machine\n" % (i[0], len(li)-1)
                    strchaine +='|{0:5}|{1:7}|{2:20}|{3:35}|{4:55}|\n'.format("type",
                                                                            "uuid",
                                                                            "Machine",
                                                                            "jid",
                                                                            "platform")
                    for j in li:
                        if j[9] == 'relayserver':
                            TY = 'RSer'
                        else:
                            TY = "Mach"
                        strchaine +='|{0:5}|{1:7}|{2:20}|{3:35}|{4:55}|\n'.format(TY,
                                                                                j[5],
                                                                                j[4],
                                                                                j[1],
                                                                                j[2])
                logger.debug(strchaine)
            else:
                logger.debug("No Machine Listed")
        if self.showplugins:
            strlistplugin = ""
            #logger.debug("Machine %s"%msg['from'])
            if 'plugin' in data:
                strlistplugin += "\nlist plugins on machine %s\n"%msg['from']
                strlistplugin += "|{0:35}|{1:10}|\n".format("Plugin Name", "Version")
                for key, value in data['plugin'].iteritems():
                    strlistplugin += "|{0:35}|{1:10}|\n".format(key, value)

            if 'pluginscheduled' in data:
                strlistplugin += "\nlist scheduled plugins on machine %s\n"%msg['from']
                strlistplugin += "|{0:35}|{1:10}|\n".format("scheduled Plugin Name", "Version")
                for key, value in data['pluginscheduled'].iteritems():
                    strlistplugin += "|{0:35}|{1:10}|\n".format(key, value)
            if strlistplugin != "":
                logger.debug(strlistplugin)
            if self.showinventoryxmpp:
                del data['completedatamachine']
                del data['plugin']
                del data['pluginscheduled']
                logger.debug(json.dumps(data, indent = 4))
