# -*- coding: utf-8 -*-
#
# (c) 2019 siveo, http://www.siveo.net
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
# file pluginsmastersubstitute/plugin_loadactionupdate.py

# ce plugin install 1 fonction appeler cycliquement
# cette fonction a pour charge d'executer les actions creation des packages d'update, de deplacer les packages d'update du flip flop


import os
import logging
import ConfigParser
import shutil
import types
from lib.configuration import confParameter
from datetime import datetime, timedelta
from lib.plugins.xmpp import XmppMasterDatabase
import traceback

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION" : "1.0", "NAME" : "loadactionupdate", "TYPE" : "substitute", "LOAD" : "START" }

GLOBALPARAM={"duration" : 30 , "debuglocal" : False}

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)
    if compteurcallplugin == 0:
        read_conf_loadactionupdate(objectxmpp)
        # install code dynamique : fonction Action_update ci dessous
        objectxmpp.Action_update = types.MethodType(Action_update, objectxmpp)
        # schedule appel de cette fonction cette fonctions
        objectxmpp.schedule('Action_update', objectxmpp.time_scrutation, objectxmpp.Action_update, repeat=True)
        objectxmpp.Action_update()
    else:
        read_debub_conf(objectxmpp)


def read_conf_loadactionupdate(objectxmpp):
    """
        Read plugin configuration
        The folder holding the config file is in the variable objectxmpp.config.pathdirconffile
    """
    nameconffile = plugin['NAME'] + ".ini"
    pathconffile = os.path.join( objectxmpp.config.pathdirconffile, nameconffile )
    objectxmpp.time_scrutation = GLOBALPARAM["duration"]
    objectxmpp.debuglocal = GLOBALPARAM["debuglocal"]
    if not os.path.isfile(pathconffile):
        logger.error("plugin %s\nConfiguration file missing\n  %s" \
            "\neg conf:\n[global]\ntime_scrutation = %s\n" \
                "\ndebuglocal=%s" %(plugin['NAME'], pathconffile, GLOBALPARAM["duration"], GLOBALPARAM["debuglocal"]))

        logger.warning("default value for time_scrutation is %s secondes" % objectxmpp.time_scrutation)

    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("global", "time_scrutation"):
            objectxmpp.time_scrutation = Config.getint('parameters', 'time_scrutation')




def read_debub_conf(objectxmpp):
    """
        Read plugin configuration
        et interprete informatin de debug local
        parametre debuglocal=True
    """
    nameconffile = plugin['NAME'] + ".ini"
    pathconffile = os.path.join( objectxmpp.config.pathdirconffile, nameconffile )
    if os.path.isfile(pathconffile):
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("global", "debuglocal"):
            objectxmpp.debuglocal = Config.getboolean('parameters', 'debuglocal')

def Action_update(self):
    """
        Runs the log rotation
    """
    try:
        if self.debuglocal:
            logger.info("===================Action_update=====================")
        XmppMasterDatabase().get_all_Up_action_update_packages()
        if self.debuglocal:
            logger.info("===================Action_update=====================")
    except Exception as e:
        logger.error("Plugin %s, we encountered the error %s" % ( plugin['NAME'], str(e)))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())
