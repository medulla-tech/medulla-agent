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
# file pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_master_agent.py
#
import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.manageRSAsigned import MsgsignedRSA
from slixmpp import jid
from lib.utils import getRandomName, call_plugin, call_plugin_separate

# , call_pluginseparatedthred
import re
from distutils.version import LooseVersion
import configparser
import netaddr

# this import will be used later
import types

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "master_agent", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        logger.debug("========================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            logger.debug("===================== master_agent =====================")
            logger.debug("========================================================")
            read_conf_remote_master_agent(xmppobject)
            logger.debug("========================================================")
    except Exception as e:
        logger.error(
            "The master_agent substitute failed. We encountered the error %s" % str(e)
        )
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def read_conf_remote_master_agent(xmppobject):
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    conffile_name = plugin["NAME"] + ".ini"
    xmppobject.masterfunctioncode = types.MethodType(masterfunctioncode, xmppobject)
    module = "%s/plugin_%s.py" % (xmppobject.modulepath, "__server_file")
    logger.debug("module :% s " % module)
    call_plugin(module, xmppobject, "server_file")
    try:
        conffile_path = os.path.join(xmppobject.config.pathdirconffile, conffile_name)
        if not os.path.isfile(conffile_path):
            logger.warning(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing" % (plugin["NAME"], conffile_path)
            )
    except Exception as e:
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def masterfunctioncode(self):
    # TODO: IMPLEMENT ME
    logger.debug("IMPLEMENT ME")
