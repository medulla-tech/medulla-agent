# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file pluginsmastersubstitute/plugin_greenit_mesures.py

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
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion
import configparser
import netaddr

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "greenit_mesures", "TYPE": "submaster"}



def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            read_conf_greenit_mesures(xmppobject)
        main_plugin(xmppobject, action, sessionid, data, msg, ret, dataobj)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))

def main_plugin(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("====================data=========================")
    logger.debug(json.dumps(data, indent=4))
    logger.debug("====================data=========================")

def read_conf_greenit_mesures(xmppobject):
    """
    Read plugin configuration
    The folder holding the config file is in the variable xmppobject.config.pathdirconffile
    """
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(xmppobject.config.pathdirconffile, nameconffile)
    if not os.path.isfile(pathconffile):
        logger.error(
            "plugin %s\nConfiguration file missing\n  %s"
            % (
                plugin["NAME"],
                pathconffile,
            )
        )
        create_default_config(xmppobject)
    else:
        # on charge ici les parametre
        #Config = configparser.ConfigParser()
        #Config.read(pathconffile)
        #if os.path.exists(pathconffile + ".local"):
            #Config.read(pathconffile + ".local")
       pass


# creation fichier de configuration par default
def create_default_config(objectxmpp):
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    if not os.path.isfile(pathconffile):
        logger.warning("Creation default config file %s" % pathconffile)
        #Config = configparser.ConfigParser()
        ## Ajouter des commentaires dans la configuration
        #Config.add_section("# plugin %s"%plugin['NAME'])
        #Config.set("# plugin %s"%plugin['NAME'], "# key = value ", "ajouter de parametre de cette facon")
        strcomment="""
# exemple de parametre
# [SectionName]
#key1 = value1
#key2 = value2
#key3 = value3"""
        with open(pathconffile, "w") as configfile:
            configfile.write(strcomment)
    else:
        logger.debug("file config plugin %s" % pathconffile)

