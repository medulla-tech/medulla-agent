# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : plugin_load_mach_mps.py
import base64
import traceback
import os
import json
import sys
import logging
from lib import utils
from lib.networkinfo import organizationbymachine, organizationbyuser
from slixmpp import jid
import subprocess
import threading
import psutil
import zlib
import configparser
import re
import time
import sqlite3
from collections import defaultdict


from sqlite3 import Error
# this import will be used later
import types
if sys.platform.startswith("win"):
    import wmi
    import pythoncom

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "load_mach_mps", "VERSIONAGENT": "2.0.0", "TYPE": "machine"}  # fmt: skip


"""
    Ce plugin analyse les informations d'energie recuperer dans la base de l'agent mps
"""

@utils.set_logging_level
def action(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        logger.debug("###################################################")
        logger.debug(f'call {plugin} from {msg["from"]}')
        logger.debug("###################################################")
        strjidagent = str(xmppobject.boundjid.bare)
        if not sys.platform.startswith("win"):
            logger.debug(f'{plugin} for windows only')
            return
        try:
            xmppobject.sub_greenit
        except:
            xmppobject.sub_greenit = jid.JID("master_upd@pulse")
        logger.debug("========================================================")
        logger.debug(f'call {plugin} from {msg["from"]}')
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, f"num_call{action}")
        if compteurcallplugin == 0:
            logger.debug("===================== master_agent =====================")
            logger.debug("========================================================")
            read_conf_plugin_load_mach_mps(xmppobject)
            logger.debug("========================================================")
        main_plugin(xmppobject, action, sessionid, data, msg,dataerreur)
    except Exception as e:
        logger.error(f"Plugin load_agent_machine, we encountered the error {str(e)}")
        logger.error(f"We obtained the backtrace {traceback.format_exc()}")


def main_plugin(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        logger.debug("====================data=========================")
        logger.debug(json.dumps(data, indent=4))
        logger.debug("====================data=========================")

        initialise_mps(xmppobject)
    except Exception as e:
        logger.error(f"initialise_mps We obtained the backtrace {traceback.format_exc()}")


def read_conf_plugin_load_mach_mps(xmppobject):
    conf_filename = plugin["NAME"] + ".ini"
    logger.debug("==================== Configuration =========================")
    logger.debug("Configuration and Initializing plugin :% s " % plugin["NAME"])
    logger.debug("============================================================")
    try:
        pathfileconf = os.path.join(xmppobject.config.nameplugindir, conf_filename)
        if not os.path.isfile(pathfileconf):
            logger.warning(
                "Plugin %s\nConfiguration file missing %s creation :" % (plugin["NAME"], pathfileconf)
            )

            # creation fichier de configuration avec parametre par default.
            config = configparser.ConfigParser()
            # Ajout des paramètres
            config['mps'] = {'database_mps': r"C:\Program Files\Pulse\var\datamps\mps.db"}

            # Écriture dans le fichier
            with open(pathfileconf, 'w') as configfile:
                config.write(configfile)
        else:
            logger.info(f"Read Configuration in File {pathfileconf}")
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(f"{pathfileconf}.local"):
            Config.read(f"{pathfileconf}.local")
        # Vérifiez si la section 'mps' et l'option 'database_mps' existent
        if 'mps' in Config and 'database_mps' in Config['mps']:
            xmppobject.database_mps = Config['mps']['database_mps']
            logger.debug(f"Le chemin {xmppobject.database_mps} est un pah base.")
        else:
            xmppobject.database_mps = r"C:\Program Files\Pulse\var\datamps\mps.db"
        xmppobject.base_directory_base = os.path.dirname(xmppobject.database_mps)
        if os.path.exists(xmppobject.base_directory_base) and os.path.isdir(xmppobject.base_directory_base):
            logger.debug('Le chemin %s est un repertoire valide.' % xmppobject.base_directory_base)
        else:
            logger.debug("Le chemin %s n est pas un repertoire valide." % xmppobject.base_directory_base)

    except Exception as e:
        logger.error(f"We obtained the backtrace {traceback.format_exc()}")

def initialise_mps(xmppobject):
    # install du code pour la gestion de mps
    logger.debug("Initializing initialise_mps")
    xmppobject.mps_initialised = False

    # # Obtenez le chemin absolu du répertoire INFOSTMP
    # xmppobject.dir_INFOSTMP = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "lib", "INFOSTMP"))
    if sys.platform.startswith("win"):
        try:
            logger.debug(f"sysinfos {json.dumps(xmppobject.infos, indent=4)}")
            xmppobject.infos['idle_time'] = utils.InputIdleTime_seconde()
            # xmppobject.infos['get_has_battery_infos'] = utils.get_has_battery_infos()
            data={
            "action" : "greenit_initialisation",
            "sessionid" : xmppobject.infos['uuid'],
            "data" : xmppobject.infos,
            "ret": 0
            }

            xmppobject.send_message(
                    mto=xmppobject.sub_greenit, mbody=json.dumps(data), mtype="chat"
                )
            logger.debug(f"Send Grenit Infos Machines {xmppobject.infos} to {xmppobject.sub_greenit}")
            xmppobject.mps_initialised = True
            # recupere les information constante pour l'energie
            # exemple lancer 1 server udp
        except Exception as e:
            logger.error(f"initialise_mps We obtained the backtrace {traceback.format_exc()}")


def compter_elements(liste):
    # Initialisation d'un dictionnaire par défaut pour stocker les comptes
    comptes = defaultdict(int)
    # Comptage des éléments dans la liste
    for element in liste:
        comptes[element] += 1
    # Conversion du dictionnaire en un dictionnaire standard
    comptes_final = dict(comptes)
    return comptes_final

def extraire_modele(liste):
    modeles = []
    for element in liste:
        if element.startswith("DISPLAY"):
            # Si la partie commence par "DISPLAY", le modèle est la partie suivante
            modele = element.split("\\")
            if len(modele)>=2:
                modeles.append(modele[1])
    return modeles
