# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# scheduling_mps.py
"""
    Ce plugin envoi les datas vers l'agent substitut greenit_mesures en xmpp
"""
import os
import json
import logging
import sys
import traceback
import sqlite3
from sqlite3 import Error
import time
from lib.utils import set_logging_level, InputIdleTime_seconde, get_has_battery_infos
import os
import json
from datetime import datetime

logger = logging.getLogger()

plugin = { "VERSION": "1.0", "NAME": "scheduling_mps", "TYPE": "all", "SCHEDULED": True}  # fmt: skip

# La variable SCHEDULE définit la planification du plugin avec la clé "schedule" et la valeur "*/5 * * * *" signifiant toutes les 5 minutes.
# nb  -1 infinie
SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

@set_logging_level
def schedule_main(xmppobject):
    logger.debug("==============Plugin scheduled scheduling_mps==============")
    logger.debug(plugin)
    logger.debug("===========================================================")

    try:
        xmppobject.sub_greenit
    except:
        xmppobject.sub_greenit = jid.JID("master_upd@pulse")
    try:
        xmppobject.mps_initialised
    except:
        xmppobject.mps_initialised = False

    try:
        if not xmppobject.mps_initialised:
            logger.debug("Plugin scheduled scheduling_mps non initialise voir plugin plugin_load_mach_mps")
            return
        logger.debug("Plugin scheduled scheduling_mps initialise")
        base_directory_base = os.path.dirname(xmppobject.database_mps)
        list_fichier_json = sorted([x for x in os.listdir(base_directory_base) if x.endswith(".json")])
        logger.debug(f"Plugin scheduled scheduling_mps initialise {list_fichier_json}")
        if list_fichier_json:
            premier_fichier_json = os.path.join(base_directory_base, list_fichier_json[0])
            Dict_json = lire_fichier_json(premier_fichier_json)
            # supprimer_fichier(premier_fichier_json)
            # "has_battery": false, "battery_mode": 0,
            if Dict_json:
                idle_time = InputIdleTime_seconde()
                get_has_battery_infos(xmppobject)
                if xmppobject.infos['battery_mode'] == 2:
                    time_reprise = xmppobject.infos['time_reprise'][1]
                else:
                    time_reprise = xmppobject.infos['time_reprise'][0]
                if idle_time > time_reprise:
                    monitor = "OFF"
                else:
                    monitor = "ON"
                sleeping = max(time_reprise- idle_time, 0)
                logger.debug(f"sleeping {sleeping}")
                datastruct = { "conso" : Dict_json,
                               "idle" : idle_time,
                               "has_battery" :  xmppobject.infos['has_battery'],
                               "battery_mode" : xmppobject.infos['battery_mode'],
                               "monitor" : monitor,
                               "sleeping" : sleeping
                                 }
                logger.debug(f"datastruct {datastruct}")
                data={  "action" : "greenit_mesures",
                        "sessionid" : xmppobject.infos['uuid'],
                        "data" : datastruct,
                     "ret": 0,
                }
                xmppobject.send_message(
                        mto=xmppobject.sub_greenit, mbody=json.dumps(data), mtype="chat"
                    )
    except Exception:
        logger.error(f"{traceback.format_exc()}")


def lire_contenu_json(chemin_fichier):
    """
        Lit le contenu JSON d'un fichier.
        Args:
            chemin_fichier (str): Chemin vers le fichier JSON.
        Returns:
            dict: Contenu JSON sous forme de dictionnaire.
    """
    with open(chemin_fichier, 'r') as fichier:
        contenu = json.load(fichier)
    return contenu

def supprimer_fichier(chemin_fichier):
    """
    Supprime un fichier.
    Args:
        chemin_fichier (str): Chemin vers le fichier à supprimer.
        le fichier a suprimer doit etre du sufice json
    Returns:
        None
    """
    if chemin_fichier.endswith(".json"):
        os.remove(chemin_fichier)

def lire_fichier_json(chemin_fichier):
    """
    Lit le fichier JSON et renvoie son contenu sous forme de dictionnaire.
    Args:
        chemin_fichier (str): Chemin vers le fichier JSON.
    Returns:
        dict: Contenu JSON sous forme de dictionnaire.
    """
    try:
        with open(chemin_fichier, 'r') as fichier:
            contenu = json.load(fichier)
        return contenu
    except json.JSONDecodeError as e:
        logger.error(f"Erreur JSON lors de la lecture du fichier {chemin_fichier}: {e}")
        return {}
