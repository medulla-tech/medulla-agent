# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Plugin de chargement pour le traitement periodique de la file reset sur substitut.

Comportement :
- Appele une seule fois au demarrage quand il est present dans pluginliststart.
- Lit la configuration dans loadresetagent.ini.
- Lie dynamiquement la methode de scan de file sur objectxmpp.
- Enregistre une tache periodique de scheduler pour traiter la file reset_machine.

Ce plugin est opt-in : l'activer uniquement sur les substituts ou le
traitement automatique de file est requis.
"""

import os
import json
import types
import logging
import traceback
import configparser

from lib.utils import call_plugin, getRandomName

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "loadresetagent", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    """Configure et demarre le scheduler de file reset une seule fois."""
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

        if compteurcallplugin == 0:
            read_conf_loadresetagent(objectxmpp)
            if objectxmpp.reset_queue_scan_enabled:
                objectxmpp.schedule(
                    "resetagent_queue_scan",
                    objectxmpp.reset_queue_scan_interval,
                    objectxmpp.resetagent_queue_scan,
                    repeat=True,
                )
                logger.info(
                    "[LOADRESETAGENT] Scheduler actif : toutes les %s secondes"
                    % objectxmpp.reset_queue_scan_interval
                )
            else:
                logger.info("[LOADRESETAGENT] Scheduler desactive par configuration")
    except Exception as e:
        logger.error("Erreur plugin loadresetagent : %s" % str(e))
        logger.error("Traceback :\n%s" % traceback.format_exc())


def resetagent_queue_scan(self):
    """Declenche plugin_resetagent en mode queue_process."""
    try:
        payload = {"mode": "queue_process"}
        dataerreur = {
            "action": "resultresetagent",
            "sessionid": getRandomName(6, "reseterr"),
            "ret": 255,
            "base64": False,
            "data": {"msg": "ERREUR: traitement de file resetagent"},
        }
        msg = {"from": self.boundjid.bare, "to": self.boundjid.bare, "type": "chat"}
        module = "%s/plugin_resetagent.py" % self.modulepath

        call_plugin(
            module,
            self,
            "resetagent",
            getRandomName(6, "resetq"),
            payload,
            msg,
            0,
            dataerreur,
        )
    except Exception as e:
        logger.error("[LOADRESETAGENT] Queue scan failed: %s" % str(e))
        logger.error(traceback.format_exc())


def read_conf_loadresetagent(objectxmpp):
    """Charge la configuration et lie les methodes runtime."""
    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)

    objectxmpp.reset_queue_scan_enabled = True
    objectxmpp.reset_queue_scan_interval = 60

    if not os.path.isfile(pathfileconf):
        logger.warning(
            "Fichier de configuration absent pour %s : %s. Valeurs par defaut appliquees."
            % (plugin["NAME"], pathfileconf)
        )
    else:
        conf = configparser.ConfigParser()
        conf.read(pathfileconf)

        if os.path.exists(pathfileconf + ".local"):
            conf.read(pathfileconf + ".local")

        if conf.has_option("parameters", "reset_queue_scan_enabled"):
            objectxmpp.reset_queue_scan_enabled = conf.getboolean(
                "parameters", "reset_queue_scan_enabled"
            )

        if conf.has_option("parameters", "reset_queue_scan_interval"):
            objectxmpp.reset_queue_scan_interval = conf.getint(
                "parameters", "reset_queue_scan_interval"
            )

    # Borne minimale de securite pour eviter un flood accidentel.
    if objectxmpp.reset_queue_scan_interval < 10:
        logger.warning(
            "reset_queue_scan_interval too low (%s). Forcing 10 seconds."
            % objectxmpp.reset_queue_scan_interval
        )
        objectxmpp.reset_queue_scan_interval = 10

    objectxmpp.resetagent_queue_scan = types.MethodType(
        resetagent_queue_scan, objectxmpp
    )
    objectxmpp.plugin_loadresetagent = types.MethodType(
        plugin_loadresetagent, objectxmpp
    )

    logger.debug(
        "[LOADRESETAGENT] enabled=%s interval=%s"
        % (objectxmpp.reset_queue_scan_enabled, objectxmpp.reset_queue_scan_interval)
    )


def plugin_loadresetagent(self, msg, data):
    """Wrapper de compatibilite pour les appels plugin par message."""
    if isinstance(data, dict) and data.get("mode") == "queue_process":
        self.resetagent_queue_scan()
        return True
    return False
