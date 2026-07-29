# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
plugin_resetagent (substitut) - Gestionnaire de reinitialisation des agents.

Ce plugin cote master substitut gere la table `reset_machine` de la base
xmppmaster. Les machines en attente de reset y sont stockees. A chaque
cycle, les machines presentes (en ligne) recoivent l'ordre de reset et sont
supprimees de la table. Les machines hors ligne sont conservees et un
compteur de tentatives est incremente.

Deux modes de declenchement :
  1. Appel direct (QA, API) : payload {"jid": "machine@...", "reason": "..."}
     -> ajoute en table si hors ligne, envoie directement si en ligne.
  2. Sans payload : traite toute la table reset_machine.

SQL de creation de la table (applique automatiquement par SQLAlchemy) :
  CREATE TABLE reset_machine (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    jid         VARCHAR(255) NOT NULL UNIQUE,
    reason      VARCHAR(255) NOT NULL DEFAULT '',
    date_request DATETIME,
    nb_attempt  INT NOT NULL DEFAULT 0
  );
"""

import json
import logging
import traceback
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import getRandomName

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.1", "NAME": "resetagent", "TYPE": "substitute"}  # fmt: skip


def _send_reset(xmppobject, jid, reason=""):
    """Envoie l'ordre de reset a la machine ciblee."""
    msg = {
        "action": "resetagent",
        "sessionid": getRandomName(5, "resetagent"),
        "data": {"reason": reason},
        "ret": 0,
        "base64": False,
    }
    xmppobject.send_message(mto=jid, mbody=json.dumps(msg), mtype="chat")
    logger.info("[RESETAGENT-SUB] Ordre de reset envoye a %s (raison: %s)" % (jid, reason or "non specifiee"))


def action(xmppobject, action, sessionid, data, message, ret=None, dataobj=None):
    """
    Traite une demande de reinitialisation d'agent.

    Accepte :
    - Appel direct : {"jid": "machine@...", "reason": "..."}
    - Appel liste QA : ["machine@...", {}, ["raison"]]
    - Sans payload : traite toute la table reset_machine
    """
    logger.debug("[RESETAGENT-SUB] Appel depuis %s" % message["from"])

    jid_target = ""
    reason = ""

    # --- Parsing du payload ---
    if isinstance(data, list) and len(data) >= 1:
        jid_target = str(data[0]).strip()
        reason = str(data[2][0]) if len(data) >= 3 and isinstance(data[2], list) else ""
    elif isinstance(data, dict):
        jid_target = str(data.get("jid", "")).strip()
        reason = str(data.get("reason", "")).strip()

    # --- Appel direct avec JID ---
    if jid_target:
        try:
            present = XmppMasterDatabase().getPresencejid(jid_target)
        except Exception:
            present = True

        if present:
            _send_reset(xmppobject, jid_target, reason)
            # Pas d'ajout en table : envoye directement
        else:
            logger.warning(
                "[RESETAGENT-SUB] %s hors ligne, ajout en table reset_machine" % jid_target
            )
            try:
                XmppMasterDatabase().reset_machine_add(jid_target, reason)
            except Exception:
                logger.error("[RESETAGENT-SUB] Impossible d'ajouter en table")
                logger.error(traceback.format_exc())
        return

    # --- Traitement de la table reset_machine ---
    try:
        queue = XmppMasterDatabase().reset_machine_get_all()
    except Exception:
        logger.error("[RESETAGENT-SUB] Impossible de lire la table reset_machine")
        logger.error(traceback.format_exc())
        return

    if not queue:
        logger.debug("[RESETAGENT-SUB] Table reset_machine vide")
        return

    logger.info("[RESETAGENT-SUB] %d machine(s) en attente de reset" % len(queue))

    for entry in queue:
        jid    = entry.get("jid", "").strip()
        r      = entry.get("reason", "")
        nb_att = entry.get("nb_attempt", 0)

        if not jid:
            continue

        try:
            present = XmppMasterDatabase().getPresencejid(jid)
        except Exception:
            present = False

        if present:
            try:
                _send_reset(xmppobject, jid, r)
                XmppMasterDatabase().reset_machine_delete(jid)
                logger.info("[RESETAGENT-SUB] %s reinitialise et retire de la table" % jid)
            except Exception:
                logger.error("[RESETAGENT-SUB] Echec reset pour %s" % jid)
                logger.error(traceback.format_exc())
                XmppMasterDatabase().reset_machine_increment_attempt(jid)
        else:
            logger.debug(
                "[RESETAGENT-SUB] %s hors ligne (tentative %d), conserve en table" % (jid, nb_att)
            )
            XmppMasterDatabase().reset_machine_increment_attempt(jid)

import json
import logging
import os
import traceback
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import getRandomName

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "resetagent", "TYPE": "substitute"}  # fmt: skip


def _queue_path(xmppobject):
    """Chemin du fichier de file d'attente."""
    return os.path.join(
        xmppobject.config.pathdirconffile, "resetagent_queue.json"
    )


def _load_queue(xmppobject):
    """Charge la file d'attente depuis le fichier JSON."""
    path = _queue_path(xmppobject)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.error("[RESETAGENT-SUB] Impossible de lire la file : %s" % e)
        return []


def _save_queue(xmppobject, queue):
    """Sauvegarde la file d'attente dans le fichier JSON."""
    path = _queue_path(xmppobject)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
    except Exception as e:
        logger.error("[RESETAGENT-SUB] Impossible de sauvegarder la file : %s" % e)


def _send_reset(xmppobject, jid, reason=""):
    """Envoie l'ordre de reset a la machine ciblee."""
    msg = {
        "action": "resetagent",
        "sessionid": getRandomName(5, "resetagent"),
        "data": {"reason": reason},
        "ret": 0,
        "base64": False,
    }
    xmppobject.send_message(mto=jid, mbody=json.dumps(msg), mtype="chat")
    logger.info("[RESETAGENT-SUB] Ordre de reset envoye a %s (raison: %s)" % (jid, reason or "non specifiee"))


def action(xmppobject, action, sessionid, data, message, ret=None, dataobj=None):
    """
    Traite une demande de reinitialisation d'agent.

    Accepte :
    - Appel direct : {"jid": "machine@...", "reason": "..."}
    - Appel liste QA : ["machine@...", {}, ["raison"]]
    - Sans payload : traite uniquement la file d'attente JSON
    """
    logger.debug("[RESETAGENT-SUB] Appel depuis %s" % message["from"])

    jid_target = ""
    reason = ""

    # --- Parsing du payload ---
    if isinstance(data, list) and len(data) >= 1:
        jid_target = str(data[0]).strip()
        reason = str(data[2][0]) if len(data) >= 3 and isinstance(data[2], list) else ""
    elif isinstance(data, dict):
        jid_target = str(data.get("jid", "")).strip()
        reason = str(data.get("reason", "")).strip()

    # --- Appel direct avec JID ---
    if jid_target:
        try:
            present = XmppMasterDatabase().getPresencejid(jid_target)
        except Exception:
            present = True  # si la DB n'est pas accessible, on tente quand meme

        if present:
            _send_reset(xmppobject, jid_target, reason)
        else:
            logger.warning(
                "[RESETAGENT-SUB] Machine %s hors ligne, ajout en file d'attente" % jid_target
            )
            queue = _load_queue(xmppobject)
            # Eviter les doublons
            if not any(e.get("jid") == jid_target for e in queue):
                queue.append({"jid": jid_target, "reason": reason})
                _save_queue(xmppobject, queue)
        return

    # --- Traitement de la file d'attente ---
    queue = _load_queue(xmppobject)
    if not queue:
        logger.debug("[RESETAGENT-SUB] File d'attente vide")
        return

    logger.info("[RESETAGENT-SUB] Traitement de la file : %d machine(s)" % len(queue))
    remaining = []
    for entry in queue:
        jid = entry.get("jid", "").strip()
        r   = entry.get("reason", "")
        if not jid:
            continue
        try:
            present = XmppMasterDatabase().getPresencejid(jid)
        except Exception:
            present = False

        if present:
            try:
                _send_reset(xmppobject, jid, r)
            except Exception:
                logger.error("[RESETAGENT-SUB] Echec envoi reset a %s" % jid)
                logger.error(traceback.format_exc())
                remaining.append(entry)
        else:
            logger.debug("[RESETAGENT-SUB] %s hors ligne, conserve en file" % jid)
            remaining.append(entry)

    _save_queue(xmppobject, remaining)
    logger.info(
        "[RESETAGENT-SUB] File traitee : %d envoyes, %d en attente"
        % (len(queue) - len(remaining), len(remaining))
    )
